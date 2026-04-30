use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rand::Rng;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::protocol::{
    decode_envelope, decode_ids_payload, encode_envelope, encode_ids_payload, frame_tcp,
    next_tcp_frame, Envelope, FLAG_BROADCAST, FLAG_HAS_DEST_ENDPOINT, FLAG_HAS_DEST_STEAM_ID,
    MSG_DISCONNECT, MSG_HEARTBEAT, MSG_HELLO, MSG_REGISTER, MSG_RELIABLE, MSG_UNRELIABLE,
    MSG_WELCOME,
};
use crate::ratelimit::Limiter;

#[derive(Clone)]
pub struct Server {
    cfg: Config,
    tcp_listener: Arc<TcpListener>,
    udp_socket: Arc<UdpSocket>,
    limiter: Arc<Limiter>,
    state: Arc<Mutex<ServerState>>,
}

struct ServerState {
    clients: HashMap<u64, Arc<Client>>,
    by_primary: HashMap<String, u64>,
    by_steam_id: HashMap<String, u64>,
    by_token: HashMap<u64, u64>,
    by_endpoint: HashMap<EndpointKey, u64>,
    stale_ids: HashMap<String, DisconnectHint>,
    stale_endpoints: HashMap<EndpointKey, DisconnectHint>,
    next_ip: u32,
    next_client_id: u64,
    reliable_routed: usize,
    unreliable_routed: usize,
    broadcast_routed: usize,
    routed_bytes: usize,
}

struct Client {
    stream: Arc<Mutex<TcpStream>>,
    data: Mutex<ClientData>,
}

struct ClientData {
    app_id: u32,
    primary_id: u64,
    listen_ids: HashSet<u64>,
    listen_port: u16,
    token: u64,
    virtual_ip: u32,
    virtual_port: u16,
    udp_addr: Option<SocketAddr>,
    last_seen: Instant,
    closing: bool,
}

#[derive(Clone, Copy, Eq)]
struct EndpointKey {
    app_id: u32,
    ip: u32,
    port: u16,
}

impl PartialEq for EndpointKey {
    fn eq(&self, other: &Self) -> bool {
        self.app_id == other.app_id && self.ip == other.ip && self.port == other.port
    }
}

impl Hash for EndpointKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.app_id.hash(state);
        self.ip.hash(state);
        self.port.hash(state);
    }
}

struct ClientSnapshot {
    app_id: u32,
    primary_id: u64,
    virtual_ip: u32,
    virtual_port: u16,
}

struct RemovedClient {
    app_id: u32,
    primary_id: u64,
    listen_port: u16,
    listen_ids: Vec<u64>,
    virtual_ip: u32,
    virtual_port: u16,
    notify: Vec<u64>,
    stream: Arc<Mutex<TcpStream>>,
}

#[derive(Clone)]
struct DisconnectHint {
    app_id: u32,
    listen_port: u16,
    listen_ids: Vec<u64>,
    virtual_ip: u32,
    virtual_port: u16,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug)]
struct Replacement {
    client_id: u64,
    suppress_disconnect: bool,
}

impl Server {
    pub fn new(cfg: Config) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind((cfg.listen_address.as_str(), cfg.tcp_port))?;
        tcp_listener.set_nonblocking(true)?;

        let udp_socket = UdpSocket::bind((cfg.listen_address.as_str(), cfg.udp_port))?;
        udp_socket.set_read_timeout(Some(Duration::from_secs(1)))?;

        Ok(Self {
            limiter: Arc::new(Limiter::new(cfg.rate_limit_per_second, cfg.rate_burst)),
            state: Arc::new(Mutex::new(ServerState {
                clients: HashMap::new(),
                by_primary: HashMap::new(),
                by_steam_id: HashMap::new(),
                by_token: HashMap::new(),
                by_endpoint: HashMap::new(),
                stale_ids: HashMap::new(),
                stale_endpoints: HashMap::new(),
                next_ip: 1,
                next_client_id: 1,
                reliable_routed: 0,
                unreliable_routed: 0,
                broadcast_routed: 0,
                routed_bytes: 0,
            })),
            tcp_listener: Arc::new(tcp_listener),
            udp_socket: Arc::new(udp_socket),
            cfg,
        })
    }

    pub fn run(&self, shutdown: Arc<AtomicBool>) -> io::Result<()> {
        let accept_server = self.clone();
        let accept_shutdown = Arc::clone(&shutdown);
        let accept_thread = thread::spawn(move || accept_server.accept_loop(accept_shutdown));

        let udp_server = self.clone();
        let udp_shutdown = Arc::clone(&shutdown);
        let udp_thread = thread::spawn(move || udp_server.udp_loop(udp_shutdown));

        let cleanup_server = self.clone();
        let cleanup_shutdown = Arc::clone(&shutdown);
        let cleanup_thread = thread::spawn(move || cleanup_server.cleanup_loop(cleanup_shutdown));

        accept_thread.join().unwrap()?;
        udp_thread.join().unwrap()?;
        cleanup_thread.join().unwrap()?;
        Ok(())
    }

    fn accept_loop(&self, shutdown: Arc<AtomicBool>) -> io::Result<()> {
        while !shutdown.load(Ordering::SeqCst) {
            match self.tcp_listener.accept() {
                Ok((stream, _remote)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                    let server = self.clone();
                    let child_shutdown = Arc::clone(&shutdown);
                    thread::spawn(move || server.handle_tcp_conn(stream, child_shutdown));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    fn handle_tcp_conn(&self, mut conn: TcpStream, shutdown: Arc<AtomicBool>) {
        let remote = conn.peer_addr().ok();
        let mut bound_client: Option<u64> = None;
        let mut buffer = Vec::new();
        let mut tmp = vec![0u8; 4096];

        loop {
            match conn.read(&mut tmp) {
                Ok(0) => {
                    info!(remote = ?remote, bound_client, "tcp connection closed by peer");
                    break;
                }
                Ok(n) => {
                    buffer.extend_from_slice(&tmp[..n]);
                    while let Some(frame) = next_tcp_frame(&mut buffer) {
                        if frame.len() >= 8 {
                            let msg_type = u16::from_le_bytes([frame[6], frame[7]]);
                            if msg_type == MSG_HELLO || msg_type == MSG_REGISTER {
                                debug!(
                                    remote = ?remote,
                                    msg_type,
                                    frame_len = frame.len(),
                                    frame_hex = %hex_bytes(&frame),
                                    "registration frame received"
                                );
                            }
                        }
                        let env = match decode_envelope(&frame) {
                            Ok(env) => env,
                            Err(err) => {
                                warn!(remote = ?remote, error = %err, "drop invalid tcp frame");
                                continue;
                            }
                        };
                        match self.handle_tcp_envelope(&conn, env, bound_client) {
                            Ok(next) => bound_client = next,
                            Err(err) => {
                                warn!(remote = ?remote, error = %err, "tcp envelope handling failed");
                                self.remove_client(bound_client, "tcp closed");
                                return;
                            }
                        }
                    }
                }
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut =>
                {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                }
                Err(err) => {
                    warn!(remote = ?remote, bound_client, error = %err, "tcp read failed");
                    break;
                }
            }
        }

        self.remove_client(bound_client, "tcp closed");
    }

    fn handle_tcp_envelope(
        &self,
        conn: &TcpStream,
        env: Envelope,
        bound_client: Option<u64>,
    ) -> io::Result<Option<u64>> {
        let remote = conn.peer_addr()?;
        if !self.limiter.allow(remote.ip(), Instant::now()) {
            warn!(remote = %remote, "tcp packet rate limited");
            return Err(io::Error::new(io::ErrorKind::Other, "rate limited"));
        }

        match env.msg_type {
            MSG_HELLO | MSG_REGISTER => self.register_client(conn, env, bound_client),
            MSG_HEARTBEAT => {
                if let Some(client_id) = bound_client {
                    self.touch_client(client_id, Instant::now());
                    if let Some(app_id) = self.client_app_id(client_id) {
                        self.send_tcp(client_id, Envelope::heartbeat(app_id))?;
                    }
                }
                Ok(bound_client)
            }
            MSG_RELIABLE => {
                let client_id = bound_client.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Other, "reliable packet before hello")
                })?;
                self.touch_client(client_id, Instant::now());
                self.route_envelope(client_id, env, true);
                Ok(Some(client_id))
            }
            _ => Ok(bound_client),
        }
    }

    fn udp_loop(&self, shutdown: Arc<AtomicBool>) -> io::Result<()> {
        let mut buf = vec![0u8; self.cfg.max_packet_size.saturating_mul(2)];
        while !shutdown.load(Ordering::SeqCst) {
            match self.udp_socket.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    if !self.limiter.allow(addr.ip(), Instant::now()) {
                        warn!(remote = %addr, "udp packet rate limited");
                        continue;
                    }

                    let env = match decode_envelope(&buf[..n]) {
                        Ok(env) => env,
                        Err(err) => {
                            warn!(remote = %addr, error = %err, "drop invalid udp frame");
                            continue;
                        }
                    };

                    let client_id = match self.lookup_client_by_token(env.session_token) {
                        Some(id) => id,
                        None => {
                            warn!(
                                remote = %addr,
                                msg_type = env.msg_type,
                                app_id = env.app_id,
                                source_id = env.source_id,
                                "udp packet with unknown token"
                            );
                            continue;
                        }
                    };

                    self.update_udp_addr(client_id, addr, Instant::now());
                    match env.msg_type {
                        MSG_HEARTBEAT => {
                            if let Some(app_id) = self.client_app_id(client_id) {
                                let _ = self.send_udp(client_id, Envelope::heartbeat(app_id));
                            }
                        }
                        MSG_UNRELIABLE => self.route_envelope(client_id, env, false),
                        _ => {}
                    }
                }
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    fn cleanup_loop(&self, shutdown: Arc<AtomicBool>) -> io::Result<()> {
        let mut next_info = Instant::now() + Duration::from_secs(60);
        let mut next_debug = Instant::now() + Duration::from_secs(5);
        while !shutdown.load(Ordering::SeqCst) {
            thread::sleep(self.cfg.cleanup_interval);
            let now = Instant::now();
            let expired: Vec<u64> = {
                let state = self.state.lock().unwrap();
                state
                    .clients
                    .iter()
                    .filter_map(|(id, client)| {
                        let data = client.data.lock().unwrap();
                        if now.duration_since(data.last_seen) > self.cfg.session_timeout {
                            Some(*id)
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            for client_id in expired {
                self.remove_client(Some(client_id), "timeout");
            }

            self.cleanup_disconnect_hints(now);
            let before = now
                .checked_sub(self.cfg.session_timeout.saturating_mul(2))
                .unwrap_or(now);
            self.limiter.cleanup(before);

            if now >= next_info {
                self.log_client_status();
                next_info = now + Duration::from_secs(60);
            }
            if now >= next_debug {
                self.flush_traffic_debug();
                next_debug = now + Duration::from_secs(5);
            }
        }
        Ok(())
    }

    fn register_client(
        &self,
        conn: &TcpStream,
        env: Envelope,
        bound_client: Option<u64>,
    ) -> io::Result<Option<u64>> {
        let (mut listen_port, mut ids) = decode_ids_payload(&env.payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if ids.is_empty() && env.source_id != 0 {
            ids.push(env.source_id);
        }
        if ids.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "registration missing ids",
            ));
        }
        if listen_port == 0 {
            listen_port = 47_584;
        }

        let primary_id = if env.source_id != 0 {
            env.source_id
        } else {
            ids[0]
        };
        let key = steam_key(env.app_id, primary_id);
        let now = Instant::now();
        let stream = Arc::new(Mutex::new(conn.try_clone()?));
        let mut replacements = Vec::new();
        let current_id;
        let mut send_welcome = env.msg_type == MSG_HELLO;

        info!(
            remote = ?conn.peer_addr().ok(),
            msg_type = env.msg_type,
            app_id = env.app_id,
            raw_source_id = %env.source_id,
            payload_ids = ?ids,
            bound_client,
            "registration received"
        );

        if env.source_id != 0 && ids.first().copied() != Some(env.source_id) {
            warn!(
                remote = ?conn.peer_addr().ok(),
                app_id = env.app_id,
                msg_type = env.msg_type,
                raw_source_id = %env.source_id,
                payload_ids = ?ids,
                bound_client,
                "registration source_id differs from first payload id"
            );
        }

        {
            let mut state = self.state.lock().unwrap();
            let current = state.by_primary.get(&key).copied();
            let alias_handoff =
                find_handoff_owner_locked(&state, env.app_id, primary_id, &ids, bound_client);
            info!(
                remote = ?conn.peer_addr().ok(),
                app_id = env.app_id,
                primary_id = %primary_id,
                current_primary_owner = ?current,
                bound_client,
                "registration ownership lookup"
            );
            let client_id = if let Some(bound_id) = bound_client {
                if let Some(current_id) = current {
                    if current_id != bound_id {
                        let suppress_disconnect =
                            client_has_primary_locked(&state, current_id, primary_id);
                        add_replacement(&mut replacements, current_id, suppress_disconnect);
                    }
                }
                bound_id
            } else if let Some(current_id) = current {
                let preserved_endpoint = client_endpoint_locked(&state, current_id);
                add_replacement(&mut replacements, current_id, true);
                self.insert_client_locked(
                    &mut state,
                    &stream,
                    env.app_id,
                    primary_id,
                    listen_port,
                    preserved_endpoint,
                    now,
                )
            } else if let Some(owner_id) = alias_handoff {
                let preserved_endpoint = client_endpoint_locked(&state, owner_id);
                add_replacement(&mut replacements, owner_id, true);
                self.insert_client_locked(
                    &mut state,
                    &stream,
                    env.app_id,
                    primary_id,
                    listen_port,
                    preserved_endpoint,
                    now,
                )
            } else {
                self.insert_client_locked(
                    &mut state,
                    &stream,
                    env.app_id,
                    primary_id,
                    listen_port,
                    None,
                    now,
                )
            };
            if send_welcome || bound_client.is_none() {
                send_welcome = true;
            }

            let client = state.clients.get(&client_id).unwrap().clone();
            let mut data = client.data.lock().unwrap();

            let old_primary_key = steam_key(data.app_id, data.primary_id);
            let old_endpoint_key = EndpointKey {
                app_id: data.app_id,
                ip: data.virtual_ip,
                port: data.virtual_port,
            };

            if old_primary_key != key {
                if state.by_primary.get(&old_primary_key).copied() == Some(client_id) {
                    state.by_primary.remove(&old_primary_key);
                }
            }
            if state.by_endpoint.get(&old_endpoint_key).copied() == Some(client_id) {
                state.by_endpoint.remove(&old_endpoint_key);
            }

            for id in &data.listen_ids {
                let listen_key = steam_key(data.app_id, *id);
                if state.by_steam_id.get(&listen_key).copied() == Some(client_id) {
                    state.by_steam_id.remove(&listen_key);
                }
            }

            data.app_id = env.app_id;
            data.primary_id = primary_id;
            data.listen_port = listen_port;
            if data.virtual_port == 0 {
                data.virtual_port = listen_port;
            }
            data.last_seen = now;
            data.closing = false;
            data.listen_ids = ids.iter().copied().collect();

            for id in &ids {
                let listen_key = steam_key(env.app_id, *id);
                match state.by_steam_id.get(&listen_key).copied() {
                    Some(owner_id) if owner_id != client_id && *id == primary_id => {
                        let suppress_disconnect =
                            client_has_primary_locked(&state, owner_id, primary_id);
                        add_replacement(&mut replacements, owner_id, suppress_disconnect);
                        state.by_steam_id.insert(listen_key, client_id);
                    }
                    Some(owner_id)
                        if owner_id != client_id
                            && is_individual_steam_id(*id)
                            && alias_handoff == Some(owner_id) =>
                    {
                        add_replacement(&mut replacements, owner_id, true);
                        state.by_steam_id.insert(listen_key, client_id);
                    }
                    Some(_) => {}
                    None => {
                        state.by_steam_id.insert(listen_key, client_id);
                    }
                }
            }

            state.by_primary.insert(key, client_id);
            state.by_token.insert(data.token, client_id);
            let current_endpoint_key = EndpointKey {
                app_id: data.app_id,
                ip: data.virtual_ip,
                port: data.virtual_port,
            };
            state.by_endpoint.insert(current_endpoint_key, client_id);
            state.stale_endpoints.remove(&current_endpoint_key);
            for id in &ids {
                state.stale_ids.remove(&steam_key(data.app_id, *id));
            }
            current_id = client_id;
        }

        if !replacements.is_empty() {
            info!(
                remote = ?conn.peer_addr().ok(),
                app_id = env.app_id,
                primary_id = %primary_id,
                current_id,
                replaced = ?replacements.iter().map(|replacement| replacement.client_id).collect::<Vec<_>>(),
                "registration will replace existing clients"
            );
        }

        for replacement in replacements {
            if replacement.client_id != current_id {
                self.remove_client_with_options(
                    Some(replacement.client_id),
                    "replaced",
                    replacement.suppress_disconnect,
                );
            }
        }

        if send_welcome {
            let welcome = {
                let state = self.state.lock().unwrap();
                let client = state.clients.get(&current_id).unwrap();
                let data = client.data.lock().unwrap();
                Envelope {
                    msg_type: MSG_WELCOME,
                    flags: 0,
                    app_id: data.app_id,
                    source_id: data.primary_id,
                    dest_id: 0,
                    source_virtual_ip: data.virtual_ip,
                    source_virtual_port: data.virtual_port,
                    dest_virtual_ip: 0,
                    dest_virtual_port: 0,
                    session_token: data.token,
                    payload: Vec::new(),
                }
            };
            self.send_tcp(current_id, welcome)?;
        }

        info!(
            remote = ?conn.peer_addr().ok(),
            app_id = env.app_id,
            primary_id = %primary_id,
            listen_ids = ?ids,
            listen_port,
            virtual_endpoint = %self.client_snapshot(current_id).map(|c| format_virtual_endpoint(c.virtual_ip, c.virtual_port)).unwrap_or_else(|| "-".to_string()),
            udp_remote = %self.client_udp_addr(current_id),
            "client connected"
        );

        Ok(Some(current_id))
    }

    fn insert_client_locked(
        &self,
        state: &mut ServerState,
        stream: &Arc<Mutex<TcpStream>>,
        app_id: u32,
        primary_id: u64,
        listen_port: u16,
        preserved_endpoint: Option<(u32, u16)>,
        now: Instant,
    ) -> u64 {
        let id = state.next_client_id;
        state.next_client_id += 1;
        let token = random_u64();
        let (virtual_ip, virtual_port) =
            preserved_endpoint.unwrap_or_else(|| (allocate_virtual_ip(state), listen_port));
        state.clients.insert(
            id,
            Arc::new(Client {
                stream: Arc::clone(stream),
                data: Mutex::new(ClientData {
                    app_id,
                    primary_id,
                    listen_ids: HashSet::new(),
                    listen_port,
                    token,
                    virtual_ip,
                    virtual_port,
                    udp_addr: None,
                    last_seen: now,
                    closing: false,
                }),
            }),
        );
        id
    }

    fn route_envelope(&self, sender_id: u64, mut env: Envelope, reliable: bool) {
        let sender = match self.client_snapshot(sender_id) {
            Some(sender) => sender,
            None => return,
        };

        env.app_id = sender.app_id;
        if env.source_id == 0 {
            env.source_id = sender.primary_id;
        }
        env.source_virtual_ip = sender.virtual_ip;
        env.source_virtual_port = sender.virtual_port;
        env.session_token = 0;

        if env.flags & FLAG_BROADCAST != 0 {
            let targets = self.clients_for_app(sender.app_id);
            let mut recipients = 0usize;
            for target in targets {
                if target != sender_id {
                    self.deliver(target, env.clone(), false);
                    recipients += 1;
                }
            }
            self.record_routed_packet(false, true, env.payload.len(), recipients);
            return;
        }

        let target_id = self.resolve_target(sender.app_id, &env);
        let Some(target_id) = target_id else {
            self.maybe_send_disconnect_hint(sender_id, sender.app_id, &env);
            warn!(
                app_id = sender.app_id,
                source_id = %env.source_id,
                dest_id = %env.dest_id,
                dest_virtual_ip = env.dest_virtual_ip,
                dest_virtual_port = env.dest_virtual_port,
                flags = env.flags,
                reliable,
                "route target not found"
            );
            return;
        };

        self.record_routed_packet(reliable, false, env.payload.len(), 1);
        self.deliver(target_id, env, reliable);
    }

    fn deliver(&self, target_id: u64, env: Envelope, reliable: bool) {
        if reliable {
            let _ = self.send_tcp(target_id, env);
            return;
        }

        match self.send_udp(target_id, env.clone()) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AddrNotAvailable => {
                debug!(
                    target_id,
                    msg_type = env.msg_type,
                    "falling back to tcp delivery before udp endpoint is learned"
                );
                let _ = self.send_tcp(target_id, env);
            }
            Err(_) => {}
        }
    }

    fn send_tcp(&self, target_id: u64, env: Envelope) -> io::Result<()> {
        let client = {
            let state = self.state.lock().unwrap();
            state.clients.get(&target_id).cloned()
        };
        let Some(client) = client else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "missing client"));
        };

        let frame = frame_tcp(&encode_envelope(&env));
        let mut stream = client.stream.lock().unwrap();
        let remote = stream.peer_addr().ok();
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        match stream.write_all(&frame) {
            Ok(()) => Ok(()),
            Err(err) => {
                drop(stream);
                warn!(target_id, remote = ?remote, msg_type = env.msg_type, error = %err, "tcp delivery failed");
                self.remove_client(Some(target_id), "tcp write failed");
                Err(err)
            }
        }
    }

    fn send_udp(&self, target_id: u64, env: Envelope) -> io::Result<()> {
        let addr = {
            let state = self.state.lock().unwrap();
            let Some(client) = state.clients.get(&target_id) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "missing client"));
            };
            let data = client.data.lock().unwrap();
            data.udp_addr
        };
        let Some(addr) = addr else {
            warn!(
                target_id,
                msg_type = env.msg_type,
                "udp delivery skipped, missing udp address"
            );
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "missing udp addr",
            ));
        };

        let payload = encode_envelope(&env);
        self.udp_socket.send_to(&payload, addr)?;
        Ok(())
    }

    fn remove_client(&self, target_id: Option<u64>, reason: &str) {
        self.remove_client_with_options(target_id, reason, false);
    }

    fn remove_client_with_options(
        &self,
        target_id: Option<u64>,
        reason: &str,
        suppress_disconnect: bool,
    ) {
        let Some(target_id) = target_id else {
            return;
        };

        let removed = {
            let mut state = self.state.lock().unwrap();
            let Some(client) = state.clients.get(&target_id).cloned() else {
                return;
            };
            let mut data = client.data.lock().unwrap();
            if data.closing {
                return;
            }
            data.closing = true;

            state.clients.remove(&target_id);
            let primary_key = steam_key(data.app_id, data.primary_id);
            if state.by_primary.get(&primary_key).copied() == Some(target_id) {
                state.by_primary.remove(&primary_key);
            }
            if state.by_token.get(&data.token).copied() == Some(target_id) {
                state.by_token.remove(&data.token);
            }
            let endpoint_key = EndpointKey {
                app_id: data.app_id,
                ip: data.virtual_ip,
                port: data.virtual_port,
            };
            if state.by_endpoint.get(&endpoint_key).copied() == Some(target_id) {
                state.by_endpoint.remove(&endpoint_key);
            }
            for id in &data.listen_ids {
                let key = steam_key(data.app_id, *id);
                if state.by_steam_id.get(&key).copied() == Some(target_id) {
                    state.by_steam_id.remove(&key);
                    if let Some(owner_id) = find_live_listen_owner(&state, data.app_id, *id) {
                        state.by_steam_id.insert(key, owner_id);
                    }
                }
            }

            let notify = if suppress_disconnect {
                Vec::new()
            } else {
                state
                    .clients
                    .iter()
                    .filter_map(|(id, peer)| {
                        let peer_data = peer.data.lock().unwrap();
                        (peer_data.app_id == data.app_id).then_some(*id)
                    })
                    .collect()
            };

            let stale_listen_ids: Vec<u64> = sorted_ids(&data.listen_ids)
                .into_iter()
                .filter(|id| {
                    state
                        .by_steam_id
                        .get(&steam_key(data.app_id, *id))
                        .is_none()
                })
                .collect();
            let endpoint_is_stale = state.by_endpoint.get(&endpoint_key).is_none();

            let hint = DisconnectHint {
                app_id: data.app_id,
                listen_port: data.listen_port,
                listen_ids: stale_listen_ids,
                virtual_ip: data.virtual_ip,
                virtual_port: data.virtual_port,
                expires_at: Instant::now() + self.cfg.session_timeout,
            };
            if !suppress_disconnect {
                if endpoint_is_stale {
                    state.stale_endpoints.insert(
                        EndpointKey {
                            app_id: hint.app_id,
                            ip: hint.virtual_ip,
                            port: hint.virtual_port,
                        },
                        hint.clone(),
                    );
                }
                for id in &hint.listen_ids {
                    state
                        .stale_ids
                        .insert(steam_key(hint.app_id, *id), hint.clone());
                }
            }

            RemovedClient {
                app_id: data.app_id,
                primary_id: data.primary_id,
                listen_port: data.listen_port,
                listen_ids: hint.listen_ids.clone(),
                virtual_ip: data.virtual_ip,
                virtual_port: data.virtual_port,
                notify,
                stream: Arc::clone(&client.stream),
            }
        };

        let tcp_remote = removed
            .stream
            .lock()
            .unwrap()
            .peer_addr()
            .ok()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "-".to_string());
        let _ = removed.stream.lock().unwrap().shutdown(Shutdown::Both);
        if !removed.notify.is_empty() && !removed.listen_ids.is_empty() {
            let disconnect = Envelope {
                msg_type: MSG_DISCONNECT,
                flags: 0,
                app_id: removed.app_id,
                source_id: removed.primary_id,
                dest_id: 0,
                source_virtual_ip: removed.virtual_ip,
                source_virtual_port: removed.virtual_port,
                dest_virtual_ip: 0,
                dest_virtual_port: 0,
                session_token: 0,
                payload: encode_ids_payload(removed.listen_port, &removed.listen_ids),
            };
            for peer_id in removed.notify {
                let _ = self.send_tcp(peer_id, disconnect.clone());
            }
        }
        info!(
            app_id = removed.app_id,
            primary_id = %removed.primary_id,
            listen_ids = ?removed.listen_ids,
            virtual_endpoint = %format_virtual_endpoint(removed.virtual_ip, removed.virtual_port),
            tcp_remote = %tcp_remote,
            reason,
            "client disconnected"
        );
    }

    fn clients_for_app(&self, app_id: u32) -> Vec<u64> {
        let state = self.state.lock().unwrap();
        state
            .clients
            .iter()
            .filter_map(|(id, client)| {
                let data = client.data.lock().unwrap();
                (data.app_id == app_id).then_some(*id)
            })
            .collect()
    }

    fn resolve_target(&self, app_id: u32, env: &Envelope) -> Option<u64> {
        let state = self.state.lock().unwrap();
        if env.flags & FLAG_HAS_DEST_ENDPOINT != 0 {
            return state
                .by_endpoint
                .get(&EndpointKey {
                    app_id,
                    ip: env.dest_virtual_ip,
                    port: env.dest_virtual_port,
                })
                .copied();
        }
        if env.flags & FLAG_HAS_DEST_STEAM_ID != 0 {
            return state
                .by_steam_id
                .get(&steam_key(app_id, env.dest_id))
                .copied();
        }
        None
    }

    fn maybe_send_disconnect_hint(&self, sender_id: u64, app_id: u32, env: &Envelope) {
        let hint = {
            let state = self.state.lock().unwrap();
            let now = Instant::now();
            if env.flags & FLAG_HAS_DEST_ENDPOINT != 0 {
                state
                    .stale_endpoints
                    .get(&EndpointKey {
                        app_id,
                        ip: env.dest_virtual_ip,
                        port: env.dest_virtual_port,
                    })
                    .filter(|hint| now < hint.expires_at)
                    .cloned()
            } else if env.flags & FLAG_HAS_DEST_STEAM_ID != 0 {
                if let Some(hint) = state.stale_ids.get(&steam_key(app_id, env.dest_id)) {
                    if now < hint.expires_at {
                        Some(hint.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        let Some(hint) = hint else {
            return;
        };

        let disconnect = Envelope {
            msg_type: MSG_DISCONNECT,
            flags: 0,
            app_id: hint.app_id,
            source_id: hint.listen_ids.first().copied().unwrap_or(0),
            dest_id: 0,
            source_virtual_ip: hint.virtual_ip,
            source_virtual_port: hint.virtual_port,
            dest_virtual_ip: 0,
            dest_virtual_port: 0,
            session_token: 0,
            payload: encode_ids_payload(hint.listen_port, &hint.listen_ids),
        };
        let _ = self.send_tcp(sender_id, disconnect);
    }

    fn lookup_client_by_token(&self, token: u64) -> Option<u64> {
        let state = self.state.lock().unwrap();
        state.by_token.get(&token).copied()
    }

    fn update_udp_addr(&self, client_id: u64, addr: SocketAddr, now: Instant) {
        let state = self.state.lock().unwrap();
        if let Some(client) = state.clients.get(&client_id) {
            let mut data = client.data.lock().unwrap();
            let changed = data.udp_addr != Some(addr);
            let first = data.udp_addr.is_none();
            data.udp_addr = Some(addr);
            data.last_seen = now;
            if first || changed {
                debug!(app_id = data.app_id, primary_id = %data.primary_id, remote = %addr, "udp endpoint learned");
            }
        }
    }

    fn touch_client(&self, client_id: u64, now: Instant) {
        let state = self.state.lock().unwrap();
        if let Some(client) = state.clients.get(&client_id) {
            client.data.lock().unwrap().last_seen = now;
        }
    }

    fn cleanup_disconnect_hints(&self, now: Instant) {
        let mut state = self.state.lock().unwrap();
        state.stale_ids.retain(|_, hint| now < hint.expires_at);
        state
            .stale_endpoints
            .retain(|_, hint| now < hint.expires_at);
    }

    fn client_app_id(&self, client_id: u64) -> Option<u32> {
        self.client_snapshot(client_id).map(|c| c.app_id)
    }

    fn client_snapshot(&self, client_id: u64) -> Option<ClientSnapshot> {
        let state = self.state.lock().unwrap();
        let client = state.clients.get(&client_id)?.clone();
        let data = client.data.lock().unwrap();
        Some(ClientSnapshot {
            app_id: data.app_id,
            primary_id: data.primary_id,
            virtual_ip: data.virtual_ip,
            virtual_port: data.virtual_port,
        })
    }

    fn client_udp_addr(&self, client_id: u64) -> String {
        let state = self.state.lock().unwrap();
        let Some(client) = state.clients.get(&client_id) else {
            return "-".to_string();
        };
        let data = client.data.lock().unwrap();
        data.udp_addr
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "-".to_string())
    }

    fn record_routed_packet(
        &self,
        reliable: bool,
        broadcast: bool,
        payload_bytes: usize,
        recipients: usize,
    ) {
        if recipients == 0 {
            return;
        }

        let mut state = self.state.lock().unwrap();
        if reliable {
            state.reliable_routed += recipients;
        } else {
            state.unreliable_routed += recipients;
        }
        if broadcast {
            state.broadcast_routed += 1;
        }
        state.routed_bytes += payload_bytes.saturating_mul(recipients);
    }

    fn flush_traffic_debug(&self) {
        if !tracing::enabled!(tracing::Level::DEBUG) {
            return;
        }

        let (active_clients, reliable, unreliable, broadcasts, bytes) = {
            let mut state = self.state.lock().unwrap();
            let active_clients = state.clients.len();
            let reliable = state.reliable_routed;
            let unreliable = state.unreliable_routed;
            let broadcasts = state.broadcast_routed;
            let bytes = state.routed_bytes;
            state.reliable_routed = 0;
            state.unreliable_routed = 0;
            state.broadcast_routed = 0;
            state.routed_bytes = 0;
            (active_clients, reliable, unreliable, broadcasts, bytes)
        };

        if reliable == 0 && unreliable == 0 && broadcasts == 0 {
            return;
        }

        debug!(
            active_clients,
            reliable_packets = reliable,
            unreliable_packets = unreliable,
            broadcast_packets = broadcasts,
            delivered_bytes = bytes,
            "traffic summary"
        );
    }

    fn log_client_status(&self) {
        let clients = self.client_status_lines();
        if clients.is_empty() {
            return;
        }

        info!(
            connected = clients.len(),
            clients = %clients.join(" | "),
            "client status"
        );
    }

    fn client_status_lines(&self) -> Vec<String> {
        let state = self.state.lock().unwrap();
        let mut lines = Vec::with_capacity(state.clients.len());
        for client in state.clients.values() {
            let data = client.data.lock().unwrap();
            let tcp_remote = client
                .stream
                .lock()
                .unwrap()
                .peer_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| "-".to_string());
            let udp_remote = data
                .udp_addr
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "-".to_string());
            lines.push(format!(
                "app={} id={} ids={:?} virtual={} tcp={} udp={}",
                data.app_id,
                data.primary_id,
                sorted_ids(&data.listen_ids),
                format_virtual_endpoint(data.virtual_ip, data.virtual_port),
                tcp_remote,
                udp_remote
            ));
        }
        lines.sort_unstable();
        lines
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn add_replacement(replacements: &mut Vec<Replacement>, client_id: u64, suppress_disconnect: bool) {
    if let Some(existing) = replacements
        .iter_mut()
        .find(|replacement| replacement.client_id == client_id)
    {
        existing.suppress_disconnect |= suppress_disconnect;
        return;
    }
    replacements.push(Replacement {
        client_id,
        suppress_disconnect,
    });
}

fn client_has_primary_locked(state: &ServerState, client_id: u64, primary_id: u64) -> bool {
    state
        .clients
        .get(&client_id)
        .map(|client| client.data.lock().unwrap().primary_id == primary_id)
        .unwrap_or(false)
}

fn client_endpoint_locked(state: &ServerState, client_id: u64) -> Option<(u32, u16)> {
    state.clients.get(&client_id).map(|client| {
        let data = client.data.lock().unwrap();
        (data.virtual_ip, data.virtual_port)
    })
}

fn find_handoff_owner_locked(
    state: &ServerState,
    app_id: u32,
    primary_id: u64,
    ids: &[u64],
    bound_client: Option<u64>,
) -> Option<u64> {
    ids.iter()
        .copied()
        .filter(|id| *id != primary_id && is_individual_steam_id(*id))
        .filter_map(|id| state.by_steam_id.get(&steam_key(app_id, id)).copied())
        .find(|owner_id| Some(*owner_id) != bound_client)
}

fn find_live_listen_owner(state: &ServerState, app_id: u32, listen_id: u64) -> Option<u64> {
    state
        .clients
        .iter()
        .filter_map(|(client_id, client)| {
            let data = client.data.lock().unwrap();
            (data.app_id == app_id && data.listen_ids.contains(&listen_id)).then_some(*client_id)
        })
        .max()
}

fn is_individual_steam_id(steam_id: u64) -> bool {
    const ACCOUNT_TYPE_INDIVIDUAL: u64 = 1;
    ((steam_id >> 52) & 0xF) == ACCOUNT_TYPE_INDIVIDUAL
}

fn sorted_ids(ids: &HashSet<u64>) -> Vec<u64> {
    let mut out: Vec<u64> = ids.iter().copied().collect();
    out.sort_unstable();
    out
}

fn steam_key(app_id: u32, steam_id: u64) -> String {
    format!("{app_id}:{steam_id}")
}

fn allocate_virtual_ip(state: &mut ServerState) -> u32 {
    let ip = 0x0AC8_0000 + state.next_ip;
    state.next_ip += 1;
    ip
}

fn random_u64() -> u64 {
    let token = rand::thread_rng().gen::<u64>();
    if token == 0 {
        1
    } else {
        token
    }
}

#[allow(dead_code)]
fn format_virtual_endpoint(ip: u32, port: u16) -> String {
    let ip = Ipv4Addr::from(ip);
    format!("{ip}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};

    const APP_ID: u32 = 3_124_540;
    const LISTEN_PORT: u16 = 47_584;

    fn test_server() -> Server {
        Server::new(Config {
            listen_address: "127.0.0.1".to_string(),
            tcp_port: 0,
            udp_port: 0,
            ..Config::default()
        })
        .unwrap()
    }

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        (server, client)
    }

    fn registration_env(msg_type: u16, primary_id: u64, ids: &[u64]) -> Envelope {
        Envelope {
            msg_type,
            flags: 0,
            app_id: APP_ID,
            source_id: primary_id,
            dest_id: 0,
            source_virtual_ip: 0,
            source_virtual_port: 0,
            dest_virtual_ip: 0,
            dest_virtual_port: 0,
            session_token: 0,
            payload: encode_ids_payload(LISTEN_PORT, ids),
        }
    }

    fn read_tcp_envelope(stream: &mut TcpStream) -> Envelope {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).unwrap();
        let len = u32::from_le_bytes(len) as usize;
        let mut frame = vec![0u8; len];
        stream.read_exact(&mut frame).unwrap();
        decode_envelope(&frame).unwrap()
    }

    fn register(server: &Server, primary_id: u64, ids: &[u64]) -> (u64, TcpStream) {
        let (server_stream, mut client_stream) = tcp_pair();
        let client_id = server
            .register_client(
                &server_stream,
                registration_env(MSG_HELLO, primary_id, ids),
                None,
            )
            .unwrap()
            .unwrap();
        let welcome = read_tcp_envelope(&mut client_stream);
        assert_eq!(welcome.msg_type, MSG_WELCOME);
        (client_id, client_stream)
    }

    #[test]
    fn same_primary_reconnect_preserves_endpoint_and_indexes() {
        let server = test_server();
        let primary_id = 8_556_839_772_967_8218;
        let secondary_id = 76_561_198_374_632_266;
        let (old_client_id, _old_client) =
            register(&server, primary_id, &[primary_id, secondary_id]);
        let old_snapshot = server.client_snapshot(old_client_id).unwrap();

        let (server_stream, mut new_client) = tcp_pair();
        let new_client_id = server
            .register_client(
                &server_stream,
                registration_env(MSG_HELLO, primary_id, &[primary_id, secondary_id]),
                None,
            )
            .unwrap()
            .unwrap();
        let welcome = read_tcp_envelope(&mut new_client);
        assert_eq!(welcome.msg_type, MSG_WELCOME);

        let state = server.state.lock().unwrap();
        assert!(!state.clients.contains_key(&old_client_id));
        assert_eq!(
            state
                .by_primary
                .get(&steam_key(APP_ID, primary_id))
                .copied(),
            Some(new_client_id)
        );
        assert_eq!(
            state
                .by_steam_id
                .get(&steam_key(APP_ID, secondary_id))
                .copied(),
            Some(new_client_id)
        );
        assert_eq!(
            state
                .by_endpoint
                .get(&EndpointKey {
                    app_id: APP_ID,
                    ip: old_snapshot.virtual_ip,
                    port: old_snapshot.virtual_port,
                })
                .copied(),
            Some(new_client_id)
        );
        assert_eq!(welcome.source_virtual_ip, old_snapshot.virtual_ip);
        assert_eq!(welcome.source_virtual_port, old_snapshot.virtual_port);
        assert!(state.stale_ids.is_empty());
        assert!(state.stale_endpoints.is_empty());
    }

    #[test]
    fn new_goldberg_server_primary_with_same_user_alias_hands_off_session() {
        let server = test_server();
        let old_primary = 8_556_839_772_967_8218;
        let new_primary = 8_556_839_830_666_3778;
        let stable_user = 76_561_198_374_632_266;
        let (old_client_id, _old_client) =
            register(&server, old_primary, &[old_primary, stable_user]);
        let old_snapshot = server.client_snapshot(old_client_id).unwrap();

        let (server_stream, mut new_client) = tcp_pair();
        let new_client_id = server
            .register_client(
                &server_stream,
                registration_env(MSG_HELLO, new_primary, &[new_primary, stable_user]),
                None,
            )
            .unwrap()
            .unwrap();
        let welcome = read_tcp_envelope(&mut new_client);

        let state = server.state.lock().unwrap();
        assert!(!state.clients.contains_key(&old_client_id));
        assert_eq!(
            state
                .by_primary
                .get(&steam_key(APP_ID, old_primary))
                .copied(),
            None
        );
        assert_eq!(
            state
                .by_primary
                .get(&steam_key(APP_ID, new_primary))
                .copied(),
            Some(new_client_id)
        );
        assert_eq!(
            state
                .by_steam_id
                .get(&steam_key(APP_ID, stable_user))
                .copied(),
            Some(new_client_id)
        );
        assert_eq!(
            state
                .by_endpoint
                .get(&EndpointKey {
                    app_id: APP_ID,
                    ip: old_snapshot.virtual_ip,
                    port: old_snapshot.virtual_port,
                })
                .copied(),
            Some(new_client_id)
        );
        assert_eq!(welcome.source_virtual_ip, old_snapshot.virtual_ip);
        assert_eq!(welcome.source_virtual_port, old_snapshot.virtual_port);
        assert!(state.stale_ids.is_empty());
        assert!(state.stale_endpoints.is_empty());
    }

    #[test]
    fn removing_old_shared_secondary_reindexes_to_remaining_client() {
        let server = test_server();
        let old_primary = 10;
        let new_primary = 11;
        let shared_secondary = 99;
        let (old_client_id, _old_client) =
            register(&server, old_primary, &[old_primary, shared_secondary]);
        let (new_client_id, _new_client) =
            register(&server, new_primary, &[new_primary, shared_secondary]);

        {
            let state = server.state.lock().unwrap();
            assert_eq!(
                state
                    .by_steam_id
                    .get(&steam_key(APP_ID, shared_secondary))
                    .copied(),
                Some(old_client_id)
            );
        }

        server.remove_client(Some(old_client_id), "test");

        let state = server.state.lock().unwrap();
        assert_eq!(
            state
                .by_steam_id
                .get(&steam_key(APP_ID, shared_secondary))
                .copied(),
            Some(new_client_id)
        );
        assert!(state
            .stale_ids
            .get(&steam_key(APP_ID, shared_secondary))
            .is_none());
        assert!(state
            .stale_ids
            .get(&steam_key(APP_ID, old_primary))
            .is_some());
    }

    #[test]
    fn unreliable_delivery_falls_back_to_tcp_until_udp_addr_is_known() {
        let server = test_server();
        let (sender_id, _sender_client) = register(&server, 100, &[100]);
        let (_target_id, mut target_client) = register(&server, 200, &[200]);

        server.route_envelope(
            sender_id,
            Envelope {
                msg_type: MSG_UNRELIABLE,
                flags: FLAG_HAS_DEST_STEAM_ID,
                app_id: APP_ID,
                source_id: 100,
                dest_id: 200,
                source_virtual_ip: 0,
                source_virtual_port: 0,
                dest_virtual_ip: 0,
                dest_virtual_port: 0,
                session_token: 0,
                payload: vec![1, 2, 3],
            },
            false,
        );

        let delivered = read_tcp_envelope(&mut target_client);
        assert_eq!(delivered.msg_type, MSG_UNRELIABLE);
        assert_eq!(delivered.source_id, 100);
        assert_eq!(delivered.dest_id, 200);
        assert_eq!(delivered.payload, vec![1, 2, 3]);
    }

    #[test]
    fn endpoint_routing_takes_precedence_over_stale_dest_id() {
        let server = test_server();
        let (sender_id, _sender_client) = register(&server, 100, &[100]);
        let (_steam_id_owner, _owner_client) = register(&server, 200, &[200]);
        let (_endpoint_owner, mut endpoint_client) = register(&server, 300, &[300]);
        let endpoint = server.client_snapshot(_endpoint_owner).unwrap();

        server.route_envelope(
            sender_id,
            Envelope {
                msg_type: MSG_UNRELIABLE,
                flags: FLAG_HAS_DEST_STEAM_ID | FLAG_HAS_DEST_ENDPOINT,
                app_id: APP_ID,
                source_id: 100,
                dest_id: 200,
                source_virtual_ip: 0,
                source_virtual_port: 0,
                dest_virtual_ip: endpoint.virtual_ip,
                dest_virtual_port: endpoint.virtual_port,
                session_token: 0,
                payload: vec![9, 8, 7],
            },
            false,
        );

        let delivered = read_tcp_envelope(&mut endpoint_client);
        assert_eq!(delivered.msg_type, MSG_UNRELIABLE);
        assert_eq!(delivered.dest_id, 200);
        assert_eq!(delivered.dest_virtual_ip, endpoint.virtual_ip);
        assert_eq!(delivered.dest_virtual_port, endpoint.virtual_port);
        assert_eq!(delivered.payload, vec![9, 8, 7]);
    }
}
