use std::collections::{HashMap, HashSet};
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
    MSG_HEARTBEAT, MSG_HELLO, MSG_REGISTER, MSG_RELIABLE, MSG_UNRELIABLE, MSG_WELCOME,
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
    next_ip: u32,
    next_client_id: u64,
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
                next_ip: 1,
                next_client_id: 1,
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

        info!(
            tcp_port = self.cfg.tcp_port,
            udp_port = self.cfg.udp_port,
            "relay listening"
        );

        accept_thread.join().unwrap()?;
        udp_thread.join().unwrap()?;
        cleanup_thread.join().unwrap()?;
        Ok(())
    }

    fn accept_loop(&self, shutdown: Arc<AtomicBool>) -> io::Result<()> {
        while !shutdown.load(Ordering::SeqCst) {
            match self.tcp_listener.accept() {
                Ok((stream, remote)) => {
                    info!(remote = %remote, "tcp client accepted");
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
                Ok(0) => break,
                Ok(n) => {
                    buffer.extend_from_slice(&tmp[..n]);
                    while let Some(frame) = next_tcp_frame(&mut buffer) {
                        let env = match decode_envelope(&frame) {
                            Ok(env) => env,
                            Err(err) => {
                                warn!(remote = ?remote, error = %err, "drop invalid tcp frame");
                                continue;
                            }
                        };
                        debug!(
                            remote = ?remote,
                            msg_type = env.msg_type,
                            app_id = env.app_id,
                            source_id = env.source_id,
                            dest_id = env.dest_id,
                            flags = env.flags,
                            payload_bytes = env.payload.len(),
                            "tcp frame received"
                        );
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
                Err(_) => break,
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
                    debug!(
                        remote = %addr,
                        msg_type = env.msg_type,
                        app_id = env.app_id,
                        source_id = env.source_id,
                        dest_id = env.dest_id,
                        flags = env.flags,
                        payload_bytes = env.payload.len(),
                        "udp frame received"
                    );

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

            let before = now
                .checked_sub(self.cfg.session_timeout.saturating_mul(2))
                .unwrap_or(now);
            self.limiter.cleanup(before);
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

        let primary_id = if env.source_id != 0 { env.source_id } else { ids[0] };
        let key = steam_key(env.app_id, primary_id);
        let now = Instant::now();
        let stream = Arc::new(Mutex::new(conn.try_clone()?));
        let mut replaced = Vec::new();
        let current_id;
        let mut send_welcome = env.msg_type == MSG_HELLO;

        {
            let mut state = self.state.lock().unwrap();
            let current = state.by_primary.get(&key).copied();
            let client_id = if let Some(bound_id) = bound_client {
                if let Some(current_id) = current {
                    if current_id != bound_id {
                        replaced.push(current_id);
                    }
                }
                bound_id
            } else if let Some(current_id) = current {
                replaced.push(current_id);
                let id = state.next_client_id;
                state.next_client_id += 1;
                let token = random_u64();
                let virtual_ip = allocate_virtual_ip(&mut state);
                state.clients.insert(
                    id,
                    Arc::new(Client {
                        stream: Arc::clone(&stream),
                        data: Mutex::new(ClientData {
                            app_id: env.app_id,
                            primary_id,
                            listen_ids: HashSet::new(),
                            listen_port,
                            token,
                            virtual_ip,
                            virtual_port: listen_port,
                            udp_addr: None,
                            last_seen: now,
                            closing: false,
                        }),
                    }),
                );
                send_welcome = true;
                id
            } else {
                let id = state.next_client_id;
                state.next_client_id += 1;
                let token = random_u64();
                let virtual_ip = allocate_virtual_ip(&mut state);
                state.clients.insert(
                    id,
                    Arc::new(Client {
                        stream: Arc::clone(&stream),
                        data: Mutex::new(ClientData {
                            app_id: env.app_id,
                            primary_id,
                            listen_ids: HashSet::new(),
                            listen_port,
                            token,
                            virtual_ip,
                            virtual_port: listen_port,
                            udp_addr: None,
                            last_seen: now,
                            closing: false,
                        }),
                    }),
                );
                send_welcome = true;
                id
            };

            let client = state.clients.get(&client_id).unwrap().clone();
            let mut data = client.data.lock().unwrap();

            let old_primary_key = steam_key(data.app_id, data.primary_id);
            let old_endpoint_key = EndpointKey {
                app_id: data.app_id,
                ip: data.virtual_ip,
                port: data.virtual_port,
            };

            if old_primary_key != key {
                state.by_primary.remove(&old_primary_key);
            }
            state.by_endpoint.remove(&old_endpoint_key);

            for id in &data.listen_ids {
                let listen_key = steam_key(data.app_id, *id);
                if state.by_steam_id.get(&listen_key).copied() == Some(client_id) {
                    state.by_steam_id.remove(&listen_key);
                }
            }

            data.app_id = env.app_id;
            data.primary_id = primary_id;
            data.listen_port = listen_port;
            data.virtual_port = listen_port;
            data.last_seen = now;
            data.closing = false;
            data.listen_ids = ids.iter().copied().collect();

            for id in &ids {
                let listen_key = steam_key(env.app_id, *id);
                match state.by_steam_id.get(&listen_key).copied() {
                    Some(owner_id) if owner_id != client_id && *id == primary_id => {
                        replaced.push(owner_id);
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
            state.by_endpoint.insert(
                EndpointKey {
                    app_id: data.app_id,
                    ip: data.virtual_ip,
                    port: data.virtual_port,
                },
                client_id,
            );
            current_id = client_id;
        }

        for client_id in replaced {
            if client_id != current_id {
                self.remove_client(Some(client_id), "replaced");
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
            primary_id,
            listen_ids = ?ids,
            listen_port,
            welcome_sent = send_welcome,
            "client registered"
        );

        Ok(Some(current_id))
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
            info!(
                app_id = sender.app_id,
                source_id = env.source_id,
                payload_bytes = env.payload.len(),
                recipients,
                "broadcast routed"
            );
            return;
        }

        let target_id = self.resolve_target(sender.app_id, &env);
        let Some(target_id) = target_id else {
            warn!(
                app_id = sender.app_id,
                source_id = env.source_id,
                dest_id = env.dest_id,
                dest_virtual_ip = env.dest_virtual_ip,
                dest_virtual_port = env.dest_virtual_port,
                flags = env.flags,
                reliable,
                "route target not found"
            );
            return;
        };

        info!(
            app_id = sender.app_id,
            source_id = env.source_id,
            dest_id = self.client_snapshot(target_id).map(|c| c.primary_id).unwrap_or(0),
            payload_bytes = env.payload.len(),
            reliable,
            "packet routed"
        );
        self.deliver(target_id, env, reliable);
    }

    fn deliver(&self, target_id: u64, env: Envelope, reliable: bool) {
        if reliable {
            let _ = self.send_tcp(target_id, env);
        } else {
            let _ = self.send_udp(target_id, env);
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
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        match stream.write_all(&frame) {
            Ok(()) => Ok(()),
            Err(err) => {
                drop(stream);
                warn!(target_id, msg_type = env.msg_type, error = %err, "tcp delivery failed");
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
            warn!(target_id, msg_type = env.msg_type, "udp delivery skipped, missing udp address");
            return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "missing udp addr"));
        };

        let payload = encode_envelope(&env);
        self.udp_socket.send_to(&payload, addr)?;
        Ok(())
    }

    fn remove_client(&self, target_id: Option<u64>, reason: &str) {
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
            state.by_primary.remove(&steam_key(data.app_id, data.primary_id));
            state.by_token.remove(&data.token);
            state.by_endpoint.remove(&EndpointKey {
                app_id: data.app_id,
                ip: data.virtual_ip,
                port: data.virtual_port,
            });
            for id in &data.listen_ids {
                let key = steam_key(data.app_id, *id);
                if state.by_steam_id.get(&key).copied() == Some(target_id) {
                    state.by_steam_id.remove(&key);
                }
            }

            let notify = state
                .clients
                .iter()
                .filter_map(|(id, peer)| {
                    let peer_data = peer.data.lock().unwrap();
                    (peer_data.app_id == data.app_id).then_some(*id)
                })
                .collect();

            RemovedClient {
                app_id: data.app_id,
                primary_id: data.primary_id,
                listen_port: data.listen_port,
                listen_ids: sorted_ids(&data.listen_ids),
                virtual_ip: data.virtual_ip,
                virtual_port: data.virtual_port,
                notify,
                stream: Arc::clone(&client.stream),
            }
        };

        let _ = removed.stream.lock().unwrap().shutdown(Shutdown::Both);
        let disconnect = Envelope {
            msg_type: crate::protocol::MSG_DISCONNECT,
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
        info!(app_id = removed.app_id, steam_id = removed.primary_id, reason, "client removed");
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
        if env.flags & FLAG_HAS_DEST_STEAM_ID != 0 {
            return state.by_steam_id.get(&steam_key(app_id, env.dest_id)).copied();
        }
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
        None
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
                info!(app_id = data.app_id, steam_id = data.primary_id, remote = %addr, "udp endpoint learned");
            }
        }
    }

    fn touch_client(&self, client_id: u64, now: Instant) {
        let state = self.state.lock().unwrap();
        if let Some(client) = state.clients.get(&client_id) {
            client.data.lock().unwrap().last_seen = now;
        }
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
