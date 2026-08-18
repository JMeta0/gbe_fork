# ICE server stack (STUN + TURN + Signaling)

When peers are on different networks (not the same LAN), the emulator's
internet transport needs three cooperating services. This directory contains
all three, deployable together with Docker:

| Service | Role | What the emulator does with it |
|---|---|---|
| **Signaling** (`signaling.go`) | WebSocket rendezvous between peers | peers exchange ICE offers/answers/candidates (`offer`/`answer`/`candidate` messages) through it |
| **STUN** (`coturn`, UDP 3478) | tells a peer its own public IP:port | ICE "server-reflexive" candidates for NAT hole punching |
| **TURN** (`coturn`, UDP 3478 + relay range) | relays the actual game traffic when hole punching fails | ICE "relay" candidates — the guaranteed fallback behind symmetric NAT |

This is the internet-play equivalent of the LAN setup: signaling replaces the
UDP broadcast, and STUN/TURN replace "host candidates on the same machine".

## 1. Files

```
ice-stack/
├── signaling.go             # WebSocket signaling server (stdlib only)
├── Dockerfile               # multi-stage build, alpine runtime
├── docker-compose.yml       # signaling + coturn (STUN/TURN)
└── turnserver.example.conf  # coturn config template
```

## 2. Configure coturn

```bash
cd ice-stack
cp turnserver.example.conf turnserver.conf
```

Edit `turnserver.conf`:

```ini
realm=my-realm                       # any string
user=myuser:mypass                   # TURN credentials (also go in the emulator config)
external-ip=203.0.113.10             # the server's public IP; if your host IP is
                                     # auto-detected, set DETECT_EXTERNAL_IP=yes
                                     # in docker-compose.yml and leave this out
```

- `external-ip` is only needed when the server sits behind a NAT (most cloud
  VPS boxes with a public IP can rely on auto-detection).
- The relay range `min-port=49152 max-port=51152` bounds the UDP ports TURN
  allocates per relayed session. In a full-mesh P2P session of $N$ players, up to
  $N \times (N - 1)$ allocations are made when peers rely on TURN (e.g. 20 players
  = ~380 ports). A range of 1,000–2,000 ports is recommended for 20+ concurrent players.
  Every port in the range must be reachable.

### Alternative TURN images

The compose file ships with the official `coturn/coturn` image (minimal,
config-file driven) — that *is* the recommended pre-built image. There are
pre-built env-var-driven alternatives; the popular one is
[`ich777/stun-turn-server`](https://hub.docker.com/r/ich777/stun-turn-server)
(coturn under the hood, aimed at Unraid/Nextcloud). It works, but two of its
defaults clash with the emulator's ICE client and must be overridden:

1. **Auth model** — the image is built around a shared `SECRET`
   (`static-auth-secret`, TURN REST API style). The emulator cannot compute
   REST/HMAC credentials: it only sends **static long-term credentials**
   (`turn_user`/`turn_pass` → `lt-cred-mech`). Force `lt-cred-mech` + a static
   user via `EXTRA_PARAMS`:
   ```yaml
   EXTRA_PARAMS: --lt-cred-mech --user=myuser:mypass
   ```
2. **Default port** — the image listens on **5349 (TLS)**; the emulator uses
   plain `turn:` (UDP). Set `PORT=3478` and open that port for UDP + TCP.

Example service block (also in `docker-compose.yml`, commented out):

```yaml
coturn-alt:
  image: ich777/stun-turn-server:latest
  network_mode: host
  restart: unless-stopped
  environment:
    - PORT=3478
    - REALM=my-realm
    - SECRET=                 # leave empty; auto-generated into secret.txt
    - EXTRA_PARAMS=--lt-cred-mech --user=myuser:mypass
  volumes:
    - ./turn-data:/stun-turn  # config/secret persist here
```

Why not make ich777 the default: with `coturn/coturn` you get exactly the
`lt-cred-mech` + `user=` model the emulator speaks, and the relay port range is
set in the same config file (`min-port`/`max-port`) instead of being baked in.
Both images serve the same binary; ich777 just adds auto-generated
certs/secrets you don't need for plain `turn:`.

## 3. Deploy

```bash
docker compose up -d --build
docker compose ps          # both services healthy?
```

Ports exposed (must be opened in the server firewall — see below):

| Port | Proto | Service |
|---|---|---|
| 49100 | TCP | signaling WebSocket (`ws://<server>:49100/<peer_id>`) |
| 3478 | UDP+TCP | coturn: STUN and TURN listening port |
| 5349 | TCP | coturn: TURNS (TLS) — optional |
| 49152–51152 | UDP | coturn: relayed traffic (1000-2000 ports recommended) |

Example `ufw`/firewalld rules:

```bash
ufw allow 49100/tcp
ufw allow 3478/udp
ufw allow 3478/tcp
ufw allow 5349/tcp            # optional (TURNS)
ufw allow 49152:51152/udp
```

## 4. Emulator configuration

On every client, in `steam_settings/configs.main.ini` under
`[main::connectivity]`:

```ini
enable_ice=1
signaling_host=<server>
signaling_port=49100
; signaling_secret=change-me-signaling-secret   ; must match the signaling server's -secret flag
stun_host=<server>
stun_port=3478
; turn_host=<server>                            ; optional but recommended
; turn_port=3478
; turn_user=myuser                              ; must match turnserver.conf
; turn_pass=mypass
```

- `signaling_host`/`signaling_port`: the emulator connects to
  `ws://<host>:<port>/<peer-id>`.
- `signaling_secret` (optional) must match the `-secret` flag the signaling
  server was started with (see the `command:` in `docker-compose.yml`);
  empty/missing = no auth, and a mismatch is rejected with `401`.
- `stun_host`/`stun_port`: the same coturn instance serves STUN on 3478.
  Without STUN the client only gets host candidates (fine on LAN).
- `turn_user`/`turn_pass`/`turn_host`/`turn_port` must match `user=`/`realm`
  in `turnserver.conf`. When set, the ICE layer is allowed relay candidates,
  so the connection has a guaranteed fallback behind symmetric NAT.

## 5. How the pieces fit together

1. Each client connects to the signaling server:
   `ws://<server>:49100/<peer-id>` (peer id = the primary SteamID of the
   emulated user).
2. The signaling server answers `list` with the other connected peer ids,
   pushes `peer_connected`/`peer_disconnected` events, and forwards
   `offer`/`answer`/`candidate` messages (`{"id": <dest>, "source_id": <src>,
   "type": ..., ...}`) to the destination peer.
3. On discovering a new peer (from a `list` answer or `peer_connected`), both
   sides create an ICE agent and exchange their candidates. ICE tries, in
   order: host candidates (direct IPs) → server-reflexive candidates (via
   STUN) → relay candidates (via TURN), and picks the best working pair.
4. Game traffic then flows over the ICE channel (direct P2P when possible);
   TURN relays it only when hole punching fails.

## 6. Verification

On the server (install `coturn` tools or use the container image):

```bash
# STUN: should print your server's public IP:port
turnutils_stunclient -p 3478 <server>

# TURN: allocate a relayed allocation with the configured credentials
turnutils_uclient -p 3478 -u myuser -w mypass -y <server>
```

**Signaling** (`docker compose logs -f signaling`) — the server logs every
peer join/leave and every forwarded message. A healthy session looks like:

```
peer f6c21498aed068b603df432be59a2fbc connected from 84.23.12.7:52134
peer 7766319cbde0be97188f15cee79f291d connected from 84.23.12.7:52189
```

`list` requests are *not* logged (the emulator polls every ~2 s), so silence
between connect/forward lines is normal. If you see connects but no
`forward` lines, peers never exchanged rendezvous — check both clients really
use the same `signaling_host`/`signaling_port`.

**coturn** (`docker compose logs -f coturn`) — with `log-file=stdout` +
`log-level=INFO` it prints its startup banner ("config file found",
"listening on ..."). It only logs TURN *activity* when a client actually
uses it: a `new UDP endpoint` / allocation line per relayed session. If you
never see such lines, either the direct ICE path succeeded (TURN was never
needed — normal) or clients couldn't reach 3478/udp at all.

## 7. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| ICE times out connecting | signaling works but ICE finds no path: check STUN/TURN reachability from the *client* (`turnutils_stunclient <server>`), firewall UDP 3478 + relay range |
| TURN allocation rejected | credentials in `turn_user`/`turn_pass` don't match `turnserver.conf` (user/realm), or `lt-cred-mech` missing |
| Clients connect over LAN but not internet | signaling server not reachable (TCP 49100), or signaling_secret mismatch (`401`) |
| Works between LAN peers but never via TURN | expected if direct ICE succeeds — check relay only by blocking the direct path |
| `external-ip` wrong | relay candidates advertise a private/unreachable address; fix `external-ip` or enable `DETECT_EXTERNAL_IP=yes` |

## 8. Security notes

- The signaling server and coturn config here are minimal reference setups:
  no TLS, no rate limiting, static TURN credentials. For anything beyond a
  private test deployment, terminate TLS in front of the signaling server
  (the emulator connects with `ws://`; a reverse proxy can upgrade to
  `wss://` if you extend the emulator's URL handling) and use per-user TURN
  credentials.
- The relay port range only needs to be open for UDP. Keep it tight
  (49160–49200) instead of the full 49152–65535.
- `realm` is a partition for TURN credentials, not a security boundary; treat
  the `user:pass` pair as a shared secret for your play group.
