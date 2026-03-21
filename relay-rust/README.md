# Goldberg Relay Rust

Rust port of the Go relay broker in [`../relay`](../relay).

## Run

```bash
cargo run --release -- -config ./config.example.json
```

The JSON config matches the Go relay, including duration values encoded as Go-style nanoseconds.

## Docker

```bash
docker build -t goldberg-relay-rust .
docker run --rm \
  -p 23010:23010/tcp \
  -p 23011:23011/udp \
  -v "$(pwd)/config.example.json:/app/config.json:ro" \
  goldberg-relay-rust
```
