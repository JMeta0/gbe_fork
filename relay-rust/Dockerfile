FROM rust:1.87-alpine AS build

WORKDIR /src

RUN apk add --no-cache musl-dev

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

FROM alpine:3.20

RUN addgroup -S goldberg && adduser -S -G goldberg goldberg

WORKDIR /app

COPY --from=build /src/target/release/goldberg-relay-rust /usr/local/bin/goldberg-relay-rust
COPY config.example.json /app/config.json

USER goldberg

ENTRYPOINT ["/usr/local/bin/goldberg-relay-rust"]
CMD ["-config", "/app/config.json"]
