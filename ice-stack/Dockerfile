# Build the emulator's WebSocket signaling server (stdlib only, no modules).
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY signaling.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/signaling signaling.go

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/signaling /usr/local/bin/signaling
EXPOSE 49100
ENTRYPOINT ["/usr/local/bin/signaling"]
CMD ["-addr", ":49100"]
