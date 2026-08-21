// Command signaling is a minimal reference implementation of the WebSocket
// signaling server used by the emulator's "signaling_servers" setting.
//
// It implements a tiny RFC 6455 WebSocket server (stdlib only, no external
// dependencies) that:
//
//   - registers each connection under the peer id in the URL path
//     (clients connect to ws://host:port/<32-hex peer id>),
//   - answers "list" requests with the set of currently connected peer ids,
//   - forwards any message carrying "id" + "source_id" (gns_signal, SDP
//     offer/answer/candidate, ...) to the peer named by "id".
//
// The emulator requires every server->client message to carry "source_id",
// so it is always set here. See README.md in this directory for the full
// deployment (this server + coturn for STUN/TURN).
//
// Usage:
//
//	go run extra/signaling/signaling.go -addr :49100
//
// Then set "signaling_servers": ["<server>:49100"] in the emulator config.
package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// ---------- minimal RFC 6455 framing ----------

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// writeFrame writes one WebSocket frame. Server -> client frames are never
// masked per RFC 6455.
func writeFrame(w io.Writer, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode} // FIN + opcode
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, byte(n))
	case n <= 0xFFFF:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		header = append(header, 127)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		header = append(header, b[:]...)
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one WebSocket frame. Client -> server frames must be masked;
// the mask is applied before returning the payload.
func readFrame(r io.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	opcode := h[0] & 0x0F
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > 1<<20 { // signaling messages are small; sanity cap at 1 MiB
		return 0, nil, errors.New("frame too large")
	}
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return opcode, payload, nil
}

// ---------- signaling hub ----------

type peerConn struct {
	id   string
	conn net.Conn
	mu   sync.Mutex // serializes writes
}

type hub struct {
	mu     sync.Mutex
	peers  map[string]map[*peerConn]struct{}
	secret string // optional shared secret; empty disables auth
}

func newHub(secret string) *hub {
	return &hub{peers: make(map[string]map[*peerConn]struct{}), secret: secret}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func (h *hub) list(exclude string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.peers))
	for id := range h.peers {
		if id != exclude {
			ids = append(ids, id)
		}
	}
	return ids
}

func (h *hub) register(id string, c *peerConn) {
	log.Printf("peer %s connected from %s", id, c.conn.RemoteAddr())

	h.mu.Lock()
	group, exists := h.peers[id]
	isNew := !exists || len(group) == 0
	if !exists {
		group = make(map[*peerConn]struct{})
		h.peers[id] = group
	}
	group[c] = struct{}{}

	others := make([]string, 0, len(h.peers)-1)
	for pid := range h.peers {
		if pid != id {
			others = append(others, pid)
		}
	}
	h.mu.Unlock()

	if isNew {
		for _, pid := range others {
			h.send(pid, mustJSON(map[string]any{"type": "peer_connected", "peer_id": id}))
		}
	}
}

func (h *hub) unregister(id string, c *peerConn) {
	h.mu.Lock()
	group, exists := h.peers[id]
	if !exists {
		h.mu.Unlock()
		return
	}
	delete(group, c)
	isDead := len(group) == 0
	if isDead {
		delete(h.peers, id)
		log.Printf("peer %s disconnected", id)
	}

	others := make([]string, 0, len(h.peers))
	if isDead {
		for pid := range h.peers {
			others = append(others, pid)
		}
	}
	h.mu.Unlock()

	if isDead {
		for _, pid := range others {
			h.send(pid, mustJSON(map[string]any{"type": "peer_disconnected", "peer_id": id}))
		}
	}
}

func (h *hub) send(id string, payload []byte) {
	h.mu.Lock()
	group, ok := h.peers[id]
	if !ok || len(group) == 0 {
		h.mu.Unlock()
		return
	}
	conns := make([]*peerConn, 0, len(group))
	for c := range group {
		conns = append(conns, c)
	}
	h.mu.Unlock()

	for _, c := range conns {
		c.mu.Lock()
		_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := writeFrame(c.conn, opText, payload); err != nil {
			c.conn.Close()
		}
		c.mu.Unlock()
	}
}

// sendList replies with the current peer set. The emulator drops server
// messages without "source_id", so it is always included.
func (h *hub) sendList(to string) {
	h.send(to, mustJSON(map[string]any{
		"source_id": to,
		"type":      "list",
		"peer_ids":  h.list(to),
	}))
}

// forward relays a client message to the peer named by "id", preserving the
// envelope. The emulator sends {"id": <dest>, "source_id": <self>, "type": ...,
// ...payload...} for gns_signal and WebRTC SDP messages alike.
func (h *hub) forward(src string, msg map[string]any) {
	dest, _ := msg["id"].(string)
	if dest == "" || dest == src {
		return
	}
	msg["source_id"] = src // never trust the client's own claim
	h.send(dest, mustJSON(msg))
}

// ---------- HTTP / WebSocket handshake ----------

func websocketAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func hijack(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijack not supported")
	}
	conn, _, err := hj.Hijack()
	return conn, err
}

func (h *hub) serve(w http.ResponseWriter, r *http.Request) {
	if !isWebSocketUpgrade(r) {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}

	if h.secret != "" && r.URL.Query().Get("secret") != h.secret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := hijack(w)
	if err != nil {
		log.Printf("hijack: %v", err)
		return
	}
	defer conn.Close()

	// The read loop below blocks until the connection dies, so without keepalive
	// a NAT/proxy that silently drops an idle websocket would leave a zombie
	// peer entry until the next write fails. Keepalive probes keep the mapping
	// alive and surface dead peers quickly.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	upgrade := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + websocketAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(upgrade)); err != nil {
		return
	}

	id := strings.Trim(r.URL.Path, "/")
	if id == "" {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		writeFrame(conn, opClose, []byte{0x03, 0xEA}) // policy violation
		return
	}

	pc := &peerConn{id: id, conn: conn}
	h.register(id, pc)
	defer h.unregister(id, pc)

	h.sendList(id)

	for {
		opcode, payload, err := readFrame(conn)
		if err != nil {
			return
		}
		switch opcode {
		case opText, opBinary:
			var msg map[string]any
			if json.Unmarshal(payload, &msg) != nil {
				continue
			}
			switch msg["type"] {
			case "list":
				h.sendList(id)
			case "gns_signal", "offer", "answer", "candidate", "data":
				h.forward(id, msg)
			}
		case opPing:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			writeFrame(conn, opPong, payload)
		case opClose:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			writeFrame(conn, opClose, payload)
			return
		}
	}
}

func main() {
	addr := flag.String("addr", ":49100", "listen address")
	secret := flag.String("secret", "", "optional shared secret required from clients")
	flag.Parse()

	h := newHub(*secret)
	http.HandleFunc("/", h.serve)
	log.Printf("signaling listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
