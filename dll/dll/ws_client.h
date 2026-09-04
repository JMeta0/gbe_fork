#ifndef WS_CLIENT_INCLUDE
#define WS_CLIENT_INCLUDE

#include "network.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Minimal RFC 6455 WebSocket *client* used by the ICE transport to talk to the
// signaling server (ice-stack/signaling.go, ws://host:port/<peer-id>[?secret=]).
//
// Threading model: all socket I/O happens on the
// network thread through Run(); send() may be called from any thread (e.g. the
// libjuice agent thread) and only appends to an outbox.
class WS_Client {
public:
    using MessageCallback = std::function<void(std::string &&payload)>; // full text payload of one message
    using StateCallback = std::function<void(bool connected)>;          // open/closed transition

    WS_Client();
    ~WS_Client();

    void configure(const std::string &host, uint16_t port, const std::string &path, const std::string &secret);
    void set_message_callback(MessageCallback cb) { message_cb = std::move(cb); }
    void set_state_callback(StateCallback cb) { state_cb = std::move(cb); }

    void connect();                 // (re)start the async connect + handshake
    void disconnect();
    bool send(const std::string &payload); // queue one text message; returns false if not open
    bool is_connected() const;      // handshake complete, socket open
    bool is_connecting() const;
    void Run();                     // advance connect / handshake / read / write

private:
    enum class State {
        Idle,
        Connecting,
        Handshaking,
        Open,
        Closed,
    };

    bool socket_valid() const;
    void close_socket();
    void close_locked();
    void finish_connect_locked();
    void begin_handshake_locked();
    void pump_read_locked();
    void pump_write_locked();
    void process_handshake_locked();
    void handle_frame_locked(uint8_t opcode, const std::vector<char> &payload);
    void deliver_message_locked();
    void queue_frame_locked(uint8_t opcode, const std::vector<char> &payload);
    void queue_raw_locked(const std::vector<char> &bytes);
    void set_state_locked(State next);

    std::string host{};
    uint16_t port = 0;
    std::string path{};
    std::string secret{};

    sock_t sock = static_cast<sock_t>(~0);
    State state = State::Idle;
    bool connect_in_progress = false;

    std::string handshake_key{};     // base64 Sec-WebSocket-Key we sent
    // Ring buffers with head offsets (P1-C): pop-front is O(1) instead of
    // erase(begin) memmove. Offsets compact when the head grows past 64KB.
    std::vector<char> send_buffer{}; // raw bytes queued to the socket
    size_t send_head = 0;
    std::vector<char> recv_buffer{}; // raw bytes read from the socket
    size_t recv_head = 0;
    void send_consume_locked(size_t n);
    void recv_consume_locked(size_t n);
    size_t send_size_locked() const { return send_buffer.size() - send_head; }
    size_t recv_size_locked() const { return recv_buffer.size() - recv_head; }
    const char *send_data_locked() const { return send_buffer.data() + send_head; }
    const char *recv_data_locked() const { return recv_buffer.data() + recv_head; }

    // incoming frame parser state
    bool frame_have_header = false;
    uint8_t frame_opcode = 0;
    bool frame_fin = false;
    bool frame_masked = false;
    uint8_t frame_mask_key[4] = {0, 0, 0, 0};
    uint64_t frame_expected = 0;
    uint64_t frame_received = 0;
    std::vector<char> frame_payload{};

    // multi-frame message reassembly (continuation frames)
    std::string message_accum{};

    // liveness / connect-deadline bookkeeping (steady clock)
    std::chrono::steady_clock::time_point last_activity{}; // any complete frame received
    std::chrono::steady_clock::time_point connect_started{}; // connect() initiated
    std::chrono::steady_clock::time_point next_ping{};       // next ping we send while Open

    // cached DNS result (network byte order) for the current host; cleared by
    // configure() so a changed host is re-resolved
    std::string resolved_host{};
    uint32_t resolved_ip = 0;
    std::chrono::steady_clock::time_point resolved_at{};
    // Async DNS: connect() never blocks the pump on getaddrinfo. First
    // connect for an unresolved host spawns a resolver thread joined on
    // destruction; the pump retries connect() on its normal cadence and
    // proceeds once the result lands (or falls back to the stale cached
    // entry on failure).
    std::thread dns_thread{};
    std::atomic<bool> dns_resolving{false};

    MessageCallback message_cb{};
    StateCallback state_cb{};
    mutable std::recursive_mutex mutex{}; // locked by const accessors (is_connected/is_connecting)
};

#endif // WS_CLIENT_INCLUDE
