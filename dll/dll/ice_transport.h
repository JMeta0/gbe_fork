#ifndef ICE_TRANSPORT_INCLUDE
#define ICE_TRANSPORT_INCLUDE

#include "network.h"
#include "ws_client.h"

#include <juice/juice.h>

#include <atomic>
#include <array>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// Internet transport for the emulator, built on a full ICE + STUN + TURN stack:
//
//   - WebSocket signaling (ice-stack/signaling.go) for peer rendezvous:
//     ws://<signaling_host>:<signaling_port>/<peer-id>[?secret=...]
//   - libjuice ICE agents (one per remote peer) doing RFC 8445 connectivity
//     checks: host candidates, server-reflexive candidates via STUN, and
//     relayed candidates via TURN (the guaranteed path behind symmetric NAT)
//   - a reliable/fragmentation layer on top of the ICE datagram channel for
//     reliable Common_Messages
//
// Peer addressing for the game: each peer gets a deterministic virtual IP:port
// derived from (appid, steamid), so getIP() / getPort() / announce handling in
// network.cpp keep the same stable endpoints for the game.
class Ice_Transport {
public:
    struct InboundPacket {
        Common_Message message{};
        IP_PORT ip_port{};
        bool reliable = false;
    };

    struct DisconnectEvent {
        std::vector<CSteamID> ids{};
        uint32 virtual_ip = 0;
        uint16 virtual_port = 0;
        // True when the session was re-negotiated (peer restarted the game and
        // re-registered on signaling). The peer itself did not go away: the
        // network layer must keep the connection/friend entry and only re-mark
        // it offline so the next data packet re-fires CONNECT.
        bool session_reset = false;
    };

    struct PendingPacket {
        std::vector<char> bytes{};
        std::chrono::steady_clock::time_point next_send{};
        std::chrono::steady_clock::time_point first_send{};
        // Message this fragment belongs to. Fragments of one message get
        // consecutive packet seqs, so they are contiguous in peer.pending;
        // eviction uses this to drop whole messages atomically.
        uint32 message_id = 0;
        // False until the first successful juice_send; the pacer's unsent
        // queue uses this to avoid double-sending if the retry path gets there
        // first.
        bool sent = false;
        // Backoff generation: each retry doubles the delay up to RTO_MAX_MS.
        // Reset to 0 when the fragment is first queued or ACK progress is made.
        int backoff_step = 0;
    };

    struct ReassemblyState {
        uint16 fragment_count = 0;
        bool reliable = false;
        // Contiguous per-message buffer: fragment i lives at i*MTU. Avoids one
        // heap allocation per fragment and a second concatenation copy.
        std::vector<char> buffer{};
        std::vector<uint16_t> sizes{};
        std::vector<bool> present{};
        std::chrono::steady_clock::time_point updated{};
    };

    // How two peers are actually connected, derived from the ICE selected
    // candidate pair: relayed through a TURN server, P2P through NAT (reflexive
    // address discovered via STUN or learned from connectivity checks), or a
    // direct host-to-host path.
    enum class PeerConnectionType {
        Unknown = 0,
        Direct, // host-host, no server involved
        Stun,   // srflx/prflx, P2P via NAT hole punching
        Turn,   // relayed through the TURN server
    };

    struct Peer {
        uint64 primary_id = 0;
        std::vector<uint64> ids{};          // steamids this peer announced
        std::string signaling_id{};         // id string the peer uses on the signaling server
        juice_agent_t *agent = nullptr;
        bool connected = false;
        bool description_sent = false;
        bool remote_description_set = false;
        std::vector<std::string> pending_remote_candidates{};
        uint32 virtual_ip = 0;
        uint16 virtual_port = 0;

        // reliability / fragmentation state (one direction of the channel)
        // Reliable and unreliable fragments use separate sequence spaces: a
        // lost unreliable packet must never stall the reliable cumulative ACK.
        uint32 next_reliable_seq = 1;
        uint32 next_packet_seq = 1; // unreliable sequence space
        // Cumulative ACK: every packet_seq <= this has been received.
        uint32 highest_contiguous_seq = 0;
        // 32-bit SACK bitmap for highest_contiguous_seq + 1 .. + 32.
        uint32 remote_ack_bits = 0;
        // Sliding ring bitmap for reliable seqs above highest_contiguous_seq.
        // 131072 bits (16 KiB) covers the whole sender window with headroom.
        static constexpr uint32 RECV_WINDOW_BITS = 1u << 17;
        std::vector<uint64_t> recv_bitmap{};
        uint32 recv_bitmap_head = 0; // ring index of highest_contiguous_seq + 1
        uint32 ooo_count = 0;
        // Latest cumulative ACK + SACK bitmap received from this peer for the
        // data we sent it. Drives the retransmit set so we only resend holes,
        // not every out-of-order fragment sitting in `pending`.
        uint32 peer_ack = 0;
        uint32 peer_ack_bits = 0;
        // Session epoch: changes whenever this side recreates its ICE agent.
        // The peer resets its reliable state when it observes a new epoch, so
        // a one-sided restart cannot leave the sequence spaces out of sync.
        uint64 local_session_epoch = 0;
        uint64 remote_session_epoch = 0;
        // Adaptive token-bucket pacer for reliable data. Bursts above the
        // measured path rate create the loss that the ARQ then has to repair.
        // Start well below the observed path ceiling (7-8 MB/s): the first
        // large state sync must not overrun the peer's socket/event queue.
        double send_rate_bps = 4.0 * 1024 * 1024;
        double send_tokens = 0.0;
        std::chrono::steady_clock::time_point send_token_time{};
        // Reliable fragments queued but not yet handed to libjuice. The pacer
        // and transient send failures drain this in sequence order.
        std::deque<uint32> unsent_seqs{};
        std::chrono::steady_clock::time_point next_unsent_at{};
        // Unique reliable fragments first-sent (retransmits excluded). Compared
        // with the peer's recv_unique report to measure current burst loss.
        uint32 reliable_frags_sent = 0;
        uint32 last_reliable_frags_sent = 0;
        // Receiver-side telemetry, echoed in every ACK payload. Counting all
        // DATA bytes (including duplicates) measures the path throughput even
        // while the cumulative ACK is stalled behind a hole.
        uint32 recv_unique = 0;   // first-time reliable fragments accepted
        uint32 recv_bytes = 0;    // reliable DATA payload bytes seen
        uint32 recv_highest = 0;  // highest reliable packet_seq seen
        uint32 remote_recv_unique = 0;
        uint32 remote_recv_bytes = 0;
        uint32 remote_recv_highest = 0;
        uint32 remote_ooo = 0;
        bool remote_telemetry_valid = false;
        bool remote_telemetry_sampled = false;
        uint32 last_remote_recv_unique = 0;
        uint32 last_remote_recv_bytes = 0;
        // 1024-bit extended SACK from the peer (ack+33 .. ack+1056), plus the
        // cumulative ACK it belongs to. Used to free received fragments and
        // to retransmit several holes in parallel.
        std::array<uint32, 32> peer_ack_ext{};
        uint32 peer_ack_ext_base = 0;
        // Message-level ACK queue: messages delivered to the game, waiting for
        // an ACK that lets the sender free their fragments immediately. Without
        // this, delivered-but-out-of-order messages fill the retransmit window
        // until the cumulative hole is repaired.
        std::deque<uint32> completed_ack_ids{};
        // Outgoing message fragment ranges, keyed by message_id. Lets a
        // message-level ACK erase exactly that message from `pending`.
        std::map<uint32, std::pair<uint32, uint32>> pending_msg_ranges{};
        // Incoming reliable messages: complete ones wait here until every
        // lower message_id has been delivered, preserving SteamNetworking's
        // ordered-reliable guarantee. incomplete_reliable_ids holds messages
        // that still have missing fragments and therefore block the ones above.
        std::map<uint32, InboundPacket> ordered_reliable{};
        std::set<uint32> incomplete_reliable_ids{};
        size_t ordered_highwater = 0;
        uint32 next_message_id = 1;
        std::map<uint32, PendingPacket> pending{};
        // Smoothed RTT (ms), anchored to the 2s PING and bounded by it; drives
        // the adaptive RTO. -1 = no sample yet.
        double srtt_ms = -1.0;
        double rttvar_ms = 0.0;
        // Last cumulative ACK seen; ACK progress gives the next hole a fresh
        // RTO instead of the backoff it built up behind the old hole.
        uint32 last_fast_rtx_ack = 0;
        // Set when a received reliable packet must be acknowledged. ACKs are
        // coalesced: flush_pending_acks_locked() sends one ACK per peer after
        // the pump drains its events (the ACK carries highest_contiguous_seq
        // plus a 32-bit SACK bitmap), instead of one packet per fragment.
        bool ack_pending = false;
        std::map<uint32, ReassemblyState> reassembly{};
        std::deque<uint32> completed_messages{};
        std::set<uint32> completed_message_set{};
        std::chrono::steady_clock::time_point last_seen{};
        // Set when signaling reports this peer disconnected while its ICE
        // session is still up; cleared by any incoming ICE activity or a
        // re-registration. After ICE_DISCONNECT_GRACE_SEC without either, the
        // peer is presumed gone and removed (fast friend-list cleanup).
        std::chrono::steady_clock::time_point signal_disconnected_at{};

        // Cadence for the 2s ping / connection-type refresh. Only touched by
        // update_peer_stats_locked() on the pump thread.
        std::chrono::steady_clock::time_point next_ping_at{};
        // P2-E: connection_type cache deadline (refresh every 10s, not every ping).
        std::chrono::steady_clock::time_point next_conn_type_at{};
        PeerConnectionType connection_type = PeerConnectionType::Unknown;
    };

    // Snapshot of a peer's connection telemetry, read by the overlay.
    struct PeerStats {
        bool connected = false;
        PeerConnectionType connection_type = PeerConnectionType::Unknown;
        int rtt_ms = -1; // -1 = no sample yet
    };

    Ice_Transport(
        const std::string &signaling_host, uint16 signaling_port, const std::string &signaling_secret,
        const std::string &stun_host, uint16 stun_port,
        const std::string &turn_host, uint16 turn_port, const std::string &turn_user, const std::string &turn_pass,
        uint16 listen_port, uint32 appid, CSteamID initial_id);
    ~Ice_Transport();

    bool enabled() const;
    bool ready();
    // Advances the whole ICE protocol: drains libjuice callback events,
    // drives the signaling websocket, retries reliable fragments, arms pings
    // and garbage-collects stale state. Runs on the dedicated pump thread at
    // ICE_PUMP_INTERVAL_MS, independent of the game's render loop.
    void Run();
    void set_appid(uint32 appid);
    void add_listen_id(CSteamID id);
    bool Send(Common_Message *msg, bool reliable);
    bool SendToEndpoint(Common_Message *msg, uint32 ip, uint16 port, bool reliable);
    bool SendBroadcast(Common_Message *msg);
    bool PollPacket(Common_Message *msg, IP_PORT *ip_port, bool *reliable);
    bool PollDisconnect(std::vector<CSteamID> &ids, uint32 &virtual_ip, uint16 &virtual_port, bool &session_reset);
    bool poll_new_connection();
    void request_list();
    // Fills `out` with the peer's current connection telemetry (RTT + selected
    // candidate type). Returns false when the peer is unknown (e.g. ICE
    // disabled or no session for this id yet).
    bool GetPeerStats(uint64 primary_id, PeerStats &out);
    uint32 virtual_ip();
    uint16 virtual_port();

private:
    // Per-agent context passed to libjuice as user_ptr. Carries the owning
    // transport and the peer id so the callbacks never need to touch the
    // transport mutex (libjuice invokes callbacks while holding its own
    // per-agent lock; taking the transport mutex there can deadlock against
    // Run() calling into libjuice while holding it).
    struct AgentContext {
        Ice_Transport *self = nullptr;
        uint64 peer_id = 0;
        juice_agent_t *agent = nullptr;
        // Gathered candidate type counts (filled by juice_candidate on the
        // agent thread, summarized in juice_gathering_done) so a config with
        // unreachable STUN/TURN is diagnosable from the debug log.
        int host_candidates = 0;
        int srflx_candidates = 0;
        int relay_candidates = 0;
        // Snapshot of our primary id taken at agent creation (under the
        // transport mutex), so the PING fast path can reply on the agent
        // thread without reading local_ids.
        uint64 primary_id = 0;
        // ---- fast-path ping state (RTT over the active ICE path) ----
        // Armed by update_peer_stats_locked() on the pump thread, answered
        // and stamped by juice_recv()/handle_pong_fast() on the agent thread
        // the moment the PONG arrives. Atomic so neither side needs the
        // transport mutex. ping_sent_at_us is the steady-clock timestamp in
        // microseconds (the same value as the PING token).
        std::atomic<uint64_t> ping_token{0};
        std::atomic<int64_t> ping_sent_at_us{0};
        std::atomic<int> rtt_ms{-1}; // last measured round-trip in ms, -1 = no sample yet
    };

    // Events queued by libjuice callbacks and processed on the pump thread
    // inside Run() under the transport mutex.
    struct JuiceEvent {
        enum class Kind {
            StateChanged,
            Candidate,
            Recv,
        } kind = Kind::StateChanged;
        uint64 peer_id = 0;
        // The agent that produced this event. During an ICE restart the old
        // agent is replaced; events it queued before destruction must not be
        // applied to the new session, so process_juice_events_locked() skips
        // events whose agent differs from the peer's current one. The pointer
        // is only compared, never dereferenced.
        juice_agent_t *agent = nullptr;
        juice_state_t state = JUICE_STATE_DISCONNECTED;
        std::string payload{}; // candidate SDP or received datagram bytes
    };

    // ---- libjuice callbacks (run on the agent threads) ----
    static void juice_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr);
    static void juice_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr);
    static void juice_gathering_done(juice_agent_t *agent, void *user_ptr);
    static void juice_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);
    // Fast path for an incoming PONG: runs on the agent thread, matches the
    // token armed by update_peer_stats_locked() and stamps the RTT without
    // touching the transport mutex.
    void handle_pong_fast(AgentContext *ctx, uint64 token);

    // ---- WebSocket callbacks (run on the pump thread inside Run()) ----
    void ws_message_handler(std::string &&payload);
    void ws_state_handler(bool connected);

    void process_ws_message_locked(const std::string &payload);
    void process_juice_events_locked();
    void ensure_agent_locked(uint64 peer_id, const std::string &signaling_id);
    juice_agent_t *create_agent_locked(uint64 peer_id);
    void queue_agent_destroy_locked(juice_agent_t *agent);
    void destroy_queued_agents();
    void remove_peer_locked(uint64 primary_id, bool notify_disconnect);
    Peer *find_peer_locked(uint64 id);
    Peer *find_peer_by_endpoint_locked(uint32 ip, uint16 port);
    uint64 primary_id() const;
    std::string peer_id_string(uint64 id) const;
    uint64 parse_peer_id(const std::string &value) const;

    // Dedicated pump thread: loops Run() + sleep at ICE_PUMP_INTERVAL_MS so
    // the ICE protocol never depends on the game calling SteamAPI_RunCallbacks
    // (which only happens once per rendered frame).
    void pump_proc();
    // Wake the pump thread immediately (juice event / ws message arrived).
    void pump_wake();

    void handle_description_locked(uint64 peer_id, const std::string &sdp, bool is_offer);
    void restart_agent_locked(uint64 peer_id, const std::string &offer_sdp);
    void send_description_locked(Peer &peer, const char *type);
    void handle_candidate_locked(uint64 peer_id, const std::string &candidate);
    void send_candidate_locked(Peer &peer, const char *sdp);

    // ---- reliability / fragmentation layer ----
    bool send_ice_packet_locked(Peer &peer, uint8 type, uint32 flags, uint64 source_id, uint64 dest_id,
                                uint32 packet_seq, uint32 message_id, uint16 fragment_index,
                                uint16 fragment_count, const std::vector<char> &payload,
                                uint64 token = 0);
    bool send_fragments_locked(Peer &peer, uint64 dest_id, const std::vector<char> &payload, bool reliable);
    void send_pending_reliable_locked();
    // Token-bucket admission for reliable data. Returns false when the peer's
    // paced budget is exhausted; the fragment stays in `pending`.
    bool take_send_tokens_locked(Peer &peer, size_t bytes);
    // Sends queued-but-unsent reliable fragments while the token bucket allows.
    void drain_unsent_locked(Peer &peer);
    // Clears both directions of the reliable stream (sequence counters, pending
    // retransmits, receive window, reassembly and ordered-delivery buffers).
    void reset_reliable_state_locked(Peer &peer);
    // Parses one wire frame in place (no payload copy): `data`/`size` are the
    // datagram bytes as received. The ACK for a reliable message is only
    // queued once the reassembled message is safely in inbound_packets (or was
    // already delivered), so a full queue cannot lose a message the sender
    // already forgot.
    void handle_ice_packet_locked(Peer &peer, const char *data, size_t size);
    // Delivers a fully-reassembled message from peer.reassembly to
    // inbound_packets. Returns false without erasing the assembly when the
    // queue is full and the message is reliable (the caller retries later);
    // unreliable overflow drops the oldest queued message instead. On success
    // arms the coalesced ACK for reliable messages.
    bool try_deliver_message_locked(Peer &peer, uint32 message_id, bool reliable);
    // Retries reliable messages that were fully reassembled but could not be
    // queued (delivery backpressure). Runs from Run() so they land as soon as
    // the game drains inbound_packets.
    void flush_reliable_assemblies_locked();
    // Drains complete reliable messages in message_id order once the game
    // queue has room, preserving ordered-reliable delivery per peer.
    void deliver_ordered_reliable_locked(Peer &peer);
    // Sends at most one coalesced ACK per peer that has ack_pending set.
    void flush_pending_acks_locked();
    // Periodically pings connected peers (RTT) and refreshes the selected
    // candidate pair type. Runs on the pump thread inside Run().
    void update_peer_stats_locked(std::chrono::steady_clock::time_point now);

    // ---- virtual endpoint derivation ----
    uint32 derive_virtual_ip(uint64 id) const;
    uint16 derive_virtual_port(uint64 id) const;

    std::string signaling_host{};
    uint16 signaling_port = 0;
    std::string signaling_secret{};
    std::string stun_host{};
    uint16 stun_port = 0;
    std::string turn_host{};
    uint16 turn_port = 0;
    std::string turn_user{};
    std::string turn_pass{};
    uint16 listen_port = 0;
    uint32 appid = 0;
    std::vector<CSteamID> local_ids{};

    WS_Client ws{};
    bool ws_connected = false;
    bool list_requested = false;
    bool client_identity_promoted = false; // add_listen_id promoted the client id to primary
    bool has_new_connection = false;
    std::chrono::steady_clock::time_point next_connect_attempt{};
    // Exponential reconnect backoff for signaling: starts at 1s, doubles per
    // failed attempt, capped at 30s; reset to 1s on a successful connect.
    int reconnect_delay_ms = 1000;
    std::chrono::steady_clock::time_point next_list_poll{};
    std::deque<std::string> ws_inbox{};

    std::map<uint64, Peer> peers{};                    // by primary id
    std::map<uint64, uint64> peer_by_alias{};          // announced steamid -> primary id
    std::map<uint32, uint64> peer_by_virtual_ip{};     // virtual ip -> primary id
    std::map<juice_agent_t *, AgentContext *> agent_ctx{}; // agent -> per-agent context
    std::deque<AgentContext *> destroy_queue{};        // contexts to destroy outside the lock

    std::deque<InboundPacket> inbound_packets{};
    std::deque<DisconnectEvent> disconnect_events{};

    // Events pushed by libjuice callbacks (agent threads) and drained by Run().
    std::deque<JuiceEvent> juice_events{};
    std::mutex juice_events_mutex{};
    // Callbacks dropped because the bounded event queue was full. Non-zero
    // means the pump could not drain fast enough and packets were lost before
    // reassembly; the sender then has to repair them.
    std::atomic<uint64_t> juice_drops{0};
    // Event-driven pump wakeup: juice/ws callbacks notify, pump_proc() waits
    // on this with a short wait_for() fallback so no path can sleep through an
    // event (missed notify -> at most ICE_PUMP_FALLBACK_MS extra latency).
    std::mutex pump_wake_mutex{};
    std::condition_variable pump_wake_cv{};
    std::atomic<bool> pump_wake_flag{false};

    // ---- 1s traffic rollup (DEBUG) ----
    // Reuses existing counters; emitted from the pump slow path so per-packet
    // TRACE detail is off by default and "traffic flowing" is one line/sec.
    struct TrafficCounters {
        uint64_t msgs_sent = 0;
        uint64_t msgs_recvd = 0;
        uint64_t bytes_sent = 0;
        uint64_t bytes_recvd = 0;
        uint64_t retries = 0;
        uint64_t drops = 0;
        uint64_t evicts = 0;
        uint64_t backpressure = 0;
        uint64_t hole_retries = 0;
        uint64_t data_pkts = 0;
        uint64_t recv_events = 0;
        uint64_t stale_events = 0;
        uint64_t parse_fail = 0;
        uint64_t zero_payload = 0;
        uint64_t deliver_attempts = 0;
        uint64_t deliver_early = 0;
        uint64_t juice_drops = 0;
    };
    TrafficCounters traffic_counters{};
    std::chrono::steady_clock::time_point next_traffic_rollup{};
    void emit_traffic_rollup_locked(std::chrono::steady_clock::time_point now);

    // Dedicated pump thread (see pump_proc()). Started in the constructor,
    // stopped and joined at the top of the destructor before any teardown.
    std::thread pump_thread{};
    std::atomic<bool> pump_stop{false};

    std::recursive_mutex mutex{};
};

#endif // ICE_TRANSPORT_INCLUDE
