#ifndef ICE_TRANSPORT_INCLUDE
#define ICE_TRANSPORT_INCLUDE

#include "network.h"
#include "ws_client.h"

#include <juice/juice.h>

#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
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
    };

    struct ReassemblyState {
        uint16 fragment_count = 0;
        bool reliable = false;
        std::vector<std::vector<char>> fragments{};
        std::vector<bool> present{};
        std::chrono::steady_clock::time_point updated{};
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
        uint32 next_packet_seq = 1;
        uint32 highest_remote_seq = 0;
        uint32 remote_ack_bits = 0;
        uint32 next_message_id = 1;
        std::map<uint32, PendingPacket> pending{};
        std::map<uint32, ReassemblyState> reassembly{};
        std::deque<uint32> completed_messages{};
        std::set<uint32> completed_message_set{};
        std::chrono::steady_clock::time_point last_seen{};
        // Set when signaling reports this peer disconnected while its ICE
        // session is still up; cleared by any incoming ICE activity or a
        // re-registration. After ICE_DISCONNECT_GRACE_SEC without either, the
        // peer is presumed gone and removed (fast friend-list cleanup).
        std::chrono::steady_clock::time_point signal_disconnected_at{};
    };

    Ice_Transport(
        const std::string &signaling_host, uint16 signaling_port, const std::string &signaling_secret,
        const std::string &stun_host, uint16 stun_port,
        const std::string &turn_host, uint16 turn_port, const std::string &turn_user, const std::string &turn_pass,
        uint16 listen_port, uint32 appid, CSteamID initial_id);
    ~Ice_Transport();

    bool enabled() const;
    bool ready();
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
    };

    // Events queued by libjuice callbacks and processed on the network thread
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

    // ---- WebSocket callbacks (run on the network thread inside Run()) ----
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

    void handle_description_locked(uint64 peer_id, const std::string &sdp, bool is_offer);
    void restart_agent_locked(uint64 peer_id, const std::string &offer_sdp);
    void send_description_locked(Peer &peer, const char *type);
    void handle_candidate_locked(uint64 peer_id, const std::string &candidate);
    void send_candidate_locked(Peer &peer, const char *sdp);

    // ---- reliability / fragmentation layer ----
    bool send_ice_packet_locked(Peer &peer, uint8 type, uint32 flags, uint64 source_id, uint64 dest_id,
                                uint32 packet_seq, uint32 message_id, uint16 fragment_index,
                                uint16 fragment_count, const std::vector<char> &payload);
    bool send_fragments_locked(Peer &peer, uint64 dest_id, const std::vector<char> &payload, bool reliable);
    void send_pending_reliable_locked();
    void handle_ice_packet_locked(Peer &peer, const std::vector<char> &packet);

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

    std::recursive_mutex mutex{};
};

#endif // ICE_TRANSPORT_INCLUDE
