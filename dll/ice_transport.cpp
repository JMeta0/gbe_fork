#include "dll/ice_transport.h"

#include "json/json.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace {

// ---- ICE datagram protocol ----
// The libjuice agent only provides an authenticated, connected datagram
// channel. On top of it we keep the proven wire format for reliable delivery,
// fragmentation and acknowledgment.

constexpr uint32 ICE_MAGIC = 0x4E505447; // GPTN
constexpr uint8 ICE_VERSION = 2;
constexpr uint8 ICE_PKT_DATA = 3;
constexpr uint8 ICE_PKT_ACK = 4;
constexpr uint8 ICE_PKT_PING = 5;
constexpr uint8 ICE_PKT_PONG = 6;
constexpr uint8 ICE_PKT_MSGACK = 7;
constexpr uint32 ICE_FLAG_RELIABLE = 1u << 0;
constexpr size_t ICE_FRAGMENT_MTU = 1150;
constexpr int ICE_RTO_INITIAL_MS = 250;
constexpr int ICE_RTO_MIN_MS = 50;
constexpr int ICE_RTO_MAX_MS = 1000;
constexpr size_t MAX_PENDING_RELIABLE = 49152; // ~54 MB per peer; 1.6x the observed burst
// How often a connected peer is pinged (RTT) and its selected candidate pair
// type re-checked. Small frames over the active ICE path; 2s keeps the overlay
// stats fresh without measurable overhead.
constexpr int ICE_PING_INTERVAL_MS = 2000;
// P2-E: the selected candidate pair barely changes mid-session; re-classify
// at most every 10s instead of strstr() on every 2s ping tick.
constexpr int ICE_CONN_TYPE_REFRESH_MS = 10000;
// Cadence of the dedicated pump thread fallback wait. The pump is woken
// immediately by juice/ws events via pump_wake_cv; the wait_for() fallback
// only bounds the damage of a missed notify. Fast path (event drain, send,
// ACK/PING/PONG) therefore runs at event latency instead of a fixed 10ms
// poll quantization; slow path (list, stats, GC, rollup) stays cadenced.
// 5ms keeps idle wakeups low (~200/s) while a missed notify still costs at
// most 5ms; the fast path is event-driven, so this is not on the latency
// path. If wakeups stop arriving, raise this, never re-add a fixed poll.
constexpr int ICE_PUMP_FALLBACK_MS = 5;
constexpr int ICE_PUMP_INTERVAL_MS = 10; // slow-path cadence only (kept for tuning compat)
// How long to keep an established ICE session after signaling reports the peer
// disconnected before presuming it gone. Peers broadcast announces every ~5s,
// so any live peer clears the grace flag well within this window; a process
// that quit stays silent and is removed (friend list updated) shortly after.
constexpr double ICE_DISCONNECT_GRACE_SEC = 8.0;
// How long an incomplete incoming message may sit in peer.reassembly before it
// is garbage-collected. The sender retries on its adaptive RTO (initial
// 250ms, backoff to 1s), so a partial message that receives no fragment for
// this long is unrecoverable; keeping it would only leak memory.
constexpr double ICE_REASSEMBLY_GC_SEC = 10.0; // holes recover in ~250ms; bound the ordered block
// Upper bound for the libjuice callback event queue. While the pump thread
// is stalled (e.g. a large state sync building fragments under the lock),
// callbacks keep queueing; beyond this cap the oldest events are dropped so
// memory stays bounded. 1024 was only ~100ms at 10k pps, which turned a short
// stall into large contiguous losses; 8192 gives the pump room to catch up.
constexpr size_t MAX_JUICE_EVENTS = 8192;
// Upper bound for inbound messages waiting for the game to drain them (the
// pump thread fills this queue at packet rate; the game drains per frame, the
// 300ms fallback thread when it stalls). Oldest messages are dropped beyond
// the cap so memory stays bounded during a long game stall.
constexpr size_t MAX_INBOUND_PACKETS = 1024;

struct IceHeader {
    uint8 version = ICE_VERSION;
    uint8 type = 0;
    uint16 reserved = 0;
    uint32 flags = 0;
    uint32 packet_seq = 0;
    uint32 ack = 0;
    uint32 ack_bits = 0;
    uint64 source_id = 0;
    uint64 dest_id = 0;
    uint64 token = 0; // unused over ICE (authenticated by libjuice)
    uint64 session_epoch = 0; // changes when a side recreates its ICE agent
    uint32 message_id = 0;
    uint16 fragment_index = 0;
    uint16 fragment_count = 0;
};

void append_u16(std::vector<char> &out, uint16 value)
{
    out.push_back(static_cast<char>(value & 0xFF));
    out.push_back(static_cast<char>((value >> 8) & 0xFF));
}

void append_u32(std::vector<char> &out, uint32 value)
{
    out.push_back(static_cast<char>(value & 0xFF));
    out.push_back(static_cast<char>((value >> 8) & 0xFF));
    out.push_back(static_cast<char>((value >> 16) & 0xFF));
    out.push_back(static_cast<char>((value >> 24) & 0xFF));
}

void append_u64(std::vector<char> &out, uint64 value)
{
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<char>((value >> (i * 8)) & 0xFF));
    }
}

// Wire size of IceHeader on the wire (GPTN v2): magic(4) + ver(1) + type(1)
// + reserved(2) + flags(4) + seq(4) + ack(4) + ack_bits(4) + src(8) + dst(8)
// + token(8) + epoch(8) + msg_id(4) + frag_idx(2) + frag_cnt(2) + payload_len(4) = 68.
constexpr size_t ICE_HEADER_SIZE = 68;
static_assert(ICE_HEADER_SIZE == 4 + 1 + 1 + 2 + 4 + 4 + 4 + 4 + 8 + 8 + 8 + 8 + 4 + 2 + 2 + 4,
              "ICE_HEADER_SIZE must match append_ice_header()");

void append_ice_header(std::vector<char> &out, const IceHeader &header)
{
    append_u32(out, ICE_MAGIC);
    out.push_back(static_cast<char>(header.version));
    out.push_back(static_cast<char>(header.type));
    append_u16(out, header.reserved);
    append_u32(out, header.flags);
    append_u32(out, header.packet_seq);
    append_u32(out, header.ack);
    append_u32(out, header.ack_bits);
    append_u64(out, header.source_id);
    append_u64(out, header.dest_id);
    append_u64(out, header.token);
    append_u64(out, header.session_epoch);
    append_u32(out, header.message_id);
    append_u16(out, header.fragment_index);
    append_u16(out, header.fragment_count);
}

bool read_u16(const char *in, size_t size, size_t &offset, uint16 &value)
{
    if (offset + 2 > size) return false;
    value = static_cast<uint16>(static_cast<uint8_t>(in[offset])) |
            (static_cast<uint16>(static_cast<uint8_t>(in[offset + 1])) << 8);
    offset += 2;
    return true;
}

bool read_u32(const char *in, size_t size, size_t &offset, uint32 &value)
{
    if (offset + 4 > size) return false;
    value =
        static_cast<uint32>(static_cast<uint8_t>(in[offset])) |
        (static_cast<uint32>(static_cast<uint8_t>(in[offset + 1])) << 8) |
        (static_cast<uint32>(static_cast<uint8_t>(in[offset + 2])) << 16) |
        (static_cast<uint32>(static_cast<uint8_t>(in[offset + 3])) << 24);
    offset += 4;
    return true;
}

bool read_u64(const char *in, size_t size, size_t &offset, uint64 &value)
{
    if (offset + 8 > size) return false;
    value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64>(static_cast<uint8_t>(in[offset + i])) << (i * 8);
    }
    offset += 8;
    return true;
}

// Zero-alloc variant: appends a full frame into a reused buffer
// (thread-local send buffers, or a queued pending buffer) instead of
// allocating per fragment.
void serialize_ice_header_into(std::vector<char> &out, const IceHeader &header, const char *payload, size_t payload_size)
{
    append_ice_header(out, header);
    append_u32(out, static_cast<uint32>(payload_size));
    if (payload_size != 0) {
        out.insert(out.end(), payload, payload + payload_size);
    }
}

// Parses a frame in place: on success `payload_offset`/`payload_size` point at
// the payload inside the caller's datagram buffer, so the header read does not
// copy the payload. The caller copies only what it must retain (reassembly).
bool deserialize_ice_header(const char *data, size_t size, IceHeader &header, size_t &payload_offset, size_t &payload_size)
{
    size_t offset = 0;
    uint32 magic = 0;
    uint32 plen = 0;
    if (!read_u32(data, size, offset, magic) || magic != ICE_MAGIC) return false;
    if (offset + 2 > size) return false;
    header.version = static_cast<uint8>(data[offset++]);
    header.type = static_cast<uint8>(data[offset++]);
    if (header.version != ICE_VERSION) return false;
    if (!read_u16(data, size, offset, header.reserved)) return false;
    if (!read_u32(data, size, offset, header.flags)) return false;
    if (!read_u32(data, size, offset, header.packet_seq)) return false;
    if (!read_u32(data, size, offset, header.ack)) return false;
    if (!read_u32(data, size, offset, header.ack_bits)) return false;
    if (!read_u64(data, size, offset, header.source_id)) return false;
    if (!read_u64(data, size, offset, header.dest_id)) return false;
    if (!read_u64(data, size, offset, header.token)) return false;
    if (!read_u64(data, size, offset, header.session_epoch)) return false;
    if (!read_u32(data, size, offset, header.message_id)) return false;
    if (!read_u16(data, size, offset, header.fragment_index)) return false;
    if (!read_u16(data, size, offset, header.fragment_count)) return false;
    if (!read_u32(data, size, offset, plen)) return false;
    if (offset + plen > size) return false;
    payload_offset = offset;
    payload_size = plen;
    return true;
}

bool seq_is_more_recent(uint32 seq, uint32 expected)
{
    return ((seq > expected) && (seq - expected <= 0x80000000u)) ||
           ((expected > seq) && (expected - seq > 0x80000000u));
}

// Unique per agent creation. The low bits come from the monotonic clock, the
// counter guarantees uniqueness if two agents are created in the same tick.
uint64 make_session_epoch()
{
    static std::atomic<uint64_t> counter{1};
    uint64_t now = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    return now ^ (counter.fetch_add(1, std::memory_order_relaxed) << 32) ^
           0x9E3779B97F4A7C15ull;
}

// deterministic FNV-1a over (appid, steamid) -> virtual endpoint
uint32 fnv1a32(uint32 appid, uint64 id)
{
    uint32 hash = 2166136261u;
    auto mix = [&hash](uint32 byte) {
        hash ^= byte;
        hash *= 16777619u;
    };
    mix(appid & 0xFF);
    mix((appid >> 8) & 0xFF);
    mix((appid >> 16) & 0xFF);
    mix((appid >> 24) & 0xFF);
    for (int i = 0; i < 8; ++i) {
        mix(static_cast<uint32>((id >> (i * 8)) & 0xFF));
    }
    return hash;
}

// Classifies the live connection from the ICE selected candidate pair:
// relayed via TURN if either side uses a relay candidate; otherwise the
// path is P2P — srflx (reflexive address learned via STUN) or host (direct).
Ice_Transport::PeerConnectionType selected_candidate_connection_type(juice_agent_t *agent)
{
    if (!agent) return Ice_Transport::PeerConnectionType::Unknown;
    char local[512]{};
    char remote[512]{};
    if (juice_get_selected_candidates(agent, local, sizeof(local), remote, sizeof(remote)) != JUICE_ERR_SUCCESS) {
        return Ice_Transport::PeerConnectionType::Unknown;
    }
    if (strstr(local, "typ relay") || strstr(remote, "typ relay")) {
        return Ice_Transport::PeerConnectionType::Turn;
    }
    // Peer-reflexive candidates are learned during connectivity checks when the
    // peer's actual source address differs from every announced candidate (e.g.
    // symmetric NAT). The path is still P2P NAT traversal, so group it with
    // srflx under Stun instead of mislabeling it as a direct host-host path.
    if (strstr(local, "typ srflx") || strstr(remote, "typ srflx") ||
        strstr(local, "typ prflx") || strstr(remote, "typ prflx")) {
        return Ice_Transport::PeerConnectionType::Stun;
    }
    return Ice_Transport::PeerConnectionType::Direct;
}

// Lock-free raw send used by the juice_recv fast path (agent thread). Builds
// an ICE frame and hands it straight to libjuice without touching any Peer
// state or the transport mutex. Safe to call from a libjuice callback: the
// conn mutex is recursive ("Recursive to allow calls from user callbacks",
// conn_thread.c) and libjuice itself sends STUN replies from that context.
// Header fields not passed in (ack/ack_bits/message_id/fragment_*) are 0, the
// same as the PING/PONG frames already on the wire.
bool send_raw_ice_packet(juice_agent_t *agent, uint8 type, uint32 flags, uint64 source_id, uint64 dest_id,
                         uint32 packet_seq, uint32 message_id, uint16 fragment_index,
                         uint16 fragment_count, const std::vector<char> &payload, uint64 token)
{
    if (!agent) return false;
    IceHeader header{};
    header.type = type;
    header.flags = flags;
    header.packet_seq = packet_seq;
    header.source_id = source_id;
    header.dest_id = dest_id;
    header.token = token;
    header.message_id = message_id;
    header.fragment_index = fragment_index;
    header.fragment_count = fragment_count;
    // Reuse a per-thread frame buffer: the fast PING/PONG path runs at datagram
    // rate and must not allocate (the buffer is consumed by juice_send before
    // this function returns).
    thread_local std::vector<char> tls_raw_frame{};
    tls_raw_frame.clear();
    serialize_ice_header_into(tls_raw_frame, header, payload.empty() ? nullptr : payload.data(), payload.size());
    return juice_send(agent, tls_raw_frame.data(), tls_raw_frame.size()) == JUICE_ERR_SUCCESS;
}

} // namespace

Ice_Transport::Ice_Transport(
    const std::string &signaling_host_, uint16 signaling_port_, const std::string &signaling_secret_,
    const std::string &stun_host_, uint16 stun_port_,
    const std::string &turn_host_, uint16 turn_port_, const std::string &turn_user_, const std::string &turn_pass_,
    uint16 listen_port_, uint32 appid_, CSteamID initial_id)
    : signaling_host(signaling_host_)
    , signaling_port(signaling_port_)
    , signaling_secret(signaling_secret_)
    , stun_host(stun_host_)
    , stun_port(stun_port_)
    , turn_host(turn_host_)
    , turn_port(turn_port_)
    , turn_user(turn_user_)
    , turn_pass(turn_pass_)
    , listen_port(listen_port_)
    , appid(appid_)
{
    if (initial_id.IsValid()) {
        local_ids.push_back(initial_id);
    }
    next_connect_attempt = std::chrono::steady_clock::now();

    ws.set_message_callback([this](std::string &&payload) { ws_message_handler(std::move(payload)); });
    ws.set_state_callback([this](bool connected) { ws_state_handler(connected); });
    ws.configure(signaling_host, signaling_port, peer_id_string(primary_id()), signaling_secret);

    // Start the dedicated protocol pump so the ICE layer ticks at a fixed
    // ~10ms regardless of how often the game calls SteamAPI_RunCallbacks.
    pump_thread = std::thread(&Ice_Transport::pump_proc, this);

    PRINT_DEBUG("ice transport created host='%s' port=%u appid=%u ids=%llu stun='%s:%u' turn='%s:%u' user='%s'", signaling_host.c_str(), signaling_port, appid, static_cast<unsigned long long>(primary_id()), stun_host.c_str(), stun_port, turn_host.c_str(), turn_port, turn_user.c_str());
}

Ice_Transport::~Ice_Transport()
{
    // Stop and join the pump thread FIRST, before any teardown: the pump may
    // be mid-Run() (holding the mutex briefly) and must never observe
    // half-destroyed peers/agents/ws state.
    pump_stop.store(true);
    pump_wake();
    if (pump_thread.joinable()) {
        pump_thread.join();
    }

    std::vector<AgentContext *> to_destroy{};
    {
        std::lock_guard<std::recursive_mutex> lock(mutex);
        ws.disconnect();
        for (auto &[id, peer] : peers) {
            if (peer.agent) {
                auto it = agent_ctx.find(peer.agent);
                if (it != agent_ctx.end()) to_destroy.push_back(it->second);
            }
        }
        for (auto *ctx : destroy_queue) {
            if (ctx) to_destroy.push_back(ctx);
        }
        destroy_queue.clear();
        peers.clear();
        peer_by_alias.clear();
        peer_by_virtual_ip.clear();
        agent_ctx.clear();
    }
    for (auto *ctx : to_destroy) {
        if (!ctx) continue;
        if (ctx->agent) juice_destroy(ctx->agent);
        delete ctx;
    }
}

bool Ice_Transport::enabled() const
{
    return !signaling_host.empty() && signaling_port != 0;
}

bool Ice_Transport::ready()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    return ws_connected && !local_ids.empty();
}

uint32 Ice_Transport::virtual_ip()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    return derive_virtual_ip(primary_id());
}

uint16 Ice_Transport::virtual_port()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    return derive_virtual_port(primary_id());
}

uint64 Ice_Transport::primary_id() const
{
    return local_ids.empty() ? 0 : local_ids.front().ConvertToUint64();
}

std::string Ice_Transport::peer_id_string(uint64 id) const
{
    // appid is part of the signaling identity so two games running under the
    // same steamid on the same signaling server stay isolated.
    return std::to_string(appid) + "/" + std::to_string(id);
}

uint64 Ice_Transport::parse_peer_id(const std::string &value) const
{
    if (value.empty()) return 0;
    size_t slash = value.find_last_of('/');
    if (slash != std::string::npos) {
        uint32 peer_appid = static_cast<uint32>(std::strtoul(value.c_str(), nullptr, 10));
        if (peer_appid != 0 && peer_appid != appid && peer_appid != LOBBY_CONNECT_APPID) {
            return 0;
        }
    }
    const char *start = slash == std::string::npos ? value.c_str() : value.c_str() + slash + 1;
    if (*start == '\0') return 0;
    return static_cast<uint64>(std::strtoull(start, nullptr, 10));
}

void Ice_Transport::set_appid(uint32 next_appid)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (appid == next_appid) return;
    appid = next_appid;

    // virtual endpoints depend on the appid; recompute for every peer
    peer_by_virtual_ip.clear();
    for (auto &[id, peer] : peers) {
        peer.virtual_ip = derive_virtual_ip(peer.primary_id);
        peer.virtual_port = derive_virtual_port(peer.primary_id);
        peer_by_virtual_ip[peer.virtual_ip] = peer.primary_id;
    }

    // our signaling identity changed -> reconnect with the new path
    ws.configure(signaling_host, signaling_port, peer_id_string(primary_id()), signaling_secret);
    ws.disconnect();
    ws_connected = false;
    list_requested = false;
    next_connect_attempt = std::chrono::steady_clock::now();
    PRINT_DEBUG("ice appid changed appid=%u", appid);
}

void Ice_Transport::add_listen_id(CSteamID id)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (!id.IsValid()) return;
    auto found = std::find(local_ids.begin(), local_ids.end(), id);
    if (found != local_ids.end()) return;
    local_ids.push_back(id);

    // The signaling identity must be unique per player (the EOS emu registers
    // under its per-user ProductUserId; see Nemirtingas_Epic_emu eossdk_platform.cpp
    // SetPeerId(pUser->ProductUserId->to_string())). This transport is born with
    // the game-server id, which every client of the same game shares, so two
    // clients would collide on the same signaling path and kick each other.
    // Promote the first distinct id (the per-player client id) to primary and
    // reconnect under ws://<host>:<port>/<appid>/<client-id>.
    if (!client_identity_promoted && id.ConvertToUint64() != primary_id()) {
        client_identity_promoted = true;
        local_ids.erase(std::find(local_ids.begin(), local_ids.end(), id));
        local_ids.insert(local_ids.begin(), id);
        ws.configure(signaling_host, signaling_port, peer_id_string(id.ConvertToUint64()), signaling_secret);
        ws.disconnect();
        ws_connected = false;
        list_requested = false;
        next_connect_attempt = std::chrono::steady_clock::now();
        PRINT_DEBUG("ice signaling identity promoted to client id=%llu", static_cast<unsigned long long>(id.ConvertToUint64()));
    }

    PRINT_DEBUG("ice add_listen_id id=%llu", static_cast<unsigned long long>(id.ConvertToUint64()));
}

uint32 Ice_Transport::derive_virtual_ip(uint64 id) const
{
    return 0x0AC80000u | (fnv1a32(appid, id) & 0x0000FFFFu); // 10.200.x.y, same range as the old broker
}

uint16 Ice_Transport::derive_virtual_port(uint64 id) const
{
    return static_cast<uint16>(1024 + ((fnv1a32(appid, id) >> 16) % 60000u));
}

// ---- WebSocket signaling ----

// NOTE on lock order: this callback runs on the pump thread while the WS
// client holds its own mutex (Run()/close_locked()), so the order here is
// ws-mutex -> ice-mutex. Everywhere else the order is ice-mutex -> ws-mutex
// (e.g. Ice_Transport::Send -> WS_Client::send). This inversion only works
// because both mutexes are recursive and the callbacks fire on the same thread
// that already holds the ice-mutex (Ice_Transport::Run() on the pump thread).
// Do not add any path that invokes a WS callback from a thread not already
// holding the ice-mutex, or decouple the callback via the ws_inbox first.

void Ice_Transport::ws_state_handler(bool connected)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (connected) {
        ws_connected = true;
        list_requested = false;
        reconnect_delay_ms = 1000; // backoff resets once signaling is up
        PRINT_DEBUG("ice signaling connected");
    } else {
        ws_connected = false;
        list_requested = false;
        next_connect_attempt = std::chrono::steady_clock::now() + std::chrono::milliseconds(reconnect_delay_ms);

        // Candidates and descriptions sent while signaling is down cannot be
        // replayed by the WebSocket client. Recreate peers that never reached
        // ICE connected so the next peer list starts a fresh negotiation.
        std::vector<uint64> incomplete_peers{};
        for (const auto &[peer_id, peer] : peers) {
            if (!peer.connected) {
                incomplete_peers.push_back(peer_id);
            }
        }
        for (uint64 peer_id : incomplete_peers) {
            remove_peer_locked(peer_id, false);
        }

        PRINT_DEBUG("ice signaling disconnected");
    }
}

void Ice_Transport::ws_message_handler(std::string &&payload)
{
    {
        std::lock_guard<std::recursive_mutex> lock(mutex);
        ws_inbox.push_back(std::move(payload));
    }
    // Wake outside the transport mutex: pump_wake() only touches the wakeup
    // mutex/CV, and the pump never takes the transport mutex while waiting.
    pump_wake();
}

void Ice_Transport::pump_wake()
{
    {
        std::lock_guard<std::mutex> wlock(pump_wake_mutex);
        pump_wake_flag.store(true);
    }
    pump_wake_cv.notify_one();
}

void Ice_Transport::process_ws_message_locked(const std::string &payload)
{
    // The signaling server relays messages from arbitrary peers, so field
    // types are not trustworthy: "type": 123 (or any non-string where a
    // string is expected) makes json.value()/get<>() throw a
    // nlohmann::json::type_error. json::parse already runs with
    // allow_exceptions=false; the try/catch covers the extractions below so a
    // malformed message can never crash the pump thread.
    try {
    auto json = nlohmann::json::parse(payload, nullptr, false);
    if (json.is_discarded() || !json.is_object()) return;

    std::string type = json.value("type", "");
    if (type == "list") {
        size_t peer_count = json.contains("peer_ids") && json["peer_ids"].is_array() ? json["peer_ids"].size() : 0;
        PRINT_TRACE("ice signaling list peers=%zu", peer_count);
        if (json.contains("peer_ids") && json["peer_ids"].is_array()) {
            for (const auto &item : json["peer_ids"]) {
                if (!item.is_string()) continue;
                std::string id_str = item.get<std::string>();
                uint64 peer_id = parse_peer_id(id_str);
                if (peer_id != 0 && peer_id != primary_id()) {
                    ensure_agent_locked(peer_id, id_str);
                }
            }
        }
    } else if (type == "peer_connected") {
        std::string id_str = json.value("peer_id", "");
        uint64 peer_id = parse_peer_id(id_str);
        PRINT_DEBUG("ice signaling peer connected peer=%llu id='%s'", static_cast<unsigned long long>(peer_id), id_str.c_str());
        if (peer_id != 0 && peer_id != primary_id()) {
            auto pit = peers.find(peer_id);
            if (pit != peers.end()) {
                // The peer re-registered on signaling (e.g. it restarted the
                // game): it is clearly still alive, cancel any disconnect grace.
                pit->second.signal_disconnected_at = {};
            }
            ensure_agent_locked(peer_id, id_str);
        }
    } else if (type == "peer_disconnected") {
        std::string id_str = json.value("peer_id", "");
        uint64 peer_id = parse_peer_id(id_str);
        PRINT_DEBUG("ice signaling peer disconnected peer=%llu id='%s'", static_cast<unsigned long long>(peer_id), id_str.c_str());
        if (peer_id != 0) {
            auto pit = peers.find(peer_id);
            if (pit != peers.end() && pit->second.connected) {
                // The signaling channel is only needed for ICE negotiation. Once a
                // session is established the data path is independent of it, so a
                // signaling drop (websocket blip, hub write-deadline close, NAT idle
                // timeout) does not mean the peer went away. Keep the session up,
                // but arm a short grace: if the peer neither sends data nor
                // re-registers (i.e. it actually quit), Run() removes it after
                // ICE_DISCONNECT_GRACE_SEC so the friend list updates quickly
                // instead of waiting for libjuice's consent timeout.
                if (pit->second.signal_disconnected_at == std::chrono::steady_clock::time_point{}) {
                    pit->second.signal_disconnected_at = std::chrono::steady_clock::now();
                }
                PRINT_DEBUG("ice signaling peer disconnected ignored peer=%llu (established ICE session, grace armed)", static_cast<unsigned long long>(peer_id));
            } else {
                remove_peer_locked(peer_id, true);
            }
        }
    } else if (type == "offer" || type == "answer") {
        std::string id_str = json.value("source_id", "");
        uint64 peer_id = parse_peer_id(id_str);
        std::string sdp = json.value("sdp", "");
        if (peer_id != 0 && peer_id != primary_id() && !sdp.empty()) {
            ensure_agent_locked(peer_id, id_str);
            handle_description_locked(peer_id, sdp, type == "offer");
        }
    } else if (type == "candidate") {
        std::string id_str = json.value("source_id", "");
        uint64 peer_id = parse_peer_id(id_str);
        std::string candidate = json.value("candidate", "");
        if (peer_id != 0 && !candidate.empty()) {
            ensure_agent_locked(peer_id, id_str);
            handle_candidate_locked(peer_id, candidate);
        }
    }
    } catch (const nlohmann::json::exception &) {
        PRINT_DEBUG("ice signaling message dropped: malformed json");
    }
}

void Ice_Transport::handle_description_locked(uint64 peer_id, const std::string &sdp, bool is_offer)
{
    auto pit = peers.find(peer_id);
    if (pit == peers.end() || !pit->second.agent) return;
    Peer &peer = pit->second;
    std::string preview = sdp.size() > 96 ? sdp.substr(0, 96) + "..." : sdp;
    PRINT_TRACE("ice remote %s peer=%llu sdp='%s'", is_offer ? "offer" : "answer", static_cast<unsigned long long>(peer_id), preview.c_str());

    peer.signal_disconnected_at = {};

    if (is_offer && peer.remote_description_set) {
        // We already negotiated this peer. Applying the new offer in place:
        // libjuice ignores an identical remote description (retransmitted
        // offer -> JUICE_ERR_SUCCESS) and rejects a genuinely new one
        // (JUICE_ERR_FAILED, "ICE restart is not supported"). Only the latter
        // means the peer restarted (new registration, fresh credentials), so
        // replace the agent and re-negotiate. The crossed-offer / glare case
        // (remote not set yet) is intentionally NOT restarted: both sides
        // offer on first discovery and libjuice connects them via the
        // connectivity checks without answers.
        int res = juice_set_remote_description(peer.agent, sdp.c_str());
        if (res == JUICE_ERR_FAILED) {
            restart_agent_locked(peer_id, sdp);
        } else if (res == JUICE_ERR_SUCCESS) {
            PRINT_TRACE("ice duplicate offer ignored peer=%llu", static_cast<unsigned long long>(peer_id));
        }
        return;
    }

    if (juice_set_remote_description(peer.agent, sdp.c_str()) < 0) {
        PRINT_DEBUG("ice set remote description failed peer=%llu", static_cast<unsigned long long>(peer_id));
    } else {
        peer.remote_description_set = true;
        for (const auto &cand : peer.pending_remote_candidates) {
            PRINT_TRACE("ice replay pending candidate peer=%llu", static_cast<unsigned long long>(peer_id));
            if (juice_add_remote_candidate(peer.agent, cand.c_str()) < 0) {
                PRINT_DEBUG("ice add remote candidate failed peer=%llu", static_cast<unsigned long long>(peer_id));
            }
        }
        peer.pending_remote_candidates.clear();
    }

    if (is_offer && !peer.description_sent) {
        peer.description_sent = true;
        send_description_locked(peer, "answer");
    }
}

void Ice_Transport::reset_reliable_state_locked(Peer &peer)
{
    peer.pending.clear();
    peer.pending_msg_ranges.clear();
    peer.reassembly.clear();
    peer.completed_messages.clear();
    peer.completed_message_set.clear();
    peer.completed_ack_ids.clear();
    peer.ordered_reliable.clear();
    peer.incomplete_reliable_ids.clear();
    peer.ordered_highwater = 0;
    peer.recv_bitmap.assign(Peer::RECV_WINDOW_BITS / 64, 0);
    peer.recv_bitmap_head = 0;
    peer.ooo_count = 0;
    peer.next_reliable_seq = 1;
    peer.next_packet_seq = 1;
    peer.next_message_id = 1;
    peer.highest_contiguous_seq = 0;
    peer.remote_ack_bits = 0;
    peer.peer_ack = 0;
    peer.peer_ack_bits = 0;
    peer.peer_ack_ext.fill(0);
    peer.peer_ack_ext_base = 0;
    peer.ack_pending = false;
    peer.last_fast_rtx_ack = 0;
    peer.send_tokens = 0.0;
    peer.send_token_time = {};
    peer.send_rate_bps = 4.0 * 1024 * 1024; // new session: restart from the safe rate
    peer.unsent_seqs.clear();
    peer.next_unsent_at = {};
    peer.reliable_frags_sent = 0;
    peer.last_reliable_frags_sent = 0;
    peer.recv_unique = 0;
    peer.recv_bytes = 0;
    peer.recv_highest = 0;
    peer.remote_recv_unique = 0;
    peer.remote_recv_bytes = 0;
    peer.remote_recv_highest = 0;
    peer.remote_ooo = 0;
    peer.remote_telemetry_valid = false;
    peer.remote_telemetry_sampled = false;
    peer.last_remote_recv_unique = 0;
    peer.last_remote_recv_bytes = 0;

    // Drop game-bound messages from the previous session for this peer.
    const uint32 vip = htonl(peer.virtual_ip);
    inbound_packets.erase(
        std::remove_if(inbound_packets.begin(), inbound_packets.end(),
            [vip](const InboundPacket &packet) { return packet.ip_port.ip == vip; }),
        inbound_packets.end());
}

void Ice_Transport::restart_agent_locked(uint64 peer_id, const std::string &offer_sdp)
{
    auto pit = peers.find(peer_id);
    if (pit == peers.end()) return;
    Peer &peer = pit->second;
    PRINT_DEBUG("ice restart peer=%llu", static_cast<unsigned long long>(peer_id));

    // A re-negotiated session supersedes the old one: the peer's previous
    // process is gone (this offer came from a fresh registration), so its old
    // agent is dead even though we never saw it fail. Reset all per-session
    // state but keep the peer entry (ids, virtual endpoints, aliases).
    bool was_connected = peer.connected;
    reset_reliable_state_locked(peer);
    peer.local_session_epoch = make_session_epoch();
    peer.remote_session_epoch = 0;
    // Fresh session, fresh path: drop the old RTT estimate so the new agent
    // starts at the initial RTO.
    peer.srtt_ms = -1.0;
    peer.rttvar_ms = 0.0;
    // pending_remote_candidates is kept: they are replayed once the new agent
    // has the new remote description (and survive a create failure).
    peer.remote_description_set = false;
    peer.description_sent = false;
    peer.connected = false;
    peer.signal_disconnected_at = {};

    if (was_connected) {
        // The peer did not go away (it re-negotiated), so do not fire a real
        // disconnect. Notify the network layer so it re-marks the connection
        // offline: the first data packet of the new session then re-fires the
        // CONNECT callback, which re-pushes our friend data to the peer. This
        // is emitted before the replacement agent is created so the connection
        // is re-marked offline even if agent creation fails below.
        DisconnectEvent ev{};
        if (!peer.ids.empty()) {
            ev.ids.reserve(peer.ids.size());
            for (uint64 id : peer.ids) {
                ev.ids.emplace_back(CSteamID(id));
            }
        } else {
            ev.ids.emplace_back(CSteamID(peer_id));
        }
        ev.virtual_ip = peer.virtual_ip;
        ev.virtual_port = peer.virtual_port;
        ev.session_reset = true;
        disconnect_events.push_back(std::move(ev));
        PRINT_DEBUG("ice peer session restarted peer=%llu ids=%zu", static_cast<unsigned long long>(peer_id), ev.ids.size());
    }

    if (peer.agent) {
        queue_agent_destroy_locked(peer.agent);
    }
    peer.agent = create_agent_locked(peer_id);
    if (!peer.agent) return;

    if (juice_set_remote_description(peer.agent, offer_sdp.c_str()) < 0) {
        PRINT_DEBUG("ice set remote description failed (restart) peer=%llu", static_cast<unsigned long long>(peer_id));
        return;
    }
    peer.remote_description_set = true;
    for (const auto &cand : peer.pending_remote_candidates) {
        if (juice_add_remote_candidate(peer.agent, cand.c_str()) < 0) {
            PRINT_DEBUG("ice add remote candidate failed (restart) peer=%llu", static_cast<unsigned long long>(peer_id));
        }
    }
    peer.pending_remote_candidates.clear();
    peer.description_sent = true;
    send_description_locked(peer, "answer");
}

void Ice_Transport::send_description_locked(Peer &peer, const char *type)
{
    if (!ws_connected || !peer.agent) return;
    char sdp[JUICE_MAX_SDP_STRING_LEN]{};
    if (juice_get_local_description(peer.agent, sdp, sizeof(sdp)) < 0) {
        PRINT_DEBUG("ice get local description failed peer=%llu", static_cast<unsigned long long>(peer.primary_id));
        return;
    }
    nlohmann::json json;
    json["type"] = type;
    json["id"] = peer.signaling_id;
    json["source_id"] = peer_id_string(primary_id());
    json["sdp"] = sdp;
    std::string preview = sdp;
    if (preview.size() > 96) preview = preview.substr(0, 96) + "...";
    PRINT_TRACE("ice local %s -> peer=%llu dest='%s' sdp='%s'", type, static_cast<unsigned long long>(peer.primary_id), peer.signaling_id.c_str(), preview.c_str());
    if (!ws.send(json.dump())) {
        PRINT_DEBUG("ice %s send failed peer=%llu", type, static_cast<unsigned long long>(peer.primary_id));
    }
}

void Ice_Transport::handle_candidate_locked(uint64 peer_id, const std::string &candidate)
{
    auto pit = peers.find(peer_id);
    if (pit == peers.end() || !pit->second.agent) return;
    Peer &peer = pit->second;
    std::string preview = candidate.size() > 96 ? candidate.substr(0, 96) + "..." : candidate;
    PRINT_TRACE("ice remote candidate peer=%llu sdp='%s'", static_cast<unsigned long long>(peer_id), preview.c_str());
    peer.signal_disconnected_at = {};
    if (!peer.remote_description_set) {
        PRINT_TRACE("ice buffering candidate pending remote description peer=%llu", static_cast<unsigned long long>(peer_id));
        peer.pending_remote_candidates.push_back(candidate);
        return;
    }
    if (juice_add_remote_candidate(peer.agent, candidate.c_str()) < 0) {
        PRINT_DEBUG("ice add remote candidate failed peer=%llu", static_cast<unsigned long long>(peer_id));
    }
}

void Ice_Transport::send_candidate_locked(Peer &peer, const char *sdp)
{
    // The candidate callback can run synchronously while create_agent_locked()
    // is still assigning Peer::agent. The per-agent context already validated
    // the source agent, so do not require Peer::agent here.
    if (!ws_connected) return;
    nlohmann::json json;
    json["type"] = "candidate";
    json["id"] = peer.signaling_id;
    json["source_id"] = peer_id_string(primary_id());
    json["candidate"] = sdp;
    std::string preview = sdp ? std::string(sdp) : std::string{};
    if (preview.size() > 96) preview = preview.substr(0, 96) + "...";
    PRINT_TRACE("ice local candidate -> peer=%llu dest='%s' sdp='%s'", static_cast<unsigned long long>(peer.primary_id), peer.signaling_id.c_str(), preview.c_str());
    if (!ws.send(json.dump())) {
        PRINT_DEBUG("ice candidate send failed peer=%llu", static_cast<unsigned long long>(peer.primary_id));
    }
}

// ---- libjuice agent lifecycle ----

void Ice_Transport::ensure_agent_locked(uint64 peer_id, const std::string &signaling_id)
{
    auto pit = peers.find(peer_id);
    if (pit != peers.end()) {
        if (!signaling_id.empty()) {
            pit->second.signaling_id = signaling_id;
        }
        if (pit->second.agent) return;
        reset_reliable_state_locked(pit->second);
        pit->second.agent = create_agent_locked(peer_id);
        pit->second.local_session_epoch = make_session_epoch();
        pit->second.remote_session_epoch = 0;
        if (pit->second.agent && !pit->second.description_sent) {
            pit->second.description_sent = true;
            send_description_locked(pit->second, "offer");
        }
        return;
    }

    // Insert the peer before gathering. libjuice emits host candidates and a
    // CONNECTING state synchronously from juice_gather_candidates(), and the
    // callbacks need to find this Peer in order to forward those candidates.
    Peer peer{};
    peer.primary_id = peer_id;
    peer.signaling_id = signaling_id;
    peer.virtual_ip = derive_virtual_ip(peer_id);
    peer.virtual_port = derive_virtual_port(peer_id);
    auto [peer_it, inserted] = peers.emplace(peer_id, std::move(peer));
    if (!inserted) return;

    Peer &new_peer = peer_it->second;
    peer_by_virtual_ip[new_peer.virtual_ip] = peer_id;
    new_peer.agent = create_agent_locked(peer_id);
    new_peer.local_session_epoch = make_session_epoch();
    new_peer.remote_session_epoch = 0;
    if (!new_peer.agent) {
        peer_by_virtual_ip.erase(new_peer.virtual_ip);
        peers.erase(peer_it);
        return;
    }

    PRINT_DEBUG("ice agent created peer=%llu virtual=%u:%u", static_cast<unsigned long long>(peer_id), new_peer.virtual_ip, new_peer.virtual_port);

    if (!new_peer.description_sent) {
        new_peer.description_sent = true;
        send_description_locked(new_peer, "offer");
    }
}

juice_agent_t *Ice_Transport::create_agent_locked(uint64 peer_id)
{
    juice_config_t config{};
    std::memset(&config, 0, sizeof(config));
    config.concurrency_mode = JUICE_CONCURRENCY_MODE_THREAD;
    if (!stun_host.empty()) {
        config.stun_server_host = stun_host.c_str();
        config.stun_server_port = stun_port;
    }
    juice_turn_server_t turn{};
    if (!turn_host.empty()) {
        turn.host = turn_host.c_str();
        turn.port = turn_port;
        turn.username = turn_user.c_str();
        turn.password = turn_pass.c_str();
        config.turn_servers = &turn;
        config.turn_servers_count = 1;
    }
    config.cb_state_changed = &Ice_Transport::juice_state_changed;
    config.cb_candidate = &Ice_Transport::juice_candidate;
    config.cb_gathering_done = &Ice_Transport::juice_gathering_done;
    config.cb_recv = &Ice_Transport::juice_recv;

    // Per-agent context so the callbacks (which run on the juice agent thread
    // while libjuice holds its per-agent lock) can find the peer without
    // taking the transport mutex. Freed after juice_destroy() below, which
    // joins the agent thread so no callback can outlive the context.
    auto *ctx = new AgentContext{};
    ctx->self = this;
    ctx->peer_id = peer_id;
    ctx->primary_id = primary_id();
    config.user_ptr = ctx;

    juice_agent_t *agent = juice_create(&config);
    if (!agent) {
        delete ctx;
        PRINT_DEBUG("ice juice_create failed");
        return nullptr;
    }
    ctx->agent = agent;

    // Register the agent->context mapping BEFORE gathering: libjuice fires the
    // cb_candidate (host candidates) and the CONNECTING state change
    // synchronously inside juice_gather_candidates(), so the callbacks would
    // otherwise find no mapping and drop them (only the later srflx/relay
    // candidates from the agent thread would survive).
    agent_ctx[agent] = ctx;

    if (juice_gather_candidates(agent) < 0) {
        PRINT_DEBUG("ice juice_gather_candidates failed");
        agent_ctx.erase(agent);
        juice_destroy(agent);
        delete ctx;
        return nullptr;
    }
    return agent;
}

void Ice_Transport::queue_agent_destroy_locked(juice_agent_t *agent)
{
    if (!agent) return;
    auto it = agent_ctx.find(agent);
    if (it == agent_ctx.end()) return;
    AgentContext *ctx = it->second;
    agent_ctx.erase(it);
    destroy_queue.push_back(ctx);
}

void Ice_Transport::destroy_queued_agents()
{
    while (true) {
        AgentContext *ctx = nullptr;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex);
            if (destroy_queue.empty()) return;
            ctx = destroy_queue.front();
            destroy_queue.pop_front();
        }
        // destroyed outside the lock: juice_destroy joins the agent thread
        if (!ctx) continue;
        if (ctx->agent) juice_destroy(ctx->agent);
        delete ctx;
    }
}

void Ice_Transport::remove_peer_locked(uint64 primary_id, bool notify_disconnect)
{
    auto pit = peers.find(primary_id);
    if (pit == peers.end()) return;
    Peer &peer = pit->second;

    if (peer.connected && notify_disconnect) {
        DisconnectEvent ev{};
        if (!peer.ids.empty()) {
            ev.ids.reserve(peer.ids.size());
            for (uint64 id : peer.ids) {
                ev.ids.emplace_back(CSteamID(id));
            }
        } else {
            ev.ids.emplace_back(CSteamID(primary_id));
        }
        ev.virtual_ip = peer.virtual_ip;
        ev.virtual_port = peer.virtual_port;
        disconnect_events.push_back(std::move(ev));
        PRINT_DEBUG("ice peer disconnected peer=%llu ids=%zu", static_cast<unsigned long long>(primary_id), ev.ids.size());
    }

    if (peer.agent) {
        queue_agent_destroy_locked(peer.agent);
    }
    for (uint64 id : peer.ids) {
        peer_by_alias.erase(id);
    }
    peer_by_virtual_ip.erase(peer.virtual_ip);
    peers.erase(pit);
}

void Ice_Transport::juice_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr)
{
    auto *ctx = static_cast<AgentContext *>(user_ptr);
    if (!ctx || !ctx->self) return;
    JuiceEvent ev{};
    ev.kind = JuiceEvent::Kind::StateChanged;
    ev.peer_id = ctx->peer_id;
    ev.agent = agent;
    ev.state = state;
    // Never take the transport mutex here: libjuice invokes this callback
    // while holding its per-agent lock, and Run() calls into libjuice while
    // holding the transport mutex -> ABBA deadlock.
    std::lock_guard<std::mutex> lock(ctx->self->juice_events_mutex);
    if (ctx->self->juice_events.size() >= MAX_JUICE_EVENTS) {
        ctx->self->juice_events.pop_front(); // bound memory; keep the newest events
        ctx->self->juice_drops.fetch_add(1, std::memory_order_relaxed);
    }
    ctx->self->juice_events.push_back(std::move(ev));
    ctx->self->pump_wake();
}

void Ice_Transport::juice_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr)
{
    auto *ctx = static_cast<AgentContext *>(user_ptr);
    if (!ctx || !ctx->self || !sdp) return;
    // Count by candidate type for the gathering summary (all on the agent
    // thread; the counters are read in juice_gathering_done on the same thread).
    if (strstr(sdp, "typ relay")) {
        ++ctx->relay_candidates;
    } else if (strstr(sdp, "typ srflx")) {
        ++ctx->srflx_candidates;
    } else if (strstr(sdp, "typ host")) {
        ++ctx->host_candidates;
    }
    JuiceEvent ev{};
    ev.kind = JuiceEvent::Kind::Candidate;
    ev.peer_id = ctx->peer_id;
    ev.agent = agent;
    ev.payload = sdp;
    std::lock_guard<std::mutex> lock(ctx->self->juice_events_mutex);
    if (ctx->self->juice_events.size() >= MAX_JUICE_EVENTS) {
        ctx->self->juice_events.pop_front();
        ctx->self->juice_drops.fetch_add(1, std::memory_order_relaxed);
    }
    ctx->self->juice_events.push_back(std::move(ev));
    ctx->self->pump_wake();
}

void Ice_Transport::juice_gathering_done(juice_agent_t *agent, void *user_ptr)
{
    auto *ctx = static_cast<AgentContext *>(user_ptr);
    if (!ctx || !ctx->self) return;
    // Runs on the agent thread after all candidates were reported; the type
    // counts make "TURN unreachable" (0 relay candidates) visible in the log.
    PRINT_DEBUG("ice gathering done peer=%llu host=%d srflx=%d relay=%d",
                static_cast<unsigned long long>(ctx->peer_id),
                ctx->host_candidates, ctx->srflx_candidates, ctx->relay_candidates);
    (void)agent;
}

void Ice_Transport::juice_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr)
{
    auto *ctx = static_cast<AgentContext *>(user_ptr);
    if (!ctx || !ctx->self || !data || size == 0) return;

    // Fast path: PING/PONG are answered and stamped right here on the agent
    // thread, the moment the datagram arrives. Routing them through the
    // frame-tick slow path (queue -> next Run() -> reply -> queue -> next
    // Run() -> stamp) would add up to two frame periods (~33ms at 60fps) to
    // the measured RTT, which is why a direct loopback link showed 11-33ms.
    // The reply touches no Peer state and no transport mutex, so it cannot
    // deadlock against Run() (see send_raw_ice_packet).
    {
        // In-place parse (P1-C): the datagram is only borrowed here; no copy
        // is made unless the packet has to be queued for the pump below.
        IceHeader header{};
        size_t payload_offset = 0;
        size_t payload_size = 0;
        if (deserialize_ice_header(data, size, header, payload_offset, payload_size)) {
            if (header.type == ICE_PKT_PING) {
                // Echo the id the sender addressed us with (what the peer
                // believes our id is); falls back to the snapshot taken at
                // agent creation. No local_ids read on this thread.
                uint64 our_id = header.dest_id != 0 ? header.dest_id : ctx->primary_id;
                std::vector<char> empty{};
                send_raw_ice_packet(agent, ICE_PKT_PONG, 0, our_id, header.source_id, 0, 0, 0, 0, empty, header.token);
                return;
            }
            if (header.type == ICE_PKT_PONG) {
                ctx->self->handle_pong_fast(ctx, header.token);
                return;
            }
        }
    }

    JuiceEvent ev{};
    ev.kind = JuiceEvent::Kind::Recv;
    ev.peer_id = ctx->peer_id;
    ev.agent = agent;
    ev.payload.assign(data, data + size);
    std::lock_guard<std::mutex> lock(ctx->self->juice_events_mutex);
    if (ctx->self->juice_events.size() >= MAX_JUICE_EVENTS) {
        ctx->self->juice_events.pop_front();
        ctx->self->juice_drops.fetch_add(1, std::memory_order_relaxed);
    }
    ctx->self->juice_events.push_back(std::move(ev));
    ctx->self->pump_wake();
}

void Ice_Transport::handle_pong_fast(AgentContext *ctx, uint64 token)
{
    if (!ctx || token == 0) return;
    // Ignore stale PONGs (token mismatch): the token is a steady-clock
    // timestamp in microseconds, unique within the 2s ping window.
    if (ctx->ping_token.load() != token) return;
    int64_t sent_us = ctx->ping_sent_at_us.load();
    if (sent_us == 0) return;
    int64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    int rtt = static_cast<int>((now_us - sent_us) / 1000);
    ctx->rtt_ms.store(std::max(rtt, 0));
    ctx->ping_token.store(0);
    ctx->ping_sent_at_us.store(0);
}

void Ice_Transport::process_juice_events_locked()
{
    std::deque<JuiceEvent> events{};
    {
        // Leaf lock: held only for the swap, never while calling into libjuice
        // or while holding the transport mutex across a libjuice call.
        std::lock_guard<std::mutex> qlock(juice_events_mutex);
        events.swap(juice_events);
    }

    for (const auto &ev : events) {
        auto pit = peers.find(ev.peer_id);
        if (pit == peers.end()) continue;
        Peer &peer = pit->second;
        // Skip events produced by a superseded agent (ICE restart replaced the
        // peer's agent; events the old agent queued before destruction must not
        // be applied to the new session). The pointer is only compared.
        if (ev.agent != nullptr && ev.agent != peer.agent) {
            ++traffic_counters.stale_events;
            continue;
        }

        switch (ev.kind) {
        case JuiceEvent::Kind::StateChanged:
            switch (ev.state) {
            case JUICE_STATE_CONNECTED:
            case JUICE_STATE_COMPLETED:
                if (!peer.connected) {
                    peer.connected = true;
                    has_new_connection = true;
                    PRINT_DEBUG("ice peer connected peer=%llu state=%s", static_cast<unsigned long long>(ev.peer_id), ev.state == JUICE_STATE_COMPLETED ? "completed" : "connected");
                }
                // A connected session is proof of life; also covers the
                // re-negotiated session of a restarted peer.
                peer.last_seen = std::chrono::steady_clock::now();
                peer.signal_disconnected_at = {};
                break;
            case JUICE_STATE_FAILED:
            case JUICE_STATE_DISCONNECTED:
                if (ev.state == JUICE_STATE_FAILED) {
                    PRINT_DEBUG("ice peer failed peer=%llu", static_cast<unsigned long long>(ev.peer_id));
                } else {
                    PRINT_DEBUG("ice peer disconnected peer=%llu", static_cast<unsigned long long>(ev.peer_id));
                }
                remove_peer_locked(ev.peer_id, true);
                break;
            default:
                PRINT_TRACE("ice peer state peer=%llu state=%u", static_cast<unsigned long long>(ev.peer_id), static_cast<unsigned>(ev.state));
                break;
            }
            break;

        case JuiceEvent::Kind::Candidate:
            send_candidate_locked(peer, ev.payload.c_str());
            break;

        case JuiceEvent::Kind::Recv:
            ++traffic_counters.recv_events;
            handle_ice_packet_locked(peer, ev.payload.data(), ev.payload.size());
            break;
        }
    }
}

void Ice_Transport::flush_pending_acks_locked()
{
    for (auto &[peer_id, peer] : peers) {
        (void)peer_id;
        if (!peer.agent || !peer.connected) {
            peer.ack_pending = false;
            peer.completed_ack_ids.clear();
            continue;
        }
        if (peer.ack_pending) {
            peer.ack_pending = false;
            // 1024-bit extended SACK plus a fixed 16-byte receiver telemetry
            // trailer. The trailer is what lets the sender measure actual
            // delivery rate and burst loss even while the cumulative ACK is
            // stalled behind a hole. Always full-size so the sender can read
            // the trailer at a fixed offset; older parsers ignore the extra
            // bytes (they cap the extension at 32 words).
            std::vector<char> ext(32 * 4 + 16, 0);
            uint32 words[32] = {};
            if (peer.ooo_count != 0) {
                // The header carries hc+1..hc+32; the extension starts at
                // hc+33, so bit i is ring index head+32+i.
                for (uint32 i = 0; i < 1024; ++i) {
                    uint32 idx = (peer.recv_bitmap_head + 32 + i) % Peer::RECV_WINDOW_BITS;
                    if (peer.recv_bitmap[idx / 64] & (1ull << (idx % 64))) {
                        words[i / 32] |= (1u << (i % 32));
                    }
                }
                for (uint32 word = 0; word < 32; ++word) {
                    uint32 bits = words[word];
                    ext[word * 4 + 0] = static_cast<char>(bits & 0xFF);
                    ext[word * 4 + 1] = static_cast<char>((bits >> 8) & 0xFF);
                    ext[word * 4 + 2] = static_cast<char>((bits >> 16) & 0xFF);
                    ext[word * 4 + 3] = static_cast<char>((bits >> 24) & 0xFF);
                }
            }
            auto put_u32 = [&ext](size_t off, uint32 value) {
                ext[off + 0] = static_cast<char>(value & 0xFF);
                ext[off + 1] = static_cast<char>((value >> 8) & 0xFF);
                ext[off + 2] = static_cast<char>((value >> 16) & 0xFF);
                ext[off + 3] = static_cast<char>((value >> 24) & 0xFF);
            };
            put_u32(32 * 4 + 0, peer.recv_unique);
            put_u32(32 * 4 + 4, peer.recv_bytes);
            put_u32(32 * 4 + 8, peer.recv_highest);
            put_u32(32 * 4 + 12, peer.ooo_count);
            send_ice_packet_locked(peer, ICE_PKT_ACK, 0, primary_id(), peer.primary_id, 0, 0, 0, 0, ext);
        }
        // Message-level ACKs: batch up to 16 completed message IDs into one
        // MSGACK packet. Each ID retires its whole fragment range on the
        // sender, even while the cumulative ACK is stalled behind a hole.
        std::vector<char> ids{};
        ids.reserve(16 * 4);
        size_t count = 0;
        while (!peer.completed_ack_ids.empty() && count < 16) {
            append_u32(ids, peer.completed_ack_ids.front());
            peer.completed_ack_ids.pop_front();
            ++count;
        }
        if (count > 0) {
            // Two copies: losing one 16-ID packet would otherwise leave those
            // messages in the sender's window until the cumulative ACK catches up.
            send_ice_packet_locked(peer, ICE_PKT_MSGACK, 0, primary_id(), peer.primary_id, 0, 0, 0, 0, ids);
            send_ice_packet_locked(peer, ICE_PKT_MSGACK, 0, primary_id(), peer.primary_id, 0, 0, 0, 0, ids);
        }
    }
}

// ---- reliability / fragmentation layer ----

bool Ice_Transport::send_ice_packet_locked(Peer &peer, uint8 type, uint32 flags, uint64 source_id, uint64 dest_id,
                                           uint32 packet_seq, uint32 message_id, uint16 fragment_index,
                                           uint16 fragment_count, const std::vector<char> &payload,
                                           uint64 token)
{
    if (!peer.agent || !peer.connected) return false;

    IceHeader header{};
    header.type = type;
    header.flags = flags;
    header.packet_seq = packet_seq;
    header.source_id = source_id;
    header.dest_id = dest_id;
    header.token = token;
    header.session_epoch = peer.local_session_epoch;
    header.message_id = message_id;
    header.fragment_index = fragment_index;
    header.fragment_count = fragment_count;
    header.ack = peer.highest_contiguous_seq;
    header.ack_bits = peer.remote_ack_bits;

    // Reuse a per-thread frame buffer: called per ACK/PING from the pump
    // thread (and potentially API threads), so avoid a heap alloc each time.
    thread_local std::vector<char> tls_control_frame{};
    tls_control_frame.clear();
    serialize_ice_header_into(tls_control_frame, header,
        payload.empty() ? nullptr : payload.data(), payload.size());
    return juice_send(peer.agent, tls_control_frame.data(), tls_control_frame.size()) == JUICE_ERR_SUCCESS;
}

bool Ice_Transport::take_send_tokens_locked(Peer &peer, size_t bytes)
{
    auto now = std::chrono::steady_clock::now();
    if (peer.send_token_time == std::chrono::steady_clock::time_point{}) {
        peer.send_token_time = now;
        peer.send_tokens = peer.send_rate_bps * 0.10; // 100ms initial burst
    } else {
        double elapsed = std::chrono::duration<double>(now - peer.send_token_time).count();
        peer.send_token_time = now;
        peer.send_tokens = std::min(peer.send_rate_bps * 0.25,
                                    peer.send_tokens + elapsed * peer.send_rate_bps);
    }
    if (peer.send_tokens < static_cast<double>(bytes)) return false;
    peer.send_tokens -= static_cast<double>(bytes);
    return true;
}

void Ice_Transport::drain_unsent_locked(Peer &peer)
{
    if (!peer.agent || !peer.connected) return;
    auto now = std::chrono::steady_clock::now();
    if (now < peer.next_unsent_at) return;
    int rto_ms = ICE_RTO_INITIAL_MS;
    if (peer.srtt_ms >= 0.0) {
        rto_ms = static_cast<int>(peer.srtt_ms + 4.0 * peer.rttvar_ms);
        rto_ms = std::max(ICE_RTO_MIN_MS, std::min(ICE_RTO_MAX_MS, rto_ms));
    }
    int rto_cap = std::max(ICE_RTO_INITIAL_MS,
                           static_cast<int>(std::max(0.0, peer.srtt_ms) * 2.0));
    rto_ms = std::min(rto_ms, rto_cap);
    while (!peer.unsent_seqs.empty()) {
        uint32 seq = peer.unsent_seqs.front();
        auto it = peer.pending.find(seq);
        if (it == peer.pending.end()) {
            peer.unsent_seqs.pop_front();
            continue;
        }
        if (it->second.sent) {
            peer.unsent_seqs.pop_front();
            continue;
        }
        if (!take_send_tokens_locked(peer, it->second.bytes.size())) {
            peer.next_unsent_at = now + std::chrono::milliseconds(5);
            return;
        }
        if (juice_send(peer.agent, it->second.bytes.data(), it->second.bytes.size()) != JUICE_ERR_SUCCESS) {
            peer.next_unsent_at = now + std::chrono::milliseconds(5);
            return; // keep at the front and retry after the backoff
        }
        ++traffic_counters.msgs_sent;
        traffic_counters.bytes_sent += it->second.bytes.size();
        it->second.sent = true;
        ++peer.reliable_frags_sent;
        it->second.next_send = now + std::chrono::milliseconds(rto_ms);
        peer.unsent_seqs.pop_front();
    }
}

bool Ice_Transport::send_fragments_locked(Peer &peer, uint64 dest_id, const std::vector<char> &payload, bool reliable)
{
    if (!peer.agent || !peer.connected) return false;

    uint16 fragment_count = static_cast<uint16>((payload.size() + ICE_FRAGMENT_MTU - 1) / ICE_FRAGMENT_MTU);
    if (fragment_count == 0) fragment_count = 1;

    // Backpressure: never evict the oldest unacked message. It contains the
    // cumulative hole, and evicting it stalls the peer's ACK forever (the
    // afterfixes2 run evicted 136k fragments and the client's ooo grew to
    // 129k). Refuse the whole new message instead; the game's next state
    // sync resends it once the ACK has drained the window.
    if (reliable && peer.pending.size() + static_cast<size_t>(fragment_count) > MAX_PENDING_RELIABLE) {
        ++traffic_counters.backpressure;
        return false;
    }

    uint32 message_id = peer.next_message_id++;
    uint64 source_id = primary_id();
    if (reliable) {
        uint32 first_seq = peer.next_reliable_seq;
        peer.pending_msg_ranges[message_id] = {first_seq, first_seq + fragment_count - 1};
    }
    auto now = std::chrono::steady_clock::now();
    // Adaptive RTO from the smoothed RTT (RFC 6298-style, clamped). First
    // message to a peer has no sample yet -> initial 250ms (old behavior).
    int rto_ms = ICE_RTO_INITIAL_MS;
    if (peer.srtt_ms >= 0.0) {
        rto_ms = static_cast<int>(peer.srtt_ms + 4.0 * peer.rttvar_ms);
        rto_ms = std::max(ICE_RTO_MIN_MS, std::min(ICE_RTO_MAX_MS, rto_ms));
    }
    // Cap the retransmit interval at ~2x the measured path RTT. On this
    // ~100ms path that is 250ms; on a 300ms path it becomes 600ms instead of
    // retransmitting prematurely. Data-ACK RTT samples can be inflated by
    // out-of-order fragments, so the cap uses the PING-derived srtt.
    int rto_cap = std::max(ICE_RTO_INITIAL_MS,
                           static_cast<int>(std::max(0.0, peer.srtt_ms) * 2.0));
    rto_ms = std::min(rto_ms, rto_cap);

    // Per-thread reusable frame buffer for the unreliable path (the reliable
    // path serializes straight into the queued PendingPacket, which must
    // retain the bytes anyway, so neither path allocates a temp frame).
    thread_local std::vector<char> tls_data_frame{};

    for (uint16 fragment_index = 0; fragment_index < fragment_count; ++fragment_index) {
        size_t offset = static_cast<size_t>(fragment_index) * ICE_FRAGMENT_MTU;
        size_t chunk = std::min(ICE_FRAGMENT_MTU, payload.size() - offset);
        uint32 seq = reliable ? peer.next_reliable_seq++ : peer.next_packet_seq++;
        uint32 flags = reliable ? ICE_FLAG_RELIABLE : 0;

        IceHeader header{};
        header.type = ICE_PKT_DATA;
        header.flags = flags;
        header.packet_seq = seq;
        header.source_id = source_id;
        header.dest_id = dest_id;
        header.message_id = message_id;
        header.fragment_index = fragment_index;
        header.fragment_count = fragment_count;
        header.ack = peer.highest_contiguous_seq;
        header.ack_bits = peer.remote_ack_bits;
        header.session_epoch = peer.local_session_epoch;

        const char *chunk_ptr = chunk ? payload.data() + static_cast<std::ptrdiff_t>(offset) : nullptr;

        // Queue reliable fragments *before* the send attempt: a transient
        // juice_send failure (TURN channel bind in progress, momentary missing
        // selected entry, socket would-block) must not lose the message.
        // send_pending_reliable_locked() retries queued fragments until ACKed.
        if (reliable) {
            PendingPacket pending{};
            serialize_ice_header_into(pending.bytes, header, chunk_ptr, chunk);
            pending.next_send = now + std::chrono::milliseconds(rto_ms);
            pending.first_send = now;
            pending.message_id = message_id;
            peer.pending.emplace(seq, std::move(pending));
            peer.unsent_seqs.push_back(seq);
        } else {
            tls_data_frame.clear();
            serialize_ice_header_into(tls_data_frame, header, chunk_ptr, chunk);
            if (juice_send(peer.agent, tls_data_frame.data(), tls_data_frame.size()) != JUICE_ERR_SUCCESS) {
                return false; // preserve fire-and-forget semantics
            }
            ++traffic_counters.msgs_sent;
            traffic_counters.bytes_sent += tls_data_frame.size();
        }
    }
    if (reliable) {
        drain_unsent_locked(peer);
    }
    return true;
}

void Ice_Transport::send_pending_reliable_locked()
{
    auto now = std::chrono::steady_clock::now();
    for (auto &[peer_id, peer] : peers) {
        (void)peer_id;
        if (!peer.agent || !peer.connected) continue;
        if (peer.pending.empty() && peer.unsent_seqs.empty()) continue;
        // Adaptive RTO from the smoothed RTT (RFC 6298-style, clamped).
        int rto_ms = ICE_RTO_INITIAL_MS;
        if (peer.srtt_ms >= 0.0) {
            rto_ms = static_cast<int>(peer.srtt_ms + 4.0 * peer.rttvar_ms);
            rto_ms = std::max(ICE_RTO_MIN_MS, std::min(ICE_RTO_MAX_MS, rto_ms));
        }
        int rto_cap = std::max(ICE_RTO_INITIAL_MS,
                               static_cast<int>(std::max(0.0, peer.srtt_ms) * 2.0));
        rto_ms = std::min(rto_ms, rto_cap);
        auto retransmit = [&](uint32 seq) -> bool {
            auto it = peer.pending.find(seq);
            if (it == peer.pending.end()) return false;
            if (now < it->second.next_send) return false;
            if (!take_send_tokens_locked(peer, it->second.bytes.size())) {
                it->second.next_send = now + std::chrono::milliseconds(5);
                return false;
            }
            // If the peer's SACK shows any later packet arrived, the peer is
            // alive and the hole is a random loss: retry at the base RTO
            // instead of backing off to 1s (which caps recovery at one hole
            // per second / ~500 fragments per second in the logs).
            bool live_sack = (peer.peer_ack_bits != 0);
            if (!live_sack && peer.peer_ack_ext_base == peer.peer_ack) {
                for (uint32 word : peer.peer_ack_ext) {
                    if (word != 0) {
                        live_sack = true;
                        break;
                    }
                }
            }
            int delay_ms = live_sack ? rto_ms
                                     : (rto_ms << std::min(it->second.backoff_step, 4));
            delay_ms = std::min(delay_ms, ICE_RTO_MAX_MS);
            it->second.next_send = now + std::chrono::milliseconds(delay_ms);
            if (!live_sack && it->second.backoff_step < 8) ++it->second.backoff_step;
            ++traffic_counters.retries;
            juice_send(peer.agent, it->second.bytes.data(), it->second.bytes.size());
            it->second.sent = true;
            return true;
        };
        // Retransmit only what the peer is actually missing: the cumulative
        // hole (peer_ack + 1) and the clear bits in its 32-bit SACK window.
        // Retransmitting every expired out-of-order fragment floods the path
        // (the previous run peaked at 75k retries/s) and prevents the single
        // hole that is stalling the cumulative ACK from getting through.
        // Fragments beyond the SACK window are left alone; they are either
        // already at the peer (and will be freed when the ACK advances) or
        // will become the next hole as the window slides.
        if (retransmit(peer.peer_ack + 1)) ++traffic_counters.hole_retries;
        for (uint32 bit = 0; bit < 32; ++bit) {
            if (!(peer.peer_ack_bits & (1u << bit))) {
                retransmit(peer.peer_ack + 1 + bit);
            }
        }
        // Use the 1024-bit extension to retransmit several holes in parallel.
        // A clear bit with a received (set) bit above it is a gap. Walking the
        // extension and sending every due gap (up to 64/tick) lets the
        // cumulative ACK advance by many holes per RTO instead of one, which
        // was the ~250 fragments/s ceiling in the afterfixes4 logs.
        if (peer.peer_ack_ext_base == peer.peer_ack) {
            int highest_set = -1;
            for (int i = 1023; i >= 0; --i) {
                uint32 word = static_cast<uint32>(i / 32);
                uint32 bit = static_cast<uint32>(i % 32);
                if ((peer.peer_ack_ext[word] >> bit) & 1u) {
                    highest_set = i;
                    break;
                }
            }
            if (highest_set >= 0) {
                // Walk the whole extension and send up to 64 holes that are
                // actually due. The previous code stopped after the first 32
                // clear positions regardless of whether retransmit() sent
                // them; when those 32 were still inside their RTO it sent
                // nothing and never reached the later holes, recovering at
                // most a few dozen fragments per RTO.
                int sent_holes = 0;
                for (int i = 0; i <= highest_set && sent_holes < 64; ++i) {
                    uint32 word = static_cast<uint32>(i / 32);
                    uint32 bit = static_cast<uint32>(i % 32);
                    if (((peer.peer_ack_ext[word] >> bit) & 1u) == 0) {
                        if (retransmit(peer.peer_ack + 33 + static_cast<uint32>(i))) {
                            ++sent_holes;
                        }
                    }
                }
            }
        }
        drain_unsent_locked(peer);
    }
}

void Ice_Transport::handle_ice_packet_locked(Peer &peer, const char *data, size_t size)
{
    IceHeader header{};
    size_t payload_offset = 0;
    size_t payload_size = 0;
    if (!deserialize_ice_header(data, size, header, payload_offset, payload_size)) {
        static bool logged_bad_frame = false;
        if (!logged_bad_frame) {
            logged_bad_frame = true;
            PRINT_DEBUG("ice bad frame size=%zu bytes=%02x %02x %02x %02x %02x %02x %02x %02x",
                size,
                size > 0 ? static_cast<unsigned>(static_cast<uint8_t>(data[0])) : 0u,
                size > 1 ? static_cast<unsigned>(static_cast<uint8_t>(data[1])) : 0u,
                size > 2 ? static_cast<unsigned>(static_cast<uint8_t>(data[2])) : 0u,
                size > 3 ? static_cast<unsigned>(static_cast<uint8_t>(data[3])) : 0u,
                size > 4 ? static_cast<unsigned>(static_cast<uint8_t>(data[4])) : 0u,
                size > 5 ? static_cast<unsigned>(static_cast<uint8_t>(data[5])) : 0u,
                size > 6 ? static_cast<unsigned>(static_cast<uint8_t>(data[6])) : 0u,
                size > 7 ? static_cast<unsigned>(static_cast<uint8_t>(data[7])) : 0u);
        }
        return;
    }

    if (header.type == ICE_PKT_DATA) {
        ++traffic_counters.data_pkts;
        peer.recv_bytes += static_cast<uint32>(payload_size);
        if ((header.flags & ICE_FLAG_RELIABLE) != 0 && header.packet_seq > peer.recv_highest) {
            peer.recv_highest = header.packet_seq;
        }
        if (traffic_counters.data_pkts == 1) {
            PRINT_DEBUG("ice first data peer=%llu ver=%u flags=%u seq=%u epoch=%llu size=%zu payload=%zu frag=%u/%u mid=%u",
                static_cast<unsigned long long>(peer.primary_id),
                static_cast<unsigned>(header.version),
                static_cast<unsigned>(header.flags),
                header.packet_seq,
                static_cast<unsigned long long>(header.session_epoch),
                size, payload_size,
                static_cast<unsigned>(header.fragment_index),
                static_cast<unsigned>(header.fragment_count),
                header.message_id);
        }
    }

    peer.last_seen = std::chrono::steady_clock::now();
    peer.signal_disconnected_at = {};
    if (header.source_id != 0) {
        peer_by_alias[header.source_id] = peer.primary_id;
    }

    // A new epoch means the peer recreated its ICE agent. Its reliable
    // sequence space and reassembly state are fresh, and it expects ours to
    // be fresh too. Ignore the initial 0 -> epoch transition: both sides start
    // fresh in that case, and resetting would discard data already in flight.
    if (header.session_epoch != 0) {
        if (peer.remote_session_epoch == 0) {
            peer.remote_session_epoch = header.session_epoch;
        } else if (header.session_epoch != peer.remote_session_epoch) {
            PRINT_DEBUG("ice session epoch changed peer=%llu epoch=%llu",
                static_cast<unsigned long long>(peer.primary_id),
                static_cast<unsigned long long>(header.session_epoch));
            const bool was_connected = peer.connected;
            reset_reliable_state_locked(peer);
            peer.remote_session_epoch = header.session_epoch;
            if (was_connected) {
                // Re-mark the game connection offline; the first data packet
                // of the new session re-fires CONNECT and re-pushes friend data.
                DisconnectEvent ev{};
                if (!peer.ids.empty()) {
                    ev.ids.reserve(peer.ids.size());
                    for (uint64 id : peer.ids) {
                        ev.ids.emplace_back(CSteamID(id));
                    }
                } else {
                    ev.ids.emplace_back(CSteamID(peer.primary_id));
                }
                ev.virtual_ip = peer.virtual_ip;
                ev.virtual_port = peer.virtual_port;
                ev.session_reset = true;
                disconnect_events.push_back(std::move(ev));
            }
        }
    }

    // Message-level ACK batch: each ID retires that message's whole fragment
    // range from our outgoing window, independent of the cumulative sequence.
    if (header.type == ICE_PKT_MSGACK) {
        size_t off = payload_offset;
        while (off + 4 <= payload_offset + payload_size) {
            uint32 mid = 0;
            if (!read_u32(data, payload_offset + payload_size, off, mid)) break;
            auto rit = peer.pending_msg_ranges.find(mid);
            if (rit != peer.pending_msg_ranges.end()) {
                uint32 first = rit->second.first;
                uint32 last = rit->second.second;
                auto it = peer.pending.lower_bound(first);
                while (it != peer.pending.end() && it->first <= last) {
                    it = peer.pending.erase(it);
                }
                peer.pending_msg_ranges.erase(rit);
            }
        }
        return;
    }

    // process acknowledgments for our reliable packets
    if (header.ack != 0 || header.ack_bits != 0) {
        // Remember the peer's view of our outgoing stream so the retry loop
        // can resend only the holes it is missing. Ignore stale ACKs from
        // reordered packets; same-ACK updates still refresh the SACK bits.
        if (header.ack != 0 &&
            (peer.peer_ack == 0 || seq_is_more_recent(header.ack, peer.peer_ack))) {
            peer.peer_ack = header.ack;
            peer.peer_ack_bits = header.ack_bits;
        } else if (header.ack == peer.peer_ack) {
            peer.peer_ack_bits = header.ack_bits;
        }
        // RTT sample from the highest newly-ACKed fragment (Karn: only
        // fragments sent once — retransmitted ones would skew the sample).
        // Feeds peer.srtt_ms/rttvar_ms for the adaptive RTO above.
        auto sample_rtt = [&](uint32 seq) {
            auto it = peer.pending.find(seq);
            if (it == peer.pending.end()) return;
            bool retransmitted = it->second.backoff_step > 0;
            auto first = it->second.first_send;
            if (retransmitted) return;
            if (first == std::chrono::steady_clock::time_point{}) return;
            double rtt = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - first).count();
            // A data ACK can cover a fragment that sat out of order for a long
            // time. Bound the sample by the ping-derived path RTT so it cannot
            // inflate the retransmit interval.
            if (peer.srtt_ms > 0.0) {
                rtt = std::min(rtt, peer.srtt_ms * 2.0);
            }
            if (peer.srtt_ms < 0.0) {
                peer.srtt_ms = rtt;
                peer.rttvar_ms = rtt / 2.0;
            } else {
                peer.rttvar_ms = 0.75 * peer.rttvar_ms + 0.25 * std::abs(peer.srtt_ms - rtt);
                peer.srtt_ms = 0.875 * peer.srtt_ms + 0.125 * rtt;
            }
        };
        if (header.ack != 0) {
            sample_rtt(header.ack);
            // Cumulative ACK: everything <= header.ack arrived. The old code
            // erased only the exact seq, leaking every fragment outside the
            // 32-bit SACK window into `pending` until it was evicted.
            peer.pending.erase(peer.pending.begin(), peer.pending.upper_bound(header.ack));
            // Drop message ranges that the cumulative ACK has fully covered.
            for (auto rit = peer.pending_msg_ranges.begin(); rit != peer.pending_msg_ranges.end();) {
                if (rit->second.second <= header.ack) {
                    rit = peer.pending_msg_ranges.erase(rit);
                } else {
                    ++rit;
                }
            }
        }
        // SACK bitmap now covers ack+1 .. ack+32 (was ack-1 .. ack-32).
        for (uint32 bit = 0; bit < 32; ++bit) {
            if (header.ack_bits & (1u << bit)) {
                uint32 seq = header.ack + 1 + bit;
                sample_rtt(seq);
                peer.pending.erase(seq);
            }
        }
        // Extended SACK (ACK payload, up to 1024 bits) covers ack+33..ack+1056.
        // These are fragments the receiver already has; retire them so they
        // stop occupying the retransmit window. Keep the bits for parallel
        // hole retransmission in send_pending_reliable_locked().
        if (header.type == ICE_PKT_ACK && header.message_id == 0) {
            peer.peer_ack_ext_base = header.ack;
            peer.peer_ack_ext.fill(0);
            if (payload_size >= 4) {
                size_t ext_offset = payload_offset;
                size_t words = std::min<size_t>(32, payload_size / 4);
                for (size_t word = 0; word < words; ++word) {
                    uint32 bits = 0;
                    if (!read_u32(data, payload_offset + payload_size, ext_offset, bits)) break;
                    peer.peer_ack_ext[word] = bits;
                    for (uint32 bit = 0; bit < 32; ++bit) {
                        if (bits & (1u << bit)) {
                            uint32 seq = header.ack + 33 +
                                         static_cast<uint32>(word) * 32 + bit;
                            peer.pending.erase(seq);
                        }
                    }
                }
            }
            // 16-byte trailer after the 1024-bit SACK extension: first-time
            // fragments received, DATA bytes seen (path throughput), highest
            // seq seen, and the receiver's out-of-order count. Used by the
            // pacer to react to burst loss before the retry counter can.
            if (payload_size >= 32 * 4 + 16) {
                size_t toff = payload_offset + 32 * 4;
                uint32 recv_unique = 0;
                uint32 recv_bytes = 0;
                uint32 recv_highest = 0;
                uint32 remote_ooo = 0;
                if (read_u32(data, payload_offset + payload_size, toff, recv_unique) &&
                    read_u32(data, payload_offset + payload_size, toff, recv_bytes) &&
                    read_u32(data, payload_offset + payload_size, toff, recv_highest) &&
                    read_u32(data, payload_offset + payload_size, toff, remote_ooo)) {
                    peer.remote_recv_unique = recv_unique;
                    peer.remote_recv_bytes = recv_bytes;
                    peer.remote_recv_highest = recv_highest;
                    peer.remote_ooo = remote_ooo;
                    peer.remote_telemetry_valid = true;
                }
            }
        }
        // ACK progress: give the next hole a fresh RTO instead of inheriting
        // the backoff it accumulated while sitting behind the old hole.
        // (No immediate retransmit here: ACKs arrive per fragment, so ack+1 is
        // usually just the next fragment still in flight. RTO handles real
        // losses without duplicating in-flight data.)
        if (header.ack != 0 && seq_is_more_recent(header.ack, peer.last_fast_rtx_ack)) {
            peer.last_fast_rtx_ack = header.ack;
            auto oldest = peer.pending.begin();
            if (oldest != peer.pending.end()) oldest->second.backoff_step = 0;
        }
    }

    // Message-level ACK: the peer delivered this whole message, so every
    // fragment of it can leave `pending` immediately, regardless of the
    // cumulative sequence window. This is what keeps delivered-but-out-of-order
    // messages from filling the retransmit window.
    if (header.type == ICE_PKT_ACK && header.message_id != 0) {
        auto rit = peer.pending_msg_ranges.find(header.message_id);
        if (rit != peer.pending_msg_ranges.end()) {
            uint32 first = rit->second.first;
            uint32 last = rit->second.second;
            auto it = peer.pending.lower_bound(first);
            while (it != peer.pending.end() && it->first <= last) {
                it = peer.pending.erase(it);
            }
            peer.pending_msg_ranges.erase(rit);
        }
    }

    // Duplicate detection and cumulative-ACK bookkeeping. A packet is a
    // duplicate only if it is at or below the cumulative ACK, or was already
    // accepted out of order. A retransmitted old hole is therefore accepted
    // no matter how far the global sequence has advanced since it was lost.
    bool duplicate = false;
    if (header.packet_seq != 0 && (header.flags & ICE_FLAG_RELIABLE) != 0) {
        if (peer.recv_bitmap.empty()) {
            peer.recv_bitmap.assign(Peer::RECV_WINDOW_BITS / 64, 0);
            peer.recv_bitmap_head = 0;
            peer.ooo_count = 0;
        }
        if (header.packet_seq <= peer.highest_contiguous_seq) {
            duplicate = true;
        } else {
            uint32 delta = header.packet_seq - (peer.highest_contiguous_seq + 1);
            if (delta >= Peer::RECV_WINDOW_BITS) {
                duplicate = true; // outside the advertised receive window
            } else {
                uint32 idx = (peer.recv_bitmap_head + delta) % Peer::RECV_WINDOW_BITS;
                uint64 mask = 1ull << (idx % 64);
                if (peer.recv_bitmap[idx / 64] & mask) {
                    duplicate = true;
                } else {
                    peer.recv_bitmap[idx / 64] |= mask;
                    ++peer.ooo_count;
                    if (delta == 0) {
                        // Advance through the contiguous run, clearing bits.
                        for (;;) {
                            uint32 hidx = peer.recv_bitmap_head;
                            uint64 hmask = 1ull << (hidx % 64);
                            if (!(peer.recv_bitmap[hidx / 64] & hmask)) break;
                            peer.recv_bitmap[hidx / 64] &= ~hmask;
                            if (peer.ooo_count > 0) --peer.ooo_count;
                            ++peer.highest_contiguous_seq;
                            peer.recv_bitmap_head = (peer.recv_bitmap_head + 1) % Peer::RECV_WINDOW_BITS;
                        }
                    }
                }
            }
        }

        // Rebuild the 32-bit SACK from the bitmap (hc+1 .. hc+32).
        uint32 bits = 0;
        for (uint32 bit = 0; bit < 32; ++bit) {
            uint32 idx = (peer.recv_bitmap_head + bit) % Peer::RECV_WINDOW_BITS;
            if (peer.recv_bitmap[idx / 64] & (1ull << (idx % 64))) {
                bits |= (1u << bit);
            }
        }
        peer.remote_ack_bits = bits;

        if (!duplicate) {
            peer.ack_pending = true;
        }
    }

    if ((header.flags & ICE_FLAG_RELIABLE) != 0 && header.type == ICE_PKT_DATA && !duplicate) {
        ++peer.recv_unique;
    }

    if (header.type == ICE_PKT_ACK) return;
    if (header.type != ICE_PKT_DATA) return;

    const bool reliable = (header.flags & ICE_FLAG_RELIABLE) != 0;

    // A duplicate reliable fragment means the sender missed our earlier ACK
    // (lost ACK, not lost data). Re-arm the coalesced ACK so it stops
    // retransmitting. In the cumulative-ACK experiment fragments are ACKed as
    // they arrive rather than on whole-message delivery, so re-ACK every
    // reliable duplicate, not just already-delivered messages.
    if (duplicate) {
        if (reliable) {
            peer.ack_pending = true;
            if (peer.completed_message_set.find(header.message_id) != peer.completed_message_set.end()) {
                peer.completed_ack_ids.push_back(header.message_id);
            }
        }
        return;
    }

    // Already-delivered message (its ACK was lost and it was retransmitted
    // without matching packet seqs): re-ACK and drop.
    if (peer.completed_message_set.find(header.message_id) != peer.completed_message_set.end()) {
        if (reliable) {
            peer.ack_pending = true;
            peer.completed_ack_ids.push_back(header.message_id);
        }
        return;
    }

    auto &assembly = peer.reassembly[header.message_id];
    if (assembly.fragment_count == 0) {
        if (header.fragment_count == 0) {
            PRINT_DEBUG("ice zero fragment_count peer=%llu mid=%u payload=%zu",
                static_cast<unsigned long long>(peer.primary_id), header.message_id, payload_size);
            header.fragment_count = 1;
        }
        assembly.fragment_count = header.fragment_count;
        assembly.reliable = reliable;
        assembly.buffer.assign(static_cast<size_t>(header.fragment_count) * ICE_FRAGMENT_MTU, 0);
        assembly.sizes.assign(header.fragment_count, 0);
        assembly.present.assign(header.fragment_count, false);
        if (reliable) {
            peer.incomplete_reliable_ids.insert(header.message_id);
        }
    }
    if (header.fragment_index >= assembly.present.size()) return;
    if (payload_size > ICE_FRAGMENT_MTU) return;
    size_t fragment_offset = static_cast<size_t>(header.fragment_index) * ICE_FRAGMENT_MTU;
    if (fragment_offset + payload_size > assembly.buffer.size()) return;
    if (payload_size) {
        memcpy(assembly.buffer.data() + fragment_offset, data + payload_offset, payload_size);
    }
    assembly.sizes[header.fragment_index] = static_cast<uint16_t>(payload_size);
    assembly.present[header.fragment_index] = true;
    assembly.updated = std::chrono::steady_clock::now();

    bool complete = std::all_of(assembly.present.begin(), assembly.present.end(), [](bool value) { return value; });
    if (!complete) return;

    // Delivery may be refused under backpressure; the complete assembly is
    // then retained in peer.reassembly and flush_reliable_assemblies_locked()
    // retries it from Run().
    try_deliver_message_locked(peer, header.message_id, reliable);
}

bool Ice_Transport::try_deliver_message_locked(Peer &peer, uint32 message_id, bool reliable)
{
    ++traffic_counters.deliver_attempts;
    auto assembly_it = peer.reassembly.find(message_id);
    if (assembly_it == peer.reassembly.end()) return false;
    ReassemblyState &assembly = assembly_it->second;
    if (assembly.present.empty() ||
        !std::all_of(assembly.present.begin(), assembly.present.end(), [](bool value) { return value; })) {
        ++traffic_counters.deliver_early;
        return false;
    }

    size_t total_payload = 0;
    for (uint16_t size : assembly.sizes) total_payload += size;
    if (total_payload == 0) {
        ++traffic_counters.zero_payload;
        peer.reassembly.erase(assembly_it);
        peer.incomplete_reliable_ids.erase(message_id);
        return false;
    }

    Common_Message msg{};
    if (!msg.ParseFromArray(assembly.buffer.data(), static_cast<int>(total_payload))) {
        // Unparsable: retransmission fails identically, so drop it. Do not
        // ACK, but remove the assembly so it cannot be retried forever.
        ++traffic_counters.parse_fail;
        peer.reassembly.erase(assembly_it);
        peer.incomplete_reliable_ids.erase(message_id);
        return false;
    }

    // learn announced steamids as aliases of this peer
    if (msg.has_announce()) {
        for (int i = 0; i < msg.announce().ids_size(); ++i) {
            uint64 id = static_cast<uint64>(msg.announce().ids(i));
            peer_by_alias[id] = peer.primary_id;
            if (std::find(peer.ids.begin(), peer.ids.end(), id) == peer.ids.end()) {
                peer.ids.push_back(id);
            }
        }
    }

    peer.completed_message_set.insert(message_id);
    peer.completed_messages.push_back(message_id);
    while (peer.completed_messages.size() > 2048) {
        uint32 old = peer.completed_messages.front();
        peer.completed_messages.pop_front();
        peer.completed_message_set.erase(old);
    }

    InboundPacket inbound{};
    inbound.message = std::move(msg);
    inbound.reliable = reliable;
    inbound.ip_port.ip = htonl(peer.virtual_ip);
    inbound.ip_port.port = htons(peer.virtual_port);

    peer.reassembly.erase(assembly_it);
    if (reliable) {
        // Hold complete reliable messages until every lower message_id has
        // been delivered. Completing out of order is fine; delivering out of
        // order is not (SteamNetworking guarantees ordered reliable delivery).
        peer.incomplete_reliable_ids.erase(message_id);
        peer.ordered_reliable[message_id] = std::move(inbound);
        peer.ordered_highwater = std::max(peer.ordered_highwater, peer.ordered_reliable.size());
        // Tell the sender it can free this whole message's fragments now,
        // even if the cumulative ACK is still stalled behind an earlier hole.
        // The flusher batches IDs and sends each batch twice.
        peer.completed_ack_ids.push_back(message_id);
        while (peer.completed_ack_ids.size() > 1024) {
            peer.completed_ack_ids.pop_front();
        }
        peer.ack_pending = true;
        deliver_ordered_reliable_locked(peer);
    } else {
        // Unreliable messages may be dropped, but never evict a reliable one
        // that is already queued: that would break ordered delivery.
        if (inbound_packets.size() < MAX_INBOUND_PACKETS) {
            inbound_packets.push_back(std::move(inbound));
        } else {
            ++traffic_counters.drops;
        }
    }
    ++traffic_counters.msgs_recvd;
    traffic_counters.bytes_recvd += total_payload;
    return true;
}

void Ice_Transport::deliver_ordered_reliable_locked(Peer &peer)
{
    for (;;) {
        // The next reliable message to deliver is the lowest message id that
        // is either still incomplete or complete-and-waiting. If that lowest
        // id is still incomplete, later complete messages must wait: that is
        // the ordered-reliable guarantee SteamNetworkingMessages makes.
        uint32 next_id = 0;
        if (!peer.incomplete_reliable_ids.empty()) {
            next_id = *peer.incomplete_reliable_ids.begin();
        }
        if (!peer.ordered_reliable.empty()) {
            uint32 ready = peer.ordered_reliable.begin()->first;
            if (next_id == 0 || ready < next_id) next_id = ready;
        }
        if (next_id == 0) return;
        auto it = peer.ordered_reliable.find(next_id);
        if (it == peer.ordered_reliable.end()) return; // blocked on a lower incomplete id
        if (inbound_packets.size() >= MAX_INBOUND_PACKETS) return; // game queue full
        inbound_packets.push_back(std::move(it->second));
        peer.ordered_reliable.erase(it);
    }
}

void Ice_Transport::flush_reliable_assemblies_locked()
{
    for (auto &[peer_id, peer] : peers) {
        (void)peer_id;
        for (auto it = peer.reassembly.begin(); it != peer.reassembly.end();) {
            ReassemblyState &assembly = it->second;
            bool complete = !assembly.present.empty() &&
                std::all_of(assembly.present.begin(), assembly.present.end(), [](bool value) { return value; });
            if (!assembly.reliable || !complete) {
                ++it;
                continue;
            }
            uint32 message_id = it->first;
            // try_deliver_message_locked() erases on success/failure-to-parse;
            // find() again because it takes the map by message id.
            if (inbound_packets.size() >= MAX_INBOUND_PACKETS) return; // still full: keep
            try_deliver_message_locked(peer, message_id, true);
            it = peer.reassembly.find(message_id);
            if (it == peer.reassembly.end()) {
                it = peer.reassembly.begin(); // restart; other entries may remain
                continue;
            }
            ++it;
        }
    }
}

void Ice_Transport::update_peer_stats_locked(std::chrono::steady_clock::time_point now)
{
    for (auto &[peer_id, peer] : peers) {
        (void)peer_id;
        if (!peer.agent || !peer.connected) continue;
        if (now < peer.next_ping_at) continue;
        peer.next_ping_at = now + std::chrono::milliseconds(ICE_PING_INTERVAL_MS);

        // Refresh the connection type from the ICE selected candidate pair.
        // P2-E: cache it — refresh at most every ICE_CONN_TYPE_REFRESH_MS
        // instead of strstr() over both SDP strings on every ping tick.
        if (now >= peer.next_conn_type_at) {
            peer.next_conn_type_at = now + std::chrono::milliseconds(ICE_CONN_TYPE_REFRESH_MS);
            peer.connection_type = selected_candidate_connection_type(peer.agent);
        }

        auto cit = agent_ctx.find(peer.agent);
        if (cit == agent_ctx.end() || !cit->second) continue;

        // Keep the data-path RTO anchored to the ICE ping RTT. Data-ACK RTT
        // samples are inflated when fragments arrive out of order, which
        // otherwise drives the retransmit interval to ~1s and starves hole
        // recovery. The ping measures the real path RTT every 2s.
        int ping_rtt = cit->second->rtt_ms.load();
        if (ping_rtt > 0) {
            peer.srtt_ms = ping_rtt;
            peer.rttvar_ms = std::max(1.0, static_cast<double>(ping_rtt) / 2.0);
        }

        // Arm the fast-path ping: the agent thread answers the PONG the moment
        // it arrives and stamps the RTT (see juice_recv/handle_pong_fast), so
        // the measurement no longer waits for the next frame tick.
        uint64 token = static_cast<uint64>(std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count());
        cit->second->ping_token.store(token);
        cit->second->ping_sent_at_us.store(static_cast<int64_t>(token));
        std::vector<char> empty{};
        send_ice_packet_locked(peer, ICE_PKT_PING, 0, primary_id(), peer.primary_id, 0, 0, 0, 0, empty, token);
    }
}

bool Ice_Transport::GetPeerStats(uint64 primary_id, PeerStats &out)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    Peer *peer = find_peer_locked(primary_id);
    if (!peer) return false;
    out.connected = peer->connected;
    out.connection_type = peer->connection_type;
    out.rtt_ms = -1;
    if (peer->agent) {
        auto cit = agent_ctx.find(peer->agent);
        if (cit != agent_ctx.end() && cit->second) {
            out.rtt_ms = cit->second->rtt_ms.load();
        }
    }
    return true;
}

// ---- public send / receive API ----

Ice_Transport::Peer *Ice_Transport::find_peer_locked(uint64 id)
{
    auto it = peers.find(id);
    if (it != peers.end()) return &it->second;
    auto alias = peer_by_alias.find(id);
    if (alias != peer_by_alias.end()) {
        auto pit = peers.find(alias->second);
        if (pit != peers.end()) return &pit->second;
    }
    return nullptr;
}

Ice_Transport::Peer *Ice_Transport::find_peer_by_endpoint_locked(uint32 ip, uint16 port)
{
    (void)port;
    auto it = peer_by_virtual_ip.find(ip);
    if (it == peer_by_virtual_ip.end()) return nullptr;
    auto pit = peers.find(it->second);
    if (pit == peers.end()) return nullptr;
    return &pit->second;
}

bool Ice_Transport::Send(Common_Message *msg, bool reliable)
{
    if (!msg) return false;
    const uint64 dest_id = msg->dest_id();
    if (dest_id == 0) return false;

    // Serialize before taking the transport lock. The caller owns `msg`, and a
    // large state message would otherwise hold the lock across the whole
    // serialization while the pump needs it for ACKs and retries.
    thread_local std::vector<char> tls_payload{};
    size_t size = msg->ByteSizeLong();
    tls_payload.resize(size);
    if (size) msg->SerializeToArray(tls_payload.data(), static_cast<int>(size));

    std::lock_guard<std::recursive_mutex> lock(mutex);
    Peer *peer = find_peer_locked(dest_id);
    if (!peer || !peer->connected) return false;
    return send_fragments_locked(*peer, dest_id, tls_payload, reliable);
}

bool Ice_Transport::SendToEndpoint(Common_Message *msg, uint32 ip, uint16 port, bool reliable)
{
    if (!msg) return false;
    const uint64 dest_id = msg->dest_id();

    thread_local std::vector<char> tls_payload{};
    size_t size = msg->ByteSizeLong();
    tls_payload.resize(size);
    if (size) msg->SerializeToArray(tls_payload.data(), static_cast<int>(size));

    std::lock_guard<std::recursive_mutex> lock(mutex);
    Peer *peer = find_peer_by_endpoint_locked(ip, port);
    if (!peer && dest_id != 0) {
        peer = find_peer_locked(dest_id);
    }
    if (!peer || !peer->connected) return false;
    return send_fragments_locked(*peer, dest_id, tls_payload, reliable);
}

bool Ice_Transport::SendBroadcast(Common_Message *msg)
{
    if (!msg) return false;

    // Serialize once, outside the lock: the payload is shared across peers.
    size_t size = msg->ByteSizeLong();
    std::vector<char> payload(size);
    if (size) msg->SerializeToArray(payload.data(), static_cast<int>(payload.size()));

    std::lock_guard<std::recursive_mutex> lock(mutex);
    bool sent = false;
    for (auto &[peer_id, peer] : peers) {
        (void)peer_id;
        if (!peer.connected) continue;
        if (send_fragments_locked(peer, 0, payload, false)) sent = true;
    }
    return sent;
}

bool Ice_Transport::PollPacket(Common_Message *msg, IP_PORT *ip_port, bool *reliable)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (inbound_packets.empty()) return false;
    InboundPacket packet = std::move(inbound_packets.front());
    inbound_packets.pop_front();
    if (msg) *msg = std::move(packet.message);
    if (ip_port) *ip_port = packet.ip_port;
    if (reliable) *reliable = packet.reliable;
    return true;
}

bool Ice_Transport::PollDisconnect(std::vector<CSteamID> &ids, uint32 &virtual_ip, uint16 &virtual_port, bool &session_reset)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (disconnect_events.empty()) return false;
    DisconnectEvent event = std::move(disconnect_events.front());
    disconnect_events.pop_front();
    ids = std::move(event.ids);
    virtual_ip = event.virtual_ip;
    virtual_port = event.virtual_port;
    session_reset = event.session_reset;
    return true;
}

bool Ice_Transport::poll_new_connection()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (has_new_connection) {
        has_new_connection = false;
        return true;
    }
    return false;
}

void Ice_Transport::request_list()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (ws_connected) {
        ws.send(R"({"type":"list"})");
        next_list_poll = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    }
}

void Ice_Transport::Run()
{
    {
        std::lock_guard<std::recursive_mutex> lock(mutex);
        if (!enabled()) return;

        // Drain libjuice callback events (state changes, gathered candidates,
        // received datagrams) first so connection/data events are not delayed
        // by signaling traffic.
        process_juice_events_locked();

        auto now = std::chrono::steady_clock::now();
        if (!ws_connected && !ws.is_connecting() && now >= next_connect_attempt) {
            next_connect_attempt = now + std::chrono::milliseconds(reconnect_delay_ms);
            reconnect_delay_ms = std::min(reconnect_delay_ms * 2, 30000);
            ws.connect();
        }

        ws.Run();

        if (ws_connected && (!list_requested || now >= next_list_poll)) {
            list_requested = true;
            next_list_poll = now + std::chrono::seconds(5);
            ws.send(R"({"type":"list"})");
        }

        while (!ws_inbox.empty()) {
            std::string payload = std::move(ws_inbox.front());
            ws_inbox.pop_front();
            process_ws_message_locked(payload);
        }

        // Fast liveness cleanup: a peer whose signaling channel dropped AND that
        // has sent no ICE data since (a process that quit stays silent) is
        // removed after the grace period so the friend list updates quickly.
        // Any packet, offer/answer, candidate, or re-registration clears the
        // flag, so a live peer with a websocket blip is never touched here.
        {
            std::vector<uint64> stale_peers{};
            for (const auto &[peer_id, peer] : peers) {
                if (peer.signal_disconnected_at != std::chrono::steady_clock::time_point{} &&
                    now - peer.signal_disconnected_at > std::chrono::duration<double>(ICE_DISCONNECT_GRACE_SEC) &&
                    now - peer.last_seen > std::chrono::duration<double>(ICE_DISCONNECT_GRACE_SEC)) {
                    stale_peers.push_back(peer_id);
                }
            }
            for (uint64 peer_id : stale_peers) {
                PRINT_DEBUG("ice peer removed after signaling disconnect grace peer=%llu", static_cast<unsigned long long>(peer_id));
                remove_peer_locked(peer_id, true);
            }
        }

        send_pending_reliable_locked();

        // Ping connected peers and refresh their selected candidate type so the
        // overlay has fresh RTT + Direct/STUN/TURN data.
        update_peer_stats_locked(now);

        // Retry reliable messages held back by delivery-queue backpressure,
        // then flush the coalesced ACKs they (and this batch) produced.
        flush_reliable_assemblies_locked();
        for (auto &[peer_id, peer] : peers) {
            (void)peer_id;
            deliver_ordered_reliable_locked(peer);
        }
        flush_pending_acks_locked();

        // Garbage-collect incomplete reassembly state. A partial message that
        // has received no fragment for ICE_REASSEMBLY_GC_SEC cannot complete
        // (the sender retries on its adaptive RTO, so silence means the
        // fragments are lost); dropping it bounds peer.reassembly instead of
        // leaking an entry per lost message. Dropping it also releases the
        // ordered-delivery barrier so later messages are not blocked forever.
        for (auto &[peer_id, peer] : peers) {
            (void)peer_id;
            for (auto it = peer.reassembly.begin(); it != peer.reassembly.end();) {
                ReassemblyState &assembly = it->second;
                bool complete = !assembly.present.empty() &&
                    std::all_of(assembly.present.begin(), assembly.present.end(), [](bool value) { return value; });
                if (!(assembly.reliable && complete) &&
                    now - assembly.updated > std::chrono::duration<double>(ICE_REASSEMBLY_GC_SEC)) {
                    peer.incomplete_reliable_ids.erase(it->first);
                    it = peer.reassembly.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // 1s aggregated traffic line at DEBUG; per-packet detail is TRACE.
        emit_traffic_rollup_locked(now);
    }

    // juice_destroy joins the agent thread, which may still be executing a
    // callback, so agents are destroyed without holding the lock.
    destroy_queued_agents();
}

void Ice_Transport::emit_traffic_rollup_locked(std::chrono::steady_clock::time_point now)
{
    if (next_traffic_rollup == std::chrono::steady_clock::time_point{}) {
        next_traffic_rollup = now + std::chrono::seconds(1);
        return;
    }
    if (now < next_traffic_rollup) return;
    next_traffic_rollup = now + std::chrono::seconds(1);

    size_t peer_count = peers.size();
    size_t connected_count = 0;
    size_t pending_count = 0;
    size_t ooo_count = 0;
    uint64 worst_pending_id = 0;
    size_t worst_pending = 0;
    uint64 worst_ooo_id = 0;
    size_t worst_ooo = 0;
    uint32 diag_ack = 0;
    uint32 diag_first_pending = 0;
    size_t diag_mranges = 0;
    size_t diag_unsent = 0;
    uint64 diag_rate = 0;
    uint32 diag_hc = 0;
    uint32 diag_first_ooo = 0;
    size_t diag_ord = 0;
    size_t diag_inc = 0;
    size_t diag_ordmax = 0;
    int best_rtt = -1;
    for (const auto &[peer_id, peer] : peers) {
        (void)peer_id;
        if (!peer.connected) continue;
        ++connected_count;
        pending_count += peer.pending.size();
        ooo_count += peer.ooo_count;
        if (peer.pending.size() > worst_pending) {
            worst_pending = peer.pending.size();
            worst_pending_id = peer_id;
            diag_ack = peer.peer_ack;
            diag_first_pending = peer.pending.empty() ? 0 : peer.pending.begin()->first;
            diag_mranges = peer.pending_msg_ranges.size();
            diag_unsent = peer.unsent_seqs.size();
            diag_rate = static_cast<uint64>(peer.send_rate_bps / 1024.0);
        }
        if (peer.ooo_count > worst_ooo) {
            worst_ooo = peer.ooo_count;
            worst_ooo_id = peer_id;
            diag_hc = peer.highest_contiguous_seq;
            uint32 first = 0;
            if (peer.ooo_count > 0 && !peer.recv_bitmap.empty()) {
                for (uint32 i = 0; i < Peer::RECV_WINDOW_BITS; ++i) {
                    uint32 idx = (peer.recv_bitmap_head + i) % Peer::RECV_WINDOW_BITS;
                    if (peer.recv_bitmap[idx / 64] & (1ull << (idx % 64))) {
                        first = peer.highest_contiguous_seq + 1 + i;
                        break;
                    }
                }
            }
            diag_first_ooo = first;
            diag_ord = peer.ordered_reliable.size();
            diag_inc = peer.incomplete_reliable_ids.size();
            diag_ordmax = peer.ordered_highwater;
        }
        if (peer.agent) {
            auto cit = agent_ctx.find(peer.agent);
            if (cit != agent_ctx.end() && cit->second) {
                int rtt = cit->second->rtt_ms.load();
                if (rtt >= 0 && (best_rtt < 0 || rtt < best_rtt)) best_rtt = rtt;
            }
        }
    }
    PRINT_DEBUG("ice traffic peers=%zu connected=%zu sent=%llu/%lluB recvd=%llu/%lluB retries=%llu drops=%llu evicts=%llu bp=%llu dpkts=%llu revts=%llu sevts=%llu pfail=%llu zpay=%llu datt=%llu dearly=%llu jdrop=%llu pending=%zu ooo=%zu pmax_id=%llu pmax=%zu omax_id=%llu omax=%zu rtt=%dms",
        peer_count, connected_count,
        static_cast<unsigned long long>(traffic_counters.msgs_sent),
        static_cast<unsigned long long>(traffic_counters.bytes_sent),
        static_cast<unsigned long long>(traffic_counters.msgs_recvd),
        static_cast<unsigned long long>(traffic_counters.bytes_recvd),
        static_cast<unsigned long long>(traffic_counters.retries),
        static_cast<unsigned long long>(traffic_counters.drops),
        static_cast<unsigned long long>(traffic_counters.evicts),
        static_cast<unsigned long long>(traffic_counters.backpressure),
        static_cast<unsigned long long>(traffic_counters.data_pkts),
        static_cast<unsigned long long>(traffic_counters.recv_events),
        static_cast<unsigned long long>(traffic_counters.stale_events),
        static_cast<unsigned long long>(traffic_counters.parse_fail),
        static_cast<unsigned long long>(traffic_counters.zero_payload),
        static_cast<unsigned long long>(traffic_counters.deliver_attempts),
        static_cast<unsigned long long>(traffic_counters.deliver_early),
        static_cast<unsigned long long>(juice_drops.load(std::memory_order_relaxed)),
        pending_count, ooo_count,
        static_cast<unsigned long long>(worst_pending_id), worst_pending,
        static_cast<unsigned long long>(worst_ooo_id), worst_ooo,
        best_rtt);
    if (worst_pending_id != 0) {
        PRINT_DEBUG("ice diag tx id=%llu ack=%u first_pending=%u pending=%zu mranges=%zu unsent=%zu rate_kbs=%llu hole_rtx=%llu",
            static_cast<unsigned long long>(worst_pending_id),
            diag_ack, diag_first_pending, worst_pending, diag_mranges,
            diag_unsent, static_cast<unsigned long long>(diag_rate),
            static_cast<unsigned long long>(traffic_counters.hole_retries));
    }
    if (worst_ooo_id != 0) {
        PRINT_DEBUG("ice diag rx id=%llu hc=%u first_ooo=%u ooo=%zu ord=%zu ordmax=%zu inc=%zu",
            static_cast<unsigned long long>(worst_ooo_id),
            diag_hc, diag_first_ooo, worst_ooo, diag_ord, diag_ordmax, diag_inc);
    }
    // Adapt the pacer from receiver telemetry. The retry counter reacts only
    // after an RTO and is dominated by app-limited recovery, so it let the
    // first 12 MB/s burst overrun the peer and lose ~40%. Each ACK now
    // reports unique fragments, DATA bytes and the ooo count; compare the
    // one-second deltas with what we sent.
    for (auto &[peer_id, peer] : peers) {
        (void)peer_id;
        if (!peer.connected) continue;
        if (peer.remote_telemetry_valid && peer.remote_telemetry_sampled) {
            uint32 d_sent = peer.reliable_frags_sent - peer.last_reliable_frags_sent;
            uint32 d_unique = peer.remote_recv_unique - peer.last_remote_recv_unique;
            uint32 d_bytes = peer.remote_recv_bytes - peer.last_remote_recv_bytes;
            double loss = d_sent
                ? 1.0 - std::min(1.0, static_cast<double>(d_unique) /
                                      static_cast<double>(d_sent))
                : 0.0;
            if (d_sent >= 64) {
                if (loss > 0.02 && d_bytes > 0) {
                    // Multiplicative decrease, bounded above by the rate the
                    // path is actually delivering (plus headroom) so a lossy
                    // burst does not keep the pacer above capacity.
                    double target = static_cast<double>(d_bytes) * 1.25;
                    peer.send_rate_bps = std::min(peer.send_rate_bps * 0.85, target);
                    peer.send_rate_bps = std::max(1.0 * 1024 * 1024, peer.send_rate_bps);
                } else if (loss < 0.005 && peer.remote_ooo < 64) {
                    peer.send_rate_bps = std::min(8.0 * 1024 * 1024,
                                                  peer.send_rate_bps + 256.0 * 1024.0);
                }
                PRINT_DEBUG("ice pace id=%llu conn=%u rate_kbs=%llu deliv_kbs=%llu loss_ppm=%u ooo=%u",
                    static_cast<unsigned long long>(peer.primary_id),
                    static_cast<unsigned>(peer.connection_type),
                    static_cast<unsigned long long>(peer.send_rate_bps / 1024.0),
                    static_cast<unsigned long long>(d_bytes / 1024.0),
                    static_cast<unsigned>(loss * 1000000.0),
                    static_cast<unsigned>(peer.remote_ooo));
            }
            peer.last_reliable_frags_sent = peer.reliable_frags_sent;
            peer.last_remote_recv_unique = peer.remote_recv_unique;
            peer.last_remote_recv_bytes = peer.remote_recv_bytes;
        } else if (peer.remote_telemetry_valid) {
            // First valid telemetry sample: establish the interval baseline
            // without adapting (the delta still spans the whole connection).
            peer.remote_telemetry_sampled = true;
            peer.last_reliable_frags_sent = peer.reliable_frags_sent;
            peer.last_remote_recv_unique = peer.remote_recv_unique;
            peer.last_remote_recv_bytes = peer.remote_recv_bytes;
        } else {
            // No telemetry trailer from this peer yet: keep the sent baseline
            // current and use the old retry-ratio control.
            peer.last_reliable_frags_sent = peer.reliable_frags_sent;
            // Fallback for a peer that does not send the telemetry trailer.
            double retry_ratio = traffic_counters.msgs_sent
                ? static_cast<double>(traffic_counters.retries) /
                  static_cast<double>(traffic_counters.msgs_sent)
                : 0.0;
            if (retry_ratio > 0.05) {
                peer.send_rate_bps = std::max(1.0 * 1024 * 1024, peer.send_rate_bps * 0.85);
            } else if (retry_ratio < 0.01) {
                peer.send_rate_bps = std::min(8.0 * 1024 * 1024, peer.send_rate_bps * 1.05);
            }
        }
    }
    traffic_counters = TrafficCounters{};
}

void Ice_Transport::pump_proc()
{
#if defined(STEAM_WIN32)
    // The default Windows timer resolution is ~15.6ms, which would silently
    // defeat the fast-path wakeup latency. Request the 1ms resolution for the
    // lifetime of this thread and release it on exit.
    timeBeginPeriod(1);
#endif

    while (!pump_stop.load()) {
        // Run() takes the transport mutex itself and early-returns when the
        // transport is disabled, so a straight call is all the loop needs.
        Run();
        pump_wake_flag.store(false);
        // Event-driven wait: juice_recv/state_changed/candidate and
        // ws_message_handler notify the CV, so the fast path runs at event
        // latency instead of poll quantization. The short wait_for() fallback
        // bounds a missed notify to ICE_PUMP_FALLBACK_MS; slow-path cadences
        // (retries, pings, GC, rollup) are enforced by timestamps in Run().
        // If wakeups stop arriving, raise the fallback, not the poll rate.
        std::unique_lock<std::mutex> wlock(pump_wake_mutex);
        pump_wake_cv.wait_for(wlock, std::chrono::milliseconds(ICE_PUMP_FALLBACK_MS),
            [this] { return pump_wake_flag.load() || pump_stop.load(); });
        pump_wake_flag.store(false);
    }

#if defined(STEAM_WIN32)
    timeEndPeriod(1);
#endif
}
