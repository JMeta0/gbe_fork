#include "dll/ice_transport.h"

#include "json/json.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace {

// ---- ICE datagram protocol ----
// The libjuice agent only provides an authenticated, connected datagram
// channel. On top of it we keep the proven wire format for reliable delivery,
// fragmentation and acknowledgment.

constexpr uint32 ICE_MAGIC = 0x4E505447; // GPTN
constexpr uint8 ICE_VERSION = 1;
constexpr uint8 ICE_PKT_DATA = 3;
constexpr uint8 ICE_PKT_ACK = 4;
constexpr uint8 ICE_PKT_PING = 5;
constexpr uint8 ICE_PKT_PONG = 6;
constexpr uint32 ICE_FLAG_RELIABLE = 1u << 0;
constexpr size_t ICE_FRAGMENT_MTU = 1100;
constexpr int ICE_RELIABLE_RETRY_MS = 250;
constexpr size_t MAX_PENDING_RELIABLE = 256;
// How often a connected peer is pinged (RTT) and its selected candidate pair
// type re-checked. Small frames over the active ICE path; 2s keeps the overlay
// stats fresh without measurable overhead.
constexpr int ICE_PING_INTERVAL_MS = 2000;
// Cadence of the dedicated pump thread. The ICE protocol (juice event
// draining, signaling, retries, pings) runs here instead of inside the game's
// per-frame SteamAPI_RunCallbacks, so it keeps flowing at a fixed ~10ms even
// when the render loop stalls. Requires the 1ms Windows timer resolution
// (timeBeginPeriod), requested once by pump_proc().
constexpr int ICE_PUMP_INTERVAL_MS = 10;
// How long to keep an established ICE session after signaling reports the peer
// disconnected before presuming it gone. Peers broadcast announces every ~5s,
// so any live peer clears the grace flag well within this window; a process
// that quit stays silent and is removed (friend list updated) shortly after.
constexpr double ICE_DISCONNECT_GRACE_SEC = 8.0;
// How long an incomplete incoming message may sit in peer.reassembly before it
// is garbage-collected. The sender retries every 250ms, so a partial message
// that receives no fragment for this long is unrecoverable; keeping it would
// only leak memory.
constexpr double ICE_REASSEMBLY_GC_SEC = 10.0;
// Upper bound for the libjuice callback event queue. While the pump thread
// is stalled (e.g. blocking DNS before the cache fix), callbacks keep queueing;
// beyond this cap the oldest events are dropped so memory stays bounded.
constexpr size_t MAX_JUICE_EVENTS = 1024;
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

bool read_u16(const std::vector<char> &in, size_t &offset, uint16 &value)
{
    if (offset + 2 > in.size()) return false;
    value = static_cast<uint16>(static_cast<uint8_t>(in[offset])) |
            (static_cast<uint16>(static_cast<uint8_t>(in[offset + 1])) << 8);
    offset += 2;
    return true;
}

bool read_u32(const std::vector<char> &in, size_t &offset, uint32 &value)
{
    if (offset + 4 > in.size()) return false;
    value =
        static_cast<uint32>(static_cast<uint8_t>(in[offset])) |
        (static_cast<uint32>(static_cast<uint8_t>(in[offset + 1])) << 8) |
        (static_cast<uint32>(static_cast<uint8_t>(in[offset + 2])) << 16) |
        (static_cast<uint32>(static_cast<uint8_t>(in[offset + 3])) << 24);
    offset += 4;
    return true;
}

bool read_u64(const std::vector<char> &in, size_t &offset, uint64 &value)
{
    if (offset + 8 > in.size()) return false;
    value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64>(static_cast<uint8_t>(in[offset + i])) << (i * 8);
    }
    offset += 8;
    return true;
}

std::vector<char> serialize_ice_header(const IceHeader &header, const std::vector<char> &payload)
{
    std::vector<char> out{};
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
    append_u32(out, header.message_id);
    append_u16(out, header.fragment_index);
    append_u16(out, header.fragment_count);
    append_u32(out, static_cast<uint32>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

bool deserialize_ice_header(const std::vector<char> &packet, IceHeader &header, std::vector<char> &payload)
{
    size_t offset = 0;
    uint32 magic = 0;
    uint32 payload_size = 0;
    if (!read_u32(packet, offset, magic) || magic != ICE_MAGIC) return false;
    if (offset + 2 > packet.size()) return false;
    header.version = static_cast<uint8>(packet[offset++]);
    header.type = static_cast<uint8>(packet[offset++]);
    if (header.version != ICE_VERSION) return false;
    if (!read_u16(packet, offset, header.reserved)) return false;
    if (!read_u32(packet, offset, header.flags)) return false;
    if (!read_u32(packet, offset, header.packet_seq)) return false;
    if (!read_u32(packet, offset, header.ack)) return false;
    if (!read_u32(packet, offset, header.ack_bits)) return false;
    if (!read_u64(packet, offset, header.source_id)) return false;
    if (!read_u64(packet, offset, header.dest_id)) return false;
    if (!read_u64(packet, offset, header.token)) return false;
    if (!read_u32(packet, offset, header.message_id)) return false;
    if (!read_u16(packet, offset, header.fragment_index)) return false;
    if (!read_u16(packet, offset, header.fragment_count)) return false;
    if (!read_u32(packet, offset, payload_size)) return false;
    if (offset + payload_size > packet.size()) return false;
    payload.assign(packet.begin() + static_cast<std::ptrdiff_t>(offset), packet.begin() + static_cast<std::ptrdiff_t>(offset + payload_size));
    return true;
}

bool seq_is_more_recent(uint32 seq, uint32 expected)
{
    return ((seq > expected) && (seq - expected <= 0x80000000u)) ||
           ((expected > seq) && (expected - seq > 0x80000000u));
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
    std::vector<char> bytes = serialize_ice_header(header, payload);
    return juice_send(agent, bytes.data(), bytes.size()) == JUICE_ERR_SUCCESS;
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
    std::lock_guard<std::recursive_mutex> lock(mutex);
    ws_inbox.push_back(std::move(payload));
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
        PRINT_DEBUG("ice signaling list peers=%zu", peer_count);
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
    PRINT_DEBUG("ice remote %s peer=%llu sdp='%s'", is_offer ? "offer" : "answer", static_cast<unsigned long long>(peer_id), preview.c_str());

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
            PRINT_DEBUG("ice duplicate offer ignored peer=%llu", static_cast<unsigned long long>(peer_id));
        }
        return;
    }

    if (juice_set_remote_description(peer.agent, sdp.c_str()) < 0) {
        PRINT_DEBUG("ice set remote description failed peer=%llu", static_cast<unsigned long long>(peer_id));
    } else {
        peer.remote_description_set = true;
        for (const auto &cand : peer.pending_remote_candidates) {
            PRINT_DEBUG("ice replay pending candidate peer=%llu", static_cast<unsigned long long>(peer_id));
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
    peer.pending.clear();
    peer.reassembly.clear();
    peer.completed_messages.clear();
    peer.completed_message_set.clear();
    peer.next_packet_seq = 1;
    peer.highest_remote_seq = 0;
    peer.remote_ack_bits = 0;
    peer.next_message_id = 1;
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
    PRINT_DEBUG("ice local %s -> peer=%llu dest='%s' sdp='%s'", type, static_cast<unsigned long long>(peer.primary_id), peer.signaling_id.c_str(), preview.c_str());
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
    PRINT_DEBUG("ice remote candidate peer=%llu sdp='%s'", static_cast<unsigned long long>(peer_id), preview.c_str());
    peer.signal_disconnected_at = {};
    if (!peer.remote_description_set) {
        PRINT_DEBUG("ice buffering candidate pending remote description peer=%llu", static_cast<unsigned long long>(peer_id));
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
    PRINT_DEBUG("ice local candidate -> peer=%llu dest='%s' sdp='%s'", static_cast<unsigned long long>(peer.primary_id), peer.signaling_id.c_str(), preview.c_str());
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
        pit->second.agent = create_agent_locked(peer_id);
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
    }
    ctx->self->juice_events.push_back(std::move(ev));
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
    }
    ctx->self->juice_events.push_back(std::move(ev));
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
        std::vector<char> packet(data, data + size);
        IceHeader header{};
        std::vector<char> payload{};
        if (deserialize_ice_header(packet, header, payload)) {
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
    }
    ctx->self->juice_events.push_back(std::move(ev));
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
        if (ev.agent != nullptr && ev.agent != peer.agent) continue;

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
                PRINT_DEBUG("ice peer state peer=%llu state=%u", static_cast<unsigned long long>(ev.peer_id), static_cast<unsigned>(ev.state));
                break;
            }
            break;

        case JuiceEvent::Kind::Candidate:
            send_candidate_locked(peer, ev.payload.c_str());
            break;

        case JuiceEvent::Kind::Recv:
            handle_ice_packet_locked(peer, std::vector<char>(ev.payload.begin(), ev.payload.end()));
            break;
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
    header.message_id = message_id;
    header.fragment_index = fragment_index;
    header.fragment_count = fragment_count;
    header.ack = peer.highest_remote_seq;
    header.ack_bits = peer.remote_ack_bits;

    std::vector<char> bytes = serialize_ice_header(header, payload);
    int res = juice_send(peer.agent, bytes.data(), bytes.size());
    return res == JUICE_ERR_SUCCESS;
}

bool Ice_Transport::send_fragments_locked(Peer &peer, uint64 dest_id, const std::vector<char> &payload, bool reliable)
{
    if (!peer.agent || !peer.connected) return false;

    uint16 fragment_count = static_cast<uint16>((payload.size() + ICE_FRAGMENT_MTU - 1) / ICE_FRAGMENT_MTU);
    if (fragment_count == 0) fragment_count = 1;
    uint32 message_id = peer.next_message_id++;
    uint64 source_id = primary_id();
    auto now = std::chrono::steady_clock::now();

    for (uint16 fragment_index = 0; fragment_index < fragment_count; ++fragment_index) {
        size_t offset = static_cast<size_t>(fragment_index) * ICE_FRAGMENT_MTU;
        size_t chunk = std::min(ICE_FRAGMENT_MTU, payload.size() - offset);
        std::vector<char> fragment(payload.begin() + static_cast<std::ptrdiff_t>(offset), payload.begin() + static_cast<std::ptrdiff_t>(offset + chunk));
        uint32 seq = peer.next_packet_seq++;
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
        header.ack = peer.highest_remote_seq;
        header.ack_bits = peer.remote_ack_bits;

        std::vector<char> bytes = serialize_ice_header(header, fragment);

        if (reliable) {
            // Queue reliable fragments *before* the send attempt: a transient
            // juice_send failure (TURN channel bind in progress, momentary missing
            // selected entry, socket would-block) must not lose the message.
            // send_pending_reliable_locked() retries queued fragments until ACKed.
            PendingPacket pending{};
            pending.bytes = bytes;
            pending.next_send = now + std::chrono::milliseconds(ICE_RELIABLE_RETRY_MS);
            pending.message_id = message_id;
            peer.pending[seq] = std::move(pending);

            // Bound the backlog: if a peer never ACKs, evict the oldest whole
            // message instead of individual fragments. Dropping one fragment of
            // a message makes it undeliverable anyway, so keeping its siblings
            // would only waste the retry budget. Fragments of a message are
            // contiguous in the seq-ordered map, so the leading run with the
            // oldest message_id is exactly that message.
            while (peer.pending.size() > MAX_PENDING_RELIABLE) {
                auto oldest = peer.pending.begin();
                if (oldest == peer.pending.end()) break;
                uint32 evict_message = oldest->second.message_id;
                auto it = peer.pending.begin();
                while (it != peer.pending.end() && it->second.message_id == evict_message) {
                    it = peer.pending.erase(it);
                }
            }
        }

        if (juice_send(peer.agent, bytes.data(), bytes.size()) != JUICE_ERR_SUCCESS) {
            if (!reliable) return false; // preserve fire-and-forget semantics
            // Reliable fragments are queued above; the retry loop will deliver them.
            continue;
        }
    }
    return true;
}

void Ice_Transport::send_pending_reliable_locked()
{
    auto now = std::chrono::steady_clock::now();
    for (auto &[peer_id, peer] : peers) {
        (void)peer_id;
        if (!peer.agent || !peer.connected) continue;
        for (auto &[seq, pending] : peer.pending) {
            (void)seq;
            if (now < pending.next_send) continue;
            // Advance the retry timestamp whether or not the send succeeded, so
            // a persistently failing peer retries at the 250ms cadence instead
            // of spinning at tick rate.
            pending.next_send = now + std::chrono::milliseconds(ICE_RELIABLE_RETRY_MS);
            juice_send(peer.agent, pending.bytes.data(), pending.bytes.size());
        }
    }
}

void Ice_Transport::handle_ice_packet_locked(Peer &peer, const std::vector<char> &packet)
{
    IceHeader header{};
    std::vector<char> payload{};
    if (!deserialize_ice_header(packet, header, payload)) return;

    peer.last_seen = std::chrono::steady_clock::now();
    peer.signal_disconnected_at = {};
    if (header.source_id != 0) {
        peer_by_alias[header.source_id] = peer.primary_id;
    }

    // process acknowledgments for our reliable packets
    if (header.ack != 0 || header.ack_bits != 0) {
        auto remove_ack = [&](uint32 seq) {
            auto it = peer.pending.find(seq);
            if (it != peer.pending.end()) peer.pending.erase(it);
        };
        remove_ack(header.ack);
        for (uint32 bit = 0; bit < 32; ++bit) {
            if (header.ack_bits & (1u << bit)) remove_ack(header.ack - (bit + 1));
        }
    }

    // duplicate detection on the packet sequence space
    bool duplicate = false;
    if (header.packet_seq != 0) {
        if (peer.highest_remote_seq == 0) {
            peer.highest_remote_seq = header.packet_seq;
            peer.remote_ack_bits = 0;
        } else if (seq_is_more_recent(header.packet_seq, peer.highest_remote_seq)) {
            uint32 shift = header.packet_seq - peer.highest_remote_seq;
            if (shift >= 32) {
                peer.remote_ack_bits = 0;
            } else {
                peer.remote_ack_bits <<= shift;
                if (shift > 0) peer.remote_ack_bits |= (1u << (shift - 1));
            }
            peer.highest_remote_seq = header.packet_seq;
        } else {
            uint32 delta = peer.highest_remote_seq - header.packet_seq;
            if (delta == 0) {
                duplicate = true;
            } else if (delta <= 32) {
                uint32 mask = (1u << (delta - 1));
                duplicate = (peer.remote_ack_bits & mask) != 0;
                peer.remote_ack_bits |= mask;
            } else {
                duplicate = true;
            }
        }
    }

    if (header.type == ICE_PKT_ACK) return;
    if (header.type != ICE_PKT_DATA || duplicate) return;

    // acknowledge reliable data
    if ((header.flags & ICE_FLAG_RELIABLE) != 0) {
        std::vector<char> empty{};
        send_ice_packet_locked(peer, ICE_PKT_ACK, 0, primary_id(), header.source_id, 0, 0, 0, 0, empty);
    }

    if (peer.completed_message_set.find(header.message_id) != peer.completed_message_set.end()) return;

    auto &assembly = peer.reassembly[header.message_id];
    if (assembly.fragment_count == 0) {
        assembly.fragment_count = header.fragment_count;
        assembly.reliable = (header.flags & ICE_FLAG_RELIABLE) != 0;
        assembly.fragments.resize(header.fragment_count);
        assembly.present.resize(header.fragment_count, false);
    }
    if (header.fragment_index >= assembly.fragments.size()) return;
    assembly.fragments[header.fragment_index] = payload;
    assembly.present[header.fragment_index] = true;
    assembly.updated = std::chrono::steady_clock::now();

    bool complete = std::all_of(assembly.present.begin(), assembly.present.end(), [](bool value) { return value; });
    if (!complete) return;

    std::vector<char> full_payload{};
    for (const auto &fragment : assembly.fragments) {
        full_payload.insert(full_payload.end(), fragment.begin(), fragment.end());
    }
    peer.reassembly.erase(header.message_id);
    peer.completed_message_set.insert(header.message_id);
    peer.completed_messages.push_back(header.message_id);
    while (peer.completed_messages.size() > 128) {
        uint32 old = peer.completed_messages.front();
        peer.completed_messages.pop_front();
        peer.completed_message_set.erase(old);
    }

    Common_Message msg{};
    if (!msg.ParseFromArray(full_payload.data(), static_cast<int>(full_payload.size()))) return;

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

    InboundPacket inbound{};
    inbound.message = std::move(msg);
    inbound.reliable = (header.flags & ICE_FLAG_RELIABLE) != 0;
    inbound.ip_port.ip = htonl(peer.virtual_ip);
    inbound.ip_port.port = htons(peer.virtual_port);
    // The pump thread fills this queue independently of the game's frame
    // loop. If the game (and its 300ms fallback drain) stalls for a long
    // time, bound the backlog by dropping the oldest messages instead of
    // growing without limit; a game that far behind is better served by
    // fresh data anyway.
    if (inbound_packets.size() >= MAX_INBOUND_PACKETS) {
        inbound_packets.pop_front();
    }
    inbound_packets.push_back(std::move(inbound));
}

void Ice_Transport::update_peer_stats_locked(std::chrono::steady_clock::time_point now)
{
    for (auto &[peer_id, peer] : peers) {
        (void)peer_id;
        if (!peer.agent || !peer.connected) continue;
        if (now < peer.next_ping_at) continue;
        peer.next_ping_at = now + std::chrono::milliseconds(ICE_PING_INTERVAL_MS);

        // Refresh the connection type from the ICE selected candidate pair.
        peer.connection_type = selected_candidate_connection_type(peer.agent);

        auto cit = agent_ctx.find(peer.agent);
        if (cit == agent_ctx.end() || !cit->second) continue;

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
    std::lock_guard<std::recursive_mutex> lock(mutex);

    uint64 dest_id = msg->dest_id();
    if (dest_id == 0) return false;
    Peer *peer = find_peer_locked(dest_id);
    if (!peer || !peer->connected) return false;

    size_t size = msg->ByteSizeLong();
    std::vector<char> payload(size);
    msg->SerializeToArray(payload.data(), static_cast<int>(payload.size()));
    return send_fragments_locked(*peer, dest_id, payload, reliable);
}

bool Ice_Transport::SendToEndpoint(Common_Message *msg, uint32 ip, uint16 port, bool reliable)
{
    if (!msg) return false;
    std::lock_guard<std::recursive_mutex> lock(mutex);

    Peer *peer = find_peer_by_endpoint_locked(ip, port);
    if (!peer && msg->dest_id() != 0) {
        peer = find_peer_locked(msg->dest_id());
    }
    if (!peer || !peer->connected) return false;

    size_t size = msg->ByteSizeLong();
    std::vector<char> payload(size);
    msg->SerializeToArray(payload.data(), static_cast<int>(payload.size()));
    return send_fragments_locked(*peer, msg->dest_id(), payload, reliable);
}

bool Ice_Transport::SendBroadcast(Common_Message *msg)
{
    if (!msg) return false;
    std::lock_guard<std::recursive_mutex> lock(mutex);

    size_t size = msg->ByteSizeLong();
    std::vector<char> payload(size);
    msg->SerializeToArray(payload.data(), static_cast<int>(payload.size()));

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

        // Garbage-collect incomplete reassembly state. A partial message that
        // has received no fragment for ICE_REASSEMBLY_GC_SEC cannot complete
        // (the sender retries every 250ms, so silence means the fragments are
        // lost); dropping it bounds peer.reassembly instead of leaking an entry
        // per lost message.
        for (auto &[peer_id, peer] : peers) {
            (void)peer_id;
            for (auto it = peer.reassembly.begin(); it != peer.reassembly.end();) {
                if (now - it->second.updated > std::chrono::duration<double>(ICE_REASSEMBLY_GC_SEC)) {
                    it = peer.reassembly.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    // juice_destroy joins the agent thread, which may still be executing a
    // callback, so agents are destroyed without holding the lock.
    destroy_queued_agents();
}

void Ice_Transport::pump_proc()
{
#if defined(STEAM_WIN32)
    // The default Windows timer resolution is ~15.6ms, which would silently
    // defeat the ~10ms pump cadence. Request the 1ms resolution for the
    // lifetime of this thread and release it on exit.
    timeBeginPeriod(1);
#endif

    while (!pump_stop.load()) {
        // Run() takes the transport mutex itself and early-returns when the
        // transport is disabled, so a straight call is all the loop needs.
        Run();
        std::this_thread::sleep_for(std::chrono::milliseconds(ICE_PUMP_INTERVAL_MS));
    }

#if defined(STEAM_WIN32)
    timeEndPeriod(1);
#endif
}
