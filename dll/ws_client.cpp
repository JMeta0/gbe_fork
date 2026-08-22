#include "dll/ws_client.h"

#include <chrono>
#include <cstring>

#if defined(STEAM_WIN32)
#include <bcrypt.h>
#endif

// Note: global winsock calls are always written ::connect() / ::send() below
// because this class has member functions of the same names.

namespace {

constexpr char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr uint64_t WS_MAX_FRAME_SIZE = 1ull << 20; // 1 MiB, mirroring the signaling server cap

// ---- socket helpers ----

bool ws_socket_valid(sock_t sock)
{
#if defined(STEAM_WIN32)
    return sock != (sock_t)INVALID_SOCKET && sock != (sock_t)~0;
#else
    return sock >= 0;
#endif
}

void ws_close_socket(sock_t &sock)
{
    if (!ws_socket_valid(sock)) return;
#if defined(STEAM_WIN32)
    closesocket(sock);
#else
    close(sock);
#endif
    sock = static_cast<sock_t>(~0);
}

bool ws_set_nonblocking(sock_t sock)
{
#if defined(STEAM_WIN32)
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool ws_last_error_is_would_block()
{
#if defined(STEAM_WIN32)
    int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEALREADY;
#else
    return errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EALREADY;
#endif
}

int ws_last_error()
{
#if defined(STEAM_WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

// ---- small self-contained crypto helpers (base64 + SHA-1, as the reference
//      signaling server uses its stdlib equivalents) ----

void ws_random_bytes(uint8_t *out, size_t len)
{
#if defined(STEAM_WIN32)
    NTSTATUS status = BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status == 0) return;
    // fallback: derive from the clock
    uint64_t seed = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    for (size_t i = 0; i < len; ++i) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        out[i] = static_cast<uint8_t>(seed >> 33);
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t got = 0;
        while (got < len) {
            ssize_t n = read(fd, out + got, len - got);
            if (n <= 0) break;
            got += static_cast<size_t>(n);
        }
        close(fd);
        if (got == len) return;
    }
    uint64_t seed = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    for (size_t i = 0; i < len; ++i) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        out[i] = static_cast<uint8_t>(seed >> 33);
    }
#endif
}

std::string ws_base64_encode(const uint8_t *data, size_t len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8) | data[i + 2];
        out.push_back(alphabet[(v >> 18) & 0x3F]);
        out.push_back(alphabet[(v >> 12) & 0x3F]);
        out.push_back(alphabet[(v >> 6) & 0x3F]);
        out.push_back(alphabet[v & 0x3F]);
        i += 3;
    }
    if (i + 1 == len) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(alphabet[(v >> 18) & 0x3F]);
        out.push_back(alphabet[(v >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (i + 2 == len) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(alphabet[(v >> 18) & 0x3F]);
        out.push_back(alphabet[(v >> 12) & 0x3F]);
        out.push_back(alphabet[(v >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

struct WsSha1 {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint64_t bit_count = 0;
    uint8_t buffer[64] = {};
    size_t buffer_len = 0;

    static uint32_t rol(uint32_t v, int bits) { return (v << bits) | (v >> (32 - bits)); }

    void process_block(const uint8_t block[64])
    {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) | (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) | block[i * 4 + 3];
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t tmp = rol(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    void update(const uint8_t *data, size_t len)
    {
        bit_count += static_cast<uint64_t>(len) * 8;
        while (len > 0) {
            size_t take = 64 - buffer_len;
            if (take > len) take = len;
            std::memcpy(buffer + buffer_len, data, take);
            buffer_len += take;
            data += take;
            len -= take;
            if (buffer_len == 64) {
                process_block(buffer);
                buffer_len = 0;
            }
        }
    }

    void finish(uint8_t out[20])
    {
        uint64_t bits = bit_count;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buffer_len != 56) update(&zero, 1);
        uint8_t len_bytes[8];
        for (int i = 0; i < 8; ++i) len_bytes[i] = static_cast<uint8_t>(bits >> ((7 - i) * 8));
        update(len_bytes, 8);
        for (int i = 0; i < 5; ++i) {
            out[i * 4] = static_cast<uint8_t>(h[i] >> 24);
            out[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 16);
            out[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 8);
            out[i * 4 + 3] = static_cast<uint8_t>(h[i]);
        }
    }
};

std::string ws_websocket_accept(const std::string &key)
{
    std::string joined = key + WS_GUID;
    uint8_t digest[20];
    WsSha1 sha1;
    sha1.update(reinterpret_cast<const uint8_t *>(joined.data()), joined.size());
    sha1.finish(digest);
    return ws_base64_encode(digest, 20);
}

std::string ws_url_encode(const std::string &value)
{
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : value) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

bool ws_header_field(const std::string &headers, const char *name, std::string &value)
{
    size_t name_len = std::strlen(name);
    size_t pos = 0;
    while (pos < headers.size()) {
        size_t line_end = headers.find("\r\n", pos);
        if (line_end == std::string::npos) line_end = headers.size();
        const std::string line = headers.substr(pos, line_end - pos);
        if (line.size() > name_len && strncmp(line.c_str(), name, name_len) == 0 && line[name_len] == ':') {
            value = line.substr(name_len + 1);
            // trim leading spaces
            size_t start = value.find_first_not_of(" \t");
            value = start == std::string::npos ? std::string{} : value.substr(start);
            return true;
        }
        if (line_end == headers.size()) break;
        pos = line_end + 2;
    }
    return false;
}

} // namespace

WS_Client::WS_Client()
{
}

WS_Client::~WS_Client()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    close_locked();
}

void WS_Client::configure(const std::string &host_, uint16_t port_, const std::string &path_, const std::string &secret_)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    host = host_;
    port = port_;
    path = path_;
    secret = secret_;
}

bool WS_Client::socket_valid() const
{
    return ws_socket_valid(sock);
}

void WS_Client::close_socket()
{
    ws_close_socket(sock);
}

void WS_Client::close_locked()
{
    ws_close_socket(sock);
    connect_in_progress = false;
    send_buffer.clear();
    recv_buffer.clear();
    frame_have_header = false;
    frame_payload.clear();
    message_accum.clear();
    set_state_locked(State::Idle);
}

void WS_Client::set_state_locked(State next)
{
    if (state == next) return;
    State previous = state;
    state = next;
    if (next == State::Open && previous != State::Open) {
        if (state_cb) state_cb(true);
    } else if (next != State::Open && previous == State::Open) {
        if (state_cb) state_cb(false);
    }
}

bool WS_Client::is_connected() const
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    return state == State::Open && socket_valid();
}

bool WS_Client::is_connecting() const
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    return state == State::Connecting || state == State::Handshaking;
}

void WS_Client::connect()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (state == State::Connecting || state == State::Handshaking || state == State::Open) return;
    close_locked();

    if (host.empty() || port == 0) {
        PRINT_DEBUG("ws connect skipped: no host/port configured");
        return;
    }

    sock = static_cast<sock_t>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (!socket_valid()) {
        PRINT_DEBUG("ws socket creation failed err=%d", ws_last_error());
        return;
    }
    if (!ws_set_nonblocking(sock)) {
        PRINT_DEBUG("ws set nonblocking failed err=%d", ws_last_error());
        close_socket();
        return;
    }

    sockaddr_in addr{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) {
        PRINT_DEBUG("ws resolve failed host='%s'", host.c_str());
        if (result) freeaddrinfo(result);
        close_socket();
        return;
    }
    auto *ipv4 = reinterpret_cast<sockaddr_in *>(result->ai_addr);
    addr.sin_addr = ipv4->sin_addr;
    freeaddrinfo(result);

    int res = ::connect(sock, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
    if (res != 0 && !ws_last_error_is_would_block()) {
        PRINT_DEBUG("ws connect failed immediately err=%d", ws_last_error());
        close_socket();
        return;
    }
    connect_in_progress = res != 0;
    state = State::Connecting;
    if (!connect_in_progress) {
        begin_handshake_locked(); // connected instantly
    }
    PRINT_DEBUG("ws connect started host='%s' port=%u path='/%s'", host.c_str(), port, path.c_str());
}

void WS_Client::disconnect()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    close_locked();
}

bool WS_Client::send(const std::string &payload)
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (state != State::Open || !socket_valid()) return false;
    std::vector<char> bytes(payload.begin(), payload.end());
    queue_frame_locked(0x1, bytes); // text frame
    return true;
}

void WS_Client::finish_connect_locked()
{
    if (!connect_in_progress || !socket_valid()) {
        connect_in_progress = false;
        return;
    }

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    int res = select(static_cast<int>(sock + 1), nullptr, &writefds, nullptr, &timeout);
    if (res == 0) return; // still connecting
    if (res < 0) {
        PRINT_DEBUG("ws connect select failed err=%d", ws_last_error());
        close_locked();
        return;
    }

    int so_error = 0;
#if defined(STEAM_WIN32)
    int len = sizeof(so_error);
#else
    socklen_t len = sizeof(so_error);
#endif
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&so_error), &len) != 0 || so_error != 0) {
        PRINT_DEBUG("ws connect failed so_error=%d", so_error);
        close_locked();
        return;
    }

    connect_in_progress = false;
    begin_handshake_locked();
}

void WS_Client::begin_handshake_locked()
{
    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char *>(&one), sizeof(one));

    // build the HTTP upgrade request
    uint8_t key_bytes[16];
    ws_random_bytes(key_bytes, sizeof(key_bytes));
    handshake_key = ws_base64_encode(key_bytes, sizeof(key_bytes));

    std::string request = "GET /" + path;
    if (!secret.empty()) {
        request += "?secret=" + ws_url_encode(secret);
    }
    request += " HTTP/1.1\r\n";
    request += "Host: " + host + ":" + std::to_string(port) + "\r\n";
    request += "Upgrade: websocket\r\n";
    request += "Connection: Upgrade\r\n";
    request += "Sec-WebSocket-Key: " + handshake_key + "\r\n";
    request += "Sec-WebSocket-Version: 13\r\n";
    request += "\r\n";

    queue_raw_locked(std::vector<char>(request.begin(), request.end()));
    state = State::Handshaking;
    PRINT_DEBUG("ws handshake request queued");
}

void WS_Client::queue_raw_locked(const std::vector<char> &bytes)
{
    send_buffer.insert(send_buffer.end(), bytes.begin(), bytes.end());
}

void WS_Client::queue_frame_locked(uint8_t opcode, const std::vector<char> &payload)
{
    std::vector<char> frame;
    frame.reserve(payload.size() + 14);
    frame.push_back(static_cast<char>(0x80 | opcode)); // FIN + opcode

    uint64_t n = payload.size();
    if (n < 126) {
        frame.push_back(static_cast<char>(0x80 | n)); // MASK + len
    } else if (n <= 0xFFFF) {
        frame.push_back(static_cast<char>(0x80 | 126));
        frame.push_back(static_cast<char>((n >> 8) & 0xFF));
        frame.push_back(static_cast<char>(n & 0xFF));
    } else {
        frame.push_back(static_cast<char>(0x80 | 127));
        for (int i = 7; i >= 0; --i) {
            frame.push_back(static_cast<char>((n >> (i * 8)) & 0xFF));
        }
    }

    uint8_t mask_key[4];
    ws_random_bytes(mask_key, sizeof(mask_key));
    for (int i = 0; i < 4; ++i) frame.push_back(static_cast<char>(mask_key[i]));

    for (size_t i = 0; i < payload.size(); ++i) {
        frame.push_back(static_cast<char>(payload[i] ^ mask_key[i % 4]));
    }
    queue_raw_locked(frame);
}

void WS_Client::pump_write_locked()
{
    if (send_buffer.empty() || !socket_valid()) return;
    int sent = ::send(sock, send_buffer.data(), static_cast<int>(send_buffer.size()), 0);
    if (sent > 0) {
        send_buffer.erase(send_buffer.begin(), send_buffer.begin() + sent);
        return;
    }
    if (sent < 0 && !ws_last_error_is_would_block()) {
        PRINT_DEBUG("ws send failed err=%d", ws_last_error());
        close_locked();
    }
}

void WS_Client::process_handshake_locked()
{
    // wait for the full header block
    auto header_end = std::search(recv_buffer.begin(), recv_buffer.end(), "\r\n\r\n", "\r\n\r\n" + 4);
    if (header_end == recv_buffer.end()) {
        if (recv_buffer.size() > 8192) {
            PRINT_DEBUG("ws handshake response too large");
            close_locked();
        }
        return;
    }

    std::string header_block(recv_buffer.begin(), header_end + 4);
    recv_buffer.erase(recv_buffer.begin(), header_end + 4);

    // status line
    size_t line_end = header_block.find("\r\n");
    std::string status_line = line_end == std::string::npos ? header_block : header_block.substr(0, line_end);
    if (status_line.find(" 101 ") == std::string::npos) {
        PRINT_DEBUG("ws handshake rejected: %s", status_line.c_str());
        close_locked();
        return;
    }

    std::string accept;
    if (!ws_header_field(header_block, "Sec-WebSocket-Accept", accept) ||
        accept != ws_websocket_accept(handshake_key)) {
        PRINT_DEBUG("ws handshake accept mismatch");
        close_locked();
        return;
    }

    state = State::Open;
    PRINT_DEBUG("ws connected");
    if (state_cb) state_cb(true);

    // any bytes after the header are the first frames
    if (!recv_buffer.empty()) pump_read_locked();
}

void WS_Client::pump_read_locked()
{
    if (!socket_valid()) return;
    while (true) {
        char buffer[4096];
        int received = ::recv(sock, buffer, sizeof(buffer), 0);
        if (received > 0) {
            recv_buffer.insert(recv_buffer.end(), buffer, buffer + received);
            continue;
        }
        if (received == 0) {
            PRINT_DEBUG("ws closed by server");
            close_locked();
            return;
        }
        if (!ws_last_error_is_would_block()) {
            PRINT_DEBUG("ws recv failed err=%d", ws_last_error());
            close_locked();
            return;
        }
        break;
    }

    if (state != State::Open) return;

    while (true) {
        if (!frame_have_header) {
            // Resync: some deployed signaling servers pushed the "list" reply
            // as raw JSON without WebSocket framing. Those bytes have the FIN
            // bit (0x80) clear, while every frame the reference server sends
            // (text/pong/close) has it set, so drop raw bytes until the next
            // real frame instead of misparsing them and closing the session.
            while (!recv_buffer.empty() && (static_cast<uint8_t>(recv_buffer[0]) & 0x80) == 0) {
                PRINT_DEBUG("ws resync: dropping non-frame byte 0x%02X", static_cast<uint8_t>(recv_buffer[0]));
                recv_buffer.erase(recv_buffer.begin());
            }
            if (recv_buffer.size() < 2) break;
            uint8_t b0 = static_cast<uint8_t>(recv_buffer[0]);
            uint8_t b1 = static_cast<uint8_t>(recv_buffer[1]);
            frame_fin = (b0 & 0x80) != 0;
            frame_opcode = b0 & 0x0F;
            frame_masked = (b1 & 0x80) != 0;
            uint64_t len = b1 & 0x7F;
            size_t header_len = 2;
            if (len == 126) {
                if (recv_buffer.size() < 4) break;
                len = (static_cast<uint64_t>(static_cast<uint8_t>(recv_buffer[2])) << 8) | static_cast<uint8_t>(recv_buffer[3]);
                header_len = 4;
            } else if (len == 127) {
                if (recv_buffer.size() < 10) break;
                len = 0;
                for (int i = 0; i < 8; ++i) {
                    len = (len << 8) | static_cast<uint8_t>(recv_buffer[2 + i]);
                }
                header_len = 10;
            }
            if (frame_masked) {
                if (recv_buffer.size() < header_len + 4) break;
                std::memcpy(frame_mask_key, recv_buffer.data() + header_len, 4);
                header_len += 4;
            }
            if (len > WS_MAX_FRAME_SIZE) {
                PRINT_DEBUG("ws frame too large len=%llu", static_cast<unsigned long long>(len));
                close_locked();
                return;
            }
            recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + header_len);
            frame_expected = len;
            frame_received = 0;
            frame_payload.clear();
            frame_payload.reserve(static_cast<size_t>(len));
            frame_have_header = true;
        }

        if (frame_received < frame_expected) {
            size_t want = static_cast<size_t>(frame_expected - frame_received);
            if (recv_buffer.size() < want) want = recv_buffer.size();
            if (want == 0) break;
            size_t base = frame_payload.size();
            frame_payload.resize(base + want);
            std::memcpy(frame_payload.data() + base, recv_buffer.data(), want);
            if (frame_masked) {
                for (size_t i = 0; i < want; ++i) {
                    frame_payload[base + i] ^= frame_mask_key[(frame_received + i) % 4];
                }
            }
            frame_received += want;
            recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + want);
            if (frame_received < frame_expected) break;
        }

        // complete frame
        uint8_t opcode = frame_opcode;
        bool fin = frame_fin;
        std::vector<char> payload = std::move(frame_payload);
        frame_have_header = false;
        frame_payload.clear();
        handle_frame_locked(opcode, payload);
        if (state != State::Open) return;
        if (fin && opcode == 0x8) return; // close handled
    }
}

void WS_Client::handle_frame_locked(uint8_t opcode, const std::vector<char> &payload)
{
    switch (opcode) {
    case 0x1: // text
    case 0x2: // binary
        if (!message_accum.empty()) {
            PRINT_DEBUG("ws new data frame during fragmented message");
            close_locked();
            return;
        }
        if (frame_fin) {
            std::string msg(payload.begin(), payload.end());
            if (message_cb) message_cb(std::move(msg));
        } else {
            message_accum.assign(payload.begin(), payload.end());
        }
        break;
    case 0x0: // continuation
        if (message_accum.empty()) {
            PRINT_DEBUG("ws unexpected continuation frame");
            close_locked();
            return;
        }
        message_accum.append(payload.begin(), payload.end());
        if (frame_fin) deliver_message_locked();
        break;
    case 0x8: // close
        queue_frame_locked(0x8, payload);
        PRINT_DEBUG("ws close received");
        close_locked();
        break;
    case 0x9: // ping -> pong
        queue_frame_locked(0xA, payload);
        break;
    case 0xA: // pong
        break;
    default:
        // Not a frame we understand (e.g. residual garbage from an unframed
        // server message that slipped past the resync). Drop it and keep the
        // connection alive instead of tearing the session down.
        PRINT_DEBUG("ws unknown opcode %u, dropping frame", opcode);
        break;
    }
}

void WS_Client::deliver_message_locked()
{
    if (message_accum.empty()) return;
    if (message_cb) {
        std::string msg = std::move(message_accum);
        message_accum.clear();
        message_cb(std::move(msg));
    }
}

void WS_Client::Run()
{
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if (!socket_valid()) return;

    if (state == State::Connecting) {
        finish_connect_locked();
        if (state != State::Handshaking) return;
    }
    if (state == State::Handshaking) {
        pump_write_locked();
        if (!socket_valid()) return;
        if (!send_buffer.empty()) return; // still writing the request
        // read the server's 101 response into recv_buffer; the frame-parsing
        // part of pump_read_locked is gated on state == Open, so this only
        // accumulates bytes for process_handshake_locked() below
        pump_read_locked();
        if (!socket_valid()) return;
        process_handshake_locked();
        if (state != State::Open) return;
    }
    if (state != State::Open) return;

    pump_write_locked();
    if (!socket_valid()) return;
    pump_read_locked();
}
