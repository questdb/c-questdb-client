/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 ******************************************************************************/

#include "qwp_mock_server.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using socket_t = SOCKET;
using ssize_t = std::intptr_t;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define close_socket(s) closesocket(s)
// Winsock spells the shutdown constants differently.
#define QWP_SHUT_RDWR SD_BOTH
#define QWP_SHUT_WR   SD_SEND
// Windows TCP has no SIGPIPE; closed-peer writes return WSAECONNRESET.
#define QWP_MSG_NOSIGNAL 0
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <cerrno>
using socket_t = int;
#define INVALID_SOCKET_VALUE (-1)
#define close_socket(s) ::close(s)
#define QWP_SHUT_RDWR SHUT_RDWR
#define QWP_SHUT_WR   SHUT_WR
// Suppress SIGPIPE on closed-peer writes. Linux exposes the flag per
// `send()` call (`MSG_NOSIGNAL`); macOS/BSD exposes it as a per-socket
// option (`SO_NOSIGPIPE` set via `setsockopt`). Define both portably so
// the mock server can refuse to take down the test process when a
// client closes the connection mid-frame.
#ifdef MSG_NOSIGNAL
#define QWP_MSG_NOSIGNAL MSG_NOSIGNAL
#else
#define QWP_MSG_NOSIGNAL 0
#endif
#endif

namespace
{
// Set the per-socket "do not raise SIGPIPE on closed-peer writes" option.
// macOS/BSD use `SO_NOSIGPIPE` because they lack `MSG_NOSIGNAL`; Linux
// already covers this via the `QWP_MSG_NOSIGNAL` flag on each `send()`.
// Windows has no SIGPIPE. Call this immediately after `socket()`/
// `accept()` for any fd the mock server will write to.
inline void set_no_sigpipe([[maybe_unused]] socket_t fd)
{
#if defined(SO_NOSIGPIPE)
    int one = 1;
    (void)::setsockopt(
        fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
}
} // namespace

namespace qwp_mock
{

// ===========================================================================
// SHA1 + Base64 — used by the WebSocket handshake to compute
// Sec-WebSocket-Accept. Hand-rolled to avoid pulling in a crypto dep.
// ===========================================================================

namespace
{

struct Sha1State
{
    uint32_t h[5];
    uint64_t total_bits;
    uint8_t buf[64];
    size_t buf_len;
};

inline uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void sha1_init(Sha1State& s)
{
    s.h[0] = 0x67452301;
    s.h[1] = 0xEFCDAB89;
    s.h[2] = 0x98BADCFE;
    s.h[3] = 0x10325476;
    s.h[4] = 0xC3D2E1F0;
    s.total_bits = 0;
    s.buf_len = 0;
}

void sha1_compress(Sha1State& s, const uint8_t* block)
{
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
    {
        w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
               (uint32_t(block[i * 4 + 2]) << 8) | uint32_t(block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; ++i)
        w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = s.h[0], b = s.h[1], c = s.h[2], d = s.h[3], e = s.h[4];
    for (int i = 0; i < 80; ++i)
    {
        uint32_t f, k;
        if (i < 20)
        {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t t = rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = t;
    }
    s.h[0] += a;
    s.h[1] += b;
    s.h[2] += c;
    s.h[3] += d;
    s.h[4] += e;
}

void sha1_update(Sha1State& s, const uint8_t* data, size_t len)
{
    s.total_bits += uint64_t(len) * 8;
    while (len > 0)
    {
        size_t take = std::min<size_t>(64 - s.buf_len, len);
        std::memcpy(s.buf + s.buf_len, data, take);
        s.buf_len += take;
        data += take;
        len -= take;
        if (s.buf_len == 64)
        {
            sha1_compress(s, s.buf);
            s.buf_len = 0;
        }
    }
}

void sha1_finish(Sha1State& s, uint8_t out[20])
{
    s.buf[s.buf_len++] = 0x80;
    if (s.buf_len > 56)
    {
        std::memset(s.buf + s.buf_len, 0, 64 - s.buf_len);
        sha1_compress(s, s.buf);
        s.buf_len = 0;
    }
    std::memset(s.buf + s.buf_len, 0, 56 - s.buf_len);
    for (int i = 7; i >= 0; --i)
        s.buf[56 + i] = uint8_t(s.total_bits >> ((7 - i) * 8));
    sha1_compress(s, s.buf);
    for (int i = 0; i < 5; ++i)
    {
        out[i * 4] = uint8_t(s.h[i] >> 24);
        out[i * 4 + 1] = uint8_t(s.h[i] >> 16);
        out[i * 4 + 2] = uint8_t(s.h[i] >> 8);
        out[i * 4 + 3] = uint8_t(s.h[i]);
    }
}

std::string base64_encode(const uint8_t* data, size_t len)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= len; i += 3)
    {
        uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) |
                     uint32_t(data[i + 2]);
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        out.push_back(tbl[(v >> 6) & 0x3F]);
        out.push_back(tbl[v & 0x3F]);
    }
    if (i < len)
    {
        uint32_t v = uint32_t(data[i]) << 16;
        if (i + 1 < len)
            v |= uint32_t(data[i + 1]) << 8;
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? tbl[(v >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

std::string compute_ws_accept(const std::string& sec_key)
{
    static const char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    Sha1State s;
    sha1_init(s);
    sha1_update(
        s, reinterpret_cast<const uint8_t*>(sec_key.data()), sec_key.size());
    sha1_update(s, reinterpret_cast<const uint8_t*>(GUID), sizeof(GUID) - 1);
    uint8_t hash[20];
    sha1_finish(s, hash);
    return base64_encode(hash, 20);
}

} // anonymous namespace

// ===========================================================================
// Wire helpers (public API).
// ===========================================================================

void encode_varint_u64(uint64_t v, std::vector<uint8_t>& out)
{
    while ((v & ~uint64_t(0x7F)) != 0)
    {
        out.push_back(uint8_t((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out.push_back(uint8_t(v));
}

std::vector<uint8_t> framed(
    uint8_t version, uint8_t flags, uint16_t table_count,
    const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> out;
    out.reserve(12 + payload.size());
    out.push_back('Q');
    out.push_back('W');
    out.push_back('P');
    out.push_back('1');
    out.push_back(version);
    out.push_back(flags);
    out.push_back(uint8_t(table_count));
    out.push_back(uint8_t(table_count >> 8));
    uint32_t plen = uint32_t(payload.size());
    out.push_back(uint8_t(plen));
    out.push_back(uint8_t(plen >> 8));
    out.push_back(uint8_t(plen >> 16));
    out.push_back(uint8_t(plen >> 24));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<uint8_t> server_info_frame(
    uint8_t role,
    const std::string& cluster_id,
    const std::string& node_id,
    uint64_t epoch,
    uint32_t capabilities,
    int64_t server_wall_ns)
{
    std::vector<uint8_t> p;
    p.push_back(MSG_SERVER_INFO);
    p.push_back(role);
    for (int i = 0; i < 8; ++i)
        p.push_back(uint8_t(epoch >> (i * 8)));
    for (int i = 0; i < 4; ++i)
        p.push_back(uint8_t(capabilities >> (i * 8)));
    for (int i = 0; i < 8; ++i)
        p.push_back(uint8_t(static_cast<uint64_t>(server_wall_ns) >> (i * 8)));
    uint16_t cl = uint16_t(cluster_id.size());
    p.push_back(uint8_t(cl));
    p.push_back(uint8_t(cl >> 8));
    p.insert(p.end(), cluster_id.begin(), cluster_id.end());
    uint16_t nl = uint16_t(node_id.size());
    p.push_back(uint8_t(nl));
    p.push_back(uint8_t(nl >> 8));
    p.insert(p.end(), node_id.begin(), node_id.end());
    return framed(2, 0, 0, p);
}

std::vector<uint8_t> result_end_frame(int64_t request_id)
{
    std::vector<uint8_t> p;
    p.push_back(MSG_RESULT_END);
    for (int i = 0; i < 8; ++i)
        p.push_back(uint8_t(request_id >> (i * 8)));
    encode_varint_u64(0, p); // final_seq
    encode_varint_u64(0, p); // total_rows (not asserted by client beyond plumbing)
    return framed(2, 0, 0, p);
}

std::vector<uint8_t> exec_done_frame(
    int64_t request_id, uint8_t op_type, uint64_t rows_affected)
{
    std::vector<uint8_t> p;
    p.push_back(MSG_EXEC_DONE);
    for (int i = 0; i < 8; ++i)
        p.push_back(uint8_t(request_id >> (i * 8)));
    p.push_back(op_type);
    encode_varint_u64(rows_affected, p);
    return framed(2, 0, 0, p);
}

std::vector<uint8_t> query_error_frame(
    int64_t request_id, uint8_t status_code, const std::string& message)
{
    std::vector<uint8_t> p;
    p.push_back(MSG_QUERY_ERROR);
    for (int i = 0; i < 8; ++i)
        p.push_back(uint8_t(request_id >> (i * 8)));
    p.push_back(status_code);
    // msg_len is u16 LE, not a varint.
    uint16_t mlen = uint16_t(message.size());
    p.push_back(uint8_t(mlen));
    p.push_back(uint8_t(mlen >> 8));
    p.insert(p.end(), message.begin(), message.end());
    return framed(2, 0, 0, p);
}

std::vector<uint8_t> cache_reset_frame(uint8_t mask)
{
    std::vector<uint8_t> p = {MSG_CACHE_RESET, mask};
    return framed(2, 0, 0, p);
}

std::vector<uint8_t> result_batch_frame(
    int64_t request_id, uint64_t batch_seq, uint64_t schema_id,
    size_t row_count, const std::vector<ColumnSpec>& columns)
{
    std::vector<uint8_t> p;
    p.push_back(MSG_RESULT_BATCH);
    for (int i = 0; i < 8; ++i)
        p.push_back(uint8_t(request_id >> (i * 8)));
    encode_varint_u64(batch_seq, p);

    // Table block.
    encode_varint_u64(0, p); // empty table name
    encode_varint_u64(uint64_t(row_count), p);
    encode_varint_u64(uint64_t(columns.size()), p);

    // Schema section: Full mode (0x00).
    p.push_back(0x00);
    encode_varint_u64(schema_id, p);
    for (const auto& c : columns)
    {
        encode_varint_u64(uint64_t(c.name.size()), p);
        p.insert(p.end(), c.name.begin(), c.name.end());
        p.push_back(c.kind);
    }

    // Per-column data.
    for (const auto& c : columns)
        p.insert(p.end(), c.data.begin(), c.data.end());

    // RESULT_BATCH frames have table_count = 1.
    return framed(2, 0, 1, p);
}

std::vector<uint8_t> fixed_column_bytes(
    size_t row_count, const std::vector<uint8_t>& packed_values)
{
    (void)row_count;
    std::vector<uint8_t> out;
    out.push_back(0x00); // null_flag = no validity
    out.insert(out.end(), packed_values.begin(), packed_values.end());
    return out;
}

std::vector<uint8_t> fixed_column_bytes_nullable(
    size_t row_count,
    const std::vector<bool>& is_null,
    const std::vector<uint8_t>& packed_non_null_values,
    size_t elem_size)
{
    assert(is_null.size() == row_count);
    std::vector<uint8_t> out;
    bool any_null = std::any_of(is_null.begin(), is_null.end(),
                                [](bool b) { return b; });
    if (!any_null)
    {
        out.push_back(0x00);
        out.insert(out.end(), packed_non_null_values.begin(),
                   packed_non_null_values.end());
        return out;
    }
    out.push_back(0x01); // null_flag = validity present
    const size_t bitmap_len = (row_count + 7) / 8;
    std::vector<uint8_t> bitmap(bitmap_len, 0);
    for (size_t i = 0; i < row_count; ++i)
        if (is_null[i])
            bitmap[i >> 3] |= uint8_t(1u << (i & 7));
    out.insert(out.end(), bitmap.begin(), bitmap.end());
    out.insert(out.end(), packed_non_null_values.begin(),
               packed_non_null_values.end());
    (void)elem_size;
    return out;
}

std::vector<uint8_t> varlen_column_bytes(
    const std::vector<std::vector<uint8_t>>& rows)
{
    std::vector<uint8_t> out;
    out.push_back(0x00); // no validity (every row non-null)
    // Wire format: `(non_null + 1) × u32_le offsets`, then `total_bytes`
    // raw data. Note: the egress decoder expects offsets *immediately
    // after* the null_flag, no varint length prefix.
    uint32_t off = 0;
    auto push_u32 = [&](uint32_t v)
    {
        out.push_back(uint8_t(v));
        out.push_back(uint8_t(v >> 8));
        out.push_back(uint8_t(v >> 16));
        out.push_back(uint8_t(v >> 24));
    };
    push_u32(off);
    for (const auto& r : rows)
    {
        off += uint32_t(r.size());
        push_u32(off);
    }
    for (const auto& r : rows)
        out.insert(out.end(), r.begin(), r.end());
    return out;
}

std::vector<uint8_t> decimal64_column_bytes(
    const std::vector<int64_t>& values, int8_t scale)
{
    std::vector<uint8_t> out;
    out.push_back(0x00); // validity: no nulls
    encode_varint_u64(uint64_t(uint8_t(scale)), out);
    for (int64_t v : values)
        for (int i = 0; i < 8; ++i)
            out.push_back(uint8_t(v >> (i * 8)));
    return out;
}

std::vector<uint8_t> decimal128_column_bytes(
    const std::vector<std::array<uint8_t, 16>>& values, int8_t scale)
{
    std::vector<uint8_t> out;
    out.push_back(0x00);
    encode_varint_u64(uint64_t(uint8_t(scale)), out);
    for (const auto& v : values)
        out.insert(out.end(), v.begin(), v.end());
    return out;
}

std::vector<uint8_t> decimal256_column_bytes(
    const std::vector<std::array<uint8_t, 32>>& values, int8_t scale)
{
    std::vector<uint8_t> out;
    out.push_back(0x00);                  // validity: no nulls
    out.push_back(uint8_t(scale));        // 1B scale (decode_decimal_wide reads u8)
    for (const auto& v : values)
        out.insert(out.end(), v.begin(), v.end());
    return out;
}

std::vector<uint8_t> geohash_column_bytes(
    const std::vector<bool>& is_null,
    const std::vector<uint8_t>& packed_non_null_values,
    uint8_t precision_bits)
{
    std::vector<uint8_t> out;
    bool any_null = std::any_of(is_null.begin(), is_null.end(),
                                [](bool b) { return b; });
    if (!any_null)
    {
        out.push_back(0x00);
    }
    else
    {
        out.push_back(0x01);
        const size_t bitmap_len = (is_null.size() + 7) / 8;
        std::vector<uint8_t> bitmap(bitmap_len, 0);
        for (size_t i = 0; i < is_null.size(); ++i)
            if (is_null[i])
                bitmap[i >> 3] |= uint8_t(1u << (i & 7));
        out.insert(out.end(), bitmap.begin(), bitmap.end());
    }
    encode_varint_u64(uint64_t(precision_bits), out);
    out.insert(out.end(), packed_non_null_values.begin(),
               packed_non_null_values.end());
    return out;
}

std::vector<uint8_t> array_column_bytes(
    const std::vector<std::optional<ArrayRow>>& rows)
{
    std::vector<uint8_t> out;
    bool any_null = std::any_of(rows.begin(), rows.end(),
                                [](const std::optional<ArrayRow>& r) { return !r.has_value(); });
    if (!any_null)
    {
        out.push_back(0x00);
    }
    else
    {
        out.push_back(0x01);
        const size_t bitmap_len = (rows.size() + 7) / 8;
        std::vector<uint8_t> bitmap(bitmap_len, 0);
        for (size_t i = 0; i < rows.size(); ++i)
            if (!rows[i].has_value())
                bitmap[i >> 3] |= uint8_t(1u << (i & 7));
        out.insert(out.end(), bitmap.begin(), bitmap.end());
    }
    for (const auto& row : rows)
    {
        if (!row.has_value())
            continue;
        out.push_back(uint8_t(row->shape.size()));
        for (uint32_t dim : row->shape)
        {
            out.push_back(uint8_t(dim));
            out.push_back(uint8_t(dim >> 8));
            out.push_back(uint8_t(dim >> 16));
            out.push_back(uint8_t(dim >> 24));
        }
        out.insert(out.end(), row->data.begin(), row->data.end());
    }
    return out;
}

// ===========================================================================
// MockServer implementation.
// ===========================================================================

namespace
{

bool send_all(socket_t fd, const uint8_t* data, size_t len)
{
    while (len > 0)
    {
        ssize_t n = ::send(fd, reinterpret_cast<const char*>(data),
#ifdef _WIN32
                           int(len),
#else
                           len,
#endif
                           QWP_MSG_NOSIGNAL);
        if (n <= 0)
            return false;
        data += n;
        len -= size_t(n);
    }
    return true;
}

bool recv_all(socket_t fd, uint8_t* data, size_t len)
{
    while (len > 0)
    {
        ssize_t n = ::recv(fd, reinterpret_cast<char*>(data),
#ifdef _WIN32
                           int(len),
#else
                           len,
#endif
                           0);
        if (n <= 0)
            return false;
        data += n;
        len -= size_t(n);
    }
    return true;
}

// Read the HTTP request, find Sec-WebSocket-Key, write the upgrade
// response with X-QWP-Version: 2. Returns true on success.
bool ws_handshake(socket_t fd, bool reject_401)
{
    std::string buf;
    buf.reserve(1024);
    char b;
    while (true)
    {
        ssize_t n = ::recv(fd, &b, 1, 0);
        if (n <= 0)
            return false;
        buf.push_back(b);
        if (buf.size() >= 4 &&
            buf.compare(buf.size() - 4, 4, "\r\n\r\n") == 0)
            break;
        if (buf.size() > 8192)
            return false;
    }

    if (reject_401)
    {
        const char resp[] =
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        send_all(fd, reinterpret_cast<const uint8_t*>(resp), sizeof(resp) - 1);
        return false;
    }

    // Find Sec-WebSocket-Key (case-insensitive).
    std::string key;
    {
        size_t p = 0;
        while (p < buf.size())
        {
            size_t eol = buf.find("\r\n", p);
            if (eol == std::string::npos)
                break;
            std::string line = buf.substr(p, eol - p);
            p = eol + 2;
            // Lowercase the header name portion before the colon.
            size_t colon = line.find(':');
            if (colon == std::string::npos)
                continue;
            std::string name = line.substr(0, colon);
            std::transform(name.begin(), name.end(), name.begin(),
                           [](char c) { return char(std::tolower(c)); });
            if (name == "sec-websocket-key")
            {
                key = line.substr(colon + 1);
                // Trim whitespace.
                size_t s = key.find_first_not_of(" \t");
                size_t e = key.find_last_not_of(" \t");
                if (s == std::string::npos)
                    key.clear();
                else
                    key = key.substr(s, e - s + 1);
                break;
            }
        }
    }
    if (key.empty())
        return false;

    std::string accept = compute_ws_accept(key);
    std::string resp =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "X-QWP-Version: 2\r\n"
        "Sec-WebSocket-Accept: " +
        accept + "\r\n\r\n";
    return send_all(fd, reinterpret_cast<const uint8_t*>(resp.data()),
                    resp.size());
}

// Read a single WebSocket frame from `fd`. Returns:
//   {opcode, payload}  — opcode is the low 4 bits (0x1 text, 0x2 binary,
//                        0x8 close, 0x9 ping, 0xA pong).
// On error / connection close returns opcode = -1.
struct WsFrame
{
    int opcode;
    std::vector<uint8_t> payload;
};

WsFrame ws_read(socket_t fd)
{
    WsFrame f{-1, {}};
    uint8_t hdr[2];
    if (!recv_all(fd, hdr, 2))
        return f;
    f.opcode = hdr[0] & 0x0F;
    bool masked = (hdr[1] & 0x80) != 0;
    uint64_t plen = hdr[1] & 0x7F;
    if (plen == 126)
    {
        uint8_t ext[2];
        if (!recv_all(fd, ext, 2))
        {
            f.opcode = -1;
            return f;
        }
        plen = (uint64_t(ext[0]) << 8) | ext[1];
    }
    else if (plen == 127)
    {
        uint8_t ext[8];
        if (!recv_all(fd, ext, 8))
        {
            f.opcode = -1;
            return f;
        }
        plen = 0;
        for (int i = 0; i < 8; ++i)
            plen = (plen << 8) | ext[i];
    }
    uint8_t mask[4] = {0};
    if (masked && !recv_all(fd, mask, 4))
    {
        f.opcode = -1;
        return f;
    }
    f.payload.resize(size_t(plen));
    if (plen > 0 && !recv_all(fd, f.payload.data(), size_t(plen)))
    {
        f.opcode = -1;
        return f;
    }
    if (masked)
        for (size_t i = 0; i < f.payload.size(); ++i)
            f.payload[i] ^= mask[i & 3];
    return f;
}

// Graceful end-of-script teardown. Sends a single WebSocket Close
// control frame (opcode 0x88, FIN bit set, zero-length payload) so
// the client sees a clean protocol-level close, then half-closes the
// TCP send side (`shutdown(SHUT_WR)`) so the FIN propagates AFTER
// any buffered RESULT_END / EXEC_DONE bytes are delivered.
//
// Why this matters: a bare `close(fd)` on macOS surfaces to the
// client as a TCP RST when there's unACK'd data in the local send
// buffer, and the kernel discards still-undelivered data on RST. The
// failure mode looks like a race — RESULT_END *was* sent, but the
// client read returns "Connection reset by peer" instead of seeing
// the frame. Half-close avoids that: the FIN is queued behind the
// data, so the client drains the recv buffer cleanly and then sees
// EOF on a subsequent read.
void graceful_close(socket_t fd)
{
    // RFC 6455 §5.5.1 server Close: 0x88 = FIN | OP_CLOSE; payload = 0.
    static const std::uint8_t ws_close[2] = {0x88, 0x00};
    (void)send(
        fd,
        reinterpret_cast<const char*>(ws_close),
        sizeof(ws_close),
        QWP_MSG_NOSIGNAL);
    (void)::shutdown(fd, QWP_SHUT_WR);
    close_socket(fd);
}

// Write a single (server-side, unmasked) binary WebSocket frame.
bool ws_write_binary(socket_t fd, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> hdr;
    hdr.push_back(0x82); // FIN + BINARY
    size_t len = payload.size();
    if (len < 126)
    {
        hdr.push_back(uint8_t(len));
    }
    else if (len <= 0xFFFF)
    {
        hdr.push_back(126);
        hdr.push_back(uint8_t(len >> 8));
        hdr.push_back(uint8_t(len));
    }
    else
    {
        hdr.push_back(127);
        for (int i = 7; i >= 0; --i)
            hdr.push_back(uint8_t(len >> (i * 8)));
    }
    if (!send_all(fd, hdr.data(), hdr.size()))
        return false;
    return send_all(fd, payload.data(), payload.size());
}

// Read frames until we observe a binary frame whose payload starts with
// `expected_kind`. Stash the captured payload into `out_captured`. Returns
// the request_id from a QUERY_REQUEST (offset 1, i64 LE) when the
// expected kind is QUERY_REQUEST; -1 otherwise. Returns -1 on error.
int64_t read_until_kind(
    socket_t fd, uint8_t expected_kind,
    std::vector<std::vector<uint8_t>>& out_captured,
    std::mutex& out_captured_mtx)
{
    while (true)
    {
        WsFrame f = ws_read(fd);
        if (f.opcode < 0)
            return -1;
        if (f.opcode == 0x8)
            return -1; // close
        if (f.opcode == 0x9)
        {
            // Reply pong with same payload, then keep reading.
            std::vector<uint8_t> hdr = {0x8A, uint8_t(f.payload.size())};
            send_all(fd, hdr.data(), hdr.size());
            if (!f.payload.empty())
                send_all(fd, f.payload.data(), f.payload.size());
            continue;
        }
        if (f.opcode != 0x2) // not binary
            continue;
        if (f.payload.empty())
            continue;
        {
            std::lock_guard<std::mutex> g(out_captured_mtx);
            out_captured.push_back(f.payload);
        }
        if (f.payload[0] == expected_kind)
        {
            if (expected_kind == MSG_QUERY_REQUEST && f.payload.size() >= 9)
            {
                int64_t rid = 0;
                for (int i = 0; i < 8; ++i)
                    rid |= int64_t(f.payload[1 + i]) << (i * 8);
                return rid;
            }
            return 0;
        }
    }
}

} // anonymous namespace

struct MockServer::Impl
{
    socket_t listen_fd = INVALID_SOCKET_VALUE;
    uint16_t port = 0;
    std::vector<Script> scripts;
    std::atomic<int> accept_count{0};
    std::atomic<bool> shutdown{false};
    std::thread listener_thread;
    std::vector<std::thread> workers;
    std::mutex workers_mtx;
    std::vector<std::vector<uint8_t>> captured;
    mutable std::mutex captured_mtx;

#ifdef _WIN32
    static void wsa_init()
    {
        static std::once_flag once;
        std::call_once(once, []
        {
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
        });
    }
#else
    static void wsa_init() {}
#endif

    void run_listener()
    {
        while (!shutdown.load())
        {
            sockaddr_in addr{};
            socklen_t addr_len = sizeof(addr);
            socket_t client = ::accept(listen_fd, (sockaddr*)&addr, &addr_len);
            if (client != INVALID_SOCKET_VALUE)
                set_no_sigpipe(client);
            if (client == INVALID_SOCKET_VALUE)
            {
                if (shutdown.load())
                    return;
                // Accept failed for a transient reason that is not the
                // shutdown path: typically EINTR, but on file-descriptor
                // exhaustion (EMFILE/ENFILE) the same `continue` would
                // spin in a tight CPU loop until a worker frees an fd.
                // Yield briefly so an exhausted fd table can recover and
                // a wedged test machine does not pin a core. EINTR is
                // rare enough that the same delay is harmless there.
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            const int n = accept_count.fetch_add(1);
            Script script;
            if (size_t(n) < scripts.size())
                script = scripts[n];
            else if (!scripts.empty())
                script = scripts.back();
            std::thread t(&Impl::run_worker, this, client, std::move(script));
            std::lock_guard<std::mutex> g(workers_mtx);
            workers.push_back(std::move(t));
        }
    }

    void run_worker(socket_t fd, Script script)
    {
        bool reject = false;
        for (const auto& a : script)
            if (std::holds_alternative<ActionReject401>(a))
            {
                reject = true;
                break;
            }
        if (!ws_handshake(fd, reject))
        {
            close_socket(fd);
            return;
        }

        int64_t last_request_id = 0;
#ifdef _MSC_VER
#pragma warning(push)
// MSVC C4456 fires spuriously on `auto* a = std::get_if<>(...)` in
// successive `else if` branches even though each branch has its own scope.
#pragma warning(disable : 4456)
#endif
        for (const auto& action : script)
        {
            if (std::holds_alternative<ActionReject401>(action))
            {
                close_socket(fd);
                return;
            }
            else if (auto* a = std::get_if<ActionSendServerInfo>(&action))
            {
                auto frame = server_info_frame(
                    a->role, a->cluster_id, a->node_id,
                    a->epoch, a->capabilities, a->server_wall_ns);
                if (!ws_write_binary(fd, frame))
                {
                    close_socket(fd);
                    return;
                }
            }
            else if (std::holds_alternative<ActionAwaitQueryRequest>(action))
            {
                int64_t rid =
                    read_until_kind(fd, MSG_QUERY_REQUEST, captured, captured_mtx);
                if (rid < 0)
                {
                    close_socket(fd);
                    return;
                }
                last_request_id = rid;
            }
            else if (auto* a = std::get_if<ActionAwaitClientFrame>(&action))
            {
                int64_t rc =
                    read_until_kind(fd, a->expected_msg_kind, captured, captured_mtx);
                if (rc < 0)
                {
                    close_socket(fd);
                    return;
                }
            }
            else if (std::holds_alternative<ActionSendResultEnd>(action))
            {
                if (!ws_write_binary(fd, result_end_frame(last_request_id)))
                {
                    close_socket(fd);
                    return;
                }
            }
            else if (auto* a = std::get_if<ActionSendExecDone>(&action))
            {
                if (!ws_write_binary(
                        fd,
                        exec_done_frame(
                            last_request_id, a->op_type, a->rows_affected)))
                {
                    close_socket(fd);
                    return;
                }
            }
            else if (auto* a = std::get_if<ActionSendCacheReset>(&action))
            {
                if (!ws_write_binary(fd, cache_reset_frame(a->mask)))
                {
                    close_socket(fd);
                    return;
                }
            }
            else if (auto* a = std::get_if<ActionSendRaw>(&action))
            {
                if (!ws_write_binary(fd, a->frame))
                {
                    close_socket(fd);
                    return;
                }
            }
            else if (auto* a = std::get_if<ActionSendBuilt>(&action))
            {
                auto frame = a->build(last_request_id);
                if (!ws_write_binary(fd, frame))
                {
                    close_socket(fd);
                    return;
                }
            }
            else if (std::holds_alternative<ActionHardDrop>(action))
            {
                close_socket(fd);
                return;
            }
        }
#ifdef _MSC_VER
#pragma warning(pop)
#endif

        // End of script: graceful close (WS Close frame, then TCP
        // half-close) so any final RESULT_END / EXEC_DONE bytes
        // already on the wire reach the client before EOF. A bare
        // `close(fd)` would race with delivery on macOS, surfacing
        // as `Connection reset by peer` on the client and tripping
        // the mid-stream `FailoverWouldDuplicate` guard in tests that
        // delivered a batch before terminating.
        graceful_close(fd);
    }
};

MockServer::MockServer(std::vector<Script> scripts)
    : _impl(std::make_unique<Impl>())
{
    Impl::wsa_init();
    _impl->scripts = std::move(scripts);

    _impl->listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (_impl->listen_fd == INVALID_SOCKET_VALUE)
        throw std::runtime_error("socket() failed");

    int one = 1;
    ::setsockopt(_impl->listen_fd, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&one), sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(_impl->listen_fd, (sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close_socket(_impl->listen_fd);
        throw std::runtime_error("bind 127.0.0.1:0 failed");
    }
    socklen_t sl = sizeof(addr);
    if (::getsockname(_impl->listen_fd, (sockaddr*)&addr, &sl) != 0)
    {
        close_socket(_impl->listen_fd);
        throw std::runtime_error("getsockname failed");
    }
    _impl->port = ntohs(addr.sin_port);
    if (::listen(_impl->listen_fd, 8) != 0)
    {
        close_socket(_impl->listen_fd);
        throw std::runtime_error("listen failed");
    }

    _impl->listener_thread = std::thread(&Impl::run_listener, _impl.get());
}

MockServer::~MockServer()
{
    if (!_impl)
        return;
    _impl->shutdown.store(true);
    // Wake an in-flight `accept(listen_fd)` deterministically WITHOUT
    // closing the fd from under it. The previous order
    // (close → join listener) raced on macOS in particular, where an
    // accept() that observed the close mid-call could hang instead of
    // returning EBADF. Two complementary mechanisms are used:
    //
    //  1. `shutdown(listen_fd, SHUT_RDWR)` — on Linux/macOS this forces
    //     a blocked accept() on the listening socket to return -1
    //     (errno = EINVAL on Linux, ECONNABORTED/EINVAL on macOS). On
    //     Windows the equivalent SD_BOTH on a listening socket is
    //     accepted but does not always wake accept(), so we still keep
    //     the connect-tickle below as a portable fallback.
    //  2. The connect-tickle: a real client connect that lands in
    //     accept's queue and pops it back to user space.
    //
    // After the listener thread has joined, the fd is owned by no one
    // else and we can finally close it. Closing before the join would
    // re-introduce the race even with shutdown() in place.
    ::shutdown(_impl->listen_fd, QWP_SHUT_RDWR);
    socket_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s != INVALID_SOCKET_VALUE)
    {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(_impl->port);
        ::connect(s, (sockaddr*)&addr, sizeof(addr));
        close_socket(s);
    }
    if (_impl->listener_thread.joinable())
        _impl->listener_thread.join();
    close_socket(_impl->listen_fd);
    std::vector<std::thread> workers;
    {
        std::lock_guard<std::mutex> g(_impl->workers_mtx);
        workers = std::move(_impl->workers);
    }
    for (auto& t : workers)
        if (t.joinable())
            t.join();
}

std::string MockServer::addr() const
{
    return "127.0.0.1:" + std::to_string(_impl->port);
}

int MockServer::accepts() const
{
    return _impl->accept_count.load();
}

std::vector<std::vector<uint8_t>> MockServer::captured_requests() const
{
    std::lock_guard<std::mutex> g(_impl->captured_mtx);
    return _impl->captured;
}

} // namespace qwp_mock
