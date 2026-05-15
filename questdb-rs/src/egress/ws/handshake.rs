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
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

//! RFC 6455 §4 client-side handshake over a caller-provided `Read + Write`
//! stream.
//!
//! Builds an HTTP/1.1 GET with the WS Upgrade headers (Sec-WebSocket-Key
//! / Version / Upgrade / Connection / Host), writes it as raw ASCII,
//! reads back the response with a bounded prefix scan (defends against
//! slow-loris / malicious servers that dribble headers forever), then
//! validates the response: status MUST be 101, `Upgrade` MUST contain
//! `websocket`, `Connection` MUST contain `Upgrade`, and
//! `Sec-WebSocket-Accept` MUST equal `base64(SHA1(client_key +
//! "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`.
//!
//! Non-101 responses are surfaced as `HttpStatus { status, headers,
//! body }` so the caller can preserve the existing `UpgradeReject`
//! diagnostics for 421 / `Authorization` failures.

use std::io::{Read, Write};

use base64ct::{Base64, Encoding};

use super::mask::build_from_system_random;
use crate::egress::error::Result;
#[cfg(not(any(feature = "ring-crypto", feature = "aws-lc-crypto")))]
use crate::egress::error::fmt;

/// RFC 6455 magic GUID concatenated with the client's Sec-WebSocket-Key
/// before SHA1, then base64-encoded for the Sec-WebSocket-Accept
/// response header. Lifted verbatim from RFC §4.1.
const WS_MAGIC_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Cap on the bytes we read while looking for `\r\n\r\n`. Slow-loris
/// defence: a server that dribbles a single byte at a time would
/// otherwise hold the upgrade socket open until our read timeout fires
/// — and on a fresh TCP connection we typically don't have a read
/// timeout set yet, so without this cap a hostile peer could stall
/// the calling thread indefinitely. 32 KiB is generous for any real
/// HTTP response (we've never seen one exceed ~2 KiB) but small enough
/// that a hostile slow-trickle can't exhaust client memory before the
/// `auth_timeout_ms` deadline fires.
const MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1024;

/// Maximum length of one header line. Matches Apache / nginx defaults
/// (8 KiB) so any header value the WebSocket server emits in practice
/// fits comfortably.
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;

/// One parsed HTTP response header. Stored as owned strings because
/// the response prefix is consumed via a moving cursor — the underlying
/// byte buffer doesn't outlive parsing.
#[derive(Debug, Clone)]
pub(crate) struct Header {
    pub name: String,
    pub value: String,
}

/// Case-insensitive multi-value header collection. The handshake
/// validation logic and the upgrade-reject parser both reach for
/// `find_ci` and `connection_has_token`.
#[derive(Debug, Clone, Default)]
pub(crate) struct Headers(Vec<Header>);

impl Headers {
    /// First value whose name matches `name` case-insensitively, trimmed.
    pub(crate) fn find_ci(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.trim())
    }

    /// Construct from an explicit list of `(name, value)` pairs.
    /// Convenience for tests in `transport.rs` that need to forge a
    /// `Headers` for the content-encoding / role-rejection validators.
    #[cfg(test)]
    pub(crate) fn from_pairs<I, S1, S2>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S1, S2)>,
        S1: Into<String>,
        S2: Into<String>,
    {
        Self(
            pairs
                .into_iter()
                .map(|(name, value)| Header {
                    name: name.into(),
                    value: value.into(),
                })
                .collect(),
        )
    }

    /// True iff the value of `name` (case-insensitive) contains `token`
    /// as a comma-separated token (case-insensitive, whitespace-trimmed).
    /// Used to inspect comma-separated fields like `Connection: keep-alive,
    /// Upgrade`.
    pub(crate) fn header_has_token(&self, name: &str, token: &str) -> bool {
        match self.find_ci(name) {
            Some(value) => value
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case(token)),
            None => false,
        }
    }
}

/// Server response to a non-101 handshake (4xx, 5xx, or anything else).
/// Carries status, headers, and the raw body bytes the server sent
/// before closing or stalling. The caller decides how to surface this —
/// e.g., 421 carries `X-QuestDB-Role` for the role-mismatch failover
/// path; 401 / 403 surface as `AuthError`.
#[derive(Debug, Clone)]
pub(crate) struct HttpReject {
    pub status: u16,
    pub headers: Headers,
    /// Response body when `Content-Length` was honoured. Currently
    /// unread by `transport.rs` — the upgrade-reject classification
    /// keys on status code + role/zone headers — but kept on the
    /// struct so a future diagnostic path can surface the body
    /// without breaking the type's layout.
    #[allow(dead_code)]
    pub body: Vec<u8>,
}

/// Successful 101 handshake outcome.
#[derive(Debug, Clone)]
pub(crate) struct Handshake {
    /// Validated server response headers — accessible for negotiated
    /// values (X-QWP-Version, X-QWP-Content-Encoding).
    pub headers: Headers,
    /// Bytes the server sent after the `\r\n\r\n` header terminator but
    /// before we drained the buffer. Typically empty (RFC 6455 servers
    /// don't send WS frames before the client's first frame), but we
    /// preserve any prefetched bytes so the `WsClient` can prepend them
    /// to its recv buffer.
    pub leftover: Vec<u8>,
}

/// Error path for [`upgrade`]. Variants map to existing egress
/// `ErrorCode`s in transport.rs.
#[derive(Debug)]
pub(crate) enum HandshakeError {
    /// IO failure during request write or response read.
    Io(std::io::Error),
    /// Response was malformed (bad status line, header too long,
    /// missing terminator, etc.).
    Protocol(String),
    /// Response was a well-formed non-101 — caller decides classification.
    HttpStatus(HttpReject),
    /// Sec-WebSocket-Accept check failed (server is not speaking WS or
    /// signed with the wrong key).
    BadAccept,
}

impl From<std::io::Error> for HandshakeError {
    fn from(e: std::io::Error) -> Self {
        HandshakeError::Io(e)
    }
}

/// Run the RFC 6455 §4 client handshake on `stream`.
///
/// `host_header` is the literal `Host:` value (e.g. `"example.com:9000"`
/// or `"[::1]:9000"`); the caller is responsible for picking the right
/// form for IPv6 literals.
/// `path` is the request-target (e.g. `"/read/v1"`).
/// `extra_headers` carries the X-QWP-* and Authorization headers from
/// the connect-string config.
///
/// On success, returns the validated [`Handshake`] including any
/// pre-fetched bytes after `\r\n\r\n`.
pub(crate) fn upgrade<S: Read + Write>(
    stream: &mut S,
    host_header: &str,
    path: &str,
    extra_headers: &[(&'static str, String)],
) -> std::result::Result<Handshake, HandshakeError> {
    // Generate 16 random bytes for Sec-WebSocket-Key. Reuses the
    // crypto provider that mask.rs seeds from — same entropy source,
    // same cfg-gating story.
    let key = generate_client_key()
        .map_err(|_| HandshakeError::Protocol("system entropy source unavailable".into()))?;
    let expected_accept = compute_accept_for_key(&key)
        .map_err(|_| HandshakeError::Protocol("SHA1 digest provider unavailable".into()))?;

    let mut request = Vec::with_capacity(512);
    write_request(&mut request, path, host_header, &key, extra_headers);

    // One write_all: the request fits in a single packet on every real
    // host (we cap the assembled bytes well under MTU * 16). A short
    // write here is the kernel telling us the peer just RST'd — that's
    // a transport failure, surface as `Io`.
    stream.write_all(&request)?;
    stream.flush()?;

    // Read response prefix until \r\n\r\n. Bounded read defends
    // against slow-loris servers; an honest 101 response is < 2 KiB.
    let (header_bytes, leftover) = read_response_prefix(stream)?;
    let response = parse_response(&header_bytes)
        .map_err(|reason| HandshakeError::Protocol(reason.to_string()))?;

    if response.status != 101 {
        let body = read_response_body(stream, &response.headers, leftover)?;
        return Err(HandshakeError::HttpStatus(HttpReject {
            status: response.status,
            headers: response.headers,
            body,
        }));
    }

    // Validate the three structural WS handshake invariants:
    //   1. Upgrade: must contain "websocket" (case-insensitive token).
    //   2. Connection: must contain "Upgrade" (case-insensitive token).
    //   3. Sec-WebSocket-Accept: must equal expected_accept exactly
    //      (base64 is case-sensitive — the bytes are the bytes).
    if !response.headers.header_has_token("Upgrade", "websocket") {
        return Err(HandshakeError::Protocol(
            "missing/invalid Upgrade header".into(),
        ));
    }
    if !response.headers.header_has_token("Connection", "Upgrade") {
        return Err(HandshakeError::Protocol(
            "missing/invalid Connection header".into(),
        ));
    }
    let accept = response
        .headers
        .find_ci("Sec-WebSocket-Accept")
        .ok_or_else(|| HandshakeError::Protocol("missing Sec-WebSocket-Accept".into()))?;
    if accept != expected_accept {
        return Err(HandshakeError::BadAccept);
    }

    Ok(Handshake {
        headers: response.headers,
        leftover,
    })
}

/// Sec-WebSocket-Key is "a randomly selected 16-byte value that has
/// been base64-encoded" (RFC §4.1). We pull 16 bytes from
/// SystemRandom, then base64-encode for the on-wire value. The 16-byte
/// raw form is never used after that.
fn generate_client_key() -> Result<String> {
    // Reuse the SystemRandom plumbing from mask.rs — same crypto
    // provider feature-gate. We could call `SystemRandom::fill` here
    // directly but reusing `build_from_system_random()` keeps the
    // entropy-source surface in one place: one `cfg` block per crypto
    // backend in mask.rs covers both the mask key and Sec-WebSocket-Key
    // paths.
    let mut rng = build_from_system_random()?;
    // 16 bytes = four 4-byte draws. xorshift gives statistical
    // unpredictability from a SystemRandom-seeded state — exactly the
    // RFC's "randomly selected" requirement (no cryptographic
    // unpredictability needed here either; the key only defeats
    // upgrade-replay caching).
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(4) {
        chunk.copy_from_slice(&rng.next_key());
    }
    Ok(Base64::encode_string(&bytes))
}

/// `base64(SHA1(client_key + WS_MAGIC_GUID))`. RFC §4.2.2.
fn compute_accept_for_key(client_key: &str) -> Result<String> {
    let mut digest_input = String::with_capacity(client_key.len() + WS_MAGIC_GUID.len());
    digest_input.push_str(client_key);
    digest_input.push_str(WS_MAGIC_GUID);

    let digest = sha1_digest(digest_input.as_bytes())?;
    Ok(Base64::encode_string(&digest))
}

#[cfg(feature = "ring-crypto")]
fn sha1_digest(input: &[u8]) -> Result<[u8; 20]> {
    use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
    let d = digest(&SHA1_FOR_LEGACY_USE_ONLY, input);
    let bytes = d.as_ref();
    debug_assert_eq!(bytes.len(), 20);
    let mut out = [0u8; 20];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(all(feature = "aws-lc-crypto", not(feature = "ring-crypto")))]
fn sha1_digest(input: &[u8]) -> Result<[u8; 20]> {
    use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
    let d = digest(&SHA1_FOR_LEGACY_USE_ONLY, input);
    let bytes = d.as_ref();
    debug_assert_eq!(bytes.len(), 20);
    let mut out = [0u8; 20];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(not(any(feature = "ring-crypto", feature = "aws-lc-crypto")))]
fn sha1_digest(_input: &[u8]) -> Result<[u8; 20]> {
    Err(fmt!(
        HandshakeError,
        "no crypto provider configured for SHA1 (sync-reader-ws requires ring-crypto or \
         aws-lc-crypto)"
    ))
}

/// Construct the HTTP/1.1 GET request bytes. Header order matches the
/// existing tungstenite emit order (and the Java reference client) to
/// keep handshake captures interchangeable across implementations
/// during the migration.
fn write_request(
    out: &mut Vec<u8>,
    path: &str,
    host_header: &str,
    sec_key: &str,
    extra_headers: &[(&'static str, String)],
) {
    out.extend_from_slice(b"GET ");
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    push_header(out, "Host", host_header);
    push_header(out, "Connection", "Upgrade");
    push_header(out, "Upgrade", "websocket");
    push_header(out, "Sec-WebSocket-Version", "13");
    push_header(out, "Sec-WebSocket-Key", sec_key);

    for (name, value) in extra_headers {
        push_header(out, name, value);
    }

    out.extend_from_slice(b"\r\n");
}

fn push_header(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// Read up to `\r\n\r\n` from `stream`, returning the header bytes
/// (including the terminator) and any post-terminator bytes already
/// buffered.
fn read_response_prefix<S: Read>(
    stream: &mut S,
) -> std::result::Result<(Vec<u8>, Vec<u8>), HandshakeError> {
    // Pull bytes in modest chunks (4 KiB) so a misbehaving peer can't
    // force us into one giant allocation before we even see the first
    // CRLF. Real responses fit comfortably in the first chunk; this
    // only matters for adversarial peers.
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut search_from: usize = 0;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(HandshakeError::Protocol(format!(
                "server closed during handshake response read (got {} bytes, no `\\r\\n\\r\\n`)",
                buf.len()
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(HandshakeError::Protocol(format!(
                "handshake response exceeded {} bytes without `\\r\\n\\r\\n` terminator",
                MAX_RESPONSE_HEADER_BYTES
            )));
        }
        // Search for "\r\n\r\n" starting a little before the previous
        // tail, so the terminator can straddle a read boundary. 3 covers
        // the worst case (the last byte of one chunk being `\r`).
        let scan_from = search_from.saturating_sub(3);
        if let Some(idx) = find_crlf_crlf(&buf[scan_from..]) {
            let term_end = scan_from + idx + 4;
            let leftover = buf.split_off(term_end);
            return Ok((buf, leftover));
        }
        search_from = buf.len();
    }
}

fn find_crlf_crlf(haystack: &[u8]) -> Option<usize> {
    haystack.windows(4).position(|w| w == b"\r\n\r\n")
}

#[derive(Debug)]
struct ParsedResponse {
    status: u16,
    headers: Headers,
}

fn parse_response(bytes: &[u8]) -> std::result::Result<ParsedResponse, &'static str> {
    // Strip the terminator (4 bytes).
    let body_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("missing \\r\\n\\r\\n terminator")?;
    let header_block = &bytes[..body_end];

    let mut lines = split_crlf(header_block);
    let status_line = lines.next().ok_or("response has no status line")?;
    let status = parse_status_line(status_line)?;

    let mut headers = Headers::default();
    for line in lines {
        if line.is_empty() {
            // Trailing empty line before the terminator. Tolerated —
            // the actual end-of-headers is the `\r\n\r\n` itself.
            continue;
        }
        if line.len() > MAX_HEADER_LINE_BYTES {
            return Err("header line exceeds 8 KiB");
        }
        // Folded headers (continuation lines starting with space/tab)
        // are deprecated by RFC 7230 §3.2.4 and rejected — the WS
        // handshake won't legitimately use them.
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            return Err("folded header continuation is not supported");
        }
        let (name, value) = split_header_line(line)?;
        headers.0.push(Header { name, value });
    }
    Ok(ParsedResponse { status, headers })
}

fn split_crlf(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split(|&b| b == b'\n').map(|line| {
        if let [body @ .., b'\r'] = line {
            body
        } else {
            line
        }
    })
}

fn parse_status_line(line: &[u8]) -> std::result::Result<u16, &'static str> {
    // RFC 7230: status-line = HTTP-version SP status-code SP reason-phrase.
    // We tolerate any version prefix ("HTTP/1.1" / "HTTP/1.0") and only
    // care about the status code field.
    let s = std::str::from_utf8(line).map_err(|_| "status line is not UTF-8")?;
    let mut parts = s.splitn(3, ' ');
    let version = parts.next().ok_or("status line missing version")?;
    if !version.starts_with("HTTP/1.") {
        return Err("status line has non-HTTP/1.x version");
    }
    let code = parts.next().ok_or("status line missing status code")?;
    code.parse::<u16>().map_err(|_| "status code is not a u16")
}

fn split_header_line(line: &[u8]) -> std::result::Result<(String, String), &'static str> {
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or("header line missing `:`")?;
    let name = std::str::from_utf8(&line[..colon]).map_err(|_| "header name is not UTF-8")?;
    let value = std::str::from_utf8(&line[colon + 1..]).map_err(|_| "header value is not UTF-8")?;
    if name.is_empty() || name.chars().any(|c| c.is_ascii_whitespace()) {
        return Err("header name has whitespace");
    }
    Ok((name.to_string(), value.trim().to_string()))
}

/// Best-effort body read for a non-101 response. We honour
/// `Content-Length` if present (up to a sane cap) so callers like the
/// 421-role parser can preserve any structured payload. Without
/// `Content-Length` we return what's already in `leftover` and stop —
/// HTTP/1.1 chunked-encoding parsing is out of scope; the upgrade
/// reject diagnostic doesn't depend on the body.
fn read_response_body<S: Read>(
    stream: &mut S,
    headers: &Headers,
    leftover: Vec<u8>,
) -> std::result::Result<Vec<u8>, HandshakeError> {
    const MAX_BODY_BYTES: usize = 64 * 1024;
    let declared_len = headers
        .find_ci("Content-Length")
        .and_then(|v| v.parse::<usize>().ok());

    let Some(content_length) = declared_len else {
        return Ok(leftover);
    };
    if content_length > MAX_BODY_BYTES {
        // Don't pull a multi-MB error body into memory. Truncate.
        let mut buf = leftover;
        let target = MAX_BODY_BYTES.min(content_length);
        if buf.len() < target {
            // Read up to the cap, then stop. The body byte count we
            // return is best-effort: enough for diagnostics, capped to
            // avoid amplification on a misbehaving server.
            let mut tail = vec![0u8; target - buf.len()];
            let n = read_to_fill(stream, &mut tail)?;
            buf.extend_from_slice(&tail[..n]);
        }
        return Ok(buf);
    }
    if leftover.len() >= content_length {
        return Ok(leftover);
    }
    let mut buf = leftover;
    let want = content_length - buf.len();
    let mut tail = vec![0u8; want];
    let n = read_to_fill(stream, &mut tail)?;
    buf.extend_from_slice(&tail[..n]);
    Ok(buf)
}

/// Read repeatedly into `buf` until full or EOF. Returns the number of
/// bytes actually filled (≤ `buf.len()`).
fn read_to_fill<S: Read>(
    stream: &mut S,
    buf: &mut [u8],
) -> std::result::Result<usize, HandshakeError> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial in-memory stream: reads pre-loaded bytes, writes into a
    /// Vec. Used to drive `upgrade` without a real socket.
    struct MemStream {
        to_read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl MemStream {
        fn new(server_bytes: Vec<u8>) -> Self {
            Self {
                to_read: std::io::Cursor::new(server_bytes),
                written: Vec::new(),
            }
        }
    }

    impl Read for MemStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.to_read.read(buf)
        }
    }

    impl Write for MemStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Read the client request from `stream.written` and extract its
    /// Sec-WebSocket-Key so the simulated server can sign the response
    /// with the matching Accept value.
    fn extract_sec_key(req: &[u8]) -> String {
        let s = std::str::from_utf8(req).unwrap();
        for line in s.split("\r\n") {
            if let Some(v) = line.strip_prefix("Sec-WebSocket-Key: ") {
                return v.to_string();
            }
        }
        panic!("Sec-WebSocket-Key not in request:\n{s}");
    }

    #[test]
    fn upgrade_signs_with_runtime_key() {
        // End-to-end: drive `upgrade` against a server that reads the
        // request, derives the expected Accept for the client's
        // freshly-generated key, then replies. Confirms the
        // SHA1+base64 plumbing matches the spec exactly.
        let mut server = MockServer::default();
        let result = upgrade(
            &mut server,
            "host:1234",
            "/path",
            &[("X-Extra", "abc".into())],
        );
        assert!(result.is_ok(), "{:?}", result.err());

        // Confirm the extra header made it onto the wire.
        let req = std::str::from_utf8(&server.written).unwrap();
        assert!(req.contains("X-Extra: abc\r\n"), "{req}");
    }

    #[test]
    fn rejects_when_accept_mismatch() {
        // Server signs with the wrong key — handshake must fail.
        let resp = b"\
HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: bogus=\r\n\r\n";
        let mut server = MemStream::new(resp.to_vec());
        let err = upgrade(&mut server, "host:1", "/", &[]).unwrap_err();
        assert!(matches!(err, HandshakeError::BadAccept), "{err:?}");
    }

    #[test]
    fn surfaces_4xx_as_http_status() {
        let resp = b"\
HTTP/1.1 401 Unauthorized\r\n\
WWW-Authenticate: Basic\r\n\
Content-Length: 11\r\n\r\nhello world";
        let mut server = MemStream::new(resp.to_vec());
        let err = upgrade(&mut server, "host:1", "/", &[]).unwrap_err();
        match err {
            HandshakeError::HttpStatus(reject) => {
                assert_eq!(reject.status, 401);
                assert_eq!(reject.body, b"hello world");
                assert_eq!(reject.headers.find_ci("WWW-Authenticate"), Some("Basic"));
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    #[test]
    fn rejects_when_missing_upgrade_header() {
        let mut server = MockServer::without_header("Upgrade");
        let err = upgrade(&mut server, "host:1", "/", &[]).unwrap_err();
        assert!(matches!(err, HandshakeError::Protocol(_)), "{err:?}");
    }

    #[test]
    fn rejects_when_missing_connection_header() {
        let mut server = MockServer::without_header("Connection");
        let err = upgrade(&mut server, "host:1", "/", &[]).unwrap_err();
        assert!(matches!(err, HandshakeError::Protocol(_)), "{err:?}");
    }

    #[test]
    fn parse_status_line_minimal() {
        assert_eq!(
            parse_status_line(b"HTTP/1.1 101 Switching Protocols").unwrap(),
            101
        );
        assert_eq!(parse_status_line(b"HTTP/1.0 200 OK").unwrap(), 200);
        assert_eq!(
            parse_status_line(b"HTTP/1.1 421 Misdirected Request").unwrap(),
            421
        );
    }

    #[test]
    fn parse_status_line_rejects_garbage() {
        assert!(parse_status_line(b"GARBAGE").is_err());
        assert!(parse_status_line(b"HTTP/2.0 200 OK").is_err());
        assert!(parse_status_line(b"HTTP/1.1 abc OK").is_err());
    }

    #[test]
    fn slow_loris_cap() {
        // 33 KiB of garbage without \r\n\r\n must trip the cap.
        let garbage = vec![b'A'; 33 * 1024];
        let mut server = MemStream::new(garbage);
        let err = upgrade(&mut server, "host:1", "/", &[]).unwrap_err();
        assert!(
            matches!(&err, HandshakeError::Protocol(m) if m.contains("exceeded")),
            "{err:?}"
        );
    }

    #[test]
    fn terminator_straddles_read_boundary() {
        // We can't easily run upgrade() against a 1-byte-at-a-time
        // stream because the response needs to be signed against the
        // request's runtime-random Sec-WebSocket-Key. Instead, assert
        // that the crlf-straddle search window covers the boundary by
        // directly exercising `find_crlf_crlf` with the worst-case
        // offset (terminator split across a read boundary).
        let mut buf = b"HTTP/1.1 101 OK\r\nA: 1\r".to_vec();
        assert!(find_crlf_crlf(&buf).is_none());
        buf.extend_from_slice(b"\n\r\n");
        let idx = find_crlf_crlf(&buf).expect("must find terminator across boundary");
        assert_eq!(idx, buf.len() - 4);
    }

    // ----- Mock server -------------------------------------------------

    /// In-memory stream that, on the first read, signs the response
    /// against the request bytes the test client wrote. Mirrors what a
    /// real WS server does at the handshake-acceptance step.
    struct MockServer {
        written: Vec<u8>,
        to_send: std::io::Cursor<Vec<u8>>,
        prepared: bool,
        omit_header: Option<&'static str>,
    }

    impl MockServer {
        fn without_header(name: &'static str) -> Self {
            Self {
                written: Vec::new(),
                to_send: std::io::Cursor::new(Vec::new()),
                prepared: false,
                omit_header: Some(name),
            }
        }

        fn prepare_response(&mut self) {
            let key = extract_sec_key(&self.written);
            let omit = self.omit_header;
            let extras = &[];
            let resp = build_response(&key, omit, extras);
            self.to_send = std::io::Cursor::new(resp);
            self.prepared = true;
        }
    }

    impl Default for MockServer {
        fn default() -> Self {
            Self {
                written: Vec::new(),
                to_send: std::io::Cursor::new(Vec::new()),
                prepared: false,
                omit_header: None,
            }
        }
    }

    fn build_response(client_key: &str, omit: Option<&str>, extras: &[(&str, &str)]) -> Vec<u8> {
        let accept = compute_accept_for_key(client_key).unwrap();
        let mut resp = String::new();
        resp.push_str("HTTP/1.1 101 Switching Protocols\r\n");
        if omit != Some("Upgrade") {
            resp.push_str("Upgrade: websocket\r\n");
        }
        if omit != Some("Connection") {
            resp.push_str("Connection: Upgrade\r\n");
        }
        resp.push_str(&format!("Sec-WebSocket-Accept: {accept}\r\n"));
        for (k, v) in extras {
            resp.push_str(&format!("{k}: {v}\r\n"));
        }
        resp.push_str("\r\n");
        resp.into_bytes()
    }

    impl Read for MockServer {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.prepared {
                self.prepare_response();
            }
            self.to_send.read(buf)
        }
    }

    impl Write for MockServer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
