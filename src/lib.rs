/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2022 QuestDB
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

use core::time::Duration;
use std::convert::{TryFrom, TryInto, Infallible};
use std::fmt::{self, Write, Display, Formatter};
use std::io::{self, BufRead, BufReader, Write as IoWrite, ErrorKind};
use std::sync::Arc;
use std::path::PathBuf;
use itoa;

use socket2::{Domain, Socket, SockAddr, Type, Protocol};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use rustls::{
    OwnedTrustAnchor, RootCertStore, ClientConnection, ServerName, StreamOwned};

pub use crate::timestamp::{TimestampMicros, TimestampNanos};

macro_rules! fmt_err {
    ($code:ident, $($arg:tt)*) => {
        crate::Error {
            code: crate::ErrorCode::$code,
            msg: format!($($arg)*)
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum Op {
    Table = 1,
    Symbol = 1 << 1,
    Column = 1 << 2,
    At = 1 << 3,
    Flush = 1 << 4
}

impl Op {
    fn descr(self) -> &'static str {
        match self {
            Op::Table => "table",
            Op::Symbol => "symbol",
            Op::Column => "column",
            Op::At => "at",
            Op::Flush => "flush"
        }
    }
}

/// Category of error.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ErrorCode {
    /// The host, port, or interface was incorrect.
    CouldNotResolveAddr,

    /// Called methods in the wrong order. E.g. `symbol` after `column`.
    InvalidApiCall,

    /// A network error connecting or flushing data out.
    SocketError,

    /// The string or symbol field is not encoded in valid UTF-8.
    InvalidUtf8,

    /// The table name or column name contains bad characters.
    InvalidName,

    /// The supplied timestamp is invalid.
    InvalidTimestamp,

    /// Error during the authentication process.
    AuthError,

    /// Error during TLS handshake.
    TlsError
}

#[derive(Debug, PartialEq)]
pub struct Error {
    code: ErrorCode,
    msg: String
}

impl Error {
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn msg(&self) -> &str {
        &self.msg
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn map_io_to_socket_err(prefix: &str, io_err: io::Error) -> Error {
    fmt_err!(SocketError, "{}{}", prefix, io_err)
}

pub struct TableName<'a> {
    name: &'a str
}

impl <'a> TableName<'a> {
    pub fn new(name: &'a str) -> Result<Self> {
        if name.is_empty() {
            return Err(fmt_err!(
                InvalidName, "Table names must have a non-zero length."));
        }

        let mut prev = '\0';
        for (index, c) in name.chars().enumerate() {
            match c {
                '.' => {
                    if index == 0 || index == name.len() - 1 || prev == '.' {
                        return Err(fmt_err!(
                            InvalidName,
                            concat!(
                                "Bad string {:?}: ",
                                "Found invalid dot `.` at position {}."),
                            name, index));
                    }
                },
                '?' | ',' | '\'' | '\"' | '\\' | '/' | ':' | ')' |
                '(' | '+' | '*' | '%' | '~' | '\r' | '\n' | '\0' |
                '\u{0001}' | '\u{0002}' | '\u{0003}' | '\u{0004}' | '\u{0005}' |
                '\u{0006}' | '\u{0007}' | '\u{0008}' | '\u{0009}' | '\u{000b}' |
                '\u{000c}' | '\u{000e}' | '\u{000f}' | '\u{007f}' => {
                    return Err(fmt_err!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Table names can't contain ",
                            "a {:?} character, which was found at ",
                            "byte position {}."),
                        name,
                        c,
                        index));
                },
                '\u{feff}' => {
                    // Reject unicode char 'ZERO WIDTH NO-BREAK SPACE',
                    // aka UTF-8 BOM if it appears anywhere in the string.
                    return Err(fmt_err!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Table names can't contain ",
                            "a UTF-8 BOM character, which was found at ",
                            "byte position {}."),
                        name,
                        index));
                },
                _ => ()
            }
            prev = c;
        }

        Ok(Self { name: name })
    }
}

pub struct ColumnName<'a> {
    name: &'a str
}

impl <'a> ColumnName<'a> {
    pub fn new(name: &'a str) -> Result<Self> {
        if name.is_empty() {
            return Err(fmt_err!(
                InvalidName,
                "Column names must have a non-zero length."));
        }

        for (index, c) in name.chars().enumerate() {
            match c {
                '?' | '.' | ',' | '\'' | '\"' | '\\' | '/' | ':' | ')' | '(' |
                '+' | '-' | '*' | '%' | '~' | '\r' | '\n' | '\0' |
                '\u{0001}' | '\u{0002}' | '\u{0003}' | '\u{0004}' | '\u{0005}' |
                '\u{0006}' | '\u{0007}' | '\u{0008}' | '\u{0009}' | '\u{000b}' |
                '\u{000c}' | '\u{000e}' | '\u{000f}' | '\u{007f}' => {
                    return Err(fmt_err!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Column names can't contain ",
                            "a {:?} character, which was found at ",
                            "byte position {}."),
                        name,
                        c,
                        index));
                },
                '\u{FEFF}' => {
                    // Reject unicode char 'ZERO WIDTH NO-BREAK SPACE',
                    // aka UTF-8 BOM if it appears anywhere in the string.
                    return Err(fmt_err!(
                        InvalidName,
                            concat!(
                                "Bad string {:?}: ",
                                "Column names can't contain ",
                                "a UTF-8 BOM character, which was found at ",
                                "byte position {}."),
                            name,
                            index));
                },
                _ => ()
            }
        }

        Ok(Self { name: name })
    }
}

impl <'a> TryFrom<&'a str> for TableName<'a> {
    type Error = self::Error;

    fn try_from(name: &'a str) -> Result<Self> {
        Self::new(name)
    }
}

impl <'a> TryFrom<&'a str> for ColumnName<'a> {
    type Error = self::Error;

    fn try_from(name: &'a str) -> Result<Self> {
        Self::new(name)
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

fn write_escaped_impl<Q, C>(
    check_escape_fn: C,
    quoting_fn: Q,
    output: &mut String,
    s: &str)
        where
            C: Fn(char) -> bool,
            Q: Fn(&mut String) -> ()
{
    let mut to_escape = 0usize;
    for c in s.chars() {
        if check_escape_fn(c) {
            to_escape += 1;
        }
    }

    quoting_fn(output);

    if to_escape == 0 {
        output.push_str(s);
    }
    else {
        output.reserve(s.len() + to_escape);
        for c in s.chars() {
            if check_escape_fn(c) {
                output.push('\\');
            }
            output.push(c);
        }
    }

    quoting_fn(output);
}

fn must_escape_unquoted(c: char) -> bool {
    match c {
        ' ' | ',' | '=' | '\n' | '\r' | '\\' => true,
        _ => false
    }
}

fn must_escape_quoted(c: char) -> bool {
    match c {
        '\n' | '\r' | '"' | '\\' => true,
        _ => false
    }
}

fn write_escaped_unquoted(output: &mut String, s: &str) {
    write_escaped_impl(
        must_escape_unquoted,
        |_output| (),
        output,
        s);
}

fn write_escaped_quoted(output: &mut String, s: &str) {
    write_escaped_impl(
        must_escape_quoted,
        |output| output.push('"'),
        output,
        s)
}

enum Connection {
    Direct(Socket),
    Tls(StreamOwned<ClientConnection, Socket>)
}

impl io::Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Direct(sock) => sock.read(buf),
            Self::Tls(stream) => stream.read(buf)
        }
    }
}

impl io::Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct(sock) => sock.write(buf),
            Self::Tls(stream) => stream.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Direct(sock) => sock.flush(),
            Self::Tls(stream) => stream.flush()
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum State {
    Init =
        Op::Table as isize,
    TableWritten =
        Op::Symbol as isize | Op::Column as isize,
    SymbolWritten =
        Op::Symbol as isize | Op::Column as isize | Op::At as isize,
    ColumnWritten =
        Op::Column as isize | Op::At as isize,
    MayFlushOrTable =
        Op::Flush as isize | Op::Table as isize
}

impl State {
    fn next_op_descr(self) -> &'static str {
        match self {
            State::Init =>
                "should have called `table` instead",
            State::TableWritten =>
                "should have called `symbol` or `column` instead",
            State::SymbolWritten =>
                "should have called `symbol`, `column` or `at` instead",
            State::ColumnWritten =>
                "should have called `column` or `at` instead",
            State::MayFlushOrTable =>
                "should have called `flush` or `table` instead"
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LineSenderBuffer {
    state: State,
    output: String,
    marker: Option<(usize, State)>,
    max_name_len: usize,
}

impl LineSenderBuffer {
    /// Construct an instance with a `max_name_len` of `127`,
    /// which is the same as the QuestDB default.
    pub fn new() -> Self {
        Self {
            state: State::Init,
            output: String::new(),
            marker: None,
            max_name_len: 127
        }
    }

    /// Construct with a custom maximum length for table and column names.
    /// This should match the `cairo.max.file.name.length` setting of the
    /// QuestDB instance you're connecting to.
    pub fn with_max_name_len(max_name_len: usize) -> Self {
        let mut buffer = Self::new();
        buffer.max_name_len = max_name_len;
        buffer
    }

    /// Pre-allocate to ensure the buffer has enough capacity for at least the
    /// specified additional byte count. This may be rounded up.
    /// This does not allocate if such additional capacity is already satisfied.
    /// See: `capacity`.
    pub fn reserve(&mut self, additional: usize) {
        self.output.reserve(additional);
    }

    pub fn len(&self) -> usize {
        self.output.len()
    }

    pub fn capacity(&self) -> usize {
        self.output.capacity()
    }

    pub fn as_str(&self) -> &str {
        &self.output
    }

    /// Mark a rewind point.
    /// This allows undoing accumulated changes to the buffer for one or more
    /// rows by calling `rewind_to_marker`.
    /// Any previous marker will be discarded.
    /// Once the marker is no longer needed, call `clear_marker`.
    pub fn set_marker(&mut self) -> Result<()> {
        if (self.state as isize & Op::Table as isize) == 0 {
            return Err(fmt_err!(
                InvalidApiCall,
                concat!(
                    "Can't set the marker whilst constructing a line. ",
                    "A marker may only be set on an empty buffer or after ",
                    "`at` or `at_now` is called.")));
        }
        self.marker = Some((self.output.len(), self.state));
        Ok(())
    }

    /// Undo all changes since the last `set_marker` call.
    /// As a side-effect, this also clears the marker.
    pub fn rewind_to_marker(&mut self) -> Result<()> {
        if let Some((position, state)) = self.marker {
            self.output.truncate(position);
            self.state = state;
            self.marker = None;
            Ok(())
        }
        else {
            Err(fmt_err!(
                InvalidApiCall,
                "Can't rewind to the marker: No marker set."))
        }
    }

    /// Discard the marker.
    pub fn clear_marker(&mut self) {
        self.marker = None;
    }

    pub fn clear(&mut self) {
        self.output.clear();
        self.marker = None;
        self.state = State::Init;
    }

    fn check_state(&self, op: Op) -> Result<()> {
        if (self.state as isize & op as isize) > 0 {
            return Ok(());
        }
        let error = fmt_err!(
            InvalidApiCall,
            "State error: Bad call to `{}`, {}.",
            op.descr(),
            self.state.next_op_descr());
        Err(error)
    }

    fn validate_max_name_len(&self, name: &str) -> Result<()> {
        if name.len() > self.max_name_len {
            return Err(fmt_err!(
                InvalidApiCall,
                "Bad name: {:?}: Too long (max {} characters)",
                name,
                self.max_name_len));
        }
        Ok(())
    }

    pub fn table<'a, N>(&mut self, name: N) -> Result<&mut Self>
        where
            N: TryInto<TableName<'a>>,
            Error: From<N::Error>
    {
        let name: TableName<'a> = name.try_into()?;
        self.validate_max_name_len(name.name)?;
        self.check_state(Op::Table)?;
        write_escaped_unquoted(&mut self.output, name.name);
        self.state = State::TableWritten;
        Ok(self)
    }

    pub fn symbol<'a, N, S>(&mut self, name: N, value: S) -> Result<&mut Self>
        where
            N: TryInto<ColumnName<'a>>,
            S: AsRef<str>,
            Error: From<N::Error>
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.name)?;
        self.check_state(Op::Symbol)?;
        self.output.push(',');
        write_escaped_unquoted(&mut self.output, name.name);
        self.output.push('=');
        write_escaped_unquoted(&mut self.output, value.as_ref());
        self.state = State::SymbolWritten;
        Ok(self)
    }

    fn write_column_key<'a, N>(&mut self, name: N) -> Result<&mut Self>
        where
            N: TryInto<ColumnName<'a>>,
            Error: From<N::Error>
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.name)?;
        self.check_state(Op::Column)?;
        self.output.push(
            if (self.state as isize & Op::Symbol as isize) > 0 {
                ' '
            } else {
                ','
            });
        write_escaped_unquoted(&mut self.output, name.name);
        self.output.push('=');
        self.state = State::ColumnWritten;
        Ok(self)
    }

    pub fn column_bool<'a, N>(
        &mut self, name: N, value: bool) -> Result<&mut Self>
        where
            N: TryInto<ColumnName<'a>>,
            Error: From<N::Error>
    {
        self.write_column_key(name)?;
        self.output.push(if value {'t'} else {'f'});
        Ok(self)
    }

    pub fn column_i64<'a, N>(
        &mut self, name: N, value: i64) -> Result<&mut Self>
        where
            N: TryInto<ColumnName<'a>>,
            Error: From<N::Error>
    {
        self.write_column_key(name)?;
        let mut buf = itoa::Buffer::new();
        let printed = buf.format(value);
        self.output.push_str(printed);
        self.output.push('i');
        Ok(self)
    }

    pub fn column_f64<'a, N>(
        &mut self, name: N, value: f64) -> Result<&mut Self>
        where
            N: TryInto<ColumnName<'a>>,
            Error: From<N::Error>
    {
        self.write_column_key(name)?;
        let mut ser = F64Serializer::new(value);
        self.output.push_str(ser.to_str());
        Ok(self)
    }

    pub fn column_str<'a, N, S>(
        &mut self, name: N, value: S) -> Result<&mut Self>
        where
            N: TryInto<ColumnName<'a>>,
            S: AsRef<str>,
            Error: From<N::Error>
    {
        self.write_column_key(name)?;
        write_escaped_quoted(&mut self.output, value.as_ref());
        Ok(self)
    }

    pub fn column_ts<'a, N, T>(
        &mut self, name: N, value: T) -> Result<&mut Self>
        where
            N: TryInto<ColumnName<'a>>,
            T: TryInto<TimestampMicros>,
            Error: From<N::Error>,
            Error: From<T::Error>
    {
        self.write_column_key(name)?;
        let timestamp: TimestampMicros = value.try_into()?;
        let mut buf = itoa::Buffer::new();
        let printed = buf.format(timestamp.as_i64());
        self.output.push_str(printed);
        self.output.push('t');
        Ok(self)
    }

    pub fn at<T>(&mut self, timestamp: T) -> Result<()>
        where
            T: TryInto<TimestampNanos>,
            Error: From<T::Error>
    {
        self.check_state(Op::At)?;
        let mut buf = itoa::Buffer::new();
        let timestamp: TimestampNanos = timestamp.try_into()?;
        let epoch_nanos = timestamp.as_i64();
        let printed = buf.format(epoch_nanos);
        self.output.push(' ');
        self.output.push_str(printed);
        self.output.push('\n');
        self.state = State::MayFlushOrTable;
        Ok(())
    }

    pub fn at_now(&mut self) -> Result<()> {
        self.check_state(Op::At)?;
        self.output.push('\n');
        self.state = State::MayFlushOrTable;
        Ok(())
    }
}

pub struct LineSender {
    descr: String,
    conn: Connection,
    connected: bool
}

impl std::fmt::Debug for LineSender {
    fn fmt(&self, f: &mut Formatter<'_>)
        -> std::result::Result<(), std::fmt::Error>
    {
        f.write_str(self.descr.as_str())
    }
}

#[derive(Debug, Clone)]
struct AuthParams {
    key_id: String,
    priv_key: String,
    pub_key_x: String,
    pub_key_y: String
}

#[derive(Debug, Clone)]
pub enum CertificateAuthority {
    WebpkiRoots,
    File(PathBuf)
}

#[derive(Debug, Clone)]
pub enum Tls {
    Disabled,
    Enabled(CertificateAuthority),

    #[cfg(feature = "insecure_skip_verify")]
    InsecureSkipVerify
}

impl Tls {
    pub fn is_disabled(&self) -> bool {
        match self {
            Tls::Disabled => true,
            _ => false
        }
    }
}

pub struct Service(String);

impl From<String> for Service {
    fn from(s: String) -> Self {
        Service(s)
    }
}

impl From<&str> for Service {
    fn from(s: &str) -> Self {
        Service(s.to_owned())
    }
}

impl From<u16> for Service {
    fn from(p: u16) -> Self {
        Service(p.to_string())
    }
}

#[cfg(feature = "insecure_skip_verify")]
mod danger {
    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

fn map_rustls_err(descr: &str, err: rustls::Error) -> Error {
    fmt_err!(TlsError, "{}: {}", descr, err)
}

fn add_webpki_roots(root_store: &mut rustls::RootCertStore) {
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )}));
}

fn configure_tls(tls: &Tls) -> Result<Option<Arc<rustls::ClientConfig>>> {
    if tls.is_disabled() {
        return Ok(None);
    }

    let mut root_store = RootCertStore::empty();

    if let Tls::Enabled(ca) = tls {
        match ca {
            CertificateAuthority::WebpkiRoots => {
                add_webpki_roots(&mut root_store);
            },
            CertificateAuthority::File(ca_file) => {
                let certfile = std::fs::File::open(ca_file)
                    .map_err(|io_err| fmt_err!(
                        TlsError,
                        concat!(
                            "Could not open certificate authority ",
                            "file from path {:?}: {}"),
                        ca_file,
                        io_err))?;
                let mut reader = BufReader::new(certfile);
                let der_certs = &rustls_pemfile::certs(&mut reader)
                    .map_err(|io_err| fmt_err!(
                        TlsError,
                        concat!(
                            "Could not read certificate authority ",
                            "file from path {:?}: {}"),
                        ca_file,
                        io_err))?;
                root_store.add_parsable_certificates(der_certs);
            }
        }
    }
    // else if let Tls::InsecureSkipVerify {
    //    We don't need to set up any certificates.
    //    An empty root is fine if we're going to ignore validity anyways.
    // }

    let mut config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .map_err(|rustls_err| map_rustls_err(
            "Bad protocol version selection", rustls_err))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // TLS log file for debugging.
    // Set the SSLKEYLOGFILE env variable to a writable location.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    #[cfg(feature = "insecure_skip_verify")]
    if let Tls::InsecureSkipVerify = tls {
        config.dangerous().set_certificate_verifier(
            Arc::new(danger::NoCertificateVerification {}));
    }

    Ok(Some(Arc::new(config)))
}

#[derive(Debug, Clone)]
pub struct LineSenderBuilder {
    capacity: usize,
    read_timeout: Duration,
    host: String,
    port: String,
    net_interface: Option<String>,
    auth: Option<AuthParams>,
    tls: Tls
}

impl LineSenderBuilder {
    /// QuestDB server and port.
    pub fn new<H: Into<String>, P: Into<Service>>(host: H, port: P) -> Self {
        let service: Service = port.into();
        Self {
            capacity: 65536,
            read_timeout: Duration::from_secs(15),
            host: host.into(),
            port: service.0,
            net_interface: None,
            auth: None,
            tls: Tls::Disabled
        }
    }

    /// Set the initial buffer capacity (byte count).
    /// The default is 65536.
    pub fn capacity(mut self, byte_count: usize) -> Self {
        self.capacity = byte_count;
        self
    }

    /// Select local outbound interface.
    pub fn net_interface<I: Into<String>>(mut self, addr: I) -> Self {
        self.net_interface = Some(addr.into());
        self
    }

    /// Authentication Parameters.
    /// Takes:
    ///   * Key id. AKA "kid"
    ///   * Private key. AKA "d".
    ///   * Public key X coordinate. AKA "x".
    ///   * Public key Y coordinate. AKA "y".
    pub fn auth<A, B, C, D>(
        mut self,
        key_id: A,
        priv_key: B,
        pub_key_x: C,
        pub_key_y: D) -> Self
            where
                A: Into<String>,
                B: Into<String>,
                C: Into<String>,
                D: Into<String>
    {
        self.auth = Some(AuthParams {
            key_id: key_id.into(),
            priv_key: priv_key.into(),
            pub_key_x: pub_key_x.into(),
            pub_key_y: pub_key_y.into()
        });
        self
    }

    /// Configure TLS handshake.
    pub fn tls(mut self, tls: Tls) -> Self {
        self.tls = tls;
        self
    }

    /// Configure how long to wait for messages from the QuestDB server during
    /// the TLS handshake and authentication process.
    /// The default is 15 seconds.
    pub fn read_timeout(mut self, value: Duration) -> Self {
        self.read_timeout = value;
        self
    }

    /// Connect synchronously.
    pub fn connect(&self) -> Result<LineSender> {
        let mut descr = format!(
            "LineSender[host={:?},port={:?},", self.host, self.port);
        let addr: SockAddr = gai::resolve_host_port(
            self.host.as_str(), self.port.as_str())?;
        let mut sock = Socket::new(
            Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .map_err(|io_err| map_io_to_socket_err(
                "Could not open TCP socket: ", io_err))?;
        sock.set_linger(Some(Duration::from_secs(120)))
            .map_err(|io_err| map_io_to_socket_err(
                "Could not set socket linger: ", io_err))?;
        sock.set_nodelay(true)
            .map_err(|io_err| map_io_to_socket_err(
                "Could not set TCP_NODELAY: ", io_err))?;
        if let Some(ref host) = self.net_interface {
            let bind_addr = gai::resolve_host(host.as_str())?;
            sock.bind(&bind_addr)
                .map_err(|io_err| map_io_to_socket_err(
                    &format!(
                        "Could not bind to interface address {:?}: ",
                        host),
                    io_err))?;
        }
        sock.connect(&addr)
            .map_err(|io_err| {
                let host_port = format!("{}:{}", self.host, self.port);
                let prefix = format!("Could not connect to {:?}: ", host_port);
                map_io_to_socket_err(&prefix, io_err)
            })?;

        // We read during both TLS handshake and authentication.
        // We set up a read timeout to prevent the client from "hanging"
        // should we be connecting to a server configured in a different way
        // from the client.
        sock.set_read_timeout(Some(self.read_timeout))
            .map_err(|io_err| map_io_to_socket_err(
                "Failed to set read timeout on socket: ", io_err))?;

        match self.tls {
            Tls::Disabled => write!(descr, "tls=enabled,").unwrap(),
            Tls::Enabled(_) => write!(descr, "tls=enabled,").unwrap(),

            #[cfg(feature="insecure_skip_verify")]
            Tls::InsecureSkipVerify => write!(
                descr, "tls=insecure_skip_verify,").unwrap(),
        }

        let conn = match configure_tls(&self.tls)? {
                Some(tls_config) => {
                    let server_name: ServerName = self.host.as_str().try_into()
                        .map_err(|inv_dns_err| fmt_err!(
                            TlsError,
                            "Bad host: {}",
                            inv_dns_err))?;
                    let mut tls_conn = ClientConnection::new(
                        tls_config, server_name)
                            .map_err(|rustls_err| fmt_err!(
                                TlsError,
                                "Could not create TLS client: {}",
                                rustls_err))?;
                    while tls_conn.wants_write() || tls_conn.is_handshaking() {
                        tls_conn.complete_io(&mut sock)
                            .map_err(|io_err|
                                if (io_err.kind() == ErrorKind::TimedOut) ||
                                    (io_err.kind() == ErrorKind::WouldBlock) {
                                    fmt_err!(TlsError,
                                        concat!(
                                            "Failed to complete TLS handshake:",
                                            " Timed out waiting for server ",
                                            "response after {:?}."),
                                        self.read_timeout)
                                } else {
                                    fmt_err!(
                                        TlsError,
                                        "Failed to complete TLS handshake: {}",
                                        io_err)
                                })?;
                    }
                    Connection::Tls(StreamOwned::new(tls_conn, sock))
                },
                None => Connection::Direct(sock)
            };
        if self.auth.is_some() {
            descr.push_str("auth=on]");
        }
        else {
            descr.push_str("auth=off]");
        }
        let mut sender = LineSender {
            descr: descr,
            conn: conn,
            connected: true
        };
        if let Some(auth) = self.auth.as_ref() {
            sender.authenticate(auth)?;
        }
        Ok(sender)
    }
}

fn b64_decode(descr: &'static str, buf: &str) -> Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(buf)
        .map_err(|b64_err| fmt_err!(
            AuthError, "Could not decode {}: {}", descr, b64_err))
}

fn parse_public_key(pub_key_x: &str, pub_key_y: &str) -> Result<Vec<u8>> {
    let mut pub_key_x = b64_decode("public key x", pub_key_x)?;
    let mut pub_key_y = b64_decode("public key y", pub_key_y)?;

    // SEC 1 Uncompressed Octet-String-to-Elliptic-Curve-Point Encoding
    let mut encoded = Vec::new();
    encoded.push(4u8);  // 0x04 magic byte that identifies this as uncompressed.
    encoded.resize((32 - pub_key_x.len()) + 1, 0u8);
    encoded.append(&mut pub_key_x);
    encoded.resize((32 - pub_key_y.len()) + 1 + 32, 0u8);
    encoded.append(&mut pub_key_y);
    Ok(encoded)
}

fn parse_key_pair(auth: &AuthParams) -> Result<EcdsaKeyPair> {
    let private_key = b64_decode(
        "private authentication key", auth.priv_key.as_str())?;
    let public_key = parse_public_key(
        auth.pub_key_x.as_str(), auth.pub_key_y.as_str())?;
    EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &private_key[..],
        &public_key[..])
            .map_err(|key_rejected| fmt_err!(
                AuthError, "Bad private key: {}", key_rejected))
}

struct F64Serializer {
    buf: ryu::Buffer,
    n: f64
}

impl F64Serializer {
    fn new(n: f64) -> Self {
        F64Serializer {
            buf: ryu::Buffer::new(),
            n: n
        }
    }

    // This function was taken and customized from the ryu crate.
    #[cold]
    #[cfg_attr(feature = "no-panic", inline)]
    fn format_nonfinite(&self) -> &'static str {
        const MANTISSA_MASK: u64 = 0x000fffffffffffff;
        const SIGN_MASK: u64 = 0x8000000000000000;
        let bits = self.n.to_bits();
        if bits & MANTISSA_MASK != 0 {
            "NaN"
        } else if bits & SIGN_MASK != 0 {
            "-Infinity"
        } else {
            "Infinity"
        }
    }

    fn to_str(&mut self) -> &str {
        if self.n.is_finite() {
            self.buf.format_finite(self.n)
        }
        else {
            self.format_nonfinite()
        }
    }
}

impl LineSender {

    fn send_key_id(&mut self, key_id: &str) -> Result<()> {
        write!(&mut self.conn, "{}\n", key_id)
            .map_err(|io_err|
                map_io_to_socket_err("Failed to send key_id: ", io_err))?;
        Ok(())
    }

    fn read_challenge(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut reader = BufReader::new(&mut self.conn);
        reader.read_until(b'\n', &mut buf)
            .map_err(|io_err| map_io_to_socket_err(
                "Failed to read authentication challenge (timed out?): ",
                io_err))?;
        if buf.last().map(|c| *c).unwrap_or(b'\0') != b'\n' {
            return Err(if buf.len() == 0 {
                    fmt_err!(
                        AuthError,
                        concat!(
                            "Did not receive auth challenge. ",
                            "Is the database configured to require ",
                            "authentication?"
                        ))
                } else {
                    fmt_err!(
                        AuthError,
                        "Received incomplete auth challenge: {:?}",
                        buf)
                });
        }
        buf.pop();  // b'\n'
        Ok(buf)
    }

    fn authenticate(&mut self, auth: &AuthParams) -> Result<()> {
        if auth.key_id.contains('\n') {
            return Err(fmt_err!(
                AuthError,
                "Bad key id {:?}: Should not contain new-line char.",
                auth.key_id));
        }
        let key_pair = parse_key_pair(&auth)?;
        self.send_key_id(auth.key_id.as_str())?;
        let challenge = self.read_challenge()?;
        let rng = ring::rand::SystemRandom::new();
        let signature = key_pair.sign(&rng, &challenge[..]).
            map_err(|unspecified_err| fmt_err!(
                AuthError,
                "Failed to sign challenge: {}",
                unspecified_err))?;
        let mut encoded_sig = Base64::encode_string(signature.as_ref());
        encoded_sig.push('\n');
        let buf = encoded_sig.as_bytes();
        if let Err(io_err) = self.conn.write_all(buf) {
            return Err(map_io_to_socket_err(
                "Could not send signed challenge: ",
                io_err));
        }
        Ok(())
    }

    /// Send accumulated lines to the QuestDB server, without clearing the
    /// buffer.
    pub fn flush_and_keep(&mut self, buf: &LineSenderBuffer) -> Result<()> {
        if !self.connected {
            return Err(fmt_err!(
                SocketError,
                "Could not flush buffer: not connected to database."));
        }
        buf.check_state(Op::Flush)?;
        let bytes = buf.as_str().as_bytes();
        if let Err(io_err) = self.conn.write_all(bytes) {
            self.connected = false;
            return Err(map_io_to_socket_err(
                "Could not flush buffer: ",
                io_err));
        }
        Ok(())
    }

    pub fn flush(&mut self, buf: &mut LineSenderBuffer) -> Result<()> {
        self.flush_and_keep(buf)?;
        buf.clear();
        Ok(())
    }

    pub fn must_close(&self) -> bool {
        !self.connected
    }
}

mod gai;
mod timestamp;

#[allow(non_camel_case_types)]
#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(test)]
mod tests;