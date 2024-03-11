/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2024 QuestDB
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

//! # Fast Ingestion of data into QuestDB
//!
//! The `ingress` module implements QuestDB's variant of the
//! [InfluxDB Line Protocol](https://questdb.io/docs/reference/api/ilp/overview/)
//! (ILP) over TCP.
//!
//! To get started:
//!   * Connect to QuestDB by creating a [`Sender`] object, usually via [`Sender::from_conf`].
//!   * Populate a [`Buffer`] with one or more rows of data.
//!   * Send the buffer via the Sender's [`flush`](Sender::flush) method.
//!
//! ```rust no_run
//! use questdb::{
//!     Result,
//!     ingress::{
//!         Sender,
//!         Buffer,
//!         TimestampNanos}};
//!
//! fn main() -> Result<()> {
//!    let mut sender = Sender::from_conf("http::addr=localhost:9000;")?;
//!    let mut buffer = Buffer::new();
//!    buffer
//!        .table("sensors")?
//!        .symbol("id", "toronto1")?
//!        .column_f64("temperature", 20.0)?
//!        .column_i64("humidity", 50)?
//!        .at(TimestampNanos::now())?;
//!    sender.flush(&mut buffer)?;
//!    Ok(())
//! }
//! ```
//!
//! # Flushing
//!
//! The Sender's [`flush`](Sender::flush) method will clear the buffer
//! which is then reusable for another batch of rows.
//!
//! Dropping the sender will close the connection to QuestDB and any unflushed
//! messages will be lost: In other words, *do not forget to
//! [`flush`](Sender::flush) before closing the connection!*
//!
//! A common technique is to flush periodically on a timer and/or once the
//! buffer exceeds a certain size.
//! You can check the buffer's size by the calling Buffer's [`len`](Buffer::len)
//! method.
//!
//! Note that flushing will automatically clear the buffer's contents.
//! If you'd rather preserve the contents (for example, to send the same data to
//! multiple QuestDB instances), you can call
//! [`flush_and_keep`](Sender::flush_and_keep) instead.
//!
//! # Connection Security Options
//!
//! To establish an [authenticated](https://questdb.io/docs/reference/api/ilp/authenticate)
//! and TLS-encrypted connection, call the SenderBuilder's authentication and tls methods.
//!
//! Here's an example that uses full security with TCP:
//!
//! ```no_run
//! # use questdb::Result;
//! use questdb::ingress::{Protocol, SenderBuilder};
//!
//! # fn main() -> Result<()> {
//! // See: https://questdb.io/docs/reference/api/ilp/authenticate
//! let mut sender = SenderBuilder::new(Protocol::Tcps, "localhost", 9009)
//!     .username("testUser1")? // kid
//!     .token("5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48")? // d
//!     .token_x("fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU")? // x
//!     .token_y("Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac")? // y
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! Note that Open Source QuestDB does not natively support TLS
//! encryption (this is a QuestDB enterprise feature).
//!
//! To use TLS with QuestDB open source, use a TLS proxy such as
//! [HAProxy](http://www.haproxy.org/).
//!
//! For testing, you can use a self-signed certificate and key.
//!
//! See our notes on [how to generate keys that this library will
//! accept](https://github.com/questdb/c-questdb-client/tree/main/tls_certs).
//!
//! From the API, you can then point to a custom CA file:
//!
//! ```no_run
//! # use questdb::Result;
//! use std::path::PathBuf;
//! use questdb::ingress::{SenderBuilder, Protocol, CertificateAuthority};
//!
//! # fn main() -> Result<()> {
//! let mut sender = SenderBuilder::new(Protocol::Tcps, "localhost", 9009)
//!     .tls_roots("/path/to/server_rootCA.pem")?
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Avoiding revalidating names
//! To avoid re-validating table and column names, consider re-using them across
//! rows.
//!
//! ```
//! # use questdb::Result;
//! use questdb::ingress::{
//!     TableName,
//!     ColumnName,
//!     Buffer,
//!     TimestampNanos};
//!
//! # fn main() -> Result<()> {
//! let mut buffer = Buffer::new();
//! let tide_name = TableName::new("tide")?;
//! let water_level_name = ColumnName::new("water_level")?;
//! buffer.table(tide_name)?.column_f64(water_level_name, 20.4)?.at(TimestampNanos::now())?;
//! buffer.table(tide_name)?.column_f64(water_level_name, 17.2)?.at(TimestampNanos::now())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Buffer API sequential coupling
//!
//! Symbols must always be written before rows. See the [`Buffer`] documentation
//! for details. Each row must be terminated with a call to either
//! [`at`](Buffer::at) or [`at_now`](Buffer::at_now).
//!
//! # Considerations
//!
//! The [Library considerations](https://github.com/questdb/c-questdb-client/blob/main/doc/CONSIDERATIONS.md) documentation
//! goes through:
//!   * Threading.
//!   * Differences between ILP vs QuestDB Data Types.
//!   * Data Quality
//!   * Client-side checks and server errors
//!   * Flushing
//!   * Disconnections, data errors and troubleshooting
//!
//! # Troubleshooting Common Issues
//!
//! ## Infrequent Flushing
//!
//! You may not see data appear in a timely manner because you’re not calling
//! the [`flush`](Sender::flush) method often enough.
//!
//! ## Debugging disconnects and inspecting errors
//!
//! The ILP protocol does not send errors back to the client.
//! Instead, on error, the QuestDB server will disconnect and any error messages
//! will be present in the
//! [server logs](https://questdb.io/docs/troubleshooting/log/).
//!
//! If you want to inspect or log a buffer's contents before it is sent, you
//! can call its [`as_str`](Buffer::as_str) method.
//!

pub use self::timestamp::*;

use crate::error::{self, Error, Result};
use crate::gai;
use crate::ingress::conf::ConfigSetting;
use core::time::Duration;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::{Debug, Display, Formatter, Write};
use std::io::{self, BufRead, BufReader, ErrorKind, Write as IoWrite};
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use rustls::{ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;
use socket2::{Domain, Protocol as SockProtocol, SockAddr, Socket, Type};

#[derive(Debug, Copy, Clone)]
enum Op {
    Table = 1,
    Symbol = 1 << 1,
    Column = 1 << 2,
    At = 1 << 3,
    Flush = 1 << 4,
}

impl Op {
    fn descr(self) -> &'static str {
        match self {
            Op::Table => "table",
            Op::Symbol => "symbol",
            Op::Column => "column",
            Op::At => "at",
            Op::Flush => "flush",
        }
    }
}

fn map_io_to_socket_err(prefix: &str, io_err: io::Error) -> Error {
    error::fmt!(SocketError, "{}{}", prefix, io_err)
}

/// A validated table name.
///
/// This type simply wraps a `&str`.
///
/// You can use it to construct it explicitly to avoid re-validating the same
/// names over and over.
#[derive(Clone, Copy)]
pub struct TableName<'a> {
    name: &'a str,
}

impl<'a> TableName<'a> {
    /// Construct a validated table name.
    pub fn new(name: &'a str) -> Result<Self> {
        if name.is_empty() {
            return Err(error::fmt!(
                InvalidName,
                "Table names must have a non-zero length."
            ));
        }

        let mut prev = '\0';
        for (index, c) in name.chars().enumerate() {
            match c {
                '.' => {
                    if index == 0 || index == name.len() - 1 || prev == '.' {
                        return Err(error::fmt!(
                            InvalidName,
                            concat!("Bad string {:?}: ", "Found invalid dot `.` at position {}."),
                            name,
                            index
                        ));
                    }
                }
                '?' | ',' | '\'' | '\"' | '\\' | '/' | ':' | ')' | '(' | '+' | '*' | '%' | '~'
                | '\r' | '\n' | '\0' | '\u{0001}' | '\u{0002}' | '\u{0003}' | '\u{0004}'
                | '\u{0005}' | '\u{0006}' | '\u{0007}' | '\u{0008}' | '\u{0009}' | '\u{000b}'
                | '\u{000c}' | '\u{000e}' | '\u{000f}' | '\u{007f}' => {
                    return Err(error::fmt!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Table names can't contain ",
                            "a {:?} character, which was found at ",
                            "byte position {}."
                        ),
                        name,
                        c,
                        index
                    ));
                }
                '\u{feff}' => {
                    // Reject unicode char 'ZERO WIDTH NO-BREAK SPACE',
                    // aka UTF-8 BOM if it appears anywhere in the string.
                    return Err(error::fmt!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Table names can't contain ",
                            "a UTF-8 BOM character, which was found at ",
                            "byte position {}."
                        ),
                        name,
                        index
                    ));
                }
                _ => (),
            }
            prev = c;
        }

        Ok(Self { name })
    }

    /// Construct an unvalidated table name.
    ///
    /// This breaks API encapsulation and is only intended for use
    /// when the the string was already previously validated.
    ///
    /// Invalid table names will be rejected by the QuestDB server.
    pub fn new_unchecked(name: &'a str) -> Self {
        Self { name }
    }
}

/// A validated column name.
///
/// This type simply wraps a `&str`.
///
/// You can use it to construct it explicitly to avoid re-validating the same
/// names over and over.
#[derive(Clone, Copy)]
pub struct ColumnName<'a> {
    name: &'a str,
}

impl<'a> ColumnName<'a> {
    /// Construct a validated table name.
    pub fn new(name: &'a str) -> Result<Self> {
        if name.is_empty() {
            return Err(error::fmt!(
                InvalidName,
                "Column names must have a non-zero length."
            ));
        }

        for (index, c) in name.chars().enumerate() {
            match c {
                '?' | '.' | ',' | '\'' | '\"' | '\\' | '/' | ':' | ')' | '(' | '+' | '-' | '*'
                | '%' | '~' | '\r' | '\n' | '\0' | '\u{0001}' | '\u{0002}' | '\u{0003}'
                | '\u{0004}' | '\u{0005}' | '\u{0006}' | '\u{0007}' | '\u{0008}' | '\u{0009}'
                | '\u{000b}' | '\u{000c}' | '\u{000e}' | '\u{000f}' | '\u{007f}' => {
                    return Err(error::fmt!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Column names can't contain ",
                            "a {:?} character, which was found at ",
                            "byte position {}."
                        ),
                        name,
                        c,
                        index
                    ));
                }
                '\u{FEFF}' => {
                    // Reject unicode char 'ZERO WIDTH NO-BREAK SPACE',
                    // aka UTF-8 BOM if it appears anywhere in the string.
                    return Err(error::fmt!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Column names can't contain ",
                            "a UTF-8 BOM character, which was found at ",
                            "byte position {}."
                        ),
                        name,
                        index
                    ));
                }
                _ => (),
            }
        }

        Ok(Self { name })
    }

    /// Construct an unvalidated column name.
    ///
    /// This breaks API encapsulation and is only intended for use
    /// when the the string was already previously validated.
    ///
    /// Invalid column names will be rejected by the QuestDB server.
    pub fn new_unchecked(name: &'a str) -> Self {
        Self { name }
    }
}

impl<'a> TryFrom<&'a str> for TableName<'a> {
    type Error = self::Error;

    fn try_from(name: &'a str) -> Result<Self> {
        Self::new(name)
    }
}

impl<'a> TryFrom<&'a str> for ColumnName<'a> {
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

fn write_escaped_impl<Q, C>(check_escape_fn: C, quoting_fn: Q, output: &mut String, s: &str)
where
    C: Fn(u8) -> bool,
    Q: Fn(&mut Vec<u8>),
{
    let output_vec = unsafe { output.as_mut_vec() };
    let mut to_escape = 0usize;
    for b in s.bytes() {
        if check_escape_fn(b) {
            to_escape += 1;
        }
    }

    quoting_fn(output_vec);

    if to_escape == 0 {
        // output.push_str(s);
        output_vec.extend_from_slice(s.as_bytes());
    } else {
        let additional = s.len() + to_escape;
        output_vec.reserve(additional);
        let mut index = output_vec.len();
        unsafe { output_vec.set_len(index + additional) };
        for b in s.bytes() {
            if check_escape_fn(b) {
                unsafe {
                    *output_vec.get_unchecked_mut(index) = b'\\';
                }
                index += 1;
            }

            unsafe {
                *output_vec.get_unchecked_mut(index) = b;
            }
            index += 1;
        }
    }

    quoting_fn(output_vec);
}

fn must_escape_unquoted(c: u8) -> bool {
    matches!(c, b' ' | b',' | b'=' | b'\n' | b'\r' | b'\\')
}

fn must_escape_quoted(c: u8) -> bool {
    matches!(c, b'\n' | b'\r' | b'"' | b'\\')
}

fn write_escaped_unquoted(output: &mut String, s: &str) {
    write_escaped_impl(must_escape_unquoted, |_output| (), output, s);
}

fn write_escaped_quoted(output: &mut String, s: &str) {
    write_escaped_impl(must_escape_quoted, |output| output.push(b'"'), output, s)
}

enum Connection {
    Direct(Socket),
    Tls(Box<StreamOwned<ClientConnection, Socket>>),
}

impl Connection {
    fn send_key_id(&mut self, key_id: &str) -> Result<()> {
        writeln!(self, "{}", key_id)
            .map_err(|io_err| map_io_to_socket_err("Failed to send key_id: ", io_err))?;
        Ok(())
    }

    fn read_challenge(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut reader = BufReader::new(self);
        reader.read_until(b'\n', &mut buf).map_err(|io_err| {
            map_io_to_socket_err(
                "Failed to read authentication challenge (timed out?): ",
                io_err,
            )
        })?;
        if buf.last().copied().unwrap_or(b'\0') != b'\n' {
            return Err(if buf.is_empty() {
                error::fmt!(
                    AuthError,
                    concat!(
                        "Did not receive auth challenge. ",
                        "Is the database configured to require ",
                        "authentication?"
                    )
                )
            } else {
                error::fmt!(AuthError, "Received incomplete auth challenge: {:?}", buf)
            });
        }
        buf.pop(); // b'\n'
        Ok(buf)
    }

    fn authenticate(&mut self, auth: &EcdsaAuthParams) -> Result<()> {
        if auth.key_id.contains('\n') {
            return Err(error::fmt!(
                AuthError,
                "Bad key id {:?}: Should not contain new-line char.",
                auth.key_id
            ));
        }
        let key_pair = parse_key_pair(auth)?;
        self.send_key_id(auth.key_id.as_str())?;
        let challenge = self.read_challenge()?;
        let rng = SystemRandom::new();
        let signature = key_pair
            .sign(&rng, &challenge[..])
            .map_err(|unspecified_err| {
                error::fmt!(AuthError, "Failed to sign challenge: {}", unspecified_err)
            })?;
        let mut encoded_sig = Base64::encode_string(signature.as_ref());
        encoded_sig.push('\n');
        let buf = encoded_sig.as_bytes();
        if let Err(io_err) = self.write_all(buf) {
            return Err(map_io_to_socket_err(
                "Could not send signed challenge: ",
                io_err,
            ));
        }
        Ok(())
    }
}

enum ProtocolHandler {
    Socket(Connection),

    #[cfg(feature = "ilp-over-http")]
    Http(HttpHandlerState),
}

impl io::Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Direct(sock) => sock.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl io::Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct(sock) => sock.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Direct(sock) => sock.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum OpCase {
    Init = Op::Table as isize,
    TableWritten = Op::Symbol as isize | Op::Column as isize,
    SymbolWritten = Op::Symbol as isize | Op::Column as isize | Op::At as isize,
    ColumnWritten = Op::Column as isize | Op::At as isize,
    MayFlushOrTable = Op::Flush as isize | Op::Table as isize,
}

impl OpCase {
    fn next_op_descr(self) -> &'static str {
        match self {
            OpCase::Init => "should have called `table` instead",
            OpCase::TableWritten => "should have called `symbol` or `column` instead",
            OpCase::SymbolWritten => "should have called `symbol`, `column` or `at` instead",
            OpCase::ColumnWritten => "should have called `column` or `at` instead",
            OpCase::MayFlushOrTable => "should have called `flush` or `table` instead",
        }
    }
}

#[derive(Debug, Clone)]
struct BufferState {
    op_case: OpCase,
    row_count: usize,
    first_table: Option<String>,
    transactional: bool,
}

impl BufferState {
    fn new() -> Self {
        Self {
            op_case: OpCase::Init,
            row_count: 0,
            first_table: None,
            transactional: true,
        }
    }

    fn clear(&mut self) {
        self.op_case = OpCase::Init;
        self.row_count = 0;
        self.first_table = None;
        self.transactional = true;
    }
}

/// A reusable buffer to prepare ILP messages.
///
/// # Example
///
/// ```
/// # use questdb::Result;
/// use questdb::ingress::{Buffer, TimestampMicros, TimestampNanos};
///
/// # fn main() -> Result<()> {
/// let mut buffer = Buffer::new();
///
/// // first row
/// buffer
///     .table("table1")?
///     .symbol("bar", "baz")?
///     .column_bool("a", false)?
///     .column_i64("b", 42)?
///     .column_f64("c", 3.14)?
///     .column_str("d", "hello")?
///     .column_ts("e", TimestampMicros::now())?
///     .at(TimestampNanos::now())?;
///
/// // second row
/// buffer
///     .table("table2")?
///     .symbol("foo", "bar")?
///     .at(TimestampNanos::now())?;
/// # Ok(())
/// # }
/// ```
///
/// The buffer can then be sent with the Sender's [`flush`](Sender::flush)
/// method.
///
/// # Sequential Coupling
/// The Buffer API is sequentially coupled:
///   * A row always starts with [`table`](Buffer::table).
///   * A row must contain at least one [`symbol`](Buffer::symbol) or
///     column (
///       [`column_bool`](Buffer::column_bool),
///       [`column_i64`](Buffer::column_i64),
///       [`column_f64`](Buffer::column_f64),
///       [`column_str`](Buffer::column_str),
///       [`column_ts`](Buffer::column_ts)).
///   * Symbols must always appear before columns.
///   * A row must be terminated with either [`at`](Buffer::at) or
///     [`at_now`](Buffer::at_now).
///
/// This diagram might help:
///
/// <img src="https://raw.githubusercontent.com/questdb/c-questdb-client/main/api_seq/seq.svg">
///
/// # Buffer method calls, Serialized ILP types and QuestDB types
///
/// | Buffer Method | Serialized as ILP type (Click on link to see possible casts) |
/// |---------------|--------------------------------------------------------------|
/// | [`symbol`](Buffer::symbol) | [`SYMBOL`](https://questdb.io/docs/concept/symbol/) |
/// | [`column_bool`](Buffer::column_bool) | [`BOOLEAN`](https://questdb.io/docs/reference/api/ilp/columnset-types#boolean) |
/// | [`column_i64`](Buffer::column_i64) | [`INTEGER`](https://questdb.io/docs/reference/api/ilp/columnset-types#integer) |
/// | [`column_f64`](Buffer::column_f64) | [`FLOAT`](https://questdb.io/docs/reference/api/ilp/columnset-types#float) |
/// | [`column_str`](Buffer::column_str) | [`STRING`](https://questdb.io/docs/reference/api/ilp/columnset-types#string) |
/// | [`column_ts`](Buffer::column_ts) | [`TIMESTAMP`](https://questdb.io/docs/reference/api/ilp/columnset-types#timestamp) |
///
/// QuestDB supports both `STRING` columns and `SYMBOL` column types.
///
/// To understand the difference refer to the
/// [QuestDB documentation](https://questdb.io/docs/concept/symbol/), but in
/// short symbols are interned strings that are most suitable for identifiers
/// that you expect to be repeated throughout the column.
///
/// # Inserting NULL values
///
/// To insert a NULL value, skip the symbol or column for that row.
///
/// # Recovering from validation errors
///
/// If you want to recover from potential validation errors, you can use the
/// [`set_marker`](Buffer::set_marker) method to track a last known good state,
/// append as many rows or parts of rows as you like and then call
/// [`clear_marker`](Buffer::clear_marker) on success.
///
/// If there was an error in one of the table names or other, you can use the
/// [`rewind_to_marker`](Buffer::rewind_to_marker) method to go back to the
/// marked last known good state.
///
#[derive(Debug, Clone)]
pub struct Buffer {
    output: String,
    state: BufferState,
    marker: Option<(usize, BufferState)>,
    max_name_len: usize,
}

impl Buffer {
    /// Construct an instance with a `max_name_len` of `127`,
    /// which is the same as the QuestDB default.
    pub fn new() -> Self {
        Self {
            output: String::new(),
            state: BufferState::new(),
            marker: None,
            max_name_len: 127,
        }
    }

    /// Construct with a custom maximum length for table and column names.
    ///
    /// This should match the `cairo.max.file.name.length` setting of the
    /// QuestDB instance you're connecting to.
    ///
    /// If the server does not configure it the default is `127` and you might
    /// as well call [`new`](Buffer::new).
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

    /// Number of bytes accumulated in the buffer.
    pub fn len(&self) -> usize {
        self.output.len()
    }

    /// The number of rows accumulated in the buffer.
    pub fn row_count(&self) -> usize {
        self.state.row_count
    }

    /// The buffer is transactional if sent over HTTP.
    /// A buffer stops being transactional if it contains rows for multiple tables.
    pub fn transactional(&self) -> bool {
        self.state.transactional
    }

    pub fn is_empty(&self) -> bool {
        self.output.is_empty()
    }

    /// Number of bytes that can be written to the buffer before it needs to
    /// resize.
    pub fn capacity(&self) -> usize {
        self.output.capacity()
    }

    /// Inspect the contents of the buffer.
    pub fn as_str(&self) -> &str {
        &self.output
    }

    /// Mark a rewind point.
    /// This allows undoing accumulated changes to the buffer for one or more
    /// rows by calling [`rewind_to_marker`](Buffer::rewind_to_marker).
    /// Any previous marker will be discarded.
    /// Once the marker is no longer needed, call
    /// [`clear_marker`](Buffer::clear_marker).
    pub fn set_marker(&mut self) -> Result<()> {
        if (self.state.op_case as isize & Op::Table as isize) == 0 {
            return Err(error::fmt!(
                InvalidApiCall,
                concat!(
                    "Can't set the marker whilst constructing a line. ",
                    "A marker may only be set on an empty buffer or after ",
                    "`at` or `at_now` is called."
                )
            ));
        }
        self.marker = Some((self.output.len(), self.state.clone()));
        Ok(())
    }

    /// Undo all changes since the last [`set_marker`](Buffer::set_marker)
    /// call.
    ///
    /// As a side-effect, this also clears the marker.
    pub fn rewind_to_marker(&mut self) -> Result<()> {
        if let Some((position, state)) = self.marker.take() {
            self.output.truncate(position);
            self.state = state;
            Ok(())
        } else {
            Err(error::fmt!(
                InvalidApiCall,
                "Can't rewind to the marker: No marker set."
            ))
        }
    }

    /// Discard any marker as may have been set by
    /// [`set_marker`](Buffer::set_marker).
    ///
    /// Idempotent.
    pub fn clear_marker(&mut self) {
        self.marker = None;
    }

    /// Reset the buffer and clear contents whilst retaining
    /// [`capacity`](Buffer::capacity).
    pub fn clear(&mut self) {
        self.output.clear();
        self.state.clear();
        self.marker = None;
    }

    /// Check if the next API operation is allowed as per the OP case state machine.
    #[inline(always)]
    fn check_op(&self, op: Op) -> Result<()> {
        if (self.state.op_case as isize & op as isize) > 0 {
            Ok(())
        } else {
            Err(error::fmt!(
                InvalidApiCall,
                "State error: Bad call to `{}`, {}.",
                op.descr(),
                self.state.op_case.next_op_descr()
            ))
        }
    }

    #[inline(always)]
    fn validate_max_name_len(&self, name: &str) -> Result<()> {
        if name.len() > self.max_name_len {
            return Err(error::fmt!(
                InvalidName,
                "Bad name: {:?}: Too long (max {} characters)",
                name,
                self.max_name_len
            ));
        }
        Ok(())
    }

    /// Begin recording a row for a given table.
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// buffer.table("table_name")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::TableName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// let table_name = TableName::new("table_name")?;
    /// buffer.table(table_name)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn table<'a, N>(&mut self, name: N) -> Result<&mut Self>
    where
        N: TryInto<TableName<'a>>,
        Error: From<N::Error>,
    {
        let name: TableName<'a> = name.try_into()?;
        self.validate_max_name_len(name.name)?;
        self.check_op(Op::Table)?;
        write_escaped_unquoted(&mut self.output, name.name);
        self.state.op_case = OpCase::TableWritten;

        // A buffer stops being transactional if it targets multiple tables.
        if let Some(first_table) = &self.state.first_table {
            if first_table != name.name {
                self.state.transactional = false;
            }
        } else {
            self.state.first_table = Some(name.name.to_owned());
        }
        Ok(self)
    }

    /// Record a symbol for a given column.
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// buffer.symbol("col_name", "value")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// let value: String = "value".to_owned();
    /// buffer.symbol("col_name", value)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.symbol(col_name, "value")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    pub fn symbol<'a, N, S>(&mut self, name: N, value: S) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.name)?;
        self.check_op(Op::Symbol)?;
        self.output.push(',');
        write_escaped_unquoted(&mut self.output, name.name);
        self.output.push('=');
        write_escaped_unquoted(&mut self.output, value.as_ref());
        self.state.op_case = OpCase::SymbolWritten;
        Ok(self)
    }

    fn write_column_key<'a, N>(&mut self, name: N) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.name)?;
        self.check_op(Op::Column)?;
        self.output
            .push(if (self.state.op_case as isize & Op::Symbol as isize) > 0 {
                ' '
            } else {
                ','
            });
        write_escaped_unquoted(&mut self.output, name.name);
        self.output.push('=');
        self.state.op_case = OpCase::ColumnWritten;
        Ok(self)
    }

    /// Record a boolean value for a column.
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// buffer.column_bool("col_name", true)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.column_bool(col_name, true)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn column_bool<'a, N>(&mut self, name: N, value: bool) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.write_column_key(name)?;
        self.output.push(if value { 't' } else { 'f' });
        Ok(self)
    }

    /// Record an integer value for a column.
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// buffer.column_i64("col_name", 42)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.column_i64(col_name, 42);
    /// # Ok(())
    /// # }
    /// ```
    pub fn column_i64<'a, N>(&mut self, name: N, value: i64) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.write_column_key(name)?;
        let mut buf = itoa::Buffer::new();
        let printed = buf.format(value);
        self.output.push_str(printed);
        self.output.push('i');
        Ok(self)
    }

    /// Record a floating point value for a column.
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// buffer.column_f64("col_name", 3.14)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.column_f64(col_name, 3.14)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn column_f64<'a, N>(&mut self, name: N, value: f64) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.write_column_key(name)?;
        let mut ser = F64Serializer::new(value);
        self.output.push_str(ser.as_str());
        Ok(self)
    }

    /// Record a string value for a column.
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// buffer.column_str("col_name", "value")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// let value: String = "value".to_owned();
    /// buffer.column_str("col_name", value)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.column_str(col_name, "value")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn column_str<'a, N, S>(&mut self, name: N, value: S) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        self.write_column_key(name)?;
        write_escaped_quoted(&mut self.output, value.as_ref());
        Ok(self)
    }

    /// Record a timestamp for a column.
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::TimestampMicros;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// buffer.column_ts("col_name", TimestampMicros::now())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::TimestampMicros;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// buffer.column_ts("col_name", TimestampMicros::new(1659548204354448))?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::TimestampMicros;
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.column_ts(col_name, TimestampMicros::now())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or you can also pass in a `TimestampNanos`.
    ///
    /// Note that both `TimestampMicros` and `TimestampNanos` can be constructed
    /// easily from either `chrono::DateTime` and `std::time::SystemTime`.
    ///
    /// This last option requires the `chrono_timestamp` feature.
    pub fn column_ts<'a, N, T>(&mut self, name: N, value: T) -> Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: TryInto<Timestamp>,
        Error: From<N::Error>,
        Error: From<T::Error>,
    {
        self.write_column_key(name)?;
        let timestamp: Timestamp = value.try_into()?;
        let timestamp: TimestampMicros = timestamp.try_into()?;
        let mut buf = itoa::Buffer::new();
        let printed = buf.format(timestamp.as_i64());
        self.output.push_str(printed);
        self.output.push('t');
        Ok(self)
    }

    /// Terminate the row with a specified timestamp.
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::TimestampNanos;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?.symbol("a", "b")?;
    /// buffer.at(TimestampNanos::now())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// use questdb::ingress::TimestampNanos;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?.symbol("a", "b")?;
    /// buffer.at(TimestampNanos::new(1659548315647406592))?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// You can also pass in a `TimestampMicros`.
    ///
    /// Note that both `TimestampMicros` and `TimestampNanos` can be constructed
    /// easily from either `chrono::DateTime` and `std::time::SystemTime`.
    ///
    pub fn at<T>(&mut self, timestamp: T) -> Result<()>
    where
        T: TryInto<Timestamp>,
        Error: From<T::Error>,
    {
        self.check_op(Op::At)?;
        let timestamp: Timestamp = timestamp.try_into()?;

        // https://github.com/rust-lang/rust/issues/115880
        let timestamp: Result<TimestampNanos> = timestamp.try_into();
        let timestamp: TimestampNanos = timestamp?;

        let epoch_nanos = timestamp.as_i64();
        if epoch_nanos < 0 {
            return Err(error::fmt!(
                InvalidTimestamp,
                "Timestamp {} is negative. It must be >= 0.",
                epoch_nanos
            ));
        }
        let mut buf = itoa::Buffer::new();
        let printed = buf.format(epoch_nanos);
        self.output.push(' ');
        self.output.push_str(printed);
        self.output.push('\n');
        self.state.op_case = OpCase::MayFlushOrTable;
        self.state.row_count += 1;
        Ok(())
    }

    /// Terminate the row with a server-specified timestamp.
    ///
    /// This is NOT equivalent to calling [`at`](Buffer::at) with the current time.
    /// There's a trade-off: Letting the server assign the timestamp can be faster
    /// since it a reliable way to avoid out-of-order operations in the database
    /// for maximum ingestion throughput.
    ///
    /// On the other hand, it removes the ability to deduplicate rows.
    ///
    /// In almost all cases, you should prefer [`at`](Buffer::at) over this method.
    ///
    /// ```
    /// # use questdb::Result;
    /// # use questdb::ingress::Buffer;
    /// # fn main() -> Result<()> {
    /// # let mut buffer = Buffer::new();
    /// # buffer.table("x")?.symbol("a", "b")?;
    /// buffer.at_now()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The QuestDB instance will set the timestamp once it receives the row.
    /// If you're [`flushing`](Sender::flush) infrequently, the timestamp
    /// assigned by the server may drift significantly from when the data
    /// was recorded in the buffer.
    pub fn at_now(&mut self) -> Result<()> {
        self.check_op(Op::At)?;
        self.output.push('\n');
        self.state.op_case = OpCase::MayFlushOrTable;
        self.state.row_count += 1;
        Ok(())
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Connects to a QuestDB instance and inserts data via the ILP protocol.
///
/// * To construct an instance, use [`Sender::from_conf`] or the [`SenderBuilder`].
/// * To prepare messages, use [`Buffer`] objects.
/// * To send messages, call the [`flush`](Sender::flush) method.
pub struct Sender {
    descr: String,
    handler: ProtocolHandler,
    connected: bool,
    max_buf_size: usize,
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.write_str(self.descr.as_str())
    }
}

#[derive(PartialEq, Debug, Clone)]
struct EcdsaAuthParams {
    key_id: String,
    priv_key: String,
    pub_key_x: String,
    pub_key_y: String,
}

#[derive(PartialEq, Debug, Clone)]
enum AuthParams {
    Ecdsa(EcdsaAuthParams),

    #[cfg(feature = "ilp-over-http")]
    Basic(BasicAuthParams),

    #[cfg(feature = "ilp-over-http")]
    Token(TokenAuthParams),
}

/// Possible sources of the root certificates used to validate the server's TLS certificate.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum CertificateAuthority {
    /// Use the root certificates provided by the
    /// [`webpki-roots`](https://crates.io/crates/webpki-roots) crate.
    #[cfg(feature = "tls-webpki-certs")]
    WebpkiRoots,

    /// Use the root certificates provided by the OS
    #[cfg(feature = "tls-native-certs")]
    OsRoots,

    /// Use the root certificates provided by both the OS and the `webpki-roots` crate.
    #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
    WebpkiAndOsRoots,

    /// Use the root certificates provided by a PEM-encoded file.
    PemFile,
}

/// A `u16` port number or `String` port service name as is registered with
/// `/etc/services` or equivalent.
///
/// ```
/// use questdb::ingress::Port;
/// use std::convert::Into;
///
/// let service: Port = 9009.into();
/// ```
///
/// or
///
/// ```
/// use questdb::ingress::Port;
/// use std::convert::Into;
///
/// // Assuming the service name is registered.
/// let service: Port = "qdb_ilp".into();  // or with a String too.
/// ```
pub struct Port(String);

impl From<String> for Port {
    fn from(s: String) -> Self {
        Port(s)
    }
}

impl From<&str> for Port {
    fn from(s: &str) -> Self {
        Port(s.to_owned())
    }
}

impl From<u16> for Port {
    fn from(p: u16) -> Self {
        Port(p.to_string())
    }
}

#[cfg(feature = "insecure-skip-verify")]
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    #[derive(Debug)]
    pub struct NoCertificateVerification {}

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

#[cfg(feature = "tls-webpki-certs")]
fn add_webpki_roots(root_store: &mut RootCertStore) {
    root_store
        .roots
        .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

#[cfg(feature = "tls-native-certs")]
fn add_os_roots(root_store: &mut RootCertStore) -> Result<()> {
    let os_certs = rustls_native_certs::load_native_certs().map_err(|io_err| {
        error::fmt!(
            TlsError,
            "Could not load OS native TLS certificates: {}",
            io_err
        )
    })?;

    let (valid_count, invalid_count) = root_store.add_parsable_certificates(os_certs);
    if valid_count == 0 && invalid_count > 0 {
        return Err(error::fmt!(
            TlsError,
            "No valid certificates found in native root store ({} found but were invalid)",
            invalid_count
        ));
    }
    Ok(())
}

fn configure_tls(
    tls_enabled: bool,
    tls_verify: bool,
    tls_ca: CertificateAuthority,
    tls_roots: &Option<PathBuf>,
) -> Result<Option<Arc<rustls::ClientConfig>>> {
    if !tls_enabled {
        return Ok(None);
    }

    let mut root_store = RootCertStore::empty();
    if tls_verify {
        match (tls_ca, tls_roots) {
            #[cfg(feature = "tls-webpki-certs")]
            (CertificateAuthority::WebpkiRoots, None) => {
                add_webpki_roots(&mut root_store);
            }

            #[cfg(feature = "tls-webpki-certs")]
            (CertificateAuthority::WebpkiRoots, Some(_)) => {
                return Err(error::fmt!(ConfigError, "Config parameter \"tls_roots\" must be unset when \"tls_ca\" is set to \"webpki_roots\"."));
            }

            #[cfg(feature = "tls-native-certs")]
            (CertificateAuthority::OsRoots, None) => {
                add_os_roots(&mut root_store)?;
            }

            #[cfg(feature = "tls-native-certs")]
            (CertificateAuthority::OsRoots, Some(_)) => {
                return Err(error::fmt!(ConfigError, "Config parameter \"tls_roots\" must be unset when \"tls_ca\" is set to \"os_roots\"."));
            }

            #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
            (CertificateAuthority::WebpkiAndOsRoots, None) => {
                add_webpki_roots(&mut root_store);
                add_os_roots(&mut root_store)?;
            }

            #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
            (CertificateAuthority::WebpkiAndOsRoots, Some(_)) => {
                return Err(error::fmt!(ConfigError, "Config parameter \"tls_roots\" must be unset when \"tls_ca\" is set to \"webpki_and_os_roots\"."));
            }

            (CertificateAuthority::PemFile, Some(ca_file)) => {
                let certfile = std::fs::File::open(ca_file).map_err(|io_err| {
                    error::fmt!(
                        TlsError,
                        concat!(
                            "Could not open tls_roots certificate authority ",
                            "file from path {:?}: {}"
                        ),
                        ca_file,
                        io_err
                    )
                })?;
                let mut reader = BufReader::new(certfile);
                let der_certs = rustls_pemfile::certs(&mut reader)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|io_err| {
                        error::fmt!(
                            TlsError,
                            concat!(
                                "Could not read certificate authority ",
                                "file from path {:?}: {}"
                            ),
                            ca_file,
                            io_err
                        )
                    })?;
                root_store.add_parsable_certificates(der_certs);
            }

            (CertificateAuthority::PemFile, None) => {
                return Err(error::fmt!(ConfigError, "Config parameter \"tls_roots\" is required when \"tls_ca\" is set to \"pem_file\"."));
            }
        }
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // TLS log file for debugging.
    // Set the SSLKEYLOGFILE env variable to a writable location.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    #[cfg(feature = "insecure-skip-verify")]
    if !tls_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }

    Ok(Some(Arc::new(config)))
}

fn validate_auto_flush_params(params: &HashMap<String, &String>) -> Result<()> {
    if let Some(&auto_flush) = params.get("auto_flush") {
        if auto_flush.as_str() != "off" {
            return Err(error::fmt!(
                ConfigError,
                "Invalid auto_flush value '{auto_flush}'. This client does not \
                support auto-flush, so the only accepted value is 'off'"
            ));
        }
    }

    for &param in ["auto_flush_rows", "auto_flush_bytes"].iter() {
        if params.contains_key(param) {
            return Err(error::fmt!(
                ConfigError,
                "Invalid configuration parameter {:?}. This client does not support auto-flush",
                param
            ));
        }
    }
    Ok(())
}

/// Protocol used to communicate with the QuestDB server.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Protocol {
    /// ILP over TCP (streaming).
    Tcp,

    /// TCP + TLS
    Tcps,

    #[cfg(feature = "ilp-over-http")]
    /// ILP over HTTP (request-response, InfluxDB-compatible).
    Http,

    #[cfg(feature = "ilp-over-http")]
    /// HTTP + TLS
    Https,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.write_str(self.schema())
    }
}

impl Protocol {
    fn default_port(&self) -> &str {
        match self {
            Protocol::Tcp | Protocol::Tcps => "9009",
            #[cfg(feature = "ilp-over-http")]
            Protocol::Http | Protocol::Https => "9000",
        }
    }

    fn tls_enabled(&self) -> bool {
        match self {
            Protocol::Tcp => false,
            Protocol::Tcps => true,
            #[cfg(feature = "ilp-over-http")]
            Protocol::Http => false,
            #[cfg(feature = "ilp-over-http")]
            Protocol::Https => true,
        }
    }

    fn is_tcpx(&self) -> bool {
        match self {
            Protocol::Tcp => true,
            Protocol::Tcps => true,
            #[cfg(feature = "ilp-over-http")]
            Protocol::Http => false,
            #[cfg(feature = "ilp-over-http")]
            Protocol::Https => false,
        }
    }

    #[cfg(feature = "ilp-over-http")]
    fn is_httpx(&self) -> bool {
        match self {
            Protocol::Tcp => false,
            Protocol::Tcps => false,
            Protocol::Http => true,
            Protocol::Https => true,
        }
    }

    fn schema(&self) -> &str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Tcps => "tcps",
            #[cfg(feature = "ilp-over-http")]
            Protocol::Http => "http",
            #[cfg(feature = "ilp-over-http")]
            Protocol::Https => "https",
        }
    }

    fn from_schema(schema: &str) -> Result<Self> {
        match schema.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "tcps" => Ok(Protocol::Tcps),
            #[cfg(feature = "ilp-over-http")]
            "http" => Ok(Protocol::Http),
            #[cfg(feature = "ilp-over-http")]
            "https" => Ok(Protocol::Https),
            _ => Err(error::fmt!(ConfigError, "Unsupported protocol: {}", schema)),
        }
    }
}

/// Accumulate parameters for a new `Sender` instance.
///
/// The `SenderBuilder` can be created either for ILP/TCP or ILP/HTTP (with the "ilp-over-http"
/// feature enabled).
///
/// It can also be created from a config string or the `QDB_CLIENT_CONF` environment variable.
///
#[cfg_attr(
    feature = "ilp-over-http",
    doc = r##"
```no_run
# use questdb::Result;
use questdb::ingress::{Protocol, SenderBuilder};
# fn main() -> Result<()> {
let mut sender = SenderBuilder::new(Protocol::Http, "localhost", 9009).build()?;
# Ok(())
# }
```
"##
)]
///
/// ```no_run
/// # use questdb::Result;
/// use questdb::ingress::{Protocol, SenderBuilder};
///
/// # fn main() -> Result<()> {
/// let mut sender = SenderBuilder::new(Protocol::Tcp, "localhost", 9009).build()?;
/// # Ok(())
/// # }
/// ```
///
/// ```no_run
/// # use questdb::Result;
/// use questdb::ingress::SenderBuilder;
///
/// # fn main() -> Result<()> {
/// let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
/// # Ok(())
/// # }
/// ```
///
/// ```no_run
/// # use questdb::Result;
/// use questdb::ingress::SenderBuilder;
///
/// # fn main() -> Result<()> {
/// // export QDB_CLIENT_CONF="https::addr=localhost:9000;"
/// let mut sender = SenderBuilder::from_env()?.build()?;
/// # Ok(())
/// # }
/// ```
///
#[derive(Debug, Clone)]
pub struct SenderBuilder {
    protocol: Protocol,
    host: ConfigSetting<String>,
    port: ConfigSetting<String>,
    net_interface: ConfigSetting<Option<String>>,
    max_buf_size: ConfigSetting<usize>,
    auth_timeout: ConfigSetting<Duration>,
    username: ConfigSetting<Option<String>>,
    password: ConfigSetting<Option<String>>,
    token: ConfigSetting<Option<String>>,
    token_x: ConfigSetting<Option<String>>,
    token_y: ConfigSetting<Option<String>>,

    #[cfg(feature = "insecure-skip-verify")]
    tls_verify: ConfigSetting<bool>,

    tls_ca: ConfigSetting<CertificateAuthority>,
    tls_roots: ConfigSetting<Option<PathBuf>>,

    #[cfg(feature = "ilp-over-http")]
    http: Option<HttpConfig>,
}

impl SenderBuilder {
    /// Create a new `SenderBuilder` instance from configuration string.
    ///
    /// The format of the string is: `"http::addr=host:port;key=value;...;"`.
    ///
    /// Alongside `"http"` you can also specify `"https"`, `"tcp"`, and `"tcps"`.
    ///
    /// HTTP is recommended in most cases as is provides better error feedback
    /// allows controlling transactions. TCP can sometimes be faster in higher-latency
    /// networks, but misses out on a number of features.
    ///
    /// The accepted set of keys and values is the same as for the `SenderBuilder`'s API.
    ///
    /// E.g. `"https::addr=host:port;username=alice;password=secret;tls_ca=os_roots;"`.
    ///
    /// If you prefer, you can also load the configuration from an environment variable.
    /// See [`SenderBuilder::from_env`].
    ///
    /// Once a `SenderBuilder` is created from a string (or from the environment variable)
    /// it can be further customized before calling [`SenderBuilder::build`].
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        let conf = conf.as_ref();
        let conf = questdb_confstr::parse_conf_str(conf)
            .map_err(|e| error::fmt!(ConfigError, "Config parse error: {}", e))?;
        let service = conf.service().to_lowercase();
        let params = conf
            .params()
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect::<HashMap<_, _>>();

        let protocol = Protocol::from_schema(service.as_str())?;

        let Some(addr) = params.get("addr") else {
            return Err(error::fmt!(
                ConfigError,
                "Missing \"addr\" parameter in config string"
            ));
        };
        let (host, port) = match addr.split_once(':') {
            Some((h, p)) => (h, p),
            None => (addr.as_str(), protocol.default_port()),
        };
        let mut builder = SenderBuilder::new(protocol, host, port);

        validate_auto_flush_params(&params)?;

        for (key, val) in params.iter().map(|(k, v)| (k.as_str(), v.as_str())) {
            builder = match key {
                "username" => builder.username(val)?,
                "password" => builder.password(val)?,
                "token" => builder.token(val)?,
                "token_x" => builder.token_x(val)?,
                "token_y" => builder.token_y(val)?,
                "bind_interface" => builder.bind_interface(val)?,

                "init_buf_size" => {
                    return Err(error::fmt!(
                        ConfigError,
                        "\"init_buf_size\" is not supported in config string"
                    ))
                }

                "max_buf_size" => builder.max_buf_size(parse_conf_value(key, val)?)?,

                "auth_timeout" => {
                    builder.auth_timeout(Duration::from_millis(parse_conf_value(key, val)?))?
                }

                "tls_verify" => {
                    let verify = match val {
                        "on" => true,
                        "unsafe_off" => false,
                        _ => {
                            return Err(error::fmt!(
                                ConfigError,
                                r##"Config parameter "tls_verify" must be either "on" or "unsafe_off".'"##,
                            ))
                        }
                    };

                    #[cfg(not(feature = "insecure-skip-verify"))]
                    {
                        if !verify {
                            return Err(error::fmt!(
                                ConfigError,
                                r##"The "insecure-skip-verify" feature is not enabled, so "tls_verify=unsafe_off" is not supported"##,
                            ));
                        }
                        builder
                    }

                    #[cfg(feature = "insecure-skip-verify")]
                    builder.tls_verify(verify)?
                }

                "tls_ca" => {
                    let ca = match val {
                        #[cfg(feature = "tls-webpki-certs")]
                        "webpki_roots" => CertificateAuthority::WebpkiRoots,

                        #[cfg(not(feature = "tls-webpki-certs"))]
                        "webpki_roots" => return Err(error::fmt!(ConfigError, "Config parameter \"tls_ca=webpki_roots\" requires the \"tls-webpki-certs\" feature")),

                        #[cfg(feature = "tls-native-certs")]
                        "os_roots" => CertificateAuthority::OsRoots,

                        #[cfg(not(feature = "tls-native-certs"))]
                        "os_roots" => return Err(error::fmt!(ConfigError, "Config parameter \"tls_ca=os_roots\" requires the \"tls-native-certs\" feature")),

                        #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
                        "webpki_and_os_roots" => CertificateAuthority::WebpkiAndOsRoots,

                        #[cfg(not(all(feature = "tls-webpki-certs", feature = "tls-native-certs")))]
                        "webpki_and_os_roots" => return Err(error::fmt!(ConfigError, "Config parameter \"tls_ca=webpki_and_os_roots\" requires both the \"tls-webpki-certs\" and \"tls-native-certs\" features")),

                        _ => return Err(error::fmt!(ConfigError, "Invalid value {val:?} for \"tls_ca\"")),
                    };
                    builder.tls_ca(ca)?
                }

                "tls_roots" => {
                    let path = PathBuf::from_str(val).map_err(|e| {
                        error::fmt!(
                            ConfigError,
                            "Invalid path {:?} for \"tls_roots\": {}",
                            val,
                            e
                        )
                    })?;
                    builder.tls_roots(path)?
                }

                "tls_roots_password" => {
                    return Err(error::fmt!(
                        ConfigError,
                        "\"tls_roots_password\" is not supported."
                    ))
                }

                #[cfg(feature = "ilp-over-http")]
                "request_min_throughput" => {
                    builder.request_min_throughput(parse_conf_value(key, val)?)?
                }

                #[cfg(feature = "ilp-over-http")]
                "request_timeout" => {
                    builder.request_timeout(Duration::from_millis(parse_conf_value(key, val)?))?
                }

                #[cfg(feature = "ilp-over-http")]
                "retry_timeout" => {
                    builder.retry_timeout(Duration::from_millis(parse_conf_value(key, val)?))?
                }
                // Ignore other parameters.
                // We don't want to fail on unknown keys as this would require releasing different
                // library implementations in lock step as soon as a new parameter is added to any of them,
                // even if it's not used.
                _ => builder,
            };
        }

        Ok(builder)
    }

    /// Create a new `SenderBuilder` instance from configuration string read from the
    /// `QDB_CLIENT_CONF` environment variable.
    ///
    /// The format of the string is the same as for [`SenderBuilder::from_conf`].
    pub fn from_env() -> Result<Self> {
        let conf = std::env::var("QDB_CLIENT_CONF").map_err(|_| {
            error::fmt!(ConfigError, "Environment variable QDB_CLIENT_CONF not set.")
        })?;
        Self::from_conf(conf)
    }

    /// Create a new `SenderBuilder` instance from the provided QuestDB
    /// server and port using ILP over the specified protocol.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// use questdb::ingress::{Protocol, SenderBuilder};
    ///
    /// # fn main() -> Result<()> {
    /// let mut sender = SenderBuilder::new(
    ///     Protocol::Tcp, "localhost", 9009).build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<H: Into<String>, P: Into<Port>>(protocol: Protocol, host: H, port: P) -> Self {
        let host = host.into();
        let port: Port = port.into();
        let port = port.0;

        #[cfg(feature = "tls-webpki-certs")]
        let tls_ca = CertificateAuthority::WebpkiRoots;

        #[cfg(all(not(feature = "tls-webpki-certs"), feature = "tls-native-certs"))]
        let tls_ca = CertificateAuthority::OsRoots;

        #[cfg(not(any(feature = "tls-webpki-certs", feature = "tls-native-certs")))]
        let tls_ca = CertificateAuthority::PemFile;

        Self {
            protocol,
            host: ConfigSetting::new_specified(host),
            port: ConfigSetting::new_specified(port),
            net_interface: ConfigSetting::new_default(None),
            max_buf_size: ConfigSetting::new_default(100 * 1024 * 1024),
            auth_timeout: ConfigSetting::new_default(Duration::from_secs(15)),
            username: ConfigSetting::new_default(None),
            password: ConfigSetting::new_default(None),
            token: ConfigSetting::new_default(None),
            token_x: ConfigSetting::new_default(None),
            token_y: ConfigSetting::new_default(None),

            #[cfg(feature = "insecure-skip-verify")]
            tls_verify: ConfigSetting::new_default(true),

            tls_ca: ConfigSetting::new_default(tls_ca),
            tls_roots: ConfigSetting::new_default(None),

            #[cfg(feature = "ilp-over-http")]
            http: if protocol.is_httpx() {
                Some(HttpConfig::default())
            } else {
                None
            },
        }
    }

    /// Select local outbound interface.
    ///
    /// This may be relevant if your machine has multiple network interfaces.
    ///
    /// The default is `"0.0.0.0"`.
    pub fn bind_interface<I: Into<String>>(mut self, addr: I) -> Result<Self> {
        self.ensure_is_tcpx("bind_interface")?;
        self.net_interface
            .set_specified("bind_interface", Some(validate_value(addr.into())?))?;
        Ok(self)
    }

    /// Set the username for authentication.
    ///
    /// For TCP this is the `kid` part of the ECDSA key set.
    /// The other fields are [`token`](SenderBuilder::token), [`token_x`](SenderBuilder::token_x),
    /// and [`token_y`](SenderBuilder::token_y).
    ///
    /// For HTTP this is part of basic authentication.
    /// Also see [`password`](SenderBuilder::password).
    pub fn username(mut self, username: &str) -> Result<Self> {
        self.username
            .set_specified("username", Some(validate_value(username.to_string())?))?;
        Ok(self)
    }

    /// Set the password for basic HTTP authentication.
    /// Also see [`username`](SenderBuilder::username).
    pub fn password(mut self, password: &str) -> Result<Self> {
        self.password
            .set_specified("password", Some(validate_value(password.to_string())?))?;
        Ok(self)
    }

    /// Token (Bearer) Authentication Parameters for ILP over HTTP,
    /// or the ECDSA private key for ILP over TCP authentication.
    pub fn token(mut self, token: &str) -> Result<Self> {
        self.token
            .set_specified("token", Some(validate_value(token.to_string())?))?;
        Ok(self)
    }

    /// The ECDSA public key X for ILP over TCP authentication.
    pub fn token_x(mut self, token_x: &str) -> Result<Self> {
        self.token_x
            .set_specified("token_x", Some(validate_value(token_x.to_string())?))?;
        Ok(self)
    }

    /// The ECDSA public key Y for ILP over TCP authentication.
    pub fn token_y(mut self, token_y: &str) -> Result<Self> {
        self.token_y
            .set_specified("token_y", Some(validate_value(token_y.to_string())?))?;
        Ok(self)
    }

    /// Configure how long to wait for messages from the QuestDB server during
    /// the TLS handshake and authentication process.
    /// The default is 15 seconds.
    pub fn auth_timeout(mut self, value: Duration) -> Result<Self> {
        self.auth_timeout.set_specified("auth_timeout", value)?;
        Ok(self)
    }

    /// Ensure that TLS is enabled for the protocol.
    pub fn ensure_tls_enabled(&self, property: &str) -> Result<()> {
        if !self.protocol.tls_enabled() {
            return Err(error::fmt!(
                ConfigError,
                "Cannot set {property:?}: TLS is not supported for protocol {}",
                self.protocol
            ));
        }
        Ok(())
    }

    /// Set to `false` to disable TLS certificate verification.
    /// This should only be used for debugging purposes as it reduces security.
    ///
    /// For testing consider specifying a path to a `.pem` file instead via
    /// the [`tls_roots`](SenderBuilder::tls_roots) method.
    #[cfg(feature = "insecure-skip-verify")]
    pub fn tls_verify(mut self, verify: bool) -> Result<Self> {
        self.ensure_tls_enabled("tls_verify")?;
        self.tls_verify.set_specified("tls_verify", verify)?;
        Ok(self)
    }

    /// Specify where to find the root certificate used to validate the
    /// server's TLS certificate.
    pub fn tls_ca(mut self, ca: CertificateAuthority) -> Result<Self> {
        self.ensure_tls_enabled("tls_ca")?;
        self.tls_ca.set_specified("tls_ca", ca)?;
        Ok(self)
    }

    /// Set the path to a custom root certificate `.pem` file.
    /// This is used to validate the server's certificate during the TLS handshake.
    ///
    /// See notes on how to test with [self-signed certificates](https://github.com/questdb/c-questdb-client/tree/main/tls_certs).
    pub fn tls_roots<P: Into<PathBuf>>(self, path: P) -> Result<Self> {
        let mut builder = self.tls_ca(CertificateAuthority::PemFile)?;
        let path = path.into();
        // Attempt to read the file here to catch any issues early.
        let _file = std::fs::File::open(&path).map_err(|io_err| {
            error::fmt!(
                ConfigError,
                "Could not open root certificate file from path {:?}: {}",
                path,
                io_err
            )
        })?;
        builder.tls_roots.set_specified("tls_roots", Some(path))?;
        Ok(builder)
    }

    /// The maximum buffer size that the client will flush to the server.
    /// The default is 100 MiB.
    pub fn max_buf_size(mut self, value: usize) -> Result<Self> {
        let min = 1024;
        if value < min {
            return Err(error::fmt!(
                ConfigError,
                "max_buf_size\" must be at least {min} bytes."
            ));
        }
        self.max_buf_size.set_specified("max_buf_size", value)?;
        Ok(self)
    }

    #[cfg(feature = "ilp-over-http")]
    /// Cumulative duration spent in retries.
    /// The default is 10 seconds.
    pub fn retry_timeout(mut self, value: Duration) -> Result<Self> {
        if let Some(http) = &mut self.http {
            http.retry_timeout.set_specified("retry_timeout", value)?;
        } else {
            return Err(error::fmt!(
                ConfigError,
                "retry_timeout is supported only in ILP over HTTP."
            ));
        }
        Ok(self)
    }

    #[cfg(feature = "ilp-over-http")]
    /// Minimum expected throughput in bytes per second for HTTP requests.
    /// If the throughput is lower than this value, the connection will time out.
    /// The default is 100 KiB/s.
    /// The value is expressed as a number of bytes per second.
    /// This is used to calculate additional request timeout, on top of
    /// the [`request_timeout`](SenderBuilder::request_timeout).
    pub fn request_min_throughput(mut self, value: u64) -> Result<Self> {
        if let Some(http) = &mut self.http {
            http.request_min_throughput
                .set_specified("request_min_throughput", value)?;
        } else {
            return Err(error::fmt!(
                ConfigError,
                "\"request_min_throughput\" is supported only in ILP over HTTP."
            ));
        }
        Ok(self)
    }

    #[cfg(feature = "ilp-over-http")]
    /// Grace request timeout before relying on the minimum throughput logic.
    /// The default is 10 seconds.
    /// See [`request_min_throughput`](SenderBuilder::request_min_throughput) for more details.
    pub fn request_timeout(mut self, value: Duration) -> Result<Self> {
        if let Some(http) = &mut self.http {
            http.request_timeout
                .set_specified("request_timeout", value)?;
        } else {
            return Err(error::fmt!(
                ConfigError,
                "\"request_timeout\" is supported only in ILP over HTTP."
            ));
        }
        Ok(self)
    }

    #[cfg(feature = "ilp-over-http")]
    /// Internal API, do not use.
    /// This is exposed exclusively for the Python client.
    /// We (QuestDB) use this to help us debug which client is being used if we encounter issues.
    #[doc(hidden)]
    pub fn user_agent(mut self, value: &str) -> Result<Self> {
        let value = validate_value(value)?;
        if let Some(http) = &mut self.http {
            http.user_agent = value.to_string();
        }
        Ok(self)
    }

    fn connect_tcp(&self, auth: &Option<AuthParams>) -> Result<ProtocolHandler> {
        let addr: SockAddr = gai::resolve_host_port(self.host.as_str(), self.port.as_str())?;
        let mut sock = Socket::new(Domain::IPV4, Type::STREAM, Some(SockProtocol::TCP))
            .map_err(|io_err| map_io_to_socket_err("Could not open TCP socket: ", io_err))?;

        // See: https://idea.popcount.org/2014-04-03-bind-before-connect/
        // We set `SO_REUSEADDR` on the outbound socket to avoid issues where a client may exhaust
        // their interface's ports. See: https://github.com/questdb/py-questdb-client/issues/21
        sock.set_reuse_address(true)
            .map_err(|io_err| map_io_to_socket_err("Could not set SO_REUSEADDR: ", io_err))?;

        sock.set_linger(Some(Duration::from_secs(120)))
            .map_err(|io_err| map_io_to_socket_err("Could not set socket linger: ", io_err))?;
        sock.set_keepalive(true)
            .map_err(|io_err| map_io_to_socket_err("Could not set SO_KEEPALIVE: ", io_err))?;
        sock.set_nodelay(true)
            .map_err(|io_err| map_io_to_socket_err("Could not set TCP_NODELAY: ", io_err))?;
        if let Some(ref host) = self.net_interface.deref() {
            let bind_addr = gai::resolve_host(host.as_str())?;
            sock.bind(&bind_addr).map_err(|io_err| {
                map_io_to_socket_err(
                    &format!("Could not bind to interface address {:?}: ", host),
                    io_err,
                )
            })?;
        }
        sock.connect(&addr).map_err(|io_err| {
            let host_port = format!("{}:{}", self.host.deref(), *self.port);
            let prefix = format!("Could not connect to {:?}: ", host_port);
            map_io_to_socket_err(&prefix, io_err)
        })?;

        // We read during both TLS handshake and authentication.
        // We set up a read timeout to prevent the client from "hanging"
        // should we be connecting to a server configured in a different way
        // from the client.
        sock.set_read_timeout(Some(*self.auth_timeout))
            .map_err(|io_err| {
                map_io_to_socket_err("Failed to set read timeout on socket: ", io_err)
            })?;

        #[cfg(feature = "insecure-skip-verify")]
        let tls_verify = *self.tls_verify;

        #[cfg(not(feature = "insecure-skip-verify"))]
        let tls_verify = true;

        let mut conn = match configure_tls(
            self.protocol.tls_enabled(),
            tls_verify,
            *self.tls_ca,
            self.tls_roots.deref(),
        )? {
            Some(tls_config) => {
                let server_name: ServerName = ServerName::try_from(self.host.as_str())
                    .map_err(|inv_dns_err| error::fmt!(TlsError, "Bad host: {}", inv_dns_err))?
                    .to_owned();
                let mut tls_conn =
                    ClientConnection::new(tls_config, server_name).map_err(|rustls_err| {
                        error::fmt!(TlsError, "Could not create TLS client: {}", rustls_err)
                    })?;
                while tls_conn.wants_write() || tls_conn.is_handshaking() {
                    tls_conn.complete_io(&mut sock).map_err(|io_err| {
                        if (io_err.kind() == ErrorKind::TimedOut)
                            || (io_err.kind() == ErrorKind::WouldBlock)
                        {
                            error::fmt!(
                                TlsError,
                                concat!(
                                    "Failed to complete TLS handshake:",
                                    " Timed out waiting for server ",
                                    "response after {:?}."
                                ),
                                *self.auth_timeout
                            )
                        } else {
                            error::fmt!(TlsError, "Failed to complete TLS handshake: {}", io_err)
                        }
                    })?;
                }
                Connection::Tls(StreamOwned::new(tls_conn, sock).into())
            }
            None => Connection::Direct(sock),
        };

        if let Some(AuthParams::Ecdsa(auth)) = auth {
            conn.authenticate(auth)?;
        }

        Ok(ProtocolHandler::Socket(conn))
    }

    fn build_auth(&self) -> Result<Option<AuthParams>> {
        match (
            self.protocol,
            self.username.deref(),
            self.password.deref(),
            self.token.deref(),
            self.token_x.deref(),
            self.token_y.deref(),
        ) {
            (_, None, None, None, None, None) => Ok(None),
            (
                protocol,
                Some(username),
                None,
                Some(token),
                Some(token_x),
                Some(token_y),
            ) if protocol.is_tcpx() => Ok(Some(AuthParams::Ecdsa(EcdsaAuthParams {
                key_id: username.to_string(),
                priv_key: token.to_string(),
                pub_key_x: token_x.to_string(),
                pub_key_y: token_y.to_string(),
            }))),
            (protocol, Some(_username), Some(_password), None, None, None)
                if protocol.is_tcpx() => {
                Err(error::fmt!(ConfigError,
                    r##"The "basic_auth" setting can only be used with the ILP/HTTP protocol."##,
                ))
            }
            (protocol, None, None, Some(_token), None, None)
                if protocol.is_tcpx() => {
                Err(error::fmt!(ConfigError, "Token authentication only be used with the ILP/HTTP protocol."))
            }
            (protocol, _username, None, _token, _token_x, _token_y)
                if protocol.is_tcpx() => {
                Err(error::fmt!(ConfigError,
                    r##"Incomplete ECDSA authentication parameters. Specify either all or none of: "username", "token", "token_x", "token_y"."##,
                ))
            }
            #[cfg(feature = "ilp-over-http")]
            (protocol, Some(username), Some(password), None, None, None)
                if protocol.is_httpx() => {
                Ok(Some(AuthParams::Basic(BasicAuthParams {
                    username: username.to_string(),
                    password: password.to_string(),
                })))
            }
            #[cfg(feature = "ilp-over-http")]
            (protocol, Some(_username), None, None, None, None)
                if protocol.is_httpx() => {
                Err(error::fmt!(ConfigError,
                    r##"Basic authentication parameter "username" is present, but "password" is missing."##,
                ))
            }
            #[cfg(feature = "ilp-over-http")]
            (protocol, None, Some(_password), None, None, None)
                if protocol.is_httpx() => {
                Err(error::fmt!(ConfigError,
                    r##"Basic authentication parameter "password" is present, but "username" is missing."##,
                ))
            }
            #[cfg(feature = "ilp-over-http")]
            (protocol, None, None, Some(token), None, None)
                if protocol.is_httpx() => {
                Ok(Some(AuthParams::Token(TokenAuthParams {
                    token: token.to_string(),
                })))
            }
            #[cfg(feature = "ilp-over-http")]
            (
                protocol,
                Some(_username),
                None,
                Some(_token),
                Some(_token_x),
                Some(_token_y),
            ) if protocol.is_httpx() => {
                Err(error::fmt!(ConfigError, "ECDSA authentication is only available with ILP/TCP and not available with ILP/HTTP."))
            }
            #[cfg(feature = "ilp-over-http")]
            (protocol, _username, _password, _token, None, None)
                if protocol.is_httpx() => {
                Err(error::fmt!(ConfigError,
                    r##"Inconsistent HTTP authentication parameters. Specify either "username" and "password", or just "token"."##,
                ))
            }
            _ => {
                Err(error::fmt!(ConfigError,
                    r##"Incomplete authentication parameters. Check "username", "password", "token", "token_x" and "token_y" parameters are set correctly."##,
                ))
            }
        }
    }

    /// Build the sender.
    ///
    /// In case of TCP, this synchronously establishes the TCP connection, and
    /// returns once the connection is fully established. If the connection
    /// requires authentication or TLS, these will also be completed before
    /// returning.
    pub fn build(&self) -> Result<Sender> {
        let mut descr = format!("Sender[host={:?},port={:?},", self.host, self.port);

        if self.protocol.tls_enabled() {
            write!(descr, "tls=enabled,").unwrap();
        } else {
            write!(descr, "tls=disabled,").unwrap();
        }

        let auth = self.build_auth()?;

        let handler = match self.protocol {
            Protocol::Tcp | Protocol::Tcps => self.connect_tcp(&auth)?,
            #[cfg(feature = "ilp-over-http")]
            Protocol::Http | Protocol::Https => {
                if self.net_interface.is_some() {
                    // See: https://github.com/algesten/ureq/issues/692
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "net_interface is not supported for ILP over HTTP."
                    ));
                }

                let user_agent = self.http.as_ref().unwrap().user_agent.as_str();
                let agent_builder = ureq::AgentBuilder::new()
                    .user_agent(user_agent)
                    .no_delay(true);

                #[cfg(feature = "insecure-skip-verify")]
                let tls_verify = *self.tls_verify;

                #[cfg(not(feature = "insecure-skip-verify"))]
                let tls_verify = true;

                let agent_builder = match configure_tls(
                    self.protocol.tls_enabled(),
                    tls_verify,
                    *self.tls_ca,
                    self.tls_roots.deref(),
                )? {
                    Some(tls_config) => agent_builder.tls_config(tls_config),
                    None => agent_builder,
                };
                let auth = match auth {
                    Some(AuthParams::Basic(ref auth)) => Some(auth.to_header_string()),
                    Some(AuthParams::Token(ref auth)) => Some(auth.to_header_string()?),
                    Some(AuthParams::Ecdsa(_)) => {
                        return Err(error::fmt!(
                            AuthError,
                            "ECDSA authentication is not supported for ILP over HTTP. \
                            Please use basic or token authentication instead."
                        ));
                    }
                    None => None,
                };
                let agent = agent_builder.build();
                let proto = self.protocol.schema();
                let url = format!(
                    "{}://{}:{}/write",
                    proto,
                    self.host.deref(),
                    self.port.deref()
                );
                ProtocolHandler::Http(HttpHandlerState {
                    agent,
                    url,
                    auth,

                    config: self.http.as_ref().unwrap().clone(),
                })
            }
        };

        if auth.is_some() {
            descr.push_str("auth=on]");
        } else {
            descr.push_str("auth=off]");
        }

        let sender = Sender {
            descr,
            handler,
            connected: true,
            max_buf_size: *self.max_buf_size,
        };

        Ok(sender)
    }

    fn ensure_is_tcpx(&mut self, param_name: &str) -> Result<()> {
        if self.protocol.is_tcpx() {
            Ok(())
        } else {
            Err(error::fmt!(
                ConfigError,
                "The {param_name:?} setting can only be used with the TCP protocol."
            ))
        }
    }
}

/// When parsing from config, we exclude certain characters.
/// Here we repeat the same validation logic for consistency.
fn validate_value<T: AsRef<str>>(value: T) -> Result<T> {
    let str_ref = value.as_ref();
    for (p, c) in str_ref.chars().enumerate() {
        if matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}') {
            return Err(error::fmt!(
                ConfigError,
                "Invalid character {c:?} at position {p}"
            ));
        }
    }
    Ok(value)
}

fn parse_conf_value<T>(param_name: &str, str_value: &str) -> Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Debug,
{
    str_value.parse().map_err(|e| {
        error::fmt!(
            ConfigError,
            "Could not parse {param_name:?} to number: {e:?}"
        )
    })
}

fn b64_decode(descr: &'static str, buf: &str) -> Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(buf).map_err(|b64_err| {
        error::fmt!(
            AuthError,
            "Misconfigured ILP authentication keys. Could not decode {}: {}. \
            Hint: Check the keys for a possible typo.",
            descr,
            b64_err
        )
    })
}

fn parse_public_key(pub_key_x: &str, pub_key_y: &str) -> Result<Vec<u8>> {
    let mut pub_key_x = b64_decode("public key x", pub_key_x)?;
    let mut pub_key_y = b64_decode("public key y", pub_key_y)?;

    // SEC 1 Uncompressed Octet-String-to-Elliptic-Curve-Point Encoding
    let mut encoded = Vec::new();
    encoded.push(4u8); // 0x04 magic byte that identifies this as uncompressed.
    let pub_key_x_ken = pub_key_x.len();
    if pub_key_x_ken > 32 {
        return Err(error::fmt!(
            AuthError,
            "Misconfigured ILP authentication keys. Public key x is too long. \
            Hint: Check the keys for a possible typo."
        ));
    }
    let pub_key_y_len = pub_key_y.len();
    if pub_key_y_len > 32 {
        return Err(error::fmt!(
            AuthError,
            "Misconfigured ILP authentication keys. Public key y is too long. \
            Hint: Check the keys for a possible typo."
        ));
    }
    encoded.resize((32 - pub_key_x_ken) + 1, 0u8);
    encoded.append(&mut pub_key_x);
    encoded.resize((32 - pub_key_y_len) + 1 + 32, 0u8);
    encoded.append(&mut pub_key_y);
    Ok(encoded)
}

fn parse_key_pair(auth: &EcdsaAuthParams) -> Result<EcdsaKeyPair> {
    let private_key = b64_decode("private authentication key", auth.priv_key.as_str())?;
    let public_key = parse_public_key(auth.pub_key_x.as_str(), auth.pub_key_y.as_str())?;
    let system_random = SystemRandom::new();
    EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &private_key[..],
        &public_key[..],
        &system_random,
    )
    .map_err(|key_rejected| {
        error::fmt!(
            AuthError,
            "Misconfigured ILP authentication keys: {}. Hint: Check the keys for a possible typo.",
            key_rejected
        )
    })
}

pub(crate) struct F64Serializer {
    buf: ryu::Buffer,
    n: f64,
}

impl F64Serializer {
    pub(crate) fn new(n: f64) -> Self {
        F64Serializer {
            buf: ryu::Buffer::new(),
            n,
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

    pub(crate) fn as_str(&mut self) -> &str {
        if self.n.is_finite() {
            self.buf.format_finite(self.n)
        } else {
            self.format_nonfinite()
        }
    }
}

impl Sender {
    /// Create a new `Sender` instance from configuration string.
    ///
    /// The format of the string is: `"http::addr=host:port;key=value;...;"`.
    ///
    /// Alongside `"http"` you can also specify `"https"`, `"tcp"`, and `"tcps"`.
    ///
    /// HTTP is recommended in most cases as is provides better error feedback
    /// allows controlling transactions. TCP can sometimes be faster in higher-latency
    /// networks, but misses out on a number of features.
    ///
    /// The accepted set of keys and values is the same as for the opt's API.
    ///
    /// E.g. `"https::addr=host:port;username=alice;password=secret;tls_ca=os_roots;"`.
    ///
    /// For full list of keys and values, see the [`SenderBuilder`] documentation:
    /// The builder API and the configuration string API are equivalent.
    ///
    /// If you prefer, you can also load the configuration from an environment variable.
    /// See [`Sender::from_env`].
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        SenderBuilder::from_conf(conf)?.build()
    }

    /// Create a new `Sender` from the `QDB_CLIENT_CONF` environment variable.
    /// The format is the same as that taken by [`Sender::from_conf`].
    pub fn from_env() -> Result<Self> {
        SenderBuilder::from_env()?.build()
    }

    #[allow(unused_variables)]
    fn flush_impl(&mut self, buf: &Buffer, transactional: bool) -> Result<()> {
        if !self.connected {
            return Err(error::fmt!(
                SocketError,
                "Could not flush buffer: not connected to database."
            ));
        }
        buf.check_op(Op::Flush)?;

        if buf.len() > self.max_buf_size {
            return Err(error::fmt!(
                InvalidApiCall,
                "Could not flush buffer: Buffer size of {} exceeds maximum configured allowed size of {} bytes.",
                buf.len(),
                self.max_buf_size
            ));
        }

        let bytes = buf.as_str().as_bytes();
        if bytes.is_empty() {
            return Ok(());
        }
        match self.handler {
            ProtocolHandler::Socket(ref mut conn) => {
                if transactional {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "Transactional flushes are not supported for ILP over TCP."
                    ));
                }
                conn.write_all(bytes).map_err(|io_err| {
                    self.connected = false;
                    map_io_to_socket_err("Could not flush buffer: ", io_err)
                })?;
            }
            #[cfg(feature = "ilp-over-http")]
            ProtocolHandler::Http(ref state) => {
                if transactional && !buf.transactional() {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "Buffer contains lines for multiple tables. \
                        Transactional flushes are only supported for buffers containing lines for a single table."
                    ));
                }
                let timeout = Duration::from_secs_f64(
                    (bytes.len() as f64) / (*state.config.request_min_throughput as f64),
                ) + *state.config.request_timeout;
                let request = state
                    .agent
                    .post(&state.url)
                    .query_pairs([("precision", "n")])
                    .timeout(timeout)
                    .set("Content-Type", "text/plain; charset=utf-8");
                let request = match state.auth.as_ref() {
                    Some(auth) => request.set("Authorization", auth),
                    None => request,
                };
                let response_or_err =
                    http_send_with_retries(request, bytes, *state.config.retry_timeout);
                match response_or_err {
                    Ok(_response) => {
                        // on success, there's no information in the response.
                    }
                    Err(ureq::Error::Status(http_status_code, response)) => {
                        return Err(parse_http_error(http_status_code, response));
                    }
                    Err(ureq::Error::Transport(transport)) => {
                        return Err(error::fmt!(
                            SocketError,
                            "Could not flush buffer: {}",
                            transport
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Variant of `.flush()` that does not clear the buffer and allows for
    /// transactional flushes.
    ///
    /// A transactional flush is simply a flush that ensures that all rows in
    /// the ILP buffer refer to the same table, thus allowing the server to
    /// treat the flush request as a single transaction.
    ///
    /// This is because QuestDB does not support transactions spanning multiple
    /// tables.
    ///
    /// Note that transactional flushes are only supported for ILP over HTTP.
    #[cfg(feature = "ilp-over-http")]
    pub fn flush_and_keep_with_flags(&mut self, buf: &Buffer, transactional: bool) -> Result<()> {
        self.flush_impl(buf, transactional)
    }

    /// Variant of `.flush()` that does not clear the buffer.
    pub fn flush_and_keep(&mut self, buf: &Buffer) -> Result<()> {
        self.flush_impl(buf, false)
    }

    /// Send buffer to the QuestDB server, clearing the buffer.
    ///
    /// If sending over HTTP, flushing will send an HTTP request and wait
    /// for the response. If the server responds with an error, this function
    /// will return a descriptive error. In case of network errors,
    /// this function will retry.
    ///
    /// If sending over TCP, this will block until the buffer is flushed to the
    /// network socket. Note that this does not guarantee that the buffer will
    /// be sent to the server or that the server has received it.
    /// In case of errors the server will disconnect: consult the server logs.
    ///
    /// Prefer HTTP in most cases, but use TCP if you need to continuously
    /// data to the server at a high rate.
    ///
    /// To improve HTTP performance, send larger buffers (with more rows),
    /// and consider parallelizing writes using multiple senders from multiple
    /// threads.
    pub fn flush(&mut self, buf: &mut Buffer) -> Result<()> {
        self.flush_impl(buf, false)?;
        buf.clear();
        Ok(())
    }

    /// The sender is no longer usable and must be dropped.
    ///
    /// This is caused if there was an earlier failure.
    ///
    /// This method is specific to ILP/TCP and is not relevant for ILP/HTTP.
    pub fn must_close(&self) -> bool {
        !self.connected
    }
}

mod conf;
mod timestamp;

#[cfg(feature = "ilp-over-http")]
mod http;

#[cfg(feature = "ilp-over-http")]
use http::*;

#[cfg(test)]
mod tests;
