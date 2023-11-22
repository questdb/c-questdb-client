/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2023 QuestDB
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
//!   * Connect to QuestDB by creating a [`Sender`] object.
//!   * Populate a [`Buffer`] with one or more rows of data.
//!   * Send the buffer via the Sender's [`flush`](Sender::flush) method.
//!
//! ```no_run
//! use questdb::{
//!     Result,
//!     ingress::{
//!         Sender,
//!         Buffer,
//!         SenderBuilder,
//!         TimestampNanos}};
//!
//! fn main() -> Result<()> {
//!    let mut sender = SenderBuilder::new("localhost", 9009).connect()?;
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
//! and TLS-encrypted connection, call the SenderBuilder's
//! [`auth`](SenderBuilder::auth) and [`tls`](SenderBuilder::tls) methods.
//!
//! Here's an example that uses full security:
//!
//! ```no_run
//! # use questdb::Result;
//! use questdb::ingress::{SenderBuilder, Tls, CertificateAuthority};
//!
//! # fn main() -> Result<()> {
//! // See: https://questdb.io/docs/reference/api/ilp/authenticate
//! let mut sender = SenderBuilder::new("localhost", 9009)
//!     .auth(
//!         "testUser1",                                    // kid
//!         "5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48",  // d
//!         "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",  // x
//!         "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac")  // y
//!     .tls(Tls::Enabled(CertificateAuthority::WebpkiRoots))
//!     .connect()?;
//! # Ok(())
//! # }
//! ```
//!
//! Note that as of writing QuestDB does not natively support TLS encryption.
//! To use TLS use a TLS proxy such as [HAProxy](http://www.haproxy.org/).
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
//! use questdb::ingress::{SenderBuilder, Tls, CertificateAuthority};
//!
//! # fn main() -> Result<()> {
//! let mut sender = SenderBuilder::new("localhost", 9009)
//!     .tls(Tls::Enabled(CertificateAuthority::File(
//!         PathBuf::from("/path/to/server_rootCA.pem"))))
//!     .connect()?;
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
use core::time::Duration;
use itoa;
use std::convert::{Infallible, TryFrom, TryInto};
use std::fmt::{Formatter, Write};
use std::io::{self, BufRead, BufReader, ErrorKind, Write as IoWrite};
use std::path::PathBuf;
use std::sync::Arc;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use rustls::{ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName, StreamOwned};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

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
enum State {
    Init = Op::Table as isize,
    TableWritten = Op::Symbol as isize | Op::Column as isize,
    SymbolWritten = Op::Symbol as isize | Op::Column as isize | Op::At as isize,
    ColumnWritten = Op::Column as isize | Op::At as isize,
    MayFlushOrTable = Op::Flush as isize | Op::Table as isize,
}

impl State {
    fn next_op_descr(self) -> &'static str {
        match self {
            State::Init => "should have called `table` instead",
            State::TableWritten => "should have called `symbol` or `column` instead",
            State::SymbolWritten => "should have called `symbol`, `column` or `at` instead",
            State::ColumnWritten => "should have called `column` or `at` instead",
            State::MayFlushOrTable => "should have called `flush` or `table` instead",
        }
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
#[derive(Debug, Clone, PartialEq)]
pub struct Buffer {
    state: State,
    output: String,
    marker: Option<(usize, State)>,
    max_name_len: usize,
}

impl Buffer {
    /// Construct an instance with a `max_name_len` of `127`,
    /// which is the same as the QuestDB default.
    pub fn new() -> Self {
        Self {
            state: State::Init,
            output: String::new(),
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
        if (self.state as isize & Op::Table as isize) == 0 {
            return Err(error::fmt!(
                InvalidApiCall,
                concat!(
                    "Can't set the marker whilst constructing a line. ",
                    "A marker may only be set on an empty buffer or after ",
                    "`at` or `at_now` is called."
                )
            ));
        }
        self.marker = Some((self.output.len(), self.state));
        Ok(())
    }

    /// Undo all changes since the last [`set_marker`](Buffer::set_marker)
    /// call.
    ///
    /// As a side-effect, this also clears the marker.
    pub fn rewind_to_marker(&mut self) -> Result<()> {
        if let Some((position, state)) = self.marker {
            self.output.truncate(position);
            self.state = state;
            self.marker = None;
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
    /// Idempodent.
    pub fn clear_marker(&mut self) {
        self.marker = None;
    }

    /// Reset the buffer and clear contents whilst retaining
    /// [`capacity`](Buffer::capacity).
    pub fn clear(&mut self) {
        self.output.clear();
        self.marker = None;
        self.state = State::Init;
    }

    #[inline(always)]
    fn check_state(&self, op: Op) -> Result<()> {
        if (self.state as isize & op as isize) > 0 {
            return Ok(());
        }
        let error = error::fmt!(
            InvalidApiCall,
            "State error: Bad call to `{}`, {}.",
            op.descr(),
            self.state.next_op_descr()
        );
        Err(error)
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
        self.check_state(Op::Table)?;
        write_escaped_unquoted(&mut self.output, name.name);
        self.state = State::TableWritten;
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
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.name)?;
        self.check_state(Op::Column)?;
        self.output
            .push(if (self.state as isize & Op::Symbol as isize) > 0 {
                ' '
            } else {
                ','
            });
        write_escaped_unquoted(&mut self.output, name.name);
        self.output.push('=');
        self.state = State::ColumnWritten;
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
        self.check_state(Op::At)?;
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
        self.state = State::MayFlushOrTable;
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
        self.check_state(Op::At)?;
        self.output.push('\n');
        self.state = State::MayFlushOrTable;
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
/// * To construct an instance, use the [`SenderBuilder`].
/// * To prepare messages, use [`Buffer`] objects.
/// * To send messages, call the [`flush`](Sender::flush) method.
pub struct Sender {
    descr: String,
    conn: Connection,
    connected: bool,
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.write_str(self.descr.as_str())
    }
}

#[derive(Debug, Clone)]
struct AuthParams {
    key_id: String,
    priv_key: String,
    pub_key_x: String,
    pub_key_y: String,
}

/// Root used to determine how to validate the server's TLS certificate.
///
/// Used when configuring the [`tls`](SenderBuilder::tls) option.
#[derive(Debug, Clone)]
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
    File(PathBuf),
}

/// Options for full-connection encryption via TLS.
#[derive(Debug, Clone)]
pub enum Tls {
    /// No TLS encryption.
    Disabled,

    /// Use TLS encryption, verifying the server's certificate.
    Enabled(CertificateAuthority),

    /// Use TLS encryption, whilst dangerously ignoring the server's certificate.
    /// This should only be used for deubgging purposes.
    /// For testing consider specifying a [`CertificateAuthority::File`] instead.
    ///
    /// *This option requires the `insecure-skip-verify` feature.*
    #[cfg(feature = "insecure-skip-verify")]
    InsecureSkipVerify,
}

impl Tls {
    /// Returns true if TLS is enabled.
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Tls::Disabled)
    }
}

/// A `u16` port number or `String` port service name as is registered with
/// `/etc/services` or equivalent.
///
/// ```
/// use questdb::ingress::Service;
/// use std::convert::Into;
///
/// let service: Service = 9009.into();
/// ```
///
/// or
///
/// ```
/// use questdb::ingress::Service;
/// use std::convert::Into;
///
/// // Assuming the service name is registered.
/// let service: Service = "qdb_ilp".into();  // or with a String too.
/// ```
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

#[cfg(feature = "insecure-skip-verify")]
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
    error::fmt!(TlsError, "{}: {}", descr, err)
}

#[cfg(feature = "tls-webpki-certs")]
fn add_webpki_roots(root_store: &mut RootCertStore) {
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
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

    let os_certs: Vec<Vec<u8>> = os_certs.into_iter().map(|cert| cert.0).collect();
    let (valid_count, invalid_count) = root_store.add_parsable_certificates(&os_certs[..]);
    if valid_count == 0 && invalid_count > 0 {
        return Err(error::fmt!(
            TlsError,
            "No valid certificates found in native root store ({} found but were invalid)",
            invalid_count
        ));
    }
    Ok(())
}

fn configure_tls(tls: &Tls) -> Result<Option<Arc<rustls::ClientConfig>>> {
    if !tls.is_enabled() {
        return Ok(None);
    }

    let mut root_store = RootCertStore::empty();

    if let Tls::Enabled(ca) = tls {
        match ca {
            #[cfg(feature = "tls-webpki-certs")]
            CertificateAuthority::WebpkiRoots => {
                add_webpki_roots(&mut root_store);
            }
            #[cfg(feature = "tls-native-certs")]
            CertificateAuthority::OsRoots => {
                add_os_roots(&mut root_store)?;
            }
            #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
            CertificateAuthority::WebpkiAndOsRoots => {
                add_webpki_roots(&mut root_store);
                add_os_roots(&mut root_store)?;
            }
            CertificateAuthority::File(ca_file) => {
                let certfile = std::fs::File::open(ca_file).map_err(|io_err| {
                    error::fmt!(
                        TlsError,
                        concat!(
                            "Could not open certificate authority ",
                            "file from path {:?}: {}"
                        ),
                        ca_file,
                        io_err
                    )
                })?;
                let mut reader = BufReader::new(certfile);
                let der_certs = &rustls_pemfile::certs(&mut reader).map_err(|io_err| {
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
        .map_err(|rustls_err| map_rustls_err("Bad protocol version selection", rustls_err))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // TLS log file for debugging.
    // Set the SSLKEYLOGFILE env variable to a writable location.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    #[cfg(feature = "insecure-skip-verify")]
    if let Tls::InsecureSkipVerify = tls {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }

    Ok(Some(Arc::new(config)))
}

/// Accumulate parameters for a new `Sender` instance.
///
/// ```no_run
/// # use questdb::Result;
/// use questdb::ingress::SenderBuilder;
///
/// # fn main() -> Result<()> {
/// let mut sender = SenderBuilder::new("localhost", 9009).connect()?;
/// # Ok(())
/// # }
/// ```
///
/// Additional options for:
///   * Binding a specific [outbound network address](SenderBuilder::net_interface).
///   * Connection security
///     ([authentication](SenderBuilder::auth), [encryption](SenderBuilder::tls)).
///   * Authentication [timeouts](SenderBuilder::read_timeout).
///
#[derive(Debug, Clone)]
pub struct SenderBuilder {
    read_timeout: Duration,
    host: String,
    port: String,
    net_interface: Option<String>,
    auth: Option<AuthParams>,
    tls: Tls,
}

impl SenderBuilder {
    /// QuestDB server and port.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// use questdb::ingress::SenderBuilder;
    ///
    /// # fn main() -> Result<()> {
    /// let mut sender = SenderBuilder::new("localhost", 9009).connect()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<H: Into<String>, P: Into<Service>>(host: H, port: P) -> Self {
        let service: Service = port.into();
        Self {
            read_timeout: Duration::from_secs(15),
            host: host.into(),
            port: service.0,
            net_interface: None,
            auth: None,
            tls: Tls::Disabled,
        }
    }

    /// Select local outbound interface.
    ///
    /// This may be relevant if your machine has multiple network interfaces.
    ///
    /// If unspecified, the default is to use any available interface and is
    /// equivalent to calling:
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::SenderBuilder;
    /// # fn main() -> Result<()> {
    /// let mut sender = SenderBuilder::new("localhost", 9009)
    ///     .net_interface("0.0.0.0")
    ///     .connect()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn net_interface<I: Into<String>>(mut self, addr: I) -> Self {
        self.net_interface = Some(addr.into());
        self
    }

    /// Authentication Parameters.
    ///
    /// If not called, authentication is disabled.
    ///
    /// # Arguments
    /// * `key_id` - Key identifier, AKA "kid" in JWT. This is sometimes
    ///   referred to as the username.
    /// * `priv_key` - Private key, AKA "d" in JWT.
    /// * `pub_key_x` - X coordinate of the public key, AKA "x" in JWT.
    /// * `pub_key_y` - Y coordinate of the public key, AKA "y" in JWT.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::SenderBuilder;
    /// # fn main() -> Result<()> {
    /// let mut sender = SenderBuilder::new("localhost", 9009)
    ///     .auth(
    ///         "testUser1",                                    // kid
    ///         "5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48",  // d
    ///         "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",  // x
    ///         "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac")  // y
    ///     .connect()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Follow the QuestDB [authentication
    /// documentation](https://questdb.io/docs/reference/api/ilp/authenticate)
    /// for instructions on generating keys.
    pub fn auth<A, B, C, D>(mut self, key_id: A, priv_key: B, pub_key_x: C, pub_key_y: D) -> Self
    where
        A: Into<String>,
        B: Into<String>,
        C: Into<String>,
        D: Into<String>,
    {
        self.auth = Some(AuthParams {
            key_id: key_id.into(),
            priv_key: priv_key.into(),
            pub_key_x: pub_key_x.into(),
            pub_key_y: pub_key_y.into(),
        });
        self
    }

    /// Configure TLS handshake.
    ///
    /// The default is [`Tls::Disabled`].
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::SenderBuilder;
    /// # use questdb::ingress::Tls;
    /// # fn main() -> Result<()> {
    /// let mut sender = SenderBuilder::new("localhost", 9009)
    ///     .tls(Tls::Disabled)
    ///     .connect()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// To enable with commonly accepted certificates, use:
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::SenderBuilder;
    /// # use questdb::ingress::Tls;
    /// use questdb::ingress::CertificateAuthority;
    ///
    /// # fn main() -> Result<()> {
    /// let mut sender = SenderBuilder::new("localhost", 9009)
    ///     .tls(Tls::Enabled(CertificateAuthority::WebpkiRoots))
    ///     .connect()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// To use [self-signed certificates](https://github.com/questdb/c-questdb-client/tree/main/tls_certs):
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::SenderBuilder;
    /// # use questdb::ingress::Tls;
    /// use questdb::ingress::CertificateAuthority;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<()> {
    /// let mut sender = SenderBuilder::new("localhost", 9009)
    ///     .tls(Tls::Enabled(CertificateAuthority::File(
    ///         PathBuf::from("/path/to/server_rootCA.pem"))))
    ///     .connect()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// If you're still struggling you may temporarily enable the dangerous
    /// `insecure-skip-verify` feature to skip the certificate verification:
    ///
    /// ```ignore
    /// let mut sender = SenderBuilder::new("localhost", 9009)
    ///    .tls(Tls::InsecureSkipVerify)
    ///    .connect()?;
    /// ```
    pub fn tls(mut self, tls: Tls) -> Self {
        self.tls = tls;
        self
    }

    /// Configure how long to wait for messages from the QuestDB server during
    /// the TLS handshake and authentication process.
    /// The default is 15 seconds.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::SenderBuilder;
    /// use std::time::Duration;
    ///
    /// # fn main() -> Result<()> {
    /// let mut sender = SenderBuilder::new("localhost", 9009)
    ///    .read_timeout(Duration::from_secs(15))
    ///    .connect()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn read_timeout(mut self, value: Duration) -> Self {
        self.read_timeout = value;
        self
    }

    /// Connect synchronously.
    ///
    /// Will return once the connection is fully established:
    /// If the connection requires authentication or TLS, these will also be
    /// completed before returning.
    pub fn connect(&self) -> Result<Sender> {
        let mut descr = format!("Sender[host={:?},port={:?},", self.host, self.port);
        let addr: SockAddr = gai::resolve_host_port(self.host.as_str(), self.port.as_str())?;
        let mut sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
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
        if let Some(ref host) = self.net_interface {
            let bind_addr = gai::resolve_host(host.as_str())?;
            sock.bind(&bind_addr).map_err(|io_err| {
                map_io_to_socket_err(
                    &format!("Could not bind to interface address {:?}: ", host),
                    io_err,
                )
            })?;
        }
        sock.connect(&addr).map_err(|io_err| {
            let host_port = format!("{}:{}", self.host, self.port);
            let prefix = format!("Could not connect to {:?}: ", host_port);
            map_io_to_socket_err(&prefix, io_err)
        })?;

        // We read during both TLS handshake and authentication.
        // We set up a read timeout to prevent the client from "hanging"
        // should we be connecting to a server configured in a different way
        // from the client.
        sock.set_read_timeout(Some(self.read_timeout))
            .map_err(|io_err| {
                map_io_to_socket_err("Failed to set read timeout on socket: ", io_err)
            })?;

        match self.tls {
            Tls::Disabled => write!(descr, "tls=enabled,").unwrap(),
            Tls::Enabled(_) => write!(descr, "tls=enabled,").unwrap(),

            #[cfg(feature = "insecure-skip-verify")]
            Tls::InsecureSkipVerify => write!(descr, "tls=insecure_skip_verify,").unwrap(),
        }

        let conn = match configure_tls(&self.tls)? {
            Some(tls_config) => {
                let server_name: ServerName =
                    self.host.as_str().try_into().map_err(|inv_dns_err| {
                        error::fmt!(TlsError, "Bad host: {}", inv_dns_err)
                    })?;
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
                                self.read_timeout
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
        if self.auth.is_some() {
            descr.push_str("auth=on]");
        } else {
            descr.push_str("auth=off]");
        }
        let mut sender = Sender {
            descr,
            conn,
            connected: true,
        };
        if let Some(auth) = self.auth.as_ref() {
            sender.authenticate(auth)?;
        }
        Ok(sender)
    }
}

fn b64_decode(descr: &'static str, buf: &str) -> Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(buf)
        .map_err(|b64_err| error::fmt!(AuthError, "Could not decode {}: {}", descr, b64_err))
}

fn parse_public_key(pub_key_x: &str, pub_key_y: &str) -> Result<Vec<u8>> {
    let mut pub_key_x = b64_decode("public key x", pub_key_x)?;
    let mut pub_key_y = b64_decode("public key y", pub_key_y)?;

    // SEC 1 Uncompressed Octet-String-to-Elliptic-Curve-Point Encoding
    let mut encoded = Vec::new();
    encoded.push(4u8); // 0x04 magic byte that identifies this as uncompressed.
    encoded.resize((32 - pub_key_x.len()) + 1, 0u8);
    encoded.append(&mut pub_key_x);
    encoded.resize((32 - pub_key_y.len()) + 1 + 32, 0u8);
    encoded.append(&mut pub_key_y);
    Ok(encoded)
}

fn parse_key_pair(auth: &AuthParams) -> Result<EcdsaKeyPair> {
    let private_key = b64_decode("private authentication key", auth.priv_key.as_str())?;
    let public_key = parse_public_key(auth.pub_key_x.as_str(), auth.pub_key_y.as_str())?;
    let system_random = SystemRandom::new();
    EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &private_key[..],
        &public_key[..],
        &system_random,
    )
    .map_err(|key_rejected| error::fmt!(AuthError, "Bad private key: {}", key_rejected))
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
    fn send_key_id(&mut self, key_id: &str) -> Result<()> {
        writeln!(&mut self.conn, "{}", key_id)
            .map_err(|io_err| map_io_to_socket_err("Failed to send key_id: ", io_err))?;
        Ok(())
    }

    fn read_challenge(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut reader = BufReader::new(&mut self.conn);
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

    fn authenticate(&mut self, auth: &AuthParams) -> Result<()> {
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
        let rng = ring::rand::SystemRandom::new();
        let signature = key_pair
            .sign(&rng, &challenge[..])
            .map_err(|unspecified_err| {
                error::fmt!(AuthError, "Failed to sign challenge: {}", unspecified_err)
            })?;
        let mut encoded_sig = Base64::encode_string(signature.as_ref());
        encoded_sig.push('\n');
        let buf = encoded_sig.as_bytes();
        if let Err(io_err) = self.conn.write_all(buf) {
            return Err(map_io_to_socket_err(
                "Could not send signed challenge: ",
                io_err,
            ));
        }
        Ok(())
    }

    /// Send buffer to the QuestDB server, without clearing the
    /// buffer.
    ///
    /// This will block until the buffer is flushed to the network socket.
    /// This does not guarantee that the buffer will be sent to the server
    /// or that the server has received it.
    pub fn flush_and_keep(&mut self, buf: &Buffer) -> Result<()> {
        if !self.connected {
            return Err(error::fmt!(
                SocketError,
                "Could not flush buffer: not connected to database."
            ));
        }
        buf.check_state(Op::Flush)?;
        let bytes = buf.as_str().as_bytes();
        if let Err(io_err) = self.conn.write_all(bytes) {
            self.connected = false;
            return Err(map_io_to_socket_err("Could not flush buffer: ", io_err));
        }
        Ok(())
    }

    /// Send buffer to the QuestDB server, clearing the buffer.
    ///
    /// This will block until the buffer is flushed to the network socket.
    /// This does not guarantee that the buffer will be sent to the server
    /// or that the server has received it.
    pub fn flush(&mut self, buf: &mut Buffer) -> Result<()> {
        self.flush_and_keep(buf)?;
        buf.clear();
        Ok(())
    }

    /// The sender is no longer usable and must be dropped.
    ///
    /// This is caused if there was an earlier failure.
    pub fn must_close(&self) -> bool {
        !self.connected
    }
}

mod timestamp;
