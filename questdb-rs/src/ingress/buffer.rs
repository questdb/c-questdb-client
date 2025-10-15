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
use crate::ingress::decimal::DecimalSerializer;
use crate::ingress::ndarr::{check_and_get_array_bytes_size, ArrayElementSealed};
use crate::ingress::{
    ndarr, ArrayElement, DebugBytes, NdArrayView, ProtocolVersion, Timestamp, TimestampMicros,
    TimestampNanos, ARRAY_BINARY_FORMAT_TYPE, DOUBLE_BINARY_FORMAT_TYPE, MAX_ARRAY_DIMS,
    MAX_NAME_LEN_DEFAULT,
};
use crate::{error, Error};
use std::fmt::{Debug, Formatter};
use std::num::NonZeroUsize;
use std::slice::from_raw_parts_mut;

fn write_escaped_impl<Q, C>(check_escape_fn: C, quoting_fn: Q, output: &mut Vec<u8>, s: &str)
where
    C: Fn(u8) -> bool,
    Q: Fn(&mut Vec<u8>),
{
    let mut to_escape = 0usize;
    for b in s.bytes() {
        if check_escape_fn(b) {
            to_escape += 1;
        }
    }

    quoting_fn(output);

    if to_escape == 0 {
        // output.push_str(s);
        output.extend_from_slice(s.as_bytes());
    } else {
        let additional = s.len() + to_escape;
        output.reserve(additional);
        let mut index = output.len();
        unsafe { output.set_len(index + additional) };
        for b in s.bytes() {
            if check_escape_fn(b) {
                unsafe {
                    *output.get_unchecked_mut(index) = b'\\';
                }
                index += 1;
            }

            unsafe {
                *output.get_unchecked_mut(index) = b;
            }
            index += 1;
        }
    }

    quoting_fn(output);
}

fn must_escape_unquoted(c: u8) -> bool {
    matches!(c, b' ' | b',' | b'=' | b'\n' | b'\r' | b'\\')
}

fn must_escape_quoted(c: u8) -> bool {
    matches!(c, b'\n' | b'\r' | b'"' | b'\\')
}

fn write_escaped_unquoted(output: &mut Vec<u8>, s: &str) {
    write_escaped_impl(must_escape_unquoted, |_output| (), output, s);
}

fn write_escaped_quoted(output: &mut Vec<u8>, s: &str) {
    write_escaped_impl(must_escape_quoted, |output| output.push(b'"'), output, s)
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

// IMPORTANT: This struct MUST remain `Copy` to ensure that
// there are no heap allocations when performing marker operations.
#[derive(Debug, Clone, Copy)]
struct BufferState {
    op_case: OpCase,
    row_count: usize,
    first_table_len: Option<NonZeroUsize>,
    transactional: bool,
}

impl BufferState {
    fn new() -> Self {
        Self {
            op_case: OpCase::Init,
            row_count: 0,
            first_table_len: None,
            transactional: true,
        }
    }
}

/// A validated table name.
///
/// This type simply wraps a `&str`.
///
/// When you pass a `TableName` instead of a plain string to a [`Buffer`] method,
/// it doesn't have to validate it again. This saves CPU cycles.
#[derive(Clone, Copy)]
pub struct TableName<'a> {
    name: &'a str,
}

impl<'a> TableName<'a> {
    /// Construct a validated table name.
    pub fn new(name: &'a str) -> crate::Result<Self> {
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
                    // Reject Unicode char 'ZERO WIDTH NO-BREAK SPACE',
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

    /// Construct a table name without validating it.
    ///
    /// This breaks API encapsulation and is only intended for use
    /// when the string was already previously validated.
    ///
    /// The QuestDB server will reject an invalid table name.
    pub fn new_unchecked(name: &'a str) -> Self {
        Self { name }
    }
}

impl<'a> TryFrom<&'a str> for TableName<'a> {
    type Error = Error;

    fn try_from(name: &'a str) -> crate::Result<Self> {
        Self::new(name)
    }
}

impl AsRef<str> for TableName<'_> {
    fn as_ref(&self) -> &str {
        self.name
    }
}

/// A validated column name.
///
/// This type simply wraps a `&str`.
///
/// When you pass a `ColumnName` instead of a plain string to a [`Buffer`] method,
/// it doesn't have to validate it again. This saves CPU cycles.
#[derive(Clone, Copy)]
pub struct ColumnName<'a> {
    name: &'a str,
}

impl<'a> ColumnName<'a> {
    /// Construct a validated table name.
    pub fn new(name: &'a str) -> crate::Result<Self> {
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
                    // Reject Unicode char 'ZERO WIDTH NO-BREAK SPACE',
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

    /// Construct a column name without validating it.
    ///
    /// This breaks API encapsulation and is only intended for use
    /// when the string was already previously validated.
    ///
    /// The QuestDB server will reject an invalid column name.
    pub fn new_unchecked(name: &'a str) -> Self {
        Self { name }
    }
}

impl<'a> TryFrom<&'a str> for ColumnName<'a> {
    type Error = Error;

    fn try_from(name: &'a str) -> crate::Result<Self> {
        Self::new(name)
    }
}

impl AsRef<str> for ColumnName<'_> {
    fn as_ref(&self) -> &str {
        self.name
    }
}

/// A reusable buffer to prepare a batch of ILP messages.
///
/// # Example
///
/// ```no_run
/// # use questdb::Result;
/// # use questdb::ingress::SenderBuilder;
///
/// # fn main() -> Result<()> {
/// # let mut sender = SenderBuilder::from_conf("http::addr=localhost:9000;")?.build()?;
/// # use questdb::Result;
/// use questdb::ingress::{Buffer, TimestampMicros, TimestampNanos};
/// let mut buffer = sender.new_buffer();
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
/// Send the buffer to QuestDB using [`sender.flush(&mut buffer)`](Sender::flush).
///
/// # Sequential Coupling
/// The Buffer API is sequentially coupled:
///   * A row always starts with [`table`](Buffer::table).
///   * A row must contain at least one [`symbol`](Buffer::symbol) or
///     column (
///     [`column_bool`](Buffer::column_bool),
///     [`column_i64`](Buffer::column_i64),
///     [`column_f64`](Buffer::column_f64),
///     [`column_str`](Buffer::column_str),
///     [`column_arr`](Buffer::column_arr),
///     [`column_ts`](Buffer::column_ts)).
///   * Symbols must appear before columns.
///   * A row must be terminated with either [`at`](Buffer::at) or
///     [`at_now`](Buffer::at_now).
///
/// This diagram visualizes the sequence:
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
/// | [`column_arr`](Buffer::column_arr) | [`ARRAY`](https://questdb.io/docs/reference/api/ilp/columnset-types#array) |
/// | [`column_ts`](Buffer::column_ts) | [`TIMESTAMP`](https://questdb.io/docs/reference/api/ilp/columnset-types#timestamp) |
///
/// QuestDB supports both `STRING` and `SYMBOL` column types.
///
/// To understand the difference, refer to the
/// [QuestDB documentation](https://questdb.io/docs/concept/symbol/). In a nutshell,
/// symbols are interned strings, most suitable for identifiers that are repeated many
/// times throughout the column. They offer an advantage in storage space and query
/// performance.
///
/// # Inserting NULL values
///
/// To insert a NULL value, skip the symbol or column for that row.
///
/// # Recovering from validation errors
///
/// If you want to recover from potential validation errors, call
/// [`buffer.set_marker()`](Buffer::set_marker) to track the last known good state,
/// append as many rows or parts of rows as you like, and then call
/// [`buffer.clear_marker()`](Buffer::clear_marker) on success.
///
/// If there was an error in one of the rows, use
/// [`buffer.rewind_to_marker()`](Buffer::rewind_to_marker) to go back to the
/// marked last known good state.
///
#[derive(Clone)]
pub struct Buffer {
    output: Vec<u8>,
    state: BufferState,
    marker: Option<(usize, BufferState)>,
    max_name_len: usize,
    protocol_version: ProtocolVersion,
}

impl Buffer {
    /// Creates a new [`Buffer`] with default parameters.
    ///
    /// - Uses the specified protocol version
    /// - Sets maximum name length to **127 characters** (QuestDB server default)
    ///
    /// This is equivalent to [`Sender::new_buffer`] when using the [`Sender::protocol_version`]
    /// and [`Sender::max_name_len`] is 127.
    ///
    /// For custom name lengths, use [`Self::with_max_name_len`]
    pub fn new(protocol_version: ProtocolVersion) -> Self {
        Self::with_max_name_len(protocol_version, MAX_NAME_LEN_DEFAULT)
    }

    /// Creates a new [`Buffer`] with a custom maximum name length.
    ///
    /// - `max_name_len`: Maximum allowed length for table/column names, match
    ///   your QuestDB server's `cairo.max.file.name.length` configuration
    /// - `protocol_version`: Protocol version to use
    ///
    /// This is equivalent to [`Sender::new_buffer`] when using the [`Sender::protocol_version`]
    /// and [`Sender::max_name_len`].
    ///
    /// For the default max name length limit (127), use [`Self::new`].
    pub fn with_max_name_len(protocol_version: ProtocolVersion, max_name_len: usize) -> Self {
        Self {
            output: Vec::new(),
            state: BufferState::new(),
            marker: None,
            max_name_len,
            protocol_version,
        }
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Pre-allocate to ensure the buffer has enough capacity for at least the
    /// specified additional byte count. This may be rounded up.
    /// This does not allocate if such additional capacity is already satisfied.
    /// See: `capacity`.
    pub fn reserve(&mut self, additional: usize) {
        self.output.reserve(additional);
    }

    /// The number of bytes accumulated in the buffer.
    pub fn len(&self) -> usize {
        self.output.len()
    }

    /// The number of rows accumulated in the buffer.
    pub fn row_count(&self) -> usize {
        self.state.row_count
    }

    /// Tells whether the buffer is transactional. It is transactional iff it contains
    /// data for at most one table. Additionally, you must send the buffer over HTTP to
    /// get transactional behavior.
    pub fn transactional(&self) -> bool {
        self.state.transactional
    }

    pub fn is_empty(&self) -> bool {
        self.output.is_empty()
    }

    /// The total number of bytes the buffer can hold before it needs to resize.
    pub fn capacity(&self) -> usize {
        self.output.capacity()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.output
    }

    /// Mark a rewind point.
    /// This allows undoing accumulated changes to the buffer for one or more
    /// rows by calling [`rewind_to_marker`](Buffer::rewind_to_marker).
    /// Any previous marker will be discarded.
    /// Once the marker is no longer needed, call
    /// [`clear_marker`](Buffer::clear_marker).
    pub fn set_marker(&mut self) -> crate::Result<()> {
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
        self.marker = Some((self.output.len(), self.state));
        Ok(())
    }

    /// Undo all changes since the last [`set_marker`](Buffer::set_marker)
    /// call.
    ///
    /// As a side effect, this also clears the marker.
    pub fn rewind_to_marker(&mut self) -> crate::Result<()> {
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
        self.state = BufferState::new();
        self.marker = None;
    }

    /// Check if the next API operation is allowed as per the OP case state machine.
    #[inline(always)]
    fn check_op(&self, op: Op) -> crate::Result<()> {
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

    /// Checks if this buffer is ready to be flushed to a sender via one of the
    /// [`Sender::flush`] functions. An [`Ok`] value indicates that the buffer
    /// is ready to be flushed via a [`Sender`] while an [`Err`] will contain a
    /// message indicating why this [`Buffer`] cannot be flushed at the moment.
    #[inline(always)]
    pub fn check_can_flush(&self) -> crate::Result<()> {
        self.check_op(Op::Flush)
    }

    #[inline(always)]
    fn validate_max_name_len(&self, name: &str) -> crate::Result<()> {
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

    /// Begin recording a new row for the given table.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// buffer.table("table_name")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::TableName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// let table_name = TableName::new("table_name")?;
    /// buffer.table(table_name)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn table<'a, N>(&mut self, name: N) -> crate::Result<&mut Self>
    where
        N: TryInto<TableName<'a>>,
        Error: From<N::Error>,
    {
        let name: TableName<'a> = name.try_into()?;
        self.validate_max_name_len(name.name)?;
        self.check_op(Op::Table)?;
        let table_begin = self.output.len();
        write_escaped_unquoted(&mut self.output, name.name);
        let table_end = self.output.len();
        self.state.op_case = OpCase::TableWritten;

        // A buffer stops being transactional if it targets multiple tables.
        if let Some(first_table_len) = &self.state.first_table_len {
            let first_table = &self.output[0..first_table_len.get()];
            let this_table = &self.output[table_begin..table_end];
            if first_table != this_table {
                self.state.transactional = false;
            }
        } else {
            debug_assert!(table_begin == 0);

            // This is a bit confusing, so worth explaining:
            // `NonZeroUsize::new(table_end)` will return `None` if `table_end` is 0,
            // but we know that `table_end` is never 0 here, we just need an option type
            // anyway, so we don't bother unwrapping it to then wrap it again.
            let first_table_len = NonZeroUsize::new(table_end);

            // Instead we just assert that it's `Some`.
            debug_assert!(first_table_len.is_some());

            self.state.first_table_len = first_table_len;
        }
        Ok(self)
    }

    /// Record a symbol for the given column.
    /// Make sure you record all symbol columns before any other column type.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// buffer.symbol("col_name", "value")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let value: String = "value".to_owned();
    /// buffer.symbol("col_name", value)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.symbol(col_name, "value")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    pub fn symbol<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.name)?;
        self.check_op(Op::Symbol)?;
        self.output.push(b',');
        write_escaped_unquoted(&mut self.output, name.name);
        self.output.push(b'=');
        write_escaped_unquoted(&mut self.output, value.as_ref());
        self.state.op_case = OpCase::SymbolWritten;
        Ok(self)
    }

    fn write_column_key<'a, N>(&mut self, name: N) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.name)?;
        self.check_op(Op::Column)?;
        self.output
            .push(if (self.state.op_case as isize & Op::Symbol as isize) > 0 {
                b' '
            } else {
                b','
            });
        write_escaped_unquoted(&mut self.output, name.name);
        self.output.push(b'=');
        self.state.op_case = OpCase::ColumnWritten;
        Ok(self)
    }

    /// Record a boolean value for the given column.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// buffer.column_bool("col_name", true)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.column_bool(col_name, true)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn column_bool<'a, N>(&mut self, name: N, value: bool) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.write_column_key(name)?;
        self.output.push(if value { b't' } else { b'f' });
        Ok(self)
    }

    /// Record an integer value for the given column.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// buffer.column_i64("col_name", 42)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.column_i64(col_name, 42)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn column_i64<'a, N>(&mut self, name: N, value: i64) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.write_column_key(name)?;
        let mut buf = itoa::Buffer::new();
        let printed = buf.format(value);
        self.output.extend_from_slice(printed.as_bytes());
        self.output.push(b'i');
        Ok(self)
    }

    /// Record a floating point value for the given column.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// buffer.column_f64("col_name", 3.14)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.column_f64(col_name, 3.14)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn column_f64<'a, N>(&mut self, name: N, value: f64) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.write_column_key(name)?;
        if !matches!(self.protocol_version, ProtocolVersion::V1) {
            self.output.push(b'=');
            self.output.push(DOUBLE_BINARY_FORMAT_TYPE);
            self.output.extend_from_slice(&value.to_le_bytes())
        } else {
            let mut ser = F64Serializer::new(value);
            self.output.extend_from_slice(ser.as_str().as_bytes())
        }
        Ok(self)
    }

    /// Record a string value for the given column.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// buffer.column_str("col_name", "value")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let value: String = "value".to_owned();
    /// buffer.column_str("col_name", value)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.column_str(col_name, "value")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn column_str<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        self.write_column_key(name)?;
        write_escaped_quoted(&mut self.output, value.as_ref());
        Ok(self)
    }

    /// Record a decimal value for the given column.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// buffer.column_dec("col_name", "123.45")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let col_name = ColumnName::new("col_name")?;
    /// buffer.column_dec(col_name, "123.45")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// With `rust_decimal` feature enabled:
    ///
    /// ```no_run
    /// # #[cfg(feature = "rust_decimal")]
    /// # {
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use rust_decimal::Decimal;
    /// use std::str::FromStr;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let value = Decimal::from_str("123.45").unwrap();
    /// buffer.column_dec("col_name", &value)?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    ///
    /// With `bigdecimal` feature enabled:
    ///
    /// ```no_run
    /// # #[cfg(feature = "bigdecimal")]
    /// # {
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use bigdecimal::BigDecimal;
    /// use std::str::FromStr;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let value = BigDecimal::from_str("0.123456789012345678901234567890").unwrap();
    /// buffer.column_dec("col_name", &value)?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn column_dec<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: DecimalSerializer,
        Error: From<N::Error>,
    {
        if !self.protocol_version.supports(ProtocolVersion::V3) {
            return Err(error::fmt!(
                ProtocolVersionError,
                "Protocol version {} does not support the decimal datatype",
                self.protocol_version
            ));
        }

        self.write_column_key(name)?;
        value.serialize(&mut self.output)?;
        Ok(self)
    }

    /// Record a multidimensional array value for the given column.
    ///
    /// Supports arrays with up to [`MAX_ARRAY_DIMS`] dimensions. The array elements must
    /// be of type `f64`, which is currently the only supported data type.
    ///
    /// **Note**: QuestDB server version 9.0.0 or later is required for array support.
    ///
    /// # Examples
    ///
    /// Recording a 2D array using slices:
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// let array_2d = vec![vec![1.1, 2.2], vec![3.3, 4.4]];
    /// buffer.column_arr("array_col", &array_2d)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Recording a 3D array using vectors:
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, ColumnName, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x1")?;
    /// let array_3d = vec![vec![vec![42.0; 4]; 3]; 2];
    /// let col_name = ColumnName::new("col1")?;
    /// buffer.column_arr(col_name, &array_3d)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if:
    /// - Array dimensions exceed [`MAX_ARRAY_DIMS`]
    /// - Failed to get dimension sizes
    /// - Column name validation fails
    /// - Protocol version v1 is used (arrays require v2+)
    #[allow(private_bounds)]
    pub fn column_arr<'a, N, T, D>(&mut self, name: N, view: &T) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: NdArrayView<D>,
        D: ArrayElement + ArrayElementSealed,
        Error: From<N::Error>,
    {
        if !self.protocol_version.supports(ProtocolVersion::V2) {
            return Err(error::fmt!(
                ProtocolVersionError,
                "Protocol version {} does not support array datatype",
                self.protocol_version
            ));
        }
        let ndim = view.ndim();
        if ndim == 0 {
            return Err(error::fmt!(
                ArrayError,
                "Zero-dimensional arrays are not supported",
            ));
        }

        // check dimension less equal than max dims
        if MAX_ARRAY_DIMS < ndim {
            return Err(error::fmt!(
                ArrayError,
                "Array dimension mismatch: expected at most {} dimensions, but got {}",
                MAX_ARRAY_DIMS,
                ndim
            ));
        }

        let array_buf_size = check_and_get_array_bytes_size(view)?;
        self.write_column_key(name)?;
        // binary format flag '='
        self.output.push(b'=');
        // binary format entity type
        self.output.push(ARRAY_BINARY_FORMAT_TYPE);
        // ndarr datatype
        self.output.push(D::type_tag());
        // ndarr dims
        self.output.push(ndim as u8);

        let dim_header_size = size_of::<u32>() * ndim;
        self.output.reserve(dim_header_size + array_buf_size);

        for i in 0..ndim {
            // ndarr shape
            self.output
                .extend_from_slice((view.dim(i)? as u32).to_le_bytes().as_slice());
        }

        let index = self.output.len();
        let writeable =
            unsafe { from_raw_parts_mut(self.output.as_mut_ptr().add(index), array_buf_size) };

        // ndarr data
        ndarr::write_array_data(view, writeable, array_buf_size)?;
        unsafe { self.output.set_len(array_buf_size + index) }
        Ok(self)
    }

    /// Record a timestamp value for the given column.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::TimestampMicros;
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// buffer.column_ts("col_name", TimestampMicros::now())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::TimestampMicros;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?;
    /// buffer.column_ts("col_name", TimestampMicros::new(1659548204354448))?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::TimestampMicros;
    /// use questdb::ingress::ColumnName;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
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
    /// easily from either `std::time::SystemTime` or `chrono::DateTime`.
    ///
    /// This last option requires the `chrono_timestamp` feature.
    pub fn column_ts<'a, N, T>(&mut self, name: N, value: T) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: TryInto<Timestamp>,
        Error: From<N::Error>,
        Error: From<T::Error>,
    {
        self.write_column_key(name)?;
        let timestamp: Timestamp = value.try_into()?;
        let (number, suffix) = match (self.protocol_version, timestamp) {
            (ProtocolVersion::V1, _) => {
                let timestamp: TimestampMicros = timestamp.try_into()?;
                (timestamp.as_i64(), b't')
            }
            (_, Timestamp::Micros(ts)) => (ts.as_i64(), b't'),
            (_, Timestamp::Nanos(ts)) => (ts.as_i64(), b'n'),
        };

        let mut buf = itoa::Buffer::new();
        let printed = buf.format(number);
        self.output.extend_from_slice(printed.as_bytes());
        self.output.push(suffix);
        Ok(self)
    }

    /// Complete the current row with the designated timestamp. After this call, you can
    /// start recording the next row by calling [Buffer::table] again, or  you can send
    /// the accumulated batch by calling [Sender::flush] or one of its variants.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::TimestampNanos;
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?.symbol("a", "b")?;
    /// buffer.at(TimestampNanos::now())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// or
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// use questdb::ingress::TimestampNanos;
    ///
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?.symbol("a", "b")?;
    /// buffer.at(TimestampNanos::new(1659548315647406592))?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// You can also pass in a `TimestampMicros`.
    ///
    /// Note that both `TimestampMicros` and `TimestampNanos` can be constructed
    /// easily from either `std::time::SystemTime` or `chrono::DateTime`.
    ///
    pub fn at<T>(&mut self, timestamp: T) -> crate::Result<()>
    where
        T: TryInto<Timestamp>,
        Error: From<T::Error>,
    {
        self.check_op(Op::At)?;
        let timestamp: Timestamp = timestamp.try_into()?;

        let (number, termination) = match (self.protocol_version, timestamp) {
            (ProtocolVersion::V1, _) => {
                let timestamp: crate::Result<TimestampNanos> = timestamp.try_into();
                (timestamp?.as_i64(), "\n")
            }
            (_, Timestamp::Micros(micros)) => (micros.as_i64(), "t\n"),
            (_, Timestamp::Nanos(nanos)) => (nanos.as_i64(), "n\n"),
        };

        if number < 0 {
            return Err(error::fmt!(
                InvalidTimestamp,
                "Timestamp {} is negative. It must be >= 0.",
                number
            ));
        }

        let mut buf = itoa::Buffer::new();
        let printed = buf.format(number);
        self.output.push(b' ');
        self.output.extend_from_slice(printed.as_bytes());
        self.output.extend_from_slice(termination.as_bytes());
        self.state.op_case = OpCase::MayFlushOrTable;
        self.state.row_count += 1;
        Ok(())
    }

    /// Complete the current row without providing a timestamp. The QuestDB instance
    /// will insert its own timestamp.
    ///
    /// Letting the server assign the timestamp can be faster since it reliably avoids
    /// out-of-order operations in the database for maximum ingestion throughput. However,
    /// it removes the ability to deduplicate rows.
    ///
    /// This is NOT equivalent to calling [Buffer::at] with the current time: the QuestDB
    /// server will set the timestamp only after receiving the row. If you're flushing
    /// infrequently, the server-assigned timestamp may be significantly behind the
    /// time the data was recorded in the buffer.
    ///
    /// In almost all cases, you should prefer the [Buffer::at] function.
    ///
    /// After this call, you can start recording the next row by calling [Buffer::table]
    /// again, or you can send the accumulated batch by calling [Sender::flush] or one of
    /// its variants.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// # use questdb::ingress::{Buffer, SenderBuilder};
    /// # fn main() -> Result<()> {
    /// # let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
    /// # let mut buffer = sender.new_buffer();
    /// # buffer.table("x")?.symbol("a", "b")?;
    /// buffer.at_now()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn at_now(&mut self) -> crate::Result<()> {
        self.check_op(Op::At)?;
        self.output.push(b'\n');
        self.state.op_case = OpCase::MayFlushOrTable;
        self.state.row_count += 1;
        Ok(())
    }
}

impl Debug for Buffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Buffer")
            .field("output", &DebugBytes(&self.output))
            .field("state", &self.state)
            .field("marker", &self.marker)
            .field("max_name_len", &self.max_name_len)
            .field("protocol_version", &self.protocol_version)
            .finish()
    }
}
