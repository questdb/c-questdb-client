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

use std::ascii;
use std::boxed::Box;
use std::convert::{From, Into};
use std::path::PathBuf;
use std::slice;
use std::str;
use libc::{c_char, size_t};
use std::ptr;

use super::{
    Error,
    ErrorCode,
    TableName,
    ColumnName,
    LineSender,
    LineSenderBuilder,
    Tls,
    CertificateAuthority};

macro_rules! bubble_err_to_c {
    ($err_out:expr, $expression:expr) => {
        bubble_err_to_c!($err_out, $expression, false)
    };
    ($err_out:expr, $expression:expr, $sentinel:expr) => {
        match $expression {
            Ok(value) => value,
            Err(err) => {
                let err_ptr = Box::into_raw(Box::new(line_sender_error(err)));
                *$err_out = err_ptr;
                return $sentinel;
            }
        }
    };
}

/// Update the Rust builder inside the C opts object
/// after calling a method that takes ownership of the builder.
macro_rules! upd_opts {
    ($opts:expr, $func:ident, $($args:expr),*) => {
        ptr::write(
            &mut (*$opts).0,
            ptr::read(&(*$opts).0).$func($($args),*));
    };
}

/// An error that occurred when using the line sender.
pub struct line_sender_error(Error);

/// Category of error.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum line_sender_error_code {
    /// The host, port, or interface was incorrect.
    line_sender_error_could_not_resolve_addr,

    /// Called methods in the wrong order. E.g. `symbol` after `column`.
    line_sender_error_invalid_api_call,

    /// A network error connecting or flushing data out.
    line_sender_error_socket_error,

    /// The string or symbol field is not encoded in valid UTF-8.
    line_sender_error_invalid_utf8,

    /// The table name, symbol name or column name contains bad characters.
    line_sender_error_invalid_name,

    /// Error during the authentication process.
    line_sender_error_auth_error,

    /// Error during TLS handshake.
    line_sender_error_tls_error,
}

impl From<ErrorCode> for line_sender_error_code {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::CouldNotResolveAddr =>
                line_sender_error_code::line_sender_error_could_not_resolve_addr,
            ErrorCode::InvalidApiCall =>
                line_sender_error_code::line_sender_error_invalid_api_call,
            ErrorCode::SocketError =>
                line_sender_error_code::line_sender_error_socket_error,
            ErrorCode::InvalidUtf8 =>
                line_sender_error_code::line_sender_error_invalid_utf8,
            ErrorCode::InvalidName =>
                line_sender_error_code::line_sender_error_invalid_name,
            ErrorCode::AuthError =>
                line_sender_error_code::line_sender_error_auth_error,
            ErrorCode::TlsError =>
                line_sender_error_code::line_sender_error_tls_error,
        }
    }
}

/** Error code categorizing the error. */
#[no_mangle]
pub unsafe extern "C" fn line_sender_error_get_code(error: *const line_sender_error) -> line_sender_error_code {
    (&*error).0.code().into()
}

/// ASCII encoded error message. Never returns NULL.
#[no_mangle]
pub unsafe extern "C" fn line_sender_error_msg(error: *const line_sender_error, len_out: *mut size_t) -> *const c_char {
    let msg: &str = &(&*error).0.msg;
    *len_out = msg.len();
    msg.as_ptr() as *mut i8
}

/// Clean up the error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_error_free(error: *mut line_sender_error) {
    if !error.is_null() {
        drop(Box::from_raw(error));
    }
}

/// Non-owning validated UTF-8 encoded string.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_utf8 {
    /// Don't initialize fields directly.
    /// Call `line_sender_utf8_init` instead.
    len: size_t,
    buf: *const c_char
}

impl line_sender_utf8 {
    fn as_str(&self) -> &str {
        unsafe {
            std::str::from_utf8_unchecked(
                slice::from_raw_parts(
                    self.buf as *const u8,
                    self.len))
        }
    }
}

/// An ASCII-safe description of a binary buffer. Trimmed if too long.
fn describe_buf(buf: &[u8]) -> String {
    let max_len = 100usize;
    let trim = buf.len() >= max_len;
    let working_len = if trim {
            max_len - 3  // 3 here for trailing "..."
        } else {
            buf.len()
        };
    let sliced = &buf[0..working_len];
    // If every byte needs escaping we'll need to 4 times as many bytes,
    // + 1 for trailing \0 added by printf functions.
    let mut output = String::with_capacity(working_len * 4 + 1);

    for &c in sliced.iter() {
        for esc in ascii::escape_default(c) {
            output.push(esc as char);
        }
    }

    if trim {
        output.push_str("...");
    }

    output
}

unsafe fn set_err_out(err_out: *mut *mut line_sender_error, code: ErrorCode, msg: String) {
    let err = line_sender_error(Error{
        code: code,
        msg: msg});
    let err_ptr = Box::into_raw(Box::new(err));
    *err_out = err_ptr;
}

unsafe fn unwrap_utf8(buf: &[u8], err_out: *mut *mut line_sender_error) -> Option<&str> {
    match str::from_utf8(buf) {
        Ok(str_ref) => {
            Some(str_ref)
        },
        Err(u8err) => {
            let buf_descr = describe_buf(buf);
            let msg = if let Some(_err_len) = u8err.error_len() {
                    format!(
                        concat!(
                            "Bad string \"{}\": Invalid UTF-8. ",
                            "Illegal codepoint starting at byte index {}."),
                        buf_descr,
                        u8err.valid_up_to())
                }
                else {  // needs more input
                    format!(
                        concat!(
                            "Bad string \"{}\": Invalid UTF-8. ",
                            "Incomplete multi-byte codepoint at end of string. ",
                            "Bad codepoint starting at byte index {}."),
                        buf_descr,
                        u8err.valid_up_to())
                };
            set_err_out(err_out, ErrorCode::InvalidUtf8, msg);
            None
        }
    }
}

/// Check the provided buffer is a valid UTF-8 encoded string.
///
/// @param[out] str The object to be initialized.
/// @param[in] len Length in bytes of the buffer.
/// @param[in] buf UTF-8 encoded buffer.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_utf8_init(
    string: *mut line_sender_utf8,
    len: size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error) -> bool
{
    let slice = slice::from_raw_parts(buf as *const u8, len);
    if let Some(str_ref) = unwrap_utf8(slice, err_out) {
        (*string).len = str_ref.len();
        (*string).buf = str_ref.as_ptr() as *const c_char;
        true
    }
    else {
        false
    }
}

/// Non-owning validated table name. UTF-8 encoded.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_table_name
{
    /// Don't initialize fields directly.
    /// Call `line_sender_table_name_init` instead.
    len: size_t,
    buf: *const c_char
}

impl line_sender_table_name {
    fn as_name<'a>(&self) -> TableName<'a> {
        let str_name = unsafe { std::str::from_utf8_unchecked(
            slice::from_raw_parts(self.buf as *const u8, self.len)) };
        TableName{ name: str_name }
    }
}

/// Non-owning validated symbol or column name. UTF-8 encoded.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_column_name
{
    /// Don't initialize fields directly.
    /// Call `line_sender_column_name_init` instead.
    len: size_t,
    buf: *const c_char
}

impl line_sender_column_name {
    fn as_name<'a>(&self) -> ColumnName<'a> {
        let str_name = unsafe { std::str::from_utf8_unchecked(
            slice::from_raw_parts(self.buf as *const u8, self.len)) };
        ColumnName{ name: str_name }
    }
}

/// Check the provided buffer is a valid UTF-8 encoded string that can be
/// used as a table name.
///
/// @param[out] name The object to be initialized.
/// @param[in] len Length in bytes of the buffer.
/// @param[in] buf UTF-8 encoded buffer.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_table_name_init(
    name: *mut line_sender_table_name,
    len: size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error) -> bool
{
    let mut u8str = line_sender_utf8{len: 0usize, buf: ptr::null_mut()};
    if !line_sender_utf8_init(&mut u8str, len, buf, err_out) {
        return false;
    }

    let str_name = std::str::from_utf8_unchecked(
        slice::from_raw_parts(buf as *const u8, len));

    bubble_err_to_c!(err_out, TableName::new(str_name));

    (*name).len = len;
    (*name).buf = buf;
    true
}

/// Check the provided buffer is a valid UTF-8 encoded string that can be
/// used as a symbol or column name.
///
/// @param[out] name The object to be initialized.
/// @param[in] len Length in bytes of the buffer.
/// @param[in] buf UTF-8 encoded buffer.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_column_name_init(
    name: *mut line_sender_column_name,
    len: size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error) -> bool
{
    let mut u8str = line_sender_utf8{len: 0usize, buf: ptr::null_mut()};
    if !line_sender_utf8_init(&mut u8str, len, buf, err_out) {
        return false;
    }

    let str_name = std::str::from_utf8_unchecked(
        slice::from_raw_parts(buf as *const u8, len));

    bubble_err_to_c!(err_out, ColumnName::new(str_name));

    (*name).len = len;
    (*name).buf = buf;
    true
}

/// Accumulates parameters for creating a line sender connection.
pub struct line_sender_opts(LineSenderBuilder);

/// A new set of options for a line sender connection.
/// @param[in] host The QuestDB database host.
/// @param[in] port The QuestDB database port.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_new(
    host: line_sender_utf8,
    port: u16) -> *mut line_sender_opts
{
    let builder = LineSenderBuilder::new(host.as_str(), port);
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// A new set of options for a line sender connection.
/// @param[in] host The QuestDB database host.
/// @param[in] port The QuestDB database port as service name.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_new_service(
    host: line_sender_utf8,
    port: line_sender_utf8) -> *mut line_sender_opts
{
    let builder = LineSenderBuilder::new(host.as_str(), port.as_str());
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Set the initial buffer capacity (byte count).
/// The default is 65536.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_capacity(
    opts: *mut line_sender_opts,
    capacity: size_t)
{
    upd_opts!(opts, capacity, capacity);
}

/// Select local outbound interface.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_net_interface(
    opts: *mut line_sender_opts,
    net_interface: line_sender_utf8)
{
    upd_opts!(opts, net_interface, net_interface.as_str());
}

/// Authentication Parameters.
/// @param[in] key_id Key id. AKA "kid"
/// @param[in] priv_key Private key. AKA "d".
/// @param[in] pub_key_x Public key X coordinate. AKA "x".
/// @param[in] pub_key_y Public key Y coordinate. AKA "y".
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_auth(
    opts: *mut line_sender_opts,
    key_id: line_sender_utf8,
    priv_key: line_sender_utf8,
    pub_key_x: line_sender_utf8,
    pub_key_y: line_sender_utf8)
{
    upd_opts!(opts, auth,
        key_id.as_str(),
        priv_key.as_str(),
        pub_key_x.as_str(),
        pub_key_y.as_str());
}

/// Enable full connection encryption via TLS.
/// The connection will accept certificates by well-known certificate
/// authorities as per the "webpki-roots" Rust crate.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls(
    opts: *mut line_sender_opts)
{
    upd_opts!(opts, tls,
        Tls::Enabled(CertificateAuthority::WebpkiRoots));
}

/// Enable full connection encryption via TLS.
/// The connection will accept certificates by the specified certificate
/// authority file.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_ca(
    opts: *mut line_sender_opts,
    ca_path: line_sender_utf8)
{
    let ca_path = PathBuf::from(ca_path.as_str());
    upd_opts!(opts, tls,
        Tls::Enabled(CertificateAuthority::File(ca_path)));
}

/// Enable TLS whilst dangerously accepting any certificate as valid.
/// This should only be used for debugging.
/// Consider using calling "tls_ca" instead.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_insecure_skip_verify(
    opts: *mut line_sender_opts)
{
    upd_opts!(opts, tls, Tls::InsecureSkipVerify);
}

/// Configure how long to wait for messages from the QuestDB server during
/// the TLS handshake and authentication process.
/// The default is 15 seconds.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_read_timeout(
    opts: *mut line_sender_opts,
    timeout_millis: u64)
{
    let timeout = std::time::Duration::from_millis(timeout_millis);
    upd_opts!(opts, read_timeout, timeout);
}

/// Set the maximum length for table and column names.
/// This should match the `cairo.max.file.name.length` setting of the
/// QuestDB instance you're connecting to.
/// The default value is 127, which is the same as the QuestDB default.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_max_name_len(
    opts: *mut line_sender_opts,
    value: size_t)
{
    upd_opts!(opts, max_name_len, value);
}

/// Duplicate the opts object.
/// Both old and new objects will have to be freed.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_clone(
    opts: *const line_sender_opts) -> *mut line_sender_opts
{
    let builder = &(*opts).0;
    let new_builder = builder.clone();
    Box::into_raw(Box::new(line_sender_opts(new_builder)))
}

/// Release the opts object.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_free(
    opts: *mut line_sender_opts)
{
    if !opts.is_null() {
        drop(Box::from_raw(opts));
    }
}

/// Insert data into QuestDB via the InfluxDB Line Protocol.
///
/// Batch up rows, then call `line_sender_flush` to send.
pub struct line_sender(LineSender);

/// Synchronously connect to the QuestDB database.
/// The connection should be accessed by only a single thread a time.
/// @param[in] opts Options for the connection.
#[no_mangle]
pub unsafe extern "C" fn line_sender_connect(
    opts: *const line_sender_opts,
    err_out: *mut *mut line_sender_error) -> *mut line_sender
{
    let builder = &(*opts).0;
    let sender = bubble_err_to_c!(err_out, builder.connect(), ptr::null_mut());
    Box::into_raw(Box::new(line_sender(sender)))
}

unsafe fn unwrap_sender<'a>(sender: *const line_sender) -> &'a LineSender {
    &(&*sender).0
}

unsafe fn unwrap_sender_mut<'a>(sender: *mut line_sender) -> &'a mut LineSender {
    &mut (&mut *sender).0
}

/// Check if an error occurred previously and the sender must be closed.
/// @param[in] sender Line sender object.
/// @return true if an error occurred with a sender and it must be closed.
#[no_mangle]
pub unsafe extern "C" fn line_sender_must_close(sender: *const line_sender) -> bool {
    unwrap_sender(sender).must_close()
}

/// Close the connection. Does not flush. Non-idempotent.
/// @param[in] sender Line sender object.
#[no_mangle]
pub unsafe extern "C" fn line_sender_close(sender: *mut line_sender) {
    if !sender.is_null() {
        drop(Box::from_raw(sender));
    }
}

/// Start batching the next row of input for the named table.
/// @param[in] sender Line sender object.
/// @param[in] name Table name.
#[no_mangle]
pub unsafe extern "C" fn line_sender_table(
    sender: *mut line_sender,
    name: line_sender_table_name,
    err_out: *mut *mut line_sender_error) -> bool
{
    let sender = unwrap_sender_mut(sender);
    bubble_err_to_c!(err_out, sender.table(name.as_name()));
    true
}

/// Append a value for a SYMBOL column.
/// Symbol columns must always be written before other columns for any given row.
/// @param[in] sender Line sender object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_symbol(
    sender: *mut line_sender,
    name: line_sender_column_name,
    value: line_sender_utf8,
    err_out: *mut *mut line_sender_error) -> bool
{
    let sender = unwrap_sender_mut(sender);
    bubble_err_to_c!(
        err_out,
        sender.symbol(name.as_name(), value.as_str()));
    true
}

/// Append a value for a BOOLEAN column.
/// @param[in] sender Line sender object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_column_bool(
    sender: *mut line_sender,
    name: line_sender_column_name,
    value: bool,
    err_out: *mut *mut line_sender_error) -> bool
{
    let sender = unwrap_sender_mut(sender);
    bubble_err_to_c!(
        err_out,
        sender.column_bool(name.as_name(), value));
    true
}

/// Append a value for a LONG column.
/// @param[in] sender Line sender object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_column_i64(
    sender: *mut line_sender,
    name: line_sender_column_name,
    value: i64,
    err_out: *mut *mut line_sender_error) -> bool
{
    let sender = unwrap_sender_mut(sender);
    bubble_err_to_c!(
        err_out,
        sender.column_i64(name.as_name(), value));
    true
}

/// Append a value for a DOUBLE column.
/// @param[in] sender Line sender object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_column_f64(
    sender: *mut line_sender,
    name: line_sender_column_name,
    value: f64,
    err_out: *mut *mut line_sender_error) -> bool
{
    let sender = unwrap_sender_mut(sender);
    bubble_err_to_c!(
        err_out,
        sender.column_f64(name.as_name(), value));
    true
}

/// Append a value for a STRING column.
/// @param[in] sender Line sender object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_column_str(
    sender: *mut line_sender,
    name: line_sender_column_name,
    value: line_sender_utf8,
    err_out: *mut *mut line_sender_error) -> bool
{
    let sender = unwrap_sender_mut(sender);
    bubble_err_to_c!(
        err_out,
        sender.column_str(name.as_name(), value.as_str()));
    true
}

/// Complete the row with a specified timestamp.
///
/// After this call, you can start batching the next row by calling
/// `line_sender_table` again, or you can send the accumulated batch by
/// calling `line_sender_flush`.
///
/// @param[in] sender Line sender object.
/// @param[in] epoch_nanos Number of nanoseconds since 1st Jan 1970 UTC.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_at(
    sender: *mut line_sender,
    epoch_nanos: i64,
    err_out: *mut *mut line_sender_error) -> bool
{
    let sender = unwrap_sender_mut(sender);
    bubble_err_to_c!(
        err_out,
        sender.at(epoch_nanos));
    true
}

/// Complete the row without providing a timestamp.
/// The QuestDB instance will insert its own timestamp.
///
/// After this call, you can start batching the next row by calling
/// `line_sender_table` again, or you can send the accumulated batch by
/// calling `line_sender_flush`.
///
/// @param[in] sender Line sender object.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_at_now(
    sender: *mut line_sender,
    err_out: *mut *mut line_sender_error) -> bool
{
    let sender = unwrap_sender_mut(sender);
    bubble_err_to_c!(
        err_out,
        sender.at_now());
    true
}

/// Number of bytes that will be sent at next call to `line_sender_flush`.
///
/// @param[in] sender Line sender object.
/// @return Accumulated batch size.
#[no_mangle]
pub unsafe extern "C" fn line_sender_pending_size(
    sender: *const line_sender) -> size_t
{
    let sender = unwrap_sender(sender);
    sender.pending_size()
}

/// Peek into the accumulated buffer that is to be sent out at the next `flush`.
///
/// @param[in] sender Line sender object.
/// @param[out] len_out The length in bytes of the accumulated buffer.
/// @return UTF-8 encoded buffer. The buffer is not nul-terminated.
#[no_mangle]
pub unsafe extern "C" fn line_sender_peek_pending(
    sender: *const line_sender,
    len_out: *mut size_t) -> *const c_char
{
    let sender = unwrap_sender(sender);
    let buf: &[u8] = sender.peek_pending().as_bytes();
    *len_out = buf.len();
    buf.as_ptr() as *const c_char
}

/// Send batch-up rows messages to the QuestDB server.
///
/// After sending a batch, you can close the connection or begin preparing
/// a new batch by calling `line_sender_table`.
///
/// @param[in] sender Line sender object.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_flush(
    sender: *mut line_sender,
    err_out: *mut *mut line_sender_error) -> bool
{
    let sender = unwrap_sender_mut(sender);
    bubble_err_to_c!(
        err_out,
        sender.flush());
    true
}
