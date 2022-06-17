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
use std::slice;
use std::str;
use std::ffi::CStr;
use libc::c_char;


/// An error that occurred when using the line sender.
pub struct line_sender_error(super::Error);

/// Category of error.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum line_sender_error_code {
    /// The host, port, or interface was incorrect.
    line_sender_error_could_not_resolve_addr,

    /// Called methods in the wrong order. E.g. `symbol` after `column`.
    line_sender_error_invalid_api_call,

    /// A network error connecting of flushing data out.
    line_sender_error_socket_error,

    /// The string or symbol field is not encoded in valid UTF-8.
    line_sender_error_invalid_utf8,

    /// The table name, symbol name or column name contains bad characters.
    line_sender_error_invalid_name,

    /** Error during the authentication process. */
    line_sender_error_auth_error
}

impl From<super::ErrorCode> for line_sender_error_code {
    fn from(code: super::ErrorCode) -> Self {
        match code {
            super::ErrorCode::CouldNotResolveAddr =>
                line_sender_error_code::line_sender_error_could_not_resolve_addr,
            super::ErrorCode::InvalidApiCall =>
                line_sender_error_code::line_sender_error_invalid_api_call,
            super::ErrorCode::SocketError =>
                line_sender_error_code::line_sender_error_socket_error,
            super::ErrorCode::InvalidUtf8 =>
                line_sender_error_code::line_sender_error_invalid_utf8,
            super::ErrorCode::InvalidName =>
                line_sender_error_code::line_sender_error_invalid_name,
            super::ErrorCode::AuthError =>
                line_sender_error_code::line_sender_error_auth_error
        }
    }
}

/** Error code categorizing the error. */
#[no_mangle]
pub extern "C" fn line_sender_error_get_code(error: *const line_sender_error) -> line_sender_error_code {
    unsafe { &*error }.0.code().into()
}

/// ASCII encoded error message. Never returns NULL.
#[no_mangle]
pub extern "C" fn line_sender_error_msg(error: *const line_sender_error, len_out: *mut libc::size_t) -> *const c_char {
    let msg: &str = &unsafe { &*error }.0.msg;
    unsafe { *len_out = msg.len() };
    msg.as_ptr() as *mut i8
}

/// Clean up the error.
#[no_mangle]
pub extern "C" fn line_sender_error_free(error: *mut line_sender_error) {
    unsafe { Box::from_raw(error) };  // drop and free up memory.
}

/// Non-owning validated UTF-8 encoded string.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_utf8 {
    /// Don't initialize fields directly.
    /// Call `line_sender_utf8_init` instead.
    len: libc::size_t,
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

fn set_err_out(err_out: *mut *mut line_sender_error, code: super::ErrorCode, msg: String) {
    let err = line_sender_error(super::Error{
        code: code,
        msg: msg});
    let err_ptr = Box::into_raw(Box::new(err));
    unsafe { *err_out = err_ptr };
}

fn unwrap_utf8(buf: &[u8], err_out: *mut *mut line_sender_error) -> Option<&str> {
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
            set_err_out(err_out, super::ErrorCode::InvalidUtf8, msg);
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
pub extern "C" fn line_sender_utf8_init(
    string: *mut line_sender_utf8,
    len: libc::size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error) -> bool
{
    let slice = unsafe { slice::from_raw_parts(buf as *const u8, len) };
    if let Some(str_ref) = unwrap_utf8(slice, err_out) {
        unsafe {
            (*string).len = str_ref.len();
            (*string).buf = str_ref.as_ptr() as *const c_char;
        }
        true
    }
    else {
        false
    }
}

/// Non-owning validated table, symbol or column name. UTF-8 encoded.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_name
{
    /// Don't initialize fields directly.
    /// Call `line_sender_name_init` instead.
    len: libc::size_t,
    buf: *const c_char
}

impl line_sender_name {
    fn as_name<'a>(&self) -> super::Name<'a> {
        let str_name = unsafe { std::str::from_utf8_unchecked(
            slice::from_raw_parts(self.buf as *const u8, self.len)) };
        super::Name{ name: str_name }
    }
}

macro_rules! bubble_err_to_c {
    ($err_out:expr, $expression:expr) => {
        if let Err(err) = $expression {
            let err_ptr = Box::into_raw(Box::new(line_sender_error(err)));
            unsafe { *$err_out = err_ptr };
            return false;
        }
    };
}

/// Authentication options.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_sec_opts
{
    /// Authentication key_id. AKA "kid".
    auth_key_id : *const libc::c_char,

    /// Authentication private key. AKA "d".
    auth_priv_key : *const libc::c_char,

    /// Authentication public key X coordinate. AKA "x".
    auth_pub_key_x : * const libc::c_char,

    /// Authentication public key Y coordinate. AKA "y".
    auth_pub_key_y : * const libc::c_char
}


/// Check the provided buffer is a valid UTF-8 encoded string that can be
/// used as a table name, symbol name or column name.
///
/// The string must not contain the following characters:
/// `?`, `.`,  `,`, `'`, `"`, `\`, `/`, `:`, `(`, `)`, `+`, `-`, `*`, `%`, `~`,
/// `' '` (space), `\0` (nul terminator), \uFEFF (ZERO WIDTH NO-BREAK SPACE).
///
/// @param[out] name The object to be initialized.
/// @param[in] len Length in bytes of the buffer.
/// @param[in] buf UTF-8 encoded buffer.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub extern "C" fn line_sender_name_init(
    name: *mut line_sender_name,
    len: libc::size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error) -> bool
{
    let mut u8str = line_sender_utf8{len: 0usize, buf: std::ptr::null_mut()};
    if !line_sender_utf8_init(&mut u8str, len, buf, err_out) {
        return false;
    }

    let str_name = unsafe { std::str::from_utf8_unchecked(
        slice::from_raw_parts(buf as *const u8, len)) };

    bubble_err_to_c!(err_out, super::Name::new(str_name));

    unsafe {
        (*name).len = len;
        (*name).buf = buf;
    }
    true
}

/// Insert data into QuestDB via the InfluxDB Line Protocol.
///
/// Batch up rows, then call `line_sender_flush` to send.
pub struct line_sender(super::LineSender);

/// Synchronously connect to the QuestDB database.
/// @param[in] net_interface Network interface to bind to.
/// If unsure, to bind to all specify "0.0.0.0".
/// @param[in] host QuestDB host, e.g. "localhost". nul-terminated.
/// @param[in] port QuestDB port, e.g. "9009". nul-terminated.
/// @param[out] err_out Set on error.
/// @return Connected sender object or NULL on error.
#[no_mangle]
pub extern "C" fn line_sender_connect(
    net_interface: *const libc::c_char,
    host: *const libc::c_char,
    port: *const libc::c_char,
    err_out: *mut *mut line_sender_error) -> *mut line_sender
{
    line_sender_connect_secure(
        net_interface,
        host,
        port,
        std::ptr::null(),
        err_out)
}

fn set_sec_opts(
    builder: &mut super::LineSenderBuilder,
    sec_opts: *const line_sender_sec_opts,
    err_out: *mut *mut line_sender_error) -> bool
{
    if sec_opts.is_null() {
        return true;
    }

    let auth_key_id = unsafe { (*sec_opts).auth_key_id };
    let auth_priv_key = unsafe { (*sec_opts).auth_priv_key };
    let auth_pub_key_x = unsafe { (*sec_opts).auth_pub_key_x };
    let auth_pub_key_y = unsafe { (*sec_opts).auth_pub_key_y };

    if auth_key_id.is_null() && auth_priv_key.is_null() &&
       auth_pub_key_x.is_null() && auth_pub_key_y.is_null() {
        return true;
    }
    else if auth_key_id.is_null() || auth_priv_key.is_null() ||
            auth_pub_key_x.is_null() || auth_pub_key_y.is_null() {
        set_err_out(
            err_out,
            super::ErrorCode::InvalidApiCall,
            "Must specify all or no auth parameters.".to_owned());
        return false;
    }

    let auth_key_id =
        if let Some(str_ref) = unwrap_utf8(unsafe {CStr::from_ptr(auth_key_id)}.to_bytes(), err_out) {
            str_ref
        }
        else {
            return false;
        };

    let auth_priv_key =
        if let Some(str_ref) = unwrap_utf8(unsafe {CStr::from_ptr(auth_priv_key)}.to_bytes(), err_out) {
            str_ref
        }
        else {
            return false;
        };

    let auth_pub_key_x =
        if let Some(str_ref) = unwrap_utf8(unsafe {CStr::from_ptr(auth_pub_key_x)}.to_bytes(), err_out) {
            str_ref
        }
        else {
            return false;
        };

    let auth_pub_key_y =
        if let Some(str_ref) = unwrap_utf8(unsafe {CStr::from_ptr(auth_pub_key_y)}.to_bytes(), err_out) {
            str_ref
        }
        else {
            return false;
        };

    builder.auth(auth_key_id, auth_priv_key, auth_pub_key_x, auth_pub_key_y);
    true
}

/// Synchronously connect securely to the QuestDB database.
/// @param[in] net_interface Network interface to bind to.
/// If unsure, to bind to all specify "0.0.0.0".
/// @param[in] host QuestDB host, e.g. "localhost". nul-terminated.
/// @param[in] port QuestDB port, e.g. "9009". nul-terminated.
/// @param[in] sec_opts Security options for authentication.
/// @param[out] err_out Set on error.
/// @return Connected sender object or NULL on error.
#[no_mangle]
pub extern "C" fn line_sender_connect_secure(
    net_interface: *const libc::c_char,
    host: *const libc::c_char,
    port: *const libc::c_char,
    sec_opts: *const line_sender_sec_opts,
    err_out: *mut *mut line_sender_error) -> *mut line_sender
{
    let host: &str =
        if let Some(str_ref) = unwrap_utf8(unsafe {CStr::from_ptr(host)}.to_bytes(), err_out) {
            str_ref
        }
        else {
            return std::ptr::null_mut();
        };

    let port: &str =
        if let Some(str_ref) = unwrap_utf8(unsafe {CStr::from_ptr(port)}.to_bytes(), err_out) {
            str_ref
        }
        else {
            return std::ptr::null_mut();
        };

    let net_interface: Option<&str> =
        if net_interface == std::ptr::null() {
            None
        }
        else if let Some(str_ref) = unwrap_utf8(unsafe {CStr::from_ptr(net_interface)}.to_bytes(), err_out) {
            Some(str_ref)
        }
        else {
            return std::ptr::null_mut();
        };

    let mut builder = super::LineSenderBuilder::new(host, port);
    if let Some(net_interface) = net_interface {
        builder.net_interface(net_interface);
    }

    if !set_sec_opts(&mut builder, sec_opts, err_out) {
        return std::ptr::null_mut();
    }

    let sender = match builder.connect() {
            Ok(sender) => sender,
            Err(err) => {
                let err = line_sender_error(err);
                let err_ptr = Box::into_raw(Box::new(err));
                unsafe { *err_out = err_ptr; };
                return std::ptr::null_mut();
            }
        };
    Box::into_raw(Box::new(line_sender(sender)))
}

fn unwrap_sender<'a>(sender: *const line_sender) -> &'a super::LineSender {
    &(unsafe { &*sender }).0
}

fn unwrap_sender_mut<'a>(sender: *mut line_sender) -> &'a mut super::LineSender {
    &mut (unsafe { &mut *sender }).0
}

/// Check if an error occured previously and the sender must be closed.
/// @param[in] sender Line sender object.
/// @return true if an error occured with a sender and it must be closed.
#[no_mangle]
pub extern "C" fn line_sender_must_close(sender: *const line_sender) -> bool {
    unwrap_sender(sender).must_close()
}

/// Close the connection. Does not flush. Non-idempotent.
/// @param[in] sender Line sender object.
#[no_mangle]
pub extern "C" fn line_sender_close(sender: *mut line_sender) {
    unsafe { Box::from_raw(sender) };  // drop and free up memory.
}

/// Start batching the next row of input for the named table.
/// @param[in] sender Line sender object.
/// @param[in] name Table name.
#[no_mangle]
pub extern "C" fn line_sender_table(
    sender: *mut line_sender,
    name: line_sender_name,
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
pub extern "C" fn line_sender_symbol(
    sender: *mut line_sender,
    name: line_sender_name,
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
pub extern "C" fn line_sender_column_bool(
    sender: *mut line_sender,
    name: line_sender_name,
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
pub extern "C" fn line_sender_column_i64(
    sender: *mut line_sender,
    name: line_sender_name,
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
pub extern "C" fn line_sender_column_f64(
    sender: *mut line_sender,
    name: line_sender_name,
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
pub extern "C" fn line_sender_column_str(
    sender: *mut line_sender,
    name: line_sender_name,
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
pub extern "C" fn line_sender_at(
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
pub extern "C" fn line_sender_at_now(
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
pub extern "C" fn line_sender_pending_size(
    sender: *const line_sender) -> libc::size_t
{
    let sender = unwrap_sender(sender);
    sender.pending_size()
}

/// Send batch-up rows messages to the QuestDB server.
///
/// After sending a batch, you can close the connection or begin preparing
/// a new batch by calling `line_sender_table`.
///
/// @param[in] sender Line sender object.
/// @return true on success, false on error.
#[no_mangle]
pub extern "C" fn line_sender_flush(
    sender: *mut line_sender,
    err_out: *mut *mut line_sender_error) -> bool
{
    let sender = unwrap_sender_mut(sender);
    bubble_err_to_c!(
        err_out,
        sender.flush());
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
