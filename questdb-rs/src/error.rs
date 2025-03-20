use std::fmt::{Display, Formatter};
use ureq::Error::StatusCode;

macro_rules! fmt {
    ($code:ident, $($arg:tt)*) => {
        crate::error::Error::new(
            crate::error::ErrorCode::$code,
            format!($($arg)*))
    }
}

/// Category of error.
///
/// Accessible via Error's [`code`](Error::code) method.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ErrorCode {
    /// The host, port, or interface was incorrect.
    CouldNotResolveAddr,

    /// Called methods in the wrong order. E.g. `symbol` after `column`.
    InvalidApiCall,

    /// A network error connecting or flushing data out.
    SocketError,

    /// The string or symbol field is not encoded in valid UTF-8.
    ///
    /// *This error is reserved for the
    /// [C and C++ API](https://github.com/questdb/c-questdb-client/).*
    InvalidUtf8,

    /// The table name or column name contains bad characters.
    InvalidName,

    /// The supplied timestamp is invalid.
    InvalidTimestamp,

    /// Error during the authentication process.
    AuthError,

    /// Error during TLS handshake.
    TlsError,

    /// The server does not support ILP-over-HTTP.
    HttpNotSupported,

    /// Error sent back from the server during flush.
    ServerFlushError,

    /// Bad configuration.
    ConfigError,
}

/// An error that occurred when using QuestDB client library.
#[derive(Debug, PartialEq)]
pub struct Error {
    code: ErrorCode,
    msg: String,
}

impl Error {
    /// Create an error with the given code and message.
    pub fn new<S: Into<String>>(code: ErrorCode, msg: S) -> Error {
        Error {
            code,
            msg: msg.into(),
        }
    }

    /// Get the error code (category) of this error.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Get the string message of this error.
    pub fn msg(&self) -> &str {
        &self.msg
    }
}

impl From<ureq::Error> for Error {
    fn from(err: ureq::Error) -> Error {
        match err {
            StatusCode(code) => {
                if code == 404 {
                    fmt!(
                        HttpNotSupported,
                        "Could not flush buffer: HTTP endpoint does not support ILP."
                    )
                } else if [401, 403].contains(&code) {
                    fmt!(
                        AuthError,
                        "Could not flush buffer: HTTP endpoint authentication error [code: {}]",
                        code
                    )
                } else {
                    fmt!(SocketError, "Could not flush buffer: {}", err)
                }
            }
            ureq::Error::Http(e) => {
                fmt!(
                    SocketError,
                    "Could not flush buffer: Inner http error: {}",
                    e
                )
            }
            ureq::Error::BadUri(s) => {
                fmt!(SocketError, "Could not flush buffer: Bad uri  {}", s)
            }
            ureq::Error::Protocol(e) => {
                fmt!(SocketError, "Could not flush buffer: Protocol error: {}", e)
            }
            ureq::Error::Io(e) => {
                fmt!(SocketError, "Could not flush buffer: Io error: {}", e)
            }
            ureq::Error::Timeout(e) => {
                fmt!(SocketError, "Could not flush buffer: Timeout {}", e)
            }
            ureq::Error::Tls(e) => {
                fmt!(SocketError, "Could not flush buffer: Tls error: {}", e)
            }
            e => {
                fmt!(SocketError, "Could not flush buffer: other error: {}", e)
            }
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

/// A specialized `Result` type for the crate's [`Error`] type.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) use fmt;
