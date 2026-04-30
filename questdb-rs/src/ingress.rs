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

#![doc = include_str!("ingress/mod.md")]

pub use self::ndarr::{ArrayElement, NdArrayView};
pub use self::timestamp::*;
use crate::error::{self, Result, fmt};
use crate::ingress::conf::ConfigSetting;
use core::time::Duration;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter, Write};

use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;

mod tls;

#[cfg(all(feature = "_sender-tcp", feature = "aws-lc-crypto"))]
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};

#[cfg(all(feature = "_sender-tcp", feature = "ring-crypto"))]
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};

mod conf;

pub(crate) mod ndarr;

mod timestamp;

mod buffer;
pub use buffer::*;

mod sender;
#[cfg(all(test, feature = "sync-sender-qwp-ws"))]
pub(crate) use sender::qwp_ws_test_support;
pub use sender::*;

mod decimal;
pub use decimal::DecimalView;

const MAX_NAME_LEN_DEFAULT: usize = 127;

/// The maximum allowed dimensions for arrays.
pub const MAX_ARRAY_DIMS: usize = 32;
pub const MAX_ARRAY_BUFFER_SIZE: usize = 512 * 1024 * 1024; // 512MiB
pub const MAX_ARRAY_DIM_LEN: usize = 0x0FFF_FFFF; // 1 << 28 - 1

pub(crate) const ARRAY_BINARY_FORMAT_TYPE: u8 = 14;
pub(crate) const DOUBLE_BINARY_FORMAT_TYPE: u8 = 16;
#[allow(dead_code)]
pub const DECIMAL_BINARY_FORMAT_TYPE: u8 = 23;

/// Transport-scoped protocol version identifier used by the ingestion APIs.
///
/// Interpret this value together with the transport protocol.
/// The same version number may correspond to different wire formats or feature
/// sets on different transports.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum ProtocolVersion {
    /// Version 1.
    V1 = 1,

    /// Version 2.
    V2 = 2,

    /// Version 3.
    V3 = 3,
}

/// List of supported ILP protocol versions, in order of preference (highest to lowest).
#[cfg(feature = "_sender-http")]
const SUPPORTED_PROTOCOL_VERSIONS: [ProtocolVersion; 3] = [
    ProtocolVersion::V3,
    ProtocolVersion::V2,
    ProtocolVersion::V1,
];

impl Display for ProtocolVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolVersion::V1 => write!(f, "v1"),
            ProtocolVersion::V2 => write!(f, "v2"),
            ProtocolVersion::V3 => write!(f, "v3"),
        }
    }
}

#[cfg(feature = "_sender-tcp")]
fn map_io_to_socket_err(prefix: &str, io_err: std::io::Error) -> error::Error {
    fmt!(SocketError, "{}{}", prefix, io_err)
}

/// Possible sources of the root certificates used to validate the server's TLS
/// certificate.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum CertificateAuthority {
    /// Use the root certificates provided by the
    /// [`webpki-roots`](https://crates.io/crates/webpki-roots) crate.
    #[cfg(feature = "tls-webpki-certs")]
    WebpkiRoots,

    /// Use the root certificates provided by the OS
    #[cfg(feature = "tls-native-certs")]
    OsRoots,

    /// Combine the root certificates provided by the OS and the `webpki-roots` crate.
    #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
    WebpkiAndOsRoots,

    /// Use the root certificates provided in a PEM-encoded file.
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

fn validate_auto_flush_params(params: &HashMap<String, String>) -> Result<()> {
    if let Some(auto_flush) = params.get("auto_flush")
        && auto_flush.as_str() != "off"
    {
        return Err(error::fmt!(
            ConfigError,
            "Invalid auto_flush value '{auto_flush}'. This client does not \
            support auto-flush, so the only accepted value is 'off'"
        ));
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
    #[cfg(feature = "_sender-tcp")]
    /// ILP over TCP (streaming).
    Tcp,

    #[cfg(feature = "_sender-tcp")]
    /// TCP + TLS
    Tcps,

    #[cfg(feature = "_sender-http")]
    /// ILP over HTTP (request-response)
    /// Version 1 is compatible with the InfluxDB Line Protocol.
    Http,

    #[cfg(feature = "_sender-http")]
    /// HTTP + TLS
    Https,

    #[cfg(feature = "_sender-qwp-udp")]
    /// Quest Wire Protocol over UDP datagrams (IPv4-only).
    QwpUdp,

    #[cfg(feature = "_sender-qwp-ws")]
    /// Quest Wire Protocol over WebSocket (RFC 6455).
    QwpWs,

    #[cfg(feature = "_sender-qwp-ws")]
    /// Quest Wire Protocol over WebSocket Secure (TLS).
    QwpWss,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.write_str(self.schema())
    }
}

impl Protocol {
    fn default_port(&self) -> &str {
        match self {
            #[cfg(feature = "_sender-tcp")]
            Protocol::Tcp | Protocol::Tcps => "9009",
            #[cfg(feature = "_sender-http")]
            Protocol::Http | Protocol::Https => "9000",
            #[cfg(feature = "_sender-qwp-udp")]
            Protocol::QwpUdp => "9007",
            #[cfg(feature = "_sender-qwp-ws")]
            Protocol::QwpWs | Protocol::QwpWss => "9000",
        }
    }

    fn tls_enabled(&self) -> bool {
        match self {
            #[cfg(feature = "_sender-tcp")]
            Protocol::Tcp => false,
            #[cfg(feature = "_sender-tcp")]
            Protocol::Tcps => true,
            #[cfg(feature = "_sender-http")]
            Protocol::Http => false,
            #[cfg(feature = "_sender-http")]
            Protocol::Https => true,
            #[cfg(feature = "_sender-qwp-udp")]
            Protocol::QwpUdp => false,
            #[cfg(feature = "_sender-qwp-ws")]
            Protocol::QwpWs => false,
            #[cfg(feature = "_sender-qwp-ws")]
            Protocol::QwpWss => true,
        }
    }

    #[cfg(feature = "_sender-tcp")]
    fn is_tcpx(&self) -> bool {
        match self {
            Protocol::Tcp | Protocol::Tcps => true,
            #[cfg(feature = "_sender-http")]
            Protocol::Http | Protocol::Https => false,
            #[cfg(feature = "_sender-qwp-udp")]
            Protocol::QwpUdp => false,
            #[cfg(feature = "_sender-qwp-ws")]
            Protocol::QwpWs | Protocol::QwpWss => false,
        }
    }

    #[cfg(feature = "_sender-http")]
    fn is_httpx(&self) -> bool {
        match self {
            #[cfg(feature = "_sender-tcp")]
            Protocol::Tcp | Protocol::Tcps => false,
            Protocol::Http | Protocol::Https => true,
            #[cfg(feature = "_sender-qwp-udp")]
            Protocol::QwpUdp => false,
            #[cfg(feature = "_sender-qwp-ws")]
            Protocol::QwpWs | Protocol::QwpWss => false,
        }
    }

    #[cfg(feature = "_sender-qwp-udp")]
    fn is_qwp_udp(&self) -> bool {
        matches!(self, Protocol::QwpUdp)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn is_qwp_ws(&self) -> bool {
        matches!(self, Protocol::QwpWs | Protocol::QwpWss)
    }

    /// True if the protocol authenticates via HTTP-style headers
    /// (basic / bearer-token), i.e. ILP/HTTP or QWP/WebSocket.
    #[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
    fn accepts_http_auth(&self) -> bool {
        let mut accepts = false;
        #[cfg(feature = "_sender-http")]
        if self.is_httpx() {
            accepts = true;
        }
        #[cfg(feature = "_sender-qwp-ws")]
        if self.is_qwp_ws() {
            accepts = true;
        }
        accepts
    }

    fn schema(&self) -> &str {
        match self {
            #[cfg(feature = "_sender-tcp")]
            Protocol::Tcp => "tcp",
            #[cfg(feature = "_sender-tcp")]
            Protocol::Tcps => "tcps",
            #[cfg(feature = "_sender-http")]
            Protocol::Http => "http",
            #[cfg(feature = "_sender-http")]
            Protocol::Https => "https",
            #[cfg(feature = "_sender-qwp-udp")]
            Protocol::QwpUdp => "qwpudp",
            #[cfg(feature = "_sender-qwp-ws")]
            Protocol::QwpWs => "qwpws",
            #[cfg(feature = "_sender-qwp-ws")]
            Protocol::QwpWss => "qwpwss",
        }
    }

    fn from_schema(schema: &str) -> Result<Self> {
        match schema {
            #[cfg(feature = "_sender-tcp")]
            "tcp" => Ok(Protocol::Tcp),
            #[cfg(feature = "_sender-tcp")]
            "tcps" => Ok(Protocol::Tcps),
            #[cfg(feature = "_sender-http")]
            "http" => Ok(Protocol::Http),
            #[cfg(feature = "_sender-http")]
            "https" => Ok(Protocol::Https),
            #[cfg(feature = "_sender-qwp-udp")]
            "qwpudp" => Ok(Protocol::QwpUdp),
            #[cfg(feature = "_sender-qwp-ws")]
            "qwpws" => Ok(Protocol::QwpWs),
            #[cfg(feature = "_sender-qwp-ws")]
            "qwpwss" => Ok(Protocol::QwpWss),
            _ => Err(error::fmt!(ConfigError, "Unsupported protocol: {}", schema)),
        }
    }
}

/// Accumulates parameters for a new `Sender` instance.
///
/// You can also create the builder from a config string.
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
/// Or create it from the `QDB_CLIENT_CONF` environment variable.
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
/// The `SenderBuilder` can also be built programmatically.
/// The minimum required parameters are the protocol, host, and port.
///
/// ```no_run
/// # use questdb::Result;
/// use questdb::ingress::SenderBuilder;
/// use questdb::ingress::Protocol;
///
/// # fn main() -> Result<()> {
/// # #[cfg(feature = "sync-sender-http")] {
/// let mut sender = SenderBuilder::new(Protocol::Http, "localhost", 9000).build()?;
/// # }
/// # #[cfg(all(not(feature = "sync-sender-http"), feature = "sync-sender-tcp"))] {
/// let mut sender = SenderBuilder::new(Protocol::Tcp, "localhost", 9009).build()?;
/// # }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SenderBuilder {
    protocol: Protocol,
    host: ConfigSetting<String>,
    port: ConfigSetting<String>,
    net_interface: ConfigSetting<Option<String>>,
    max_buf_size: ConfigSetting<usize>,
    max_name_len: ConfigSetting<usize>,
    auth_timeout: ConfigSetting<Duration>,
    username: ConfigSetting<Option<String>>,
    password: ConfigSetting<Option<String>>,
    token: ConfigSetting<Option<String>>,

    #[cfg(feature = "_sender-tcp")]
    token_x: ConfigSetting<Option<String>>,

    #[cfg(feature = "_sender-tcp")]
    token_y: ConfigSetting<Option<String>>,

    protocol_version: ConfigSetting<Option<ProtocolVersion>>,

    #[cfg(feature = "insecure-skip-verify")]
    tls_verify: ConfigSetting<bool>,

    tls_ca: ConfigSetting<CertificateAuthority>,
    tls_roots: ConfigSetting<Option<PathBuf>>,

    #[cfg(feature = "_sender-http")]
    http: Option<conf::HttpConfig>,

    #[cfg(feature = "_sender-qwp-udp")]
    qwp_udp: Option<conf::QwpUdpConfig>,

    #[cfg(feature = "_sender-qwp-ws")]
    qwp_ws: Option<conf::QwpWsConfig>,
}

impl SenderBuilder {
    /// Create a new `SenderBuilder` instance from the configuration string.
    ///
    /// The format of the string is: `"http::addr=host:port;key=value;...;"`.
    ///
    /// Instead of `"http"`, you can also specify `"https"`, `"tcp"`, and `"tcps"`.
    ///
    /// We recommend HTTP for most cases because it provides more features, like
    /// reporting errors to the client and supporting transaction control. TCP can
    /// sometimes be faster in higher-latency networks, but misses a number of
    /// features.
    ///
    /// The accepted keys match one-for-one with the methods on `SenderBuilder`.
    /// For example, this is a valid configuration string:
    ///
    /// "https::addr=host:port;username=alice;password=secret;"
    ///
    /// and there are matching methods [SenderBuilder::username] and
    /// [SenderBuilder::password]. The value of `addr=` is supplied directly to the
    /// `SenderBuilder` constructor, so there's no matching method for that.
    ///
    /// You can also load the configuration from an environment variable. See
    /// [`SenderBuilder::from_env`].
    ///
    /// Once you have a `SenderBuilder` instance, you can further customize it
    /// before calling [`SenderBuilder::build`], but you can't change any settings
    /// that are already set in the config string.
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        let conf = conf.as_ref();
        let conf = questdb_confstr::parse_conf_str(conf)
            .map_err(|e| error::fmt!(ConfigError, "Config parse error: {}", e))?;
        let service = conf.service();
        let params = conf.params();

        let protocol = Protocol::from_schema(service)?;

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

        validate_auto_flush_params(params)?;

        for (key, val) in params.iter().map(|(k, v)| (k.as_str(), v.as_str())) {
            builder = match key {
                "username" => builder.username(val)?,
                "password" => builder.password(val)?,
                "token" => builder.token(val)?,
                "token_x" => builder.token_x(val)?,
                "token_y" => builder.token_y(val)?,
                "bind_interface" => builder.bind_interface(val)?,
                #[cfg(feature = "_sender-qwp-udp")]
                "max_datagram_size" => builder.max_datagram_size(parse_conf_value(key, val)?)?,
                #[cfg(feature = "_sender-qwp-udp")]
                "multicast_ttl" => builder.multicast_ttl(parse_conf_value(key, val)?)?,
                #[cfg(feature = "_sender-qwp-ws")]
                "max_in_flight" => builder.max_in_flight(parse_conf_value(key, val)?)?,
                #[cfg(feature = "_sender-qwp-ws")]
                "sf_dir" => builder.store_and_forward_dir(PathBuf::from(val))?,
                #[cfg(feature = "_sender-qwp-ws")]
                "sender_id" => builder.sender_id(val)?,
                #[cfg(feature = "_sender-qwp-ws")]
                "sf_max_bytes" => {
                    builder.store_and_forward_max_bytes(parse_size_conf_value(key, val)?)?
                }
                #[cfg(feature = "_sender-qwp-ws")]
                "sf_max_total_bytes" => {
                    builder.store_and_forward_max_total_bytes(parse_size_conf_value(key, val)?)?
                }
                #[cfg(feature = "_sender-qwp-ws")]
                "sf_durability" => {
                    builder.store_and_forward_durability(parse_sf_durability_value(val)?)?
                }
                #[cfg(feature = "_sender-qwp-ws")]
                "reconnect_max_duration_millis" => builder
                    .reconnect_max_duration(Duration::from_millis(parse_conf_value(key, val)?))?,
                #[cfg(feature = "_sender-qwp-ws")]
                "reconnect_initial_backoff_millis" => builder.reconnect_initial_backoff(
                    Duration::from_millis(parse_conf_value(key, val)?),
                )?,
                #[cfg(feature = "_sender-qwp-ws")]
                "reconnect_max_backoff_millis" => builder
                    .reconnect_max_backoff(Duration::from_millis(parse_conf_value(key, val)?))?,
                #[cfg(feature = "_sender-qwp-ws")]
                "initial_connect_retry" => {
                    builder.initial_connect_retry(parse_initial_connect_retry_value(val)?)?
                }
                "protocol_version" => match val {
                    "1" => builder.protocol_version(ProtocolVersion::V1)?,
                    "2" => builder.protocol_version(ProtocolVersion::V2)?,
                    "3" => builder.protocol_version(ProtocolVersion::V3)?,
                    "auto" => builder,
                    invalid => {
                        return Err(error::fmt!(
                            ConfigError,
                            "invalid \"protocol_version\" [value={invalid}, allowed-values=[auto, 1, 2, 3]]"
                        ));
                    }
                },
                "max_name_len" => builder.max_name_len(parse_conf_value(key, val)?)?,

                "init_buf_size" => {
                    return Err(error::fmt!(
                        ConfigError,
                        "\"init_buf_size\" is not supported in config string"
                    ));
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
                            return Err(fmt!(
                                ConfigError,
                                r##"Config parameter "tls_verify" must be either "on" or "unsafe_off".'"##,
                            ));
                        }
                    };

                    #[cfg(not(feature = "insecure-skip-verify"))]
                    {
                        if !verify {
                            return Err(fmt!(
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
                    #[allow(unreachable_code, unused_variables)]
                    {
                        let ca = match val {
                            #[cfg(feature = "tls-webpki-certs")]
                            "webpki_roots" => CertificateAuthority::WebpkiRoots,

                            #[cfg(not(feature = "tls-webpki-certs"))]
                            "webpki_roots" => {
                                return Err(error::fmt!(
                                    ConfigError,
                                    "Config parameter \"tls_ca=webpki_roots\" requires the \"tls-webpki-certs\" feature"
                                ));
                            }

                            #[cfg(feature = "tls-native-certs")]
                            "os_roots" => CertificateAuthority::OsRoots,

                            #[cfg(not(feature = "tls-native-certs"))]
                            "os_roots" => {
                                return Err(error::fmt!(
                                    ConfigError,
                                    "Config parameter \"tls_ca=os_roots\" requires the \"tls-native-certs\" feature"
                                ));
                            }

                            #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
                            "webpki_and_os_roots" => CertificateAuthority::WebpkiAndOsRoots,

                            #[cfg(not(all(
                                feature = "tls-webpki-certs",
                                feature = "tls-native-certs"
                            )))]
                            "webpki_and_os_roots" => {
                                return Err(error::fmt!(
                                    ConfigError,
                                    "Config parameter \"tls_ca=webpki_and_os_roots\" requires both the \"tls-webpki-certs\" and \"tls-native-certs\" features"
                                ));
                            }

                            _ => {
                                return Err(error::fmt!(
                                    ConfigError,
                                    "Invalid value {val:?} for \"tls_ca\""
                                ));
                            }
                        };
                        builder.tls_ca(ca)?
                    }
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
                    ));
                }

                #[cfg(feature = "sync-sender-http")]
                "request_min_throughput" => {
                    builder.request_min_throughput(parse_conf_value(key, val)?)?
                }

                #[cfg(feature = "sync-sender-http")]
                "request_timeout" => {
                    builder.request_timeout(Duration::from_millis(parse_conf_value(key, val)?))?
                }

                #[cfg(feature = "sync-sender-http")]
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

    /// Create a new `SenderBuilder` instance from the configuration from the
    /// configuration stored in the `QDB_CLIENT_CONF` environment variable.
    ///
    /// The format of the string is the same as for [`SenderBuilder::from_conf`].
    pub fn from_env() -> Result<Self> {
        let conf = std::env::var("QDB_CLIENT_CONF").map_err(|_| {
            error::fmt!(ConfigError, "Environment variable QDB_CLIENT_CONF not set.")
        })?;
        Self::from_conf(conf)
    }

    /// Create a new `SenderBuilder` instance with the provided QuestDB
    /// server and port, using ILP over the specified protocol.
    ///
    /// ```no_run
    /// # use questdb::Result;
    /// use questdb::ingress::{Protocol, SenderBuilder};
    ///
    /// # fn main() -> Result<()> {
    /// # #[cfg(feature = "sync-sender-tcp")] {
    /// let mut sender = SenderBuilder::new(
    ///     Protocol::Tcp, "localhost", 9009).build()?;
    /// # }
    /// # #[cfg(all(not(feature = "sync-sender-tcp"), feature = "sync-sender-http"))] {
    /// let mut sender = SenderBuilder::new(
    ///     Protocol::Http, "localhost", 9000).build()?;
    /// # }
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
            max_name_len: ConfigSetting::new_default(MAX_NAME_LEN_DEFAULT),
            auth_timeout: ConfigSetting::new_default(Duration::from_secs(15)),
            username: ConfigSetting::new_default(None),
            password: ConfigSetting::new_default(None),
            token: ConfigSetting::new_default(None),

            #[cfg(feature = "_sender-tcp")]
            token_x: ConfigSetting::new_default(None),

            #[cfg(feature = "_sender-tcp")]
            token_y: ConfigSetting::new_default(None),

            protocol_version: ConfigSetting::new_default(None),

            #[cfg(feature = "insecure-skip-verify")]
            tls_verify: ConfigSetting::new_default(true),

            tls_ca: ConfigSetting::new_default(tls_ca),
            tls_roots: ConfigSetting::new_default(None),

            #[cfg(feature = "sync-sender-http")]
            http: if protocol.is_httpx() {
                Some(conf::HttpConfig::default())
            } else {
                None
            },

            #[cfg(feature = "_sender-qwp-udp")]
            qwp_udp: if protocol.is_qwp_udp() {
                Some(conf::QwpUdpConfig::default())
            } else {
                None
            },

            #[cfg(feature = "_sender-qwp-ws")]
            qwp_ws: if protocol.is_qwp_ws() {
                Some(conf::QwpWsConfig::default())
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
    pub fn bind_interface<I: Into<String>>(self, addr: I) -> Result<Self> {
        #[cfg(any(feature = "_sender-tcp", feature = "_sender-qwp-udp"))]
        {
            let mut builder = self;
            builder.ensure_supports_bind_interface("bind_interface")?;
            builder
                .net_interface
                .set_specified("bind_interface", Some(validate_value(addr.into())?))?;
            Ok(builder)
        }

        #[cfg(not(any(feature = "_sender-tcp", feature = "_sender-qwp-udp")))]
        {
            let _ = addr;
            Err(error::fmt!(
                ConfigError,
                "The \"bind_interface\" setting can only be used with the TCP protocol."
            ))
        }
    }

    /// Set the username for authentication.
    ///
    /// For TCP, this is the `kid` part of the ECDSA key set.
    /// The other fields are [`token`](SenderBuilder::token), [`token_x`](SenderBuilder::token_x),
    /// and [`token_y`](SenderBuilder::token_y).
    ///
    /// For HTTP, this is a part of basic authentication.
    /// See also: [`password`](SenderBuilder::password).
    pub fn username(mut self, username: &str) -> Result<Self> {
        #[cfg(feature = "_sender-qwp-udp")]
        self.reject_if_qwp_udp("username")?;
        self.username
            .set_specified("username", Some(validate_value(username.to_string())?))?;
        Ok(self)
    }

    /// Set the password for basic HTTP authentication.
    /// See also: [`username`](SenderBuilder::username).
    pub fn password(mut self, password: &str) -> Result<Self> {
        #[cfg(feature = "_sender-qwp-udp")]
        self.reject_if_qwp_udp("password")?;
        self.password
            .set_specified("password", Some(validate_value(password.to_string())?))?;
        Ok(self)
    }

    /// Set the Token (Bearer) Authentication parameter for HTTP,
    /// or the ECDSA private key for TCP authentication.
    pub fn token(mut self, token: &str) -> Result<Self> {
        #[cfg(feature = "_sender-qwp-udp")]
        self.reject_if_qwp_udp("token")?;
        self.token
            .set_specified("token", Some(validate_value(token.to_string())?))?;
        Ok(self)
    }

    /// Set the ECDSA public key X for TCP authentication.
    pub fn token_x(self, token_x: &str) -> Result<Self> {
        #[cfg(feature = "_sender-qwp-udp")]
        self.reject_if_qwp_udp("token_x")?;
        #[cfg(feature = "_sender-tcp")]
        {
            let mut builder = self;
            builder
                .token_x
                .set_specified("token_x", Some(validate_value(token_x.to_string())?))?;
            Ok(builder)
        }

        #[cfg(not(feature = "_sender-tcp"))]
        {
            let _ = token_x;
            Err(error::fmt!(
                ConfigError,
                "cannot specify \"token_x\": ECDSA authentication is only available with ILP/TCP and not available with ILP/HTTP."
            ))
        }
    }

    /// Set the ECDSA public key Y for TCP authentication.
    pub fn token_y(self, token_y: &str) -> Result<Self> {
        #[cfg(feature = "_sender-qwp-udp")]
        self.reject_if_qwp_udp("token_y")?;
        #[cfg(feature = "_sender-tcp")]
        {
            let mut builder = self;
            builder
                .token_y
                .set_specified("token_y", Some(validate_value(token_y.to_string())?))?;
            Ok(builder)
        }

        #[cfg(not(feature = "_sender-tcp"))]
        {
            let _ = token_y;
            Err(error::fmt!(
                ConfigError,
                "cannot specify \"token_y\": ECDSA authentication is only available with ILP/TCP and not available with ILP/HTTP."
            ))
        }
    }

    /// Sets the protocol version for ILP transports.
    /// - HTTP transport automatically negotiates the protocol version by default(unset, **Strong Recommended**).
    ///   You can explicitly configure the protocol version to avoid the slight latency cost at connection time.
    /// - TCP transport does not negotiate the protocol version and uses [`ProtocolVersion::V1`] by
    ///   default. You must explicitly set [`ProtocolVersion::V2`] in order to ingest
    ///   arrays.
    /// - QWP/UDP does not support explicit `protocol_version` configuration.
    ///
    /// **Note**: QuestDB server version 9.0.0 or later is required for [`ProtocolVersion::V2`] support.
    pub fn protocol_version(mut self, protocol_version: ProtocolVersion) -> Result<Self> {
        #[cfg(feature = "_sender-qwp-udp")]
        self.reject_if_qwp_udp("protocol_version")?;
        self.protocol_version
            .set_specified("protocol_version", Some(protocol_version))?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-udp")]
    /// Set the maximum datagram size in bytes for QWP/UDP transport.
    ///
    /// `value` must be between 1 and 65,507 bytes, inclusive. The upper bound
    /// is the UDP/IPv4 payload limit, not a recommended operating size. The
    /// default is 1,400 bytes, leaving room for IPv4 and UDP headers under a
    /// common 1,500-byte Ethernet MTU. If you raise this value, keep it within
    /// the effective UDP payload budget for the path MTU. Oversized IPv4
    /// packets may be fragmented when fragmentation is allowed, or dropped when
    /// it is not; fragmented UDP is fragile because losing any fragment loses
    /// the whole datagram.
    pub fn max_datagram_size(mut self, value: usize) -> Result<Self> {
        if value == 0 {
            return Err(error::fmt!(
                ConfigError,
                "\"max_datagram_size\" must be greater than 0."
            ));
        }
        if value > 65507 {
            return Err(error::fmt!(
                ConfigError,
                "\"max_datagram_size\" must not exceed 65507 (UDP/IPv4 limit)."
            ));
        }
        let Some(qwp_udp) = &mut self.qwp_udp else {
            return Err(error::fmt!(
                ConfigError,
                "The \"max_datagram_size\" setting is only supported for QWP/UDP."
            ));
        };
        qwp_udp
            .max_datagram_size
            .set_specified("max_datagram_size", value)?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-udp")]
    /// Set the multicast TTL for QWP/UDP transport. The default is 1.
    ///
    /// Use a value greater than 0 when sending to a multicast address. A value
    /// of 0 prevents multicast datagrams from leaving the local host.
    pub fn multicast_ttl(mut self, value: u32) -> Result<Self> {
        if value > 255 {
            return Err(error::fmt!(
                ConfigError,
                "\"multicast_ttl\" must be between 0 and 255."
            ));
        }
        let Some(qwp_udp) = &mut self.qwp_udp else {
            return Err(error::fmt!(
                ConfigError,
                "The \"multicast_ttl\" setting is only supported for QWP/UDP."
            ));
        };
        qwp_udp
            .multicast_ttl
            .set_specified("multicast_ttl", value)?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    /// Maximum number of unacknowledged messages a pipelined async QWP/WebSocket
    /// sender keeps in flight at once. The default is 128, matching the spec's
    /// `Max in-flight batches` limit.
    ///
    /// The window provides backpressure: once it's full, subsequent
    /// `flush().await` calls park until the server acknowledges an earlier
    /// message. Smaller windows reduce client memory and bound the impact of a
    /// stuck server; larger windows increase throughput on high-RTT links.
    pub fn max_in_flight(mut self, value: usize) -> Result<Self> {
        if value == 0 {
            return Err(error::fmt!(
                ConfigError,
                "\"max_in_flight\" must be greater than 0."
            ));
        }
        let Some(qwp_ws) = &mut self.qwp_ws else {
            return Err(error::fmt!(
                ConfigError,
                "The \"max_in_flight\" setting is only supported for QWP/WebSocket."
            ));
        };
        qwp_ws.max_in_flight.set_specified("max_in_flight", value)?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn store_and_forward_dir(mut self, dir: PathBuf) -> Result<Self> {
        if dir.as_os_str().is_empty() {
            return Err(error::fmt!(ConfigError, "\"sf_dir\" cannot be empty."));
        }
        let Some(qwp_ws) = &mut self.qwp_ws else {
            return Err(error::fmt!(
                ConfigError,
                "The \"sf_dir\" setting is only supported for QWP/WebSocket."
            ));
        };
        qwp_ws.sf_dir.set_specified("sf_dir", Some(dir))?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn sender_id(mut self, sender_id: &str) -> Result<Self> {
        let sender_id = validate_value(sender_id)?;
        if !conf::is_valid_qwp_ws_sender_id(sender_id) {
            return Err(error::fmt!(
                ConfigError,
                "invalid sender_id [value={sender_id}, allowed-chars=[A-Za-z0-9_-]]"
            ));
        }
        let Some(qwp_ws) = &mut self.qwp_ws else {
            return Err(error::fmt!(
                ConfigError,
                "The \"sender_id\" setting is only supported for QWP/WebSocket."
            ));
        };
        qwp_ws
            .sender_id
            .set_specified("sender_id", sender_id.to_owned())?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn store_and_forward_max_bytes(mut self, value: u64) -> Result<Self> {
        if value == 0 {
            return Err(error::fmt!(
                ConfigError,
                "\"sf_max_bytes\" must be greater than 0."
            ));
        }
        let Some(qwp_ws) = &mut self.qwp_ws else {
            return Err(error::fmt!(
                ConfigError,
                "The \"sf_max_bytes\" setting is only supported for QWP/WebSocket."
            ));
        };
        qwp_ws.sf_max_bytes.set_specified("sf_max_bytes", value)?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn store_and_forward_max_total_bytes(mut self, value: u64) -> Result<Self> {
        if value == 0 {
            return Err(error::fmt!(
                ConfigError,
                "\"sf_max_total_bytes\" must be greater than 0."
            ));
        }
        let Some(qwp_ws) = &mut self.qwp_ws else {
            return Err(error::fmt!(
                ConfigError,
                "The \"sf_max_total_bytes\" setting is only supported for QWP/WebSocket."
            ));
        };
        qwp_ws
            .sf_max_total_bytes
            .set_specified("sf_max_total_bytes", Some(value))?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn store_and_forward_durability(mut self, durability: conf::SfDurability) -> Result<Self> {
        let Some(qwp_ws) = &mut self.qwp_ws else {
            return Err(error::fmt!(
                ConfigError,
                "The \"sf_durability\" setting is only supported for QWP/WebSocket."
            ));
        };
        qwp_ws
            .sf_durability
            .set_specified("sf_durability", durability)?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    /// Per-outage reconnect retry budget. Default 300s.
    pub fn reconnect_max_duration(mut self, value: Duration) -> Result<Self> {
        let Some(qwp_ws) = &mut self.qwp_ws else {
            return Err(error::fmt!(
                ConfigError,
                "The \"reconnect_max_duration_millis\" setting is only supported for QWP/WebSocket."
            ));
        };
        qwp_ws
            .reconnect_max_duration
            .set_specified("reconnect_max_duration_millis", value)?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    /// Initial reconnect backoff. Default 100ms.
    pub fn reconnect_initial_backoff(mut self, value: Duration) -> Result<Self> {
        if value.is_zero() {
            return Err(error::fmt!(
                ConfigError,
                "\"reconnect_initial_backoff_millis\" must be greater than 0."
            ));
        }
        let Some(qwp_ws) = &mut self.qwp_ws else {
            return Err(error::fmt!(
                ConfigError,
                "The \"reconnect_initial_backoff_millis\" setting is only supported for QWP/WebSocket."
            ));
        };
        qwp_ws
            .reconnect_initial_backoff
            .set_specified("reconnect_initial_backoff_millis", value)?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    /// Cap on the per-attempt reconnect delay. Default 5s.
    pub fn reconnect_max_backoff(mut self, value: Duration) -> Result<Self> {
        if value.is_zero() {
            return Err(error::fmt!(
                ConfigError,
                "\"reconnect_max_backoff_millis\" must be greater than 0."
            ));
        }
        let Some(qwp_ws) = &mut self.qwp_ws else {
            return Err(error::fmt!(
                ConfigError,
                "The \"reconnect_max_backoff_millis\" setting is only supported for QWP/WebSocket."
            ));
        };
        qwp_ws
            .reconnect_max_backoff
            .set_specified("reconnect_max_backoff_millis", value)?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    /// Retry the initial connection using the reconnect policy. Default false.
    pub fn initial_connect_retry(mut self, value: bool) -> Result<Self> {
        let Some(qwp_ws) = &mut self.qwp_ws else {
            return Err(error::fmt!(
                ConfigError,
                "The \"initial_connect_retry\" setting is only supported for QWP/WebSocket."
            ));
        };
        qwp_ws
            .initial_connect_retry
            .set_specified("initial_connect_retry", value)?;
        Ok(self)
    }

    /// Configure how long to wait for messages from the QuestDB server during
    /// the TLS handshake and authentication process. This only applies to TCP.
    /// The default is 15 seconds.
    pub fn auth_timeout(mut self, value: Duration) -> Result<Self> {
        #[cfg(feature = "_sender-qwp-udp")]
        self.reject_if_qwp_udp("auth_timeout")?;
        self.auth_timeout.set_specified("auth_timeout", value)?;
        Ok(self)
    }

    #[cfg(feature = "_sender-qwp-udp")]
    fn reject_if_qwp_udp(&self, setting: &str) -> Result<()> {
        if self.protocol.is_qwp_udp() {
            return Err(error::fmt!(
                ConfigError,
                "The \"{setting}\" setting is not supported for QWP/UDP."
            ));
        }
        Ok(())
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
    /// For testing, consider specifying a path to a `.pem` file instead via
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
    /// See notes on how to test with [self-signed
    /// certificates](https://github.com/questdb/c-questdb-client/tree/main/tls_certs).
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

    /// The maximum buffered size that the client will flush to the server.
    /// The default is 100 MiB.
    ///
    /// For ILP this applies to the exact pending byte length.
    /// For QWP/UDP this applies to the buffer size hint exposed by [`Buffer::len`].
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

    /// The maximum length of a table or column name in bytes.
    /// Matches the `cairo.max.file.name.length` setting in the server.
    /// The default is 127 bytes.
    /// If running over HTTP and protocol version 2 is auto-negotiated, this
    /// value is picked up from the server.
    pub fn max_name_len(mut self, value: usize) -> Result<Self> {
        if value < 16 {
            return Err(error::fmt!(
                ConfigError,
                "max_name_len must be at least 16 bytes."
            ));
        }
        self.max_name_len.set_specified("max_name_len", value)?;
        Ok(self)
    }

    #[cfg(feature = "sync-sender-http")]
    /// Set the cumulative duration spent in retries.
    /// The value is in milliseconds, and the default is 10 seconds.
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

    #[cfg(feature = "sync-sender-http")]
    /// Set the minimum acceptable throughput while sending a buffer to the server.
    /// The sender will divide the payload size by this number to determine for how
    /// long to keep sending the payload before timing out.
    /// The value is in bytes per second, and the default is 100 KiB/s.
    /// The timeout calculated from minimum throughput is adedd to the value of
    /// [`request_timeout`](SenderBuilder::request_timeout) to get the total timeout
    /// value.
    /// A value of 0 disables this feature, so it's similar to setting "infinite"
    /// minimum throughput. The total timeout will then be equal to `request_timeout`.
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

    #[cfg(feature = "sync-sender-http")]
    /// Additional time to wait on top of that calculated from the minimum throughput.
    /// This accounts for the fixed latency of the HTTP request-response roundtrip.
    /// The default is 10 seconds.
    /// See also: [`request_min_throughput`](SenderBuilder::request_min_throughput).
    pub fn request_timeout(mut self, value: Duration) -> Result<Self> {
        if let Some(http) = &mut self.http {
            if value.is_zero() {
                return Err(error::fmt!(
                    ConfigError,
                    "\"request_timeout\" must be greater than 0."
                ));
            }
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

    #[cfg(feature = "sync-sender-http")]
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

    fn build_auth(&self) -> Result<Option<conf::AuthParams>> {
        match (
            self.protocol,
            self.username.deref(),
            self.password.deref(),
            self.token.deref(),
            #[cfg(feature = "_sender-tcp")]
            self.token_x.deref(),
            #[cfg(not(feature = "_sender-tcp"))]
            None::<String>,
            #[cfg(feature = "_sender-tcp")]
            self.token_y.deref(),
            #[cfg(not(feature = "_sender-tcp"))]
            None::<String>,
        ) {
            (_, None, None, None, None, None) => Ok(None),

            #[cfg(feature = "_sender-tcp")]
            (protocol, Some(username), None, Some(token), Some(token_x), Some(token_y))
                if protocol.is_tcpx() =>
            {
                Ok(Some(conf::AuthParams::Ecdsa(conf::EcdsaAuthParams {
                    key_id: username.to_string(),
                    priv_key: token.to_string(),
                    pub_key_x: token_x.to_string(),
                    pub_key_y: token_y.to_string(),
                })))
            }

            #[cfg(feature = "_sender-tcp")]
            (protocol, Some(_username), Some(_password), None, None, None)
                if protocol.is_tcpx() =>
            {
                Err(error::fmt!(
                    ConfigError,
                    r##"The "basic_auth" setting can only be used with the ILP/HTTP protocol."##,
                ))
            }

            #[cfg(feature = "_sender-tcp")]
            (protocol, None, None, Some(_token), None, None) if protocol.is_tcpx() => {
                Err(error::fmt!(
                    ConfigError,
                    "Token authentication only be used with the ILP/HTTP protocol."
                ))
            }

            #[cfg(feature = "_sender-tcp")]
            (protocol, _username, None, _token, _token_x, _token_y) if protocol.is_tcpx() => {
                Err(error::fmt!(
                    ConfigError,
                    r##"Incomplete ECDSA authentication parameters. Specify either all or none of: "username", "token", "token_x", "token_y"."##,
                ))
            }
            #[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
            (protocol, Some(username), Some(password), None, None, None)
                if protocol.accepts_http_auth() =>
            {
                Ok(Some(conf::AuthParams::Basic(conf::BasicAuthParams {
                    username: username.to_string(),
                    password: password.to_string(),
                })))
            }
            #[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
            (protocol, Some(_username), None, None, None, None) if protocol.accepts_http_auth() => {
                Err(error::fmt!(
                    ConfigError,
                    r##"Basic authentication parameter "username" is present, but "password" is missing."##,
                ))
            }
            #[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
            (protocol, None, Some(_password), None, None, None) if protocol.accepts_http_auth() => {
                Err(error::fmt!(
                    ConfigError,
                    r##"Basic authentication parameter "password" is present, but "username" is missing."##,
                ))
            }
            #[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
            (protocol, None, None, Some(token), None, None) if protocol.accepts_http_auth() => {
                Ok(Some(conf::AuthParams::Token(conf::TokenAuthParams {
                    token: token.to_string(),
                })))
            }
            #[cfg(feature = "_sender-http")]
            (protocol, Some(_username), None, Some(_token), Some(_token_x), Some(_token_y))
                if protocol.is_httpx() =>
            {
                Err(error::fmt!(
                    ConfigError,
                    "ECDSA authentication is only available with ILP/TCP and not available with ILP/HTTP."
                ))
            }
            #[cfg(feature = "_sender-http")]
            (protocol, _username, _password, _token, None, None) if protocol.is_httpx() => {
                Err(error::fmt!(
                    ConfigError,
                    r##"Inconsistent HTTP authentication parameters. Specify either "username" and "password", or just "token"."##,
                ))
            }
            _ => Err(error::fmt!(
                ConfigError,
                r##"Incomplete authentication parameters. Check "username", "password", "token", "token_x" and "token_y" parameters are set correctly."##,
            )),
        }
    }

    #[cfg(feature = "_sync-sender")]
    /// Build the sender.
    ///
    /// In the case of TCP, this synchronously establishes the TCP connection, and
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

        #[cfg(feature = "insecure-skip-verify")]
        let tls_verify = *self.tls_verify;

        #[allow(unused_variables)]
        let tls_settings = tls::TlsSettings::build(
            self.protocol.tls_enabled(),
            #[cfg(feature = "insecure-skip-verify")]
            tls_verify,
            *self.tls_ca,
            self.tls_roots.deref().as_deref(),
        )?;

        let auth = self.build_auth()?;

        let handler = match self.protocol {
            #[cfg(feature = "sync-sender-tcp")]
            Protocol::Tcp | Protocol::Tcps => connect_tcp(
                self.host.as_str(),
                self.port.as_str(),
                self.net_interface.deref().as_deref(),
                *self.auth_timeout,
                tls_settings,
                &auth,
            )?,
            #[cfg(feature = "sync-sender-http")]
            Protocol::Http | Protocol::Https => {
                use ureq::unversioned::transport::Connector;
                use ureq::unversioned::transport::TcpConnector;
                if self.net_interface.is_some() {
                    // See: https://github.com/algesten/ureq/issues/692
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "net_interface is not supported for ILP over HTTP."
                    ));
                }

                let http_config = self.http.as_ref().unwrap();
                let user_agent = http_config.user_agent.as_str();
                let connector = TcpConnector::default();

                let agent_builder = ureq::Agent::config_builder()
                    .user_agent(user_agent)
                    .no_delay(true);

                let tls_config = match tls_settings {
                    Some(tls_settings) => Some(tls::configure_tls(tls_settings)?),
                    None => None,
                };

                let connector = connector.chain(TlsConnector::new(tls_config));

                let auth = match auth {
                    Some(conf::AuthParams::Basic(ref auth)) => Some(auth.to_header_string()),
                    Some(conf::AuthParams::Token(ref auth)) => Some(auth.to_header_string()?),

                    #[cfg(feature = "sync-sender-tcp")]
                    Some(conf::AuthParams::Ecdsa(_)) => {
                        return Err(fmt!(
                            AuthError,
                            "ECDSA authentication is not supported for ILP over HTTP. \
                            Please use basic or token authentication instead."
                        ));
                    }
                    None => None,
                };
                let agent_builder = agent_builder
                    .timeout_connect(Some(*http_config.request_timeout.deref()))
                    .http_status_as_error(false);
                let agent = ureq::Agent::with_parts(
                    agent_builder.build(),
                    connector,
                    ureq::unversioned::resolver::DefaultResolver::default(),
                );
                let proto = self.protocol.schema();
                let url = format!(
                    "{}://{}:{}/write",
                    proto,
                    self.host.deref(),
                    self.port.deref()
                );
                SyncProtocolHandler::SyncHttp(SyncHttpHandlerState {
                    agent,
                    url,
                    auth,
                    config: self.http.as_ref().unwrap().clone(),
                })
            }
            #[cfg(feature = "sync-sender-qwp-udp")]
            Protocol::QwpUdp => {
                let Some(qwp_udp) = self.qwp_udp.as_ref() else {
                    return Err(error::fmt!(
                        ConfigError,
                        "QWP/UDP configuration is missing."
                    ));
                };
                connect_qwp_udp(
                    self.host.as_str(),
                    self.port.as_str(),
                    self.net_interface.deref().as_deref(),
                    qwp_udp,
                )?
            }
            #[cfg(feature = "sync-sender-qwp-ws")]
            Protocol::QwpWs | Protocol::QwpWss => {
                if self.net_interface.is_some() {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "net_interface is not supported for QWP over WebSocket."
                    ));
                }
                let Some(qwp_ws) = self.qwp_ws.as_ref() else {
                    return Err(error::fmt!(
                        ConfigError,
                        "QWP/WebSocket configuration is missing."
                    ));
                };
                reject_unsupported_qwp_ws_sf_config(qwp_ws)?;
                let basic_auth = match &auth {
                    Some(conf::AuthParams::Basic(b)) => Some(b.to_header_string()),
                    Some(conf::AuthParams::Token(t)) => Some(t.to_header_string()?),
                    #[cfg(feature = "_sender-tcp")]
                    Some(conf::AuthParams::Ecdsa(_)) => {
                        return Err(error::fmt!(
                            AuthError,
                            "ECDSA authentication is not supported for QWP/WebSocket. \
                             Use basic or token authentication instead."
                        ));
                    }
                    None => None,
                };
                connect_qwp_ws(
                    self.host.as_str(),
                    self.port.as_str(),
                    matches!(self.protocol, Protocol::QwpWss),
                    tls_settings,
                    qwp_ws,
                    basic_auth,
                )?
            }
        };

        #[allow(unused_mut)]
        let mut max_name_len = *self.max_name_len;

        let protocol_version = match self.protocol_version.deref() {
            Some(v) => *v,
            None => match self.protocol {
                #[cfg(feature = "sync-sender-tcp")]
                Protocol::Tcp | Protocol::Tcps => ProtocolVersion::V1,
                #[cfg(feature = "sync-sender-http")]
                Protocol::Http | Protocol::Https => {
                    #[allow(irrefutable_let_patterns)]
                    if let SyncProtocolHandler::SyncHttp(http_state) = &handler {
                        let settings_url = &format!(
                            "{}://{}:{}/settings",
                            self.protocol.schema(),
                            self.host.deref(),
                            self.port.deref()
                        );
                        let (protocol_versions, server_max_name_len) =
                            read_server_settings(http_state, settings_url, max_name_len)?;
                        max_name_len = server_max_name_len;
                        SUPPORTED_PROTOCOL_VERSIONS
                            .iter()
                            .find(|version| protocol_versions.contains(version))
                            .copied()
                            .ok_or_else(|| {
                                fmt!(
                                    ProtocolVersionError,
                                    "Server does not support any of the client protocol versions: {:?}",
                                    SUPPORTED_PROTOCOL_VERSIONS
                                )
                            })?
                    } else {
                        unreachable!("HTTP handler should be used for HTTP protocol");
                    }
                }
                #[cfg(feature = "sync-sender-qwp-udp")]
                Protocol::QwpUdp => ProtocolVersion::V1,
                #[cfg(feature = "sync-sender-qwp-ws")]
                Protocol::QwpWs | Protocol::QwpWss => ProtocolVersion::V1,
            },
        };

        if auth.is_some() {
            descr.push_str("auth=on]");
        } else {
            descr.push_str("auth=off]");
        }

        let sender = Sender::new(
            descr,
            handler,
            *self.max_buf_size,
            self.protocol,
            protocol_version,
            max_name_len,
        );

        Ok(sender)
    }

    #[cfg(any(feature = "_sender-tcp", feature = "_sender-qwp-udp"))]
    fn ensure_supports_bind_interface(&self, param_name: &str) -> Result<()> {
        #[cfg(feature = "_sender-tcp")]
        if self.protocol.is_tcpx() {
            return Ok(());
        }

        #[cfg(feature = "_sender-qwp-udp")]
        if self.protocol.is_qwp_udp() {
            return Ok(());
        }

        #[cfg(feature = "_sender-qwp-udp")]
        let supported = "TCP or QWP/UDP";
        #[cfg(not(feature = "_sender-qwp-udp"))]
        let supported = "TCP";

        Err(fmt!(
            ConfigError,
            "The {param_name:?} setting can only be used with the {supported} protocol."
        ))
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
        fmt!(
            ConfigError,
            "Could not parse {param_name:?} to number: {e:?}"
        )
    })
}

#[cfg(feature = "_sender-qwp-ws")]
fn parse_initial_connect_retry_value(str_value: &str) -> Result<bool> {
    if str_value.eq_ignore_ascii_case("on") || str_value.eq_ignore_ascii_case("true") {
        return Ok(true);
    }
    if str_value.eq_ignore_ascii_case("sync") {
        return Ok(true);
    }
    if str_value.eq_ignore_ascii_case("off") || str_value.eq_ignore_ascii_case("false") {
        return Ok(false);
    }
    if str_value.eq_ignore_ascii_case("async") {
        return Err(error::fmt!(
            ConfigError,
            "initial_connect_retry=async is not supported by the Rust QWP/WebSocket sender yet; use initial_connect_retry=sync for blocking startup retry"
        ));
    }
    Err(error::fmt!(
        ConfigError,
        "invalid initial_connect_retry [value={str_value}, allowed-values=[on, off, true, false, sync], unsupported-values=[async]]"
    ))
}

#[cfg(feature = "_sender-qwp-ws")]
fn parse_size_conf_value(param_name: &str, str_value: &str) -> Result<u64> {
    let mut end = str_value.len();
    if end == 0 {
        return Err(error::fmt!(
            ConfigError,
            "invalid {param_name} [value={str_value}]"
        ));
    }

    let bytes = str_value.as_bytes();
    if matches!(bytes[end - 1], b'b' | b'B') {
        end -= 1;
    }

    let multiplier = if end > 0 {
        match bytes[end - 1] {
            b'k' | b'K' => {
                end -= 1;
                1024
            }
            b'm' | b'M' => {
                end -= 1;
                1024 * 1024
            }
            b'g' | b'G' => {
                end -= 1;
                1024 * 1024 * 1024
            }
            b't' | b'T' => {
                end -= 1;
                1024_u64 * 1024 * 1024 * 1024
            }
            _ => 1,
        }
    } else {
        1
    };

    if end == 0 {
        return Err(error::fmt!(
            ConfigError,
            "invalid {param_name} [value={str_value}]"
        ));
    }

    let digits = &str_value[..end];
    let value = digits
        .parse::<u64>()
        .map_err(|_| error::fmt!(ConfigError, "invalid {param_name} [value={str_value}]"))?;
    value.checked_mul(multiplier).ok_or_else(|| {
        error::fmt!(
            ConfigError,
            "{param_name} overflows u64 [value={str_value}]"
        )
    })
}

#[cfg(feature = "_sender-qwp-ws")]
fn parse_sf_durability_value(str_value: &str) -> Result<conf::SfDurability> {
    if str_value.eq_ignore_ascii_case("memory") {
        return Ok(conf::SfDurability::Memory);
    }
    if str_value.eq_ignore_ascii_case("flush") {
        return Ok(conf::SfDurability::Flush);
    }
    if str_value.eq_ignore_ascii_case("append") {
        return Ok(conf::SfDurability::Append);
    }
    Err(error::fmt!(
        ConfigError,
        "invalid sf_durability [value={str_value}, allowed-values=[memory, flush, append]]"
    ))
}

#[cfg(feature = "_sender-qwp-ws")]
fn reject_unsupported_qwp_ws_sf_config(qwp_ws: &conf::QwpWsConfig) -> Result<()> {
    if *qwp_ws.sf_durability != conf::SfDurability::Memory {
        let durability = qwp_ws.sf_durability.as_conf_value();
        return Err(error::fmt!(
            ConfigError,
            "sf_durability={durability} is not yet supported (deferred follow-up; use sf_durability=memory)"
        ));
    }

    Ok(())
}

#[cfg(feature = "_sender-tcp")]
fn b64_decode(descr: &'static str, buf: &str) -> Result<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(buf).map_err(|b64_err| {
        fmt!(
            AuthError,
            "Misconfigured ILP authentication keys. Could not decode {}: {}. \
            Hint: Check the keys for a possible typo.",
            descr,
            b64_err
        )
    })
}

#[cfg(feature = "_sender-tcp")]
fn parse_public_key(pub_key_x: &str, pub_key_y: &str) -> Result<Vec<u8>> {
    let mut pub_key_x = b64_decode("public key x", pub_key_x)?;
    let mut pub_key_y = b64_decode("public key y", pub_key_y)?;

    // SEC 1 Uncompressed Octet-String-to-Elliptic-Curve-Point Encoding
    let mut encoded = Vec::new();
    encoded.push(4u8); // 0x04 magic byte that identifies this as uncompressed.
    let pub_key_x_ken = pub_key_x.len();
    if pub_key_x_ken > 32 {
        return Err(fmt!(
            AuthError,
            "Misconfigured ILP authentication keys. Public key x is too long. \
            Hint: Check the keys for a possible typo."
        ));
    }
    let pub_key_y_len = pub_key_y.len();
    if pub_key_y_len > 32 {
        return Err(fmt!(
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

#[cfg(feature = "_sender-tcp")]
fn parse_key_pair(auth: &conf::EcdsaAuthParams) -> Result<EcdsaKeyPair> {
    let private_key = b64_decode("private authentication key", auth.priv_key.as_str())?;
    let public_key = parse_public_key(auth.pub_key_x.as_str(), auth.pub_key_y.as_str())?;

    #[cfg(feature = "aws-lc-crypto")]
    let res = EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &private_key[..],
        &public_key[..],
    );

    #[cfg(feature = "ring-crypto")]
    let res = {
        let system_random = SystemRandom::new();
        EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &private_key[..],
            &public_key[..],
            &system_random,
        )
    };

    res.map_err(|key_rejected| {
        fmt!(
            AuthError,
            "Misconfigured ILP authentication keys: {}. Hint: Check the keys for a possible typo.",
            key_rejected
        )
    })
}

struct DebugBytes<'a>(pub &'a [u8]);

impl Debug for DebugBytes<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "b\"")?;

        for &byte in self.0 {
            match byte {
                // Printable ASCII characters (except backslash and quote)
                0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E => {
                    write!(f, "{}", byte as char)?;
                }
                // Common escape sequences
                b'\n' => write!(f, "\\n")?,
                b'\r' => write!(f, "\\r")?,
                b'\t' => write!(f, "\\t")?,
                b'\\' => write!(f, "\\\\")?,
                b'"' => write!(f, "\\\"")?,
                b'\0' => write!(f, "\\0")?,
                // Non-printable bytes as hex escapes
                _ => write!(f, "\\x{byte:02x}")?,
            }
        }

        write!(f, "\"")
    }
}

#[cfg(test)]
mod tests;
