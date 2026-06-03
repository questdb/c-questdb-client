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

use super::*;
use crate::ErrorCode;

#[cfg(any(feature = "sync-sender-tcp", feature = "sync-sender-qwp-ws"))]
use tempfile::TempDir;

#[cfg(feature = "sync-sender-http")]
#[test]
fn http_simple() {
    let builder = SenderBuilder::from_conf("http::addr=127.0.0.1;").unwrap();
    assert_eq!(builder.protocol, Protocol::Http);
    assert_specified_eq(&builder.host, "127.0.0.1");
    assert_specified_eq(&builder.port, Protocol::Http.default_port());
    assert!(!builder.protocol.tls_enabled());
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn https_simple() {
    let builder = SenderBuilder::from_conf("https::addr=localhost;").unwrap();
    assert_eq!(builder.protocol, Protocol::Https);
    assert_specified_eq(&builder.host, "localhost");
    assert_specified_eq(&builder.port, Protocol::Https.default_port());
    assert!(builder.protocol.tls_enabled());

    #[cfg(feature = "tls-webpki-certs")]
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);

    #[cfg(not(feature = "tls-webpki-certs"))]
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::OsRoots);
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcp_simple() {
    let builder = SenderBuilder::from_conf("tcp::addr=127.0.0.1;").unwrap();
    assert_eq!(builder.protocol, Protocol::Tcp);
    assert_specified_eq(&builder.port, Protocol::Tcp.default_port());
    assert_specified_eq(&builder.host, "127.0.0.1");
    assert!(!builder.protocol.tls_enabled());
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcps_simple() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;").unwrap();
    assert_eq!(builder.protocol, Protocol::Tcps);
    assert_specified_eq(&builder.host, "localhost");
    assert_specified_eq(&builder.port, Protocol::Tcps.default_port());
    assert!(builder.protocol.tls_enabled());

    #[cfg(feature = "tls-webpki-certs")]
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);

    #[cfg(not(feature = "tls-webpki-certs"))]
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::OsRoots);
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_simple() {
    let builder = SenderBuilder::from_conf("qwpudp::addr=127.0.0.1;").unwrap();
    assert_eq!(builder.protocol, Protocol::QwpUdp);
    assert_specified_eq(&builder.host, "127.0.0.1");
    assert_specified_eq(&builder.port, Protocol::QwpUdp.default_port());
    assert!(!builder.protocol.tls_enabled());
    let qwp_udp = builder.qwp_udp.as_ref().unwrap();
    assert_defaulted_eq(&qwp_udp.max_datagram_size, 1400usize);
    assert_defaulted_eq(&qwp_udp.multicast_ttl, 1u32);
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_custom_config() {
    let builder = SenderBuilder::from_conf(
        "qwpudp::addr=239.1.2.3:19002;bind_interface=192.168.1.10;max_datagram_size=1200;multicast_ttl=7;",
    )
    .unwrap();
    assert_eq!(builder.protocol, Protocol::QwpUdp);
    assert_specified_eq(&builder.host, "239.1.2.3");
    assert_specified_eq(&builder.port, "19002");
    assert_specified_eq(&builder.net_interface, Some("192.168.1.10".to_string()));
    let qwp_udp = builder.qwp_udp.as_ref().unwrap();
    assert_specified_eq(&qwp_udp.max_datagram_size, 1200usize);
    assert_specified_eq(&qwp_udp.multicast_ttl, 7u32);
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_sender_reports_transport_protocol() {
    let sender = SenderBuilder::new(Protocol::QwpUdp, "127.0.0.1", 9007)
        .build()
        .unwrap();
    assert_eq!(sender.protocol(), Protocol::QwpUdp);
}

#[cfg(all(feature = "sync-sender-qwp-ws", feature = "sync-sender-qwp-udp"))]
#[test]
fn qwpws_error_polling_rejects_non_websocket_sender() {
    let mut sender = SenderBuilder::new(Protocol::QwpUdp, "127.0.0.1", 9007)
        .build()
        .unwrap();

    let err = sender.poll_qwp_ws_error().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(
        err.msg()
            .contains("poll_qwp_ws_error is only supported for QWP/WebSocket")
    );

    let err = sender.qwp_ws_errors_dropped().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(
        err.msg()
            .contains("qwp_ws_errors_dropped is only supported for QWP/WebSocket")
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_store_and_forward_config_parses_java_keys() {
    let builder = SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;\
         sf_dir=/tmp/qdb-rust-sf;\
         sender_id=primary-1;\
         sf_max_bytes=64mb;\
         sf_max_total_bytes=4G;\
         sf_durability=memory;\
         sf_append_deadline_millis=1234;\
         auth_timeout_ms=750;",
    )
    .unwrap();

    assert_eq!(builder.protocol, Protocol::QwpWs);
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(&qwp_ws.sf_dir, Some(PathBuf::from("/tmp/qdb-rust-sf")));
    assert_specified_eq(&qwp_ws.sender_id, "primary-1".to_owned());
    assert_specified_eq(&qwp_ws.sf_max_bytes, 64 * 1024 * 1024_u64);
    assert_specified_eq(&qwp_ws.sf_max_total_bytes, Some(4 * 1024 * 1024 * 1024_u64));
    assert_specified_eq(&qwp_ws.sf_durability, conf::SfDurability::Memory);
    assert_specified_eq(&qwp_ws.sf_append_deadline, Duration::from_millis(1234));
    assert_specified_eq(&qwp_ws.auth_timeout, Duration::from_millis(750));
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_config_accepts_spec_websocket_aliases() {
    let plain = SenderBuilder::from_conf("ws::addr=localhost:9000;").unwrap();
    assert_eq!(plain.protocol, Protocol::QwpWs);

    let tls = SenderBuilder::from_conf("wss::addr=localhost:9000;").unwrap();
    assert_eq!(tls.protocol, Protocol::QwpWss);
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_store_and_forward_defaults_match_java() {
    let builder = SenderBuilder::from_conf("qwpws::addr=localhost:9000;").unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();

    assert_defaulted_eq(&qwp_ws.sender_id, "default".to_owned());
    assert_defaulted_eq(&qwp_ws.sf_max_bytes, 4 * 1024 * 1024_u64);
    assert_defaulted_eq(&qwp_ws.sf_max_total_bytes, None);
    assert_defaulted_eq(&qwp_ws.sf_durability, conf::SfDurability::Memory);
    assert_defaulted_eq(&qwp_ws.sf_append_deadline, Duration::from_secs(30));
    assert_defaulted_eq(&qwp_ws.auth_timeout, Duration::from_secs(15));
    assert_defaulted_eq(&qwp_ws.progress, QwpWsProgress::Background);
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_progress_config_parses_manual_and_background() {
    let builder =
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;qwp_ws_progress=manual;").unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(&qwp_ws.progress, QwpWsProgress::Manual);

    let builder =
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;qwp_ws_progress=background;").unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(&qwp_ws.progress, QwpWsProgress::Background);
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_config_accepts_java_in_flight_window_alias() {
    let builder =
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;in_flight_window=7;").unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(&qwp_ws.max_in_flight, 7usize);

    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;in_flight_window=1;"),
        "WebSocket transport requires async mode (in_flight_window > 1)",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;in_flight_window=-1;"),
        "in-flight window size must be positive[size=-1]",
    );

    let builder = SenderBuilder::from_conf("qwpws::addr=localhost:9000;max_in_flight=1;").unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(&qwp_ws.max_in_flight, 1usize);
}

/// Connect-string keys that the Rust egress reader
/// (`crate::egress::config::ReaderConfig::from_conf`) recognizes but
/// the ingress sender has no use for. Today the sender's catch-all
/// silently accepts unknown keys, so each of these falls through that
/// branch — this list pins the behavior with a regression test so a
/// future tightening of the catch-all can't break cross-role
/// portability of a shared connect string.
const EGRESS_ONLY_CONFIG_KEYS: &[&str] = &[
    // Egress-only protocol / decoder knobs
    "path",
    "max_version",
    "compression",
    "compression_level",
    "max_batch_rows",
    "client_id",
    "target",
    "auth",
    // Egress-only failover policy
    "failover",
    "failover_max_attempts",
    "failover_backoff_initial_ms",
    "failover_backoff_max_ms",
    "failover_max_duration_ms",
    // Java-egress-only decoded-batch pool size (Rust egress is sync/pull,
    // see comment in `egress/config.rs`); still ignored on ingress
    // because that's an egress-side concern either way.
    "buffer_pool_size",
    // Reserved per-category server-error policy keys
    // (java-questdb-client design/qwp-cursor-error-api.md). Both roles
    // silently accept them so the resolver can be wired without
    // breaking older clients.
    "on_server_error",
    "on_schema_error",
    "on_parse_error",
    "on_internal_error",
    "on_security_error",
    "on_write_error",
];

#[cfg(feature = "sync-sender-http")]
#[test]
fn ingress_silently_accepts_every_egress_only_key() {
    // Cross-role portability: a connect string tuned for the egress
    // reader (or written for both roles) must parse on the ingress
    // sender. Values are not inspected — the ingress role doesn't
    // care what the reader would have done with them.
    for key in EGRESS_ONLY_CONFIG_KEYS {
        for val in ["1", "primary", "halt", ""] {
            let conf = format!("http::addr=127.0.0.1;{key}={val};");
            SenderBuilder::from_conf(&conf).unwrap_or_else(|e| {
                panic!(
                    "expected ingress to silently accept egress-only \
                     key {key}={val:?}, got {}",
                    e.msg()
                )
            });
        }
    }
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn ingress_accepts_full_egress_connect_string_unchanged() {
    // End-to-end portability smoke test: an egress-flavoured connect
    // string with multiple egress-only keys interleaved with shared
    // ones parses cleanly on the ingress sender without losing the
    // shared knobs along the way.
    // Note: `tls_verify` is intentionally omitted — it's a shared key,
    // but `http::` is plain (no TLS), and under feature combos that
    // include `insecure-skip-verify` the `tls_verify` arm routes through
    // `ensure_tls_enabled` and rejects it. The portability claim is
    // about *egress-only* keys riding alongside genuinely-shared ones
    // (`addr`, `username`, `password`), not about smuggling TLS knobs
    // into a non-TLS connect string.
    let conf = "http::addr=127.0.0.1:9000\
        ;username=u;password=p\
        ;path=/exec;max_version=2;compression=zstd;compression_level=3\
        ;max_batch_rows=10000;client_id=svc-a;target=primary\
        ;failover=on;failover_max_attempts=3\
        ;on_schema_error=drop;on_parse_error=halt\
        ;buffer_pool_size=8";
    let builder = SenderBuilder::from_conf(conf).unwrap();
    assert_eq!(builder.protocol, Protocol::Http);
    assert_specified_eq(&builder.host, "127.0.0.1");
    assert_specified_eq(&builder.port, "9000");
    assert_specified_eq(&builder.username, Some("u".to_string()));
    assert_specified_eq(&builder.password, Some("p".to_string()));
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_config_silently_accepts_reserved_on_error_policy_keys() {
    // Java parity (design/qwp-cursor-error-api.md): the per-category
    // server-error policy keys are reserved so the same connect string
    // can be shared across language clients regardless of which side
    // has wired the resolver. Today the sender catches them via the
    // generic unknown-key fallthrough — this guard locks that in.
    for key in [
        "on_server_error",
        "on_schema_error",
        "on_parse_error",
        "on_internal_error",
        "on_security_error",
        "on_write_error",
    ] {
        for val in ["halt", "drop", "auto", "anything", ""] {
            let conf = format!("qwpws::addr=localhost:9000;{key}={val};");
            SenderBuilder::from_conf(&conf)
                .unwrap_or_else(|e| panic!("expected {key}={val:?} to parse, got {}", e.msg()));
        }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_store_and_forward_size_suffixes_match_java_config_surface() {
    for (input, expected) in [
        ("64k", 64 * 1024_u64),
        ("64KB", 64 * 1024_u64),
        ("64m", 64 * 1024 * 1024_u64),
        ("4g", 4 * 1024 * 1024 * 1024_u64),
        ("1T", 1024_u64 * 1024 * 1024 * 1024),
    ] {
        let conf = format!("qwpws::addr=localhost:9000;sf_max_bytes={input};");
        let builder = SenderBuilder::from_conf(conf).unwrap();
        let qwp_ws = builder.qwp_ws.as_ref().unwrap();
        assert_specified_eq(&qwp_ws.sf_max_bytes, expected);
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_store_and_forward_config_accepts_and_rejects_java_keys() {
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;request_durable_ack=off;").unwrap();
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;request_durable_ack=on;").unwrap();
    SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;request_durable_ack=off;durable_ack_keepalive_interval_millis=5000;",
    )
    .unwrap();
    SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;request_durable_ack=on;durable_ack_keepalive_interval_millis=5000;",
    )
    .unwrap();
    SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;durable_ack_keepalive_interval_millis=5000;",
    )
    .unwrap();
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;durable_ack_keepalive_interval_millis=0;")
        .unwrap();
    SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;durable_ack_keepalive_interval_millis=-1;",
    )
    .unwrap();
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;drain_orphans=off;").unwrap();
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;drain_orphans=false;").unwrap();
    SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;drain_orphans=false;max_background_drainers=2;",
    )
    .unwrap();
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;max_background_drainers=0;").unwrap();
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;max_background_drainers=2;").unwrap();
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;auth_timeout_ms=1;").unwrap();
    let builder = SenderBuilder::new(Protocol::QwpWs, "localhost", 9000)
        .auth_timeout(Duration::from_millis(750))
        .unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(&qwp_ws.auth_timeout, Duration::from_millis(750));

    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;sender_id=bad/id;"),
        "invalid sender_id [value=bad/id, allowed-chars=[A-Za-z0-9_-]]",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;sf_max_bytes=64mi;"),
        "invalid sf_max_bytes [value=64mi]",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;sf_durability=sync;"),
        "invalid sf_durability [value=sync, allowed-values=[memory, flush, append]]",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;qwp_ws_progress=sync;"),
        "invalid qwp_ws_progress [value=sync, allowed-values=[background, manual]]",
    );
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;sf_append_deadline_millis=1234;").unwrap();
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;sf_append_deadline_millis=0;"),
        "\"sf_append_deadline_millis\" must be greater than 0.",
    );
    for (input, expected) in [(-42, 0), (-1, 0), (0, 0), (5000, 5000), (120000, 120000)] {
        let conf = format!("qwpws::addr=localhost:9000;close_flush_timeout_millis={input};");
        let builder = SenderBuilder::from_conf(conf).unwrap();
        let qwp_ws = builder.qwp_ws.as_ref().unwrap();
        assert_specified_eq(
            &qwp_ws.close_flush_timeout,
            std::time::Duration::from_millis(expected as u64),
        );
    }
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;request_durable_ack=maybe;"),
        "invalid request_durable_ack [value=maybe, allowed-values=[on, off]]",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;drain_orphans=maybe;"),
        "invalid drain_orphans [value=maybe, allowed-values=[on, off, true, false]]",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;max_background_drainers=-1;"),
        "max_background_drainers must be >= 0: -1",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;auth_timeout_ms=0;"),
        "auth_timeout_ms must be > 0: 0",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;auth_timeout_ms=-1;"),
        "auth_timeout_ms must be > 0: -1",
    );
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;drain_orphans=on;").unwrap();
    SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;drain_orphans=true;max_background_drainers=0;",
    )
    .unwrap();
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;error_inbox_capacity=64;").unwrap();
    SenderBuilder::from_conf("qwpws::addr=localhost:9000;error_inbox_capacity=16;").unwrap();
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;error_inbox_capacity=15;"),
        "error_inbox_capacity must be >= 16: 15",
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_rejects_unknown_config_key_but_tolerates_egress_keys() {
    // Per the connect-string spec, a genuinely unknown key on a QWP/WebSocket
    // connect string is rejected (typo / unsupported-option safety net).
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;totally_bogus_key=1;"),
        "Unknown config key \"totally_bogus_key\"",
    );
    // Egress query-client keys are tolerated so a single ws:: connect string can
    // drive both the ingress sender and the QwpQueryClient.
    SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;target=primary;compression=zstd;failover=on;zone=eu-1;max_batch_rows=1000;",
    )
    .unwrap();
}

#[cfg(all(feature = "sync-sender-qwp-ws", feature = "sync-sender-tcp"))]
#[test]
fn qwpws_store_and_forward_config_is_websocket_only() {
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost:9009;sf_dir=/tmp/qdb-rust-sf;"),
        "The \"sf_dir\" setting is only supported for QWP/WebSocket.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost:9009;close_flush_timeout_millis=5000;"),
        "The \"close_flush_timeout_millis\" setting is only supported for QWP/WebSocket.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost:9009;auth_timeout_ms=5000;"),
        "The \"auth_timeout_ms\" setting is only supported for QWP/WebSocket.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost:9009;sf_append_deadline_millis=5000;"),
        "The \"sf_append_deadline_millis\" setting is only supported for QWP/WebSocket.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost:9009;qwp_ws_progress=manual;"),
        "The \"qwp_ws_progress\" setting is only supported for QWP/WebSocket.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost:9009;request_durable_ack=on;"),
        "The \"request_durable_ack\" setting is only supported for QWP/WebSocket.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost:9009;request_durable_ack=off;"),
        "The \"request_durable_ack\" setting is only supported for QWP/WebSocket.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost:9009;drain_orphans=off;"),
        "The \"drain_orphans\" setting is only supported for QWP/WebSocket.",
    );
    assert_conf_err(
        SenderBuilder::from_conf(
            "tcp::addr=localhost:9009;durable_ack_keepalive_interval_millis=5000;",
        ),
        "The \"durable_ack_keepalive_interval_millis\" setting is only supported for QWP/WebSocket.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost:9009;max_background_drainers=2;"),
        "The \"max_background_drainers\" setting is only supported for QWP/WebSocket.",
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_store_and_forward_reserved_durability_fails_before_connect() {
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=127.0.0.1:1;sf_durability=flush;")
            .unwrap()
            .build(),
        "sf_durability=flush is not yet supported (deferred follow-up; use sf_durability=memory)",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpws::addr=127.0.0.1:1;sf_durability=append;")
            .unwrap()
            .build(),
        "sf_durability=append is not yet supported (deferred follow-up; use sf_durability=memory)",
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn invalid_value() {
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost\n;"),
        "Config parse error: invalid char '\\n' in value at position 19",
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn specified_cant_change() {
    let mut builder = SenderBuilder::from_conf("tcp::addr=localhost;").unwrap();
    builder = builder.bind_interface("1.1.1.1").unwrap();
    assert_conf_err(
        builder.bind_interface("1.1.1.2"),
        "\"bind_interface\" is already specified",
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn missing_addr() {
    assert_conf_err(
        SenderBuilder::from_conf("tcp::"),
        "Missing \"addr\" parameter in config string",
    );
}

#[cfg(any(
    feature = "sync-sender-tcp",
    feature = "sync-sender-http",
    feature = "sync-sender-qwp-udp"
))]
#[test]
fn unsupported_service() {
    assert_conf_err(
        SenderBuilder::from_conf("xaxa::addr=localhost;"),
        "Unsupported protocol: xaxa",
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn uppercase_scheme_accepted_tcp() {
    let builder = SenderBuilder::from_conf("TCP::addr=localhost:9009;").unwrap();
    assert_eq!(builder.protocol, Protocol::Tcp);
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn uppercase_scheme_accepted_https() {
    let builder = SenderBuilder::from_conf("HTTPS::addr=localhost:9000;").unwrap();
    assert_eq!(builder.protocol, Protocol::Https);
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn uppercase_scheme_accepted_qwpudp() {
    let builder = SenderBuilder::from_conf("QWPUDP::addr=localhost:9009;").unwrap();
    assert_eq!(builder.protocol, Protocol::QwpUdp);
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn uppercase_scheme_accepted_qwpws() {
    let builder = SenderBuilder::from_conf("QWPWS::addr=localhost:9000;").unwrap();
    assert_eq!(builder.protocol, Protocol::QwpWs);
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn uppercase_qwpws_preserves_multi_addr() {
    let builder = SenderBuilder::from_conf("QWPWS::addr=h1:9001,h2:9002,h3:9003;").unwrap();
    assert_eq!(builder.protocol, Protocol::QwpWs);
    let endpoints: &Vec<conf::QwpWsEndpoint> = &builder.qwp_ws.as_ref().unwrap().endpoints;
    assert_eq!(endpoints.len(), 3);
    assert_eq!(endpoints[0].host, "h1");
    assert_eq!(endpoints[0].port, "9001");
    assert_eq!(endpoints[1].host, "h2");
    assert_eq!(endpoints[1].port, "9002");
    assert_eq!(endpoints[2].host, "h3");
    assert_eq!(endpoints[2].port, "9003");
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn mixed_case_qwpws_preserves_multi_addr() {
    let builder = SenderBuilder::from_conf("QwpWs::addr=h1:9001,h2:9002;").unwrap();
    assert_eq!(builder.protocol, Protocol::QwpWs);
    let endpoints: &Vec<conf::QwpWsEndpoint> = &builder.qwp_ws.as_ref().unwrap().endpoints;
    assert_eq!(endpoints.len(), 2);
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn http_basic_auth() {
    let builder =
        SenderBuilder::from_conf("http::addr=localhost;username=user123;password=pass321;")
            .unwrap();
    let auth = builder.build_auth().unwrap();
    match auth.unwrap() {
        conf::AuthParams::Basic(conf::BasicAuthParams { username, password }) => {
            assert_eq!(username, "user123");
            assert_eq!(password, "pass321");
        }
        _ => {
            panic!("Expected AuthParams::Basic");
        }
    }
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn http_token_auth() {
    let builder = SenderBuilder::from_conf("http::addr=localhost:9000;token=token123;").unwrap();
    let auth = builder.build_auth().unwrap();
    match auth.unwrap() {
        conf::AuthParams::Token(conf::TokenAuthParams { token }) => {
            assert_eq!(token, "token123");
        }
        _ => {
            panic!("Expected AuthParams::Token");
        }
    }
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn incomplete_basic_auth() {
    assert_conf_err(
        SenderBuilder::from_conf("http::addr=localhost;username=user123;")
            .unwrap()
            .build(),
        "Basic authentication parameter \"username\" is present, but \"password\" is missing.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("http::addr=localhost;password=pass321;")
            .unwrap()
            .build(),
        "Basic authentication parameter \"password\" is present, but \"username\" is missing.",
    );
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn zero_timeout_forbidden() {
    assert_conf_err(
        SenderBuilder::from_conf("http::addr=localhost;username=user123;request_timeout=0;"),
        "\"request_timeout\" must be greater than 0.",
    );

    assert_conf_err(
        SenderBuilder::new(Protocol::Http, "localhost", 9000)
            .request_timeout(Duration::from_millis(0)),
        "\"request_timeout\" must be greater than 0.",
    );
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn misspelled_basic_auth() {
    assert_conf_err(
        Sender::from_conf("http::addr=localhost;username=user123;pass=pass321;"),
        r##"Basic authentication parameter "username" is present, but "password" is missing."##,
    );
    assert_conf_err(
        Sender::from_conf("http::addr=localhost;user=user123;password=pass321;"),
        r##"Basic authentication parameter "password" is present, but "username" is missing."##,
    );
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn inconsistent_http_auth() {
    let expected_err_msg = r##"Inconsistent HTTP authentication parameters. Specify either "username" and "password", or just "token"."##;
    assert_conf_err(
        Sender::from_conf("http::addr=localhost;username=user123;token=token123;"),
        expected_err_msg,
    );
    assert_conf_err(
        Sender::from_conf("http::addr=localhost;password=pass321;token=token123;"),
        expected_err_msg,
    );
}

#[cfg(all(feature = "sync-sender-tcp", feature = "sync-sender-http"))]
#[test]
fn cant_use_basic_auth_with_tcp() {
    let builder = SenderBuilder::new(Protocol::Tcp, "localhost", 9000)
        .username("user123")
        .unwrap()
        .password("pass321")
        .unwrap();
    assert_conf_err(
        builder.build_auth(),
        "The \"basic_auth\" setting can only be used with the ILP/HTTP protocol.",
    );
}

#[cfg(all(feature = "sync-sender-tcp", feature = "sync-sender-http"))]
#[test]
fn cant_use_token_auth_with_tcp() {
    let builder = SenderBuilder::new(Protocol::Tcp, "localhost", 9000)
        .token("token123")
        .unwrap();
    assert_conf_err(
        builder.build_auth(),
        "Token authentication only be used with the ILP/HTTP protocol.",
    );
}

#[cfg(all(feature = "sync-sender-tcp", feature = "sync-sender-http"))]
#[test]
fn cant_use_ecdsa_auth_with_http() {
    let builder = SenderBuilder::from_conf("http::addr=localhost;")
        .unwrap()
        .username("key_id123")
        .unwrap()
        .token("priv_key123")
        .unwrap()
        .token_x("pub_key1")
        .unwrap()
        .token_y("pub_key2")
        .unwrap();
    assert_conf_err(
        builder.build_auth(),
        "ECDSA authentication is only available with ILP/TCP and not available with ILP/HTTP.",
    );
}

#[cfg(all(not(feature = "sync-sender-tcp"), feature = "sync-sender-http"))]
#[test]
fn cant_use_ecdsa_auth_with_http_ex_tcp_support() {
    let mk_builder = || {
        SenderBuilder::from_conf("http::addr=localhost;")
            .unwrap()
            .username("key_id123")
            .unwrap()
            .token("priv_key123")
            .unwrap()
    };

    assert_conf_err(
        mk_builder().token_x("pub_key1"),
        "cannot specify \"token_x\": ECDSA authentication is only available with ILP/TCP and not available with ILP/HTTP.",
    );

    assert_conf_err(
        mk_builder().token_y("pub_key2"),
        "cannot specify \"token_y\": ECDSA authentication is only available with ILP/TCP and not available with ILP/HTTP.",
    );
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_protocol_version_unsupported() {
    for version in ["1", "2", "3"] {
        let conf = format!("qwpudp::addr=localhost;protocol_version={version};");
        assert_conf_err(
            SenderBuilder::from_conf(&conf),
            "The \"protocol_version\" setting is not supported for QWP/UDP.",
        );
    }

    for version in [
        ProtocolVersion::V1,
        ProtocolVersion::V2,
        ProtocolVersion::V3,
    ] {
        assert_conf_err(
            SenderBuilder::new(Protocol::QwpUdp, "localhost", 9007).protocol_version(version),
            "The \"protocol_version\" setting is not supported for QWP/UDP.",
        );
    }
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_max_datagram_size_requires_qwp_udp() {
    assert_conf_err(
        SenderBuilder::new(Protocol::QwpUdp, "localhost", 9007).max_datagram_size(0),
        "\"max_datagram_size\" must be greater than 0.",
    );

    #[cfg(feature = "sync-sender-http")]
    assert_conf_err(
        SenderBuilder::new(Protocol::Http, "localhost", 9000).max_datagram_size(1400),
        "The \"max_datagram_size\" setting is only supported for QWP/UDP.",
    );
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_max_datagram_size_accepts_udp_limit_and_rejects_above_it() {
    let builder = SenderBuilder::new(Protocol::QwpUdp, "localhost", 9007)
        .max_datagram_size(65507)
        .unwrap();
    let Some(qwp_udp) = builder.qwp_udp.as_ref() else {
        panic!("Expected Some(QwpUdpConfig)");
    };
    assert_specified_eq(&qwp_udp.max_datagram_size, 65507usize);

    assert_conf_err(
        SenderBuilder::new(Protocol::QwpUdp, "localhost", 9007).max_datagram_size(65508),
        "\"max_datagram_size\" must not exceed 65507 (UDP/IPv4 limit).",
    );
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_multicast_ttl_requires_qwp_udp() {
    assert_conf_err(
        SenderBuilder::new(Protocol::QwpUdp, "localhost", 9007).multicast_ttl(256),
        "\"multicast_ttl\" must be between 0 and 255.",
    );

    #[cfg(feature = "sync-sender-http")]
    assert_conf_err(
        SenderBuilder::new(Protocol::Http, "localhost", 9000).multicast_ttl(1),
        "The \"multicast_ttl\" setting is only supported for QWP/UDP.",
    );
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_config_string_rejects_invalid_datagram_size_and_multicast_ttl() {
    assert_conf_err(
        SenderBuilder::from_conf("qwpudp::addr=localhost;max_datagram_size=0;"),
        "\"max_datagram_size\" must be greater than 0.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpudp::addr=localhost;max_datagram_size=65508;"),
        "\"max_datagram_size\" must not exceed 65507 (UDP/IPv4 limit).",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpudp::addr=localhost;multicast_ttl=256;"),
        "\"multicast_ttl\" must be between 0 and 255.",
    );
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_bind_interface_is_supported_via_builder_api() {
    let builder = SenderBuilder::new(Protocol::QwpUdp, "239.1.2.3", 9007)
        .bind_interface("192.168.1.10")
        .unwrap();
    assert_eq!(builder.protocol, Protocol::QwpUdp);
    assert_specified_eq(&builder.net_interface, Some("192.168.1.10".to_string()));
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_auth_settings_are_rejected_at_config_time() {
    // Config string: from_conf itself must fail.
    assert_conf_err(
        SenderBuilder::from_conf("qwpudp::addr=localhost;username=user123;"),
        "The \"username\" setting is not supported for QWP/UDP.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpudp::addr=localhost;password=pass321;"),
        "The \"password\" setting is not supported for QWP/UDP.",
    );
    assert_conf_err(
        SenderBuilder::from_conf("qwpudp::addr=localhost;token=token123;"),
        "The \"token\" setting is not supported for QWP/UDP.",
    );

    #[cfg(feature = "sync-sender-tcp")]
    {
        assert_conf_err(
            SenderBuilder::from_conf("qwpudp::addr=localhost;token_x=pub_key1;"),
            "The \"token_x\" setting is not supported for QWP/UDP.",
        );
        assert_conf_err(
            SenderBuilder::from_conf("qwpudp::addr=localhost;token_y=pub_key2;"),
            "The \"token_y\" setting is not supported for QWP/UDP.",
        );
    }

    // Builder API: setter must fail.
    assert_conf_err(
        SenderBuilder::new(Protocol::QwpUdp, "localhost", 9007).username("user123"),
        "The \"username\" setting is not supported for QWP/UDP.",
    );
    assert_conf_err(
        SenderBuilder::new(Protocol::QwpUdp, "localhost", 9007).password("pass321"),
        "The \"password\" setting is not supported for QWP/UDP.",
    );
    assert_conf_err(
        SenderBuilder::new(Protocol::QwpUdp, "localhost", 9007).token("token123"),
        "The \"token\" setting is not supported for QWP/UDP.",
    );
}

#[cfg(feature = "sync-sender-qwp-udp")]
#[test]
fn qwpudp_auth_timeout_is_rejected_at_config_time() {
    // Config string: from_conf itself must fail.
    assert_conf_err(
        SenderBuilder::from_conf("qwpudp::addr=localhost;auth_timeout=100;"),
        "The \"auth_timeout\" setting is not supported for QWP/UDP.",
    );
    // Builder API: setter must fail.
    assert_conf_err(
        SenderBuilder::new(Protocol::QwpUdp, "localhost", 9007)
            .auth_timeout(Duration::from_millis(100)),
        "The \"auth_timeout\" setting is not supported for QWP/UDP.",
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn set_auth_specifies_tcp() {
    let mut builder = SenderBuilder::new(Protocol::Tcp, "localhost", 9000);
    assert_eq!(builder.protocol, Protocol::Tcp);
    builder = builder
        .username("key_id123")
        .unwrap()
        .token("priv_key123")
        .unwrap()
        .token_x("pub_key1")
        .unwrap()
        .token_y("pub_key2")
        .unwrap();
    assert_eq!(builder.protocol, Protocol::Tcp);
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn set_net_interface_specifies_tcp() {
    let builder = SenderBuilder::new(Protocol::Tcp, "localhost", 9000);
    assert_eq!(builder.protocol, Protocol::Tcp);
    builder.bind_interface("55.88.0.4").unwrap();
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcp_ecdsa_auth() {
    let builder = SenderBuilder::from_conf(
        "tcp::addr=localhost:9000;username=user123;token=token123;token_x=xtok123;token_y=ytok123;",
    )
    .unwrap();
    let auth = builder.build_auth().unwrap();
    match auth.unwrap() {
        conf::AuthParams::Ecdsa(conf::EcdsaAuthParams {
            key_id,
            priv_key,
            pub_key_x,
            pub_key_y,
        }) => {
            assert_eq!(key_id, "user123");
            assert_eq!(priv_key, "token123");
            assert_eq!(pub_key_x, "xtok123");
            assert_eq!(pub_key_y, "ytok123");
        }
        #[cfg(feature = "sync-sender-http")]
        _ => {
            panic!("Expected AuthParams::Ecdsa");
        }
    }
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn incomplete_tcp_ecdsa_auth() {
    let expected_err_msg = r##"Incomplete ECDSA authentication parameters. Specify either all or none of: "username", "token", "token_x", "token_y"."##;
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost;username=user123;")
            .unwrap()
            .build(),
        expected_err_msg,
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost;username=user123;token=token123;")
            .unwrap()
            .build(),
        expected_err_msg,
    );
    assert_conf_err(
        SenderBuilder::from_conf(
            "tcp::addr=localhost;username=user123;token=token123;token_x=123;",
        )
        .unwrap()
        .build(),
        expected_err_msg,
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn misspelled_tcp_ecdsa_auth() {
    assert_conf_err(
        Sender::from_conf("tcp::addr=localhost;username=user123;tokenx=123;"),
        "Incomplete ECDSA authentication parameters. Specify either all or none of: \"username\", \"token\", \"token_x\", \"token_y\".",
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcps_tls_verify_on() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;tls_verify=on;").unwrap();
    assert!(builder.protocol.tls_enabled());

    #[cfg(feature = "tls-webpki-certs")]
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);

    #[cfg(not(feature = "tls-webpki-certs"))]
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::OsRoots);
}

#[cfg(feature = "sync-sender-tcp")]
#[cfg(feature = "insecure-skip-verify")]
#[test]
fn tcps_tls_verify_unsafe_off() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;tls_verify=unsafe_off;").unwrap();
    assert!(builder.protocol.tls_enabled());
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);
    assert_specified_eq(&builder.tls_verify, false);
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcps_tls_verify_invalid() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;tls_verify=off;"),
        r##"Config parameter "tls_verify" must be either "on" or "unsafe_off".'"##,
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcps_tls_roots_webpki() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;tls_ca=webpki_roots;");

    #[cfg(feature = "tls-webpki-certs")]
    {
        let builder = builder.unwrap();
        assert!(builder.protocol.tls_enabled());
        assert_specified_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);
        assert_defaulted_eq(&builder.tls_roots, None);
    }

    #[cfg(not(feature = "tls-webpki-certs"))]
    assert_eq!(
        "Config parameter \"tls_ca=webpki_roots\" requires the \"tls-webpki-certs\" feature",
        builder.unwrap_err().msg()
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[cfg(feature = "tls-native-certs")]
#[test]
fn tcps_tls_roots_os() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;tls_ca=os_roots;").unwrap();
    assert!(builder.protocol.tls_enabled());
    assert_specified_eq(&builder.tls_ca, CertificateAuthority::OsRoots);
    assert_defaulted_eq(&builder.tls_roots, None);
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcps_tls_roots_file() {
    use std::io::Write;

    // Write a dummy file to test the file path
    let tmp_dir = TempDir::new().unwrap();
    let path = tmp_dir.path().join("cacerts.pem");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(b"dummy").unwrap();
    let builder = SenderBuilder::from_conf(format!(
        "tcps::addr=localhost;tls_roots={};",
        path.to_str().unwrap()
    ))
    .unwrap();
    assert_specified_eq(&builder.tls_ca, CertificateAuthority::PemFile);
    assert_specified_eq(&builder.tls_roots, path);
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcps_tls_roots_file_missing() {
    let err =
        SenderBuilder::from_conf("tcps::addr=localhost;tls_roots=/some/invalid/path/cacerts.pem;")
            .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(
        err.msg()
            .contains("Could not open root certificate file from path")
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcps_tls_roots_file_with_password() {
    // `tls_roots_password` is QWP/WebSocket-only — ILP/TCP and
    // ILP/HTTP still read PEM only (rustls' native input), so a
    // password set on TCP must surface a precise diagnostic
    // pointing the user at the right transport.
    use std::io::Write;

    let tmp_dir = TempDir::new().unwrap();
    let path = tmp_dir.path().join("cacerts.pem");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(b"dummy").unwrap();
    let builder_or_err = SenderBuilder::from_conf(format!(
        "tcps::addr=localhost;tls_roots={};tls_roots_password=extremely_secure;",
        path.to_str().unwrap()
    ));
    assert_conf_err(
        builder_or_err,
        "\"tls_roots_password\" is only supported for QWP/WebSocket \
         (qwpws / qwpwss). ILP/TCP and ILP/HTTP transports read unencrypted \
         PEM via rustls.",
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpwss_tls_roots_password_accepted() {
    // Smoke-test that the QWP/WebSocket path accepts the pair
    // without erroring at parse time. Actually loading the keystore
    // is deferred to `build()`, so we don't need a real JKS file
    // here.
    use std::io::Write;

    let tmp_dir = TempDir::new().unwrap();
    let path = tmp_dir.path().join("trust.jks");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(b"placeholder").unwrap();
    let builder = SenderBuilder::from_conf(format!(
        "qwpwss::addr=localhost;tls_roots={};tls_roots_password=secret;",
        path.to_str().unwrap()
    ))
    .unwrap();
    assert_specified_eq(&builder.tls_roots_password, Some("secret".to_string()));
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpwss_tls_roots_password_without_path_rejected() {
    // Java enforces the same pairing: setting the password without
    // pointing at the file makes the password name nothing.
    let builder_or_err =
        SenderBuilder::from_conf("qwpwss::addr=localhost;tls_roots_password=secret;").unwrap();
    let err = builder_or_err.build().unwrap_err();
    assert!(
        err.msg().contains("tls_roots_password") && err.msg().contains("tls_roots"),
        "msg: {}",
        err.msg()
    );
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn http_request_min_throughput() {
    let builder =
        SenderBuilder::from_conf("http::addr=localhost;request_min_throughput=100;").unwrap();
    let Some(http_config) = builder.http else {
        panic!("Expected Some(HttpConfig)");
    };
    assert_specified_eq(&http_config.request_min_throughput, 100u64);
    assert_defaulted_eq(&http_config.request_timeout, Duration::from_millis(10000));
    assert_defaulted_eq(&http_config.retry_timeout, Duration::from_millis(10000));
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn http_request_timeout() {
    let builder = SenderBuilder::from_conf("http::addr=localhost;request_timeout=100;").unwrap();
    let Some(http_config) = builder.http else {
        panic!("Expected Some(HttpConfig)");
    };
    assert_defaulted_eq(&http_config.request_min_throughput, 102400u64);
    assert_specified_eq(&http_config.request_timeout, Duration::from_millis(100));
    assert_defaulted_eq(&http_config.retry_timeout, Duration::from_millis(10000));
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn http_retry_timeout() {
    let builder = SenderBuilder::from_conf("http::addr=localhost;retry_timeout=100;").unwrap();
    let Some(http_config) = builder.http else {
        panic!("Expected Some(HttpConfig)");
    };
    assert_defaulted_eq(&http_config.request_min_throughput, 102400u64);
    assert_defaulted_eq(&http_config.request_timeout, Duration::from_millis(10000));
    assert_specified_eq(&http_config.retry_timeout, Duration::from_millis(100));
    assert_defaulted_eq(&http_config.retry_max_backoff, Duration::from_millis(1000));
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn http_retry_max_backoff() {
    let builder =
        SenderBuilder::from_conf("http::addr=localhost;retry_max_backoff_millis=250;").unwrap();
    let Some(http_config) = builder.http else {
        panic!("Expected Some(HttpConfig)");
    };
    assert_specified_eq(&http_config.retry_max_backoff, Duration::from_millis(250));
    assert_defaulted_eq(&http_config.retry_timeout, Duration::from_millis(10000));
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn http_retry_max_backoff_below_min_rejected() {
    let msg = "\"retry_max_backoff_millis\" must be at least 10.";
    assert_conf_err(
        SenderBuilder::from_conf("http::addr=localhost;retry_max_backoff_millis=0;"),
        msg,
    );
    assert_conf_err(
        SenderBuilder::from_conf("http::addr=localhost;retry_max_backoff_millis=3;"),
        msg,
    );
}

#[cfg(all(feature = "sync-sender-tcp", feature = "sync-sender-http"))]
#[test]
fn retry_max_backoff_rejected_on_non_http() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;retry_max_backoff_millis=250;"),
        "retry_max_backoff_millis is supported only in ILP over HTTP.",
    );
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn connect_timeout_uses_request_timeout() {
    use std::time::Instant;
    let request_timeout = Duration::from_millis(10);
    let builder = SenderBuilder::new(Protocol::Http, "127.0.0.2", "1111")
        .request_timeout(request_timeout)
        .unwrap()
        .protocol_version(ProtocolVersion::V2)
        .unwrap()
        .retry_timeout(Duration::from_millis(10))
        .unwrap()
        .request_min_throughput(0)
        .unwrap();
    let mut sender = builder.build().unwrap();
    let mut buf = sender.new_buffer();
    buf.table("x")
        .unwrap()
        .symbol("x", "x")
        .unwrap()
        .at_now()
        .unwrap();
    let start = Instant::now();
    sender
        .flush(&mut buf)
        .expect_err("Request did not time out");
    assert!(Instant::now() - start < Duration::from_secs(10));
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn auto_flush_off() {
    SenderBuilder::from_conf("tcps::addr=localhost;auto_flush=off;").unwrap();
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn auto_flush_unsupported() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;auto_flush=on;"),
        "Invalid auto_flush value 'on'. This client does not support \
            auto-flush, so the only accepted value is 'off'",
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn auto_flush_rows_unsupported() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;auto_flush_rows=100;"),
        "Invalid configuration parameter \"auto_flush_rows\". This client does not support auto-flush",
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn auto_flush_bytes_unsupported() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;auto_flush_bytes=100;"),
        "Invalid configuration parameter \"auto_flush_bytes\". This client does not support auto-flush",
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn auto_flush_interval_unsupported() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;auto_flush_interval=500;"),
        "Invalid configuration parameter \"auto_flush_interval\". This client does not support auto-flush",
    );
}

// `reconnect_*` knobs are documented as the reconnect budget but were
// silently ignored on the *initial* connect because `initial_connect_retry`
// defaulted to `off`. A user setting `reconnect_max_duration_millis=120000`
// expecting it to cover startup races against an unhealthy server got one
// shot at the WS upgrade and no retry. `apply_reconnect_implies_initial_retry`
// (called from `from_conf` and `build`) closes this footgun by promoting
// `initial_connect_retry` to `Sync` whenever any `reconnect_*` key is
// explicitly set and the user has not picked a mode themselves.

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_defaults_leave_initial_connect_retry_off() {
    let builder = SenderBuilder::from_conf("qwpws::addr=localhost:9000;").unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_defaulted_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Off,
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_reconnect_max_duration_implies_initial_connect_retry_sync() {
    let builder = SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;reconnect_max_duration_millis=120000;",
    )
    .unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Sync,
    );
    assert_specified_eq(&qwp_ws.reconnect_max_duration, Duration::from_secs(120));
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_reconnect_initial_backoff_implies_initial_connect_retry_sync() {
    let builder = SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;reconnect_initial_backoff_millis=250;",
    )
    .unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Sync,
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_reconnect_max_backoff_implies_initial_connect_retry_sync() {
    let builder =
        SenderBuilder::from_conf("qwpws::addr=localhost:9000;reconnect_max_backoff_millis=10000;")
            .unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Sync,
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_explicit_initial_connect_retry_off_is_preserved() {
    // Belt-and-suspenders: even when the user sets a reconnect budget,
    // an explicit initial_connect_retry=off override must win.
    let builder = SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;reconnect_max_duration_millis=120000;initial_connect_retry=off;",
    )
    .unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Off,
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_explicit_initial_connect_retry_async_is_preserved() {
    let builder = SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;reconnect_max_duration_millis=120000;initial_connect_retry=async;",
    )
    .unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Async,
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_explicit_off_before_reconnect_key_is_preserved() {
    // Reversed key order from `qwpws_explicit_initial_connect_retry_off_is_preserved`:
    // the override is set first, then the reconnect budget. The promotion
    // runs after the parse loop, so the explicit `off` must still win
    // regardless of where it appeared in the conf string.
    let builder = SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;initial_connect_retry=off;reconnect_max_duration_millis=120000;",
    )
    .unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Off,
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_multiple_reconnect_keys_promote_once() {
    // Setting all three reconnect_* keys at once still resolves to a
    // single `Sync` promotion -- no interaction between the keys.
    let builder = SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;\
         reconnect_max_duration_millis=120000;\
         reconnect_initial_backoff_millis=250;\
         reconnect_max_backoff_millis=10000;",
    )
    .unwrap();
    let qwp_ws = builder.qwp_ws.as_ref().unwrap();
    assert_specified_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Sync,
    );
    assert_specified_eq(&qwp_ws.reconnect_max_duration, Duration::from_secs(120));
    assert_specified_eq(
        &qwp_ws.reconnect_initial_backoff,
        Duration::from_millis(250),
    );
    assert_specified_eq(&qwp_ws.reconnect_max_backoff, Duration::from_secs(10));
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_reconnect_implies_initial_retry_via_builder_api() {
    // The builder API reaches `build()` without going through `from_conf`,
    // so the promotion must also fire from there. We can't observe
    // `build()`'s local QwpWsConfig clone directly, but the helper that
    // implements the invariant is `pub(crate)`, so exercise it on the
    // same `QwpWsConfig` the builder would feed in.
    let builder = SenderBuilder::new(Protocol::QwpWs, "localhost", 9000)
        .reconnect_max_duration(Duration::from_secs(120))
        .unwrap();
    let mut qwp_ws = builder.qwp_ws.as_ref().unwrap().clone();
    // Before the promotion runs (mirrors the builder-state-at-build-time):
    assert_defaulted_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Off,
    );
    qwp_ws.apply_reconnect_implies_initial_retry();
    assert_specified_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Sync,
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_apply_reconnect_implies_initial_retry_is_idempotent() {
    // `from_conf` already runs the promotion at parse time; `build()`
    // then runs it again on a clone. The second run must be a no-op
    // when the first has already settled the value.
    let builder = SenderBuilder::from_conf(
        "qwpws::addr=localhost:9000;reconnect_max_duration_millis=120000;",
    )
    .unwrap();
    let mut qwp_ws = builder.qwp_ws.as_ref().unwrap().clone();
    assert_specified_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Sync,
    );
    qwp_ws.apply_reconnect_implies_initial_retry();
    assert_specified_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Sync,
    );
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[test]
fn qwpws_apply_reconnect_implies_initial_retry_no_op_without_reconnect_keys() {
    // Defaults only: no reconnect_* key was specified, so the promotion
    // is a no-op and `initial_connect_retry` stays `Defaulted(Off)`.
    let mut qwp_ws = conf::QwpWsConfig::default();
    qwp_ws.apply_reconnect_implies_initial_retry();
    assert_defaulted_eq(
        &qwp_ws.initial_connect_retry,
        conf::QwpWsInitialConnectMode::Off,
    );
}

#[test]
fn config_setting_is_specified_reports_variant() {
    let mut setting: ConfigSetting<u32> = ConfigSetting::new_default(7);
    assert!(!setting.is_specified());
    setting.set_specified("test", 42).unwrap();
    assert!(setting.is_specified());
}

fn assert_specified_eq<V: PartialEq + Debug, IntoV: Into<V>>(
    actual: &ConfigSetting<V>,
    expected: IntoV,
) {
    let expected = expected.into();
    if let ConfigSetting::Specified(actual_value) = actual {
        assert_eq!(actual_value, &expected);
    } else {
        panic!("Expected Specified({expected:?}), but got {actual:?}");
    }
}

fn assert_defaulted_eq<V: PartialEq + std::fmt::Debug, IntoV: Into<V>>(
    actual: &ConfigSetting<V>,
    expected: IntoV,
) {
    let expected = expected.into();
    if let ConfigSetting::Defaulted(actual_value) = actual {
        assert_eq!(actual_value, &expected);
    } else {
        panic!("Expected Defaulted({expected:?}), but got {actual:?}");
    }
}

fn assert_conf_err<T, M: AsRef<str>>(result: Result<T>, expect_msg: M) {
    let Err(err) = result else {
        panic!("Got Ok, expected ConfigError: {}", expect_msg.as_ref());
    };
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert_eq!(err.msg(), expect_msg.as_ref());
}
