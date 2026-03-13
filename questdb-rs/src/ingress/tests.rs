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

#[cfg(feature = "sync-sender-tcp")]
use tempfile::TempDir;

#[cfg(feature = "sync-sender-http")]
#[test]
fn http_simple() {
    let builder = SenderBuilder::from_conf("http::addr=127.0.0.1;").unwrap();
    assert_eq!(builder.protocol, Protocol::Http);
    assert_eq!(builder.addresses[0].0, "127.0.0.1");
    assert_eq!(builder.addresses[0].1, Protocol::Http.default_port());
    assert!(!builder.protocol.tls_enabled());
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn https_simple() {
    let builder = SenderBuilder::from_conf("https::addr=localhost;").unwrap();
    assert_eq!(builder.protocol, Protocol::Https);
    assert_eq!(builder.addresses[0].0, "localhost");
    assert_eq!(builder.addresses[0].1, Protocol::Https.default_port());
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
    assert_eq!(builder.addresses[0].1, Protocol::Tcp.default_port());
    assert_eq!(builder.addresses[0].0, "127.0.0.1");
    assert!(!builder.protocol.tls_enabled());
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcps_simple() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;").unwrap();
    assert_eq!(builder.protocol, Protocol::Tcps);
    assert_eq!(builder.addresses[0].0, "localhost");
    assert_eq!(builder.addresses[0].1, Protocol::Tcps.default_port());
    assert!(builder.protocol.tls_enabled());

    #[cfg(feature = "tls-webpki-certs")]
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);

    #[cfg(not(feature = "tls-webpki-certs"))]
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::OsRoots);
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

#[cfg(any(feature = "sync-sender-tcp", feature = "sync-sender-http"))]
#[test]
fn unsupported_service() {
    assert_conf_err(
        SenderBuilder::from_conf("xaxa::addr=localhost;"),
        "Unsupported protocol: xaxa",
    );
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
            .unwrap()
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
        .unwrap()
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
        .unwrap()
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

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn set_auth_specifies_tcp() {
    let mut builder = SenderBuilder::new(Protocol::Tcp, "localhost", 9000).unwrap();
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
    let builder = SenderBuilder::new(Protocol::Tcp, "localhost", 9000).unwrap();
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
    use std::io::Write;

    let tmp_dir = TempDir::new().unwrap();
    let path = tmp_dir.path().join("cacerts.pem");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(b"dummy").unwrap();
    let builder_or_err = SenderBuilder::from_conf(format!(
        "tcps::addr=localhost;tls_roots={};tls_roots_password=extremely_secure;",
        path.to_str().unwrap()
    ));
    assert_conf_err(builder_or_err, "\"tls_roots_password\" is not supported.");
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
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn connect_timeout_uses_request_timeout() {
    use std::time::Instant;
    let request_timeout = Duration::from_millis(10);
    let builder = SenderBuilder::new(Protocol::Http, "127.0.0.2", "1111")
        .unwrap()
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

// ==================== Multi-URL Config Parsing Tests ====================

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_parse_multiple_addresses_from_config_string() {
    let builder = SenderBuilder::from_conf(
        "http::addr=host1:9000;addr=host2:9001;addr=host3:9002;",
    )
    .unwrap();
    assert_eq!(builder.addresses.len(), 3);
    assert_eq!(builder.addresses[0], ("host1".to_string(), "9000".to_string()));
    assert_eq!(builder.addresses[1], ("host2".to_string(), "9001".to_string()));
    assert_eq!(builder.addresses[2], ("host3".to_string(), "9002".to_string()));
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_parse_addresses_with_default_port() {
    let builder = SenderBuilder::from_conf(
        "http::addr=host1;addr=host2;addr=host3;",
    )
    .unwrap();
    assert_eq!(builder.addresses.len(), 3);
    assert_eq!(builder.addresses[0], ("host1".to_string(), "9000".to_string()));
    assert_eq!(builder.addresses[1], ("host2".to_string(), "9000".to_string()));
    assert_eq!(builder.addresses[2], ("host3".to_string(), "9000".to_string()));
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_parse_mixed_ports_and_defaults() {
    let builder = SenderBuilder::from_conf(
        "http::addr=host1:8080;addr=host2;addr=host3:9009;",
    )
    .unwrap();
    assert_eq!(builder.addresses.len(), 3);
    assert_eq!(builder.addresses[0], ("host1".to_string(), "8080".to_string()));
    assert_eq!(builder.addresses[1], ("host2".to_string(), "9000".to_string()));
    assert_eq!(builder.addresses[2], ("host3".to_string(), "9009".to_string()));
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_https_default_port() {
    let builder = SenderBuilder::from_conf(
        "https::addr=host1;addr=host2;",
    )
    .unwrap();
    assert_eq!(builder.addresses.len(), 2);
    assert_eq!(builder.addresses[0].1, "9000");
    assert_eq!(builder.addresses[1].1, "9000");
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_single_address_defaults_to_one() {
    let builder = SenderBuilder::from_conf("http::addr=localhost:9000;").unwrap();
    assert_eq!(builder.addresses.len(), 1);
    assert_eq!(builder.addresses[0], ("localhost".to_string(), "9000".to_string()));
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_preserves_other_params() {
    let builder = SenderBuilder::from_conf(
        "http::addr=host1:9000;addr=host2:9001;username=user1;password=pass1;retry_timeout=5000;",
    )
    .unwrap();
    assert_eq!(builder.addresses.len(), 2);
    let auth = builder.build_auth().unwrap();
    match auth.unwrap() {
        conf::AuthParams::Basic(conf::BasicAuthParams { username, password }) => {
            assert_eq!(username, "user1");
            assert_eq!(password, "pass1");
        }
        _ => panic!("Expected AuthParams::Basic"),
    }
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn multi_url_tcp_rejects_multiple_addresses() {
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=host1:9009;addr=host2:9009;"),
        "Multiple addresses are only supported for HTTP/HTTPS protocols.",
    );
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn multi_url_tcps_rejects_multiple_addresses() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=host1:9009;addr=host2:9009;"),
        "Multiple addresses are only supported for HTTP/HTTPS protocols.",
    );
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_programmatic_address_chaining() {
    let builder = SenderBuilder::new(Protocol::Http, "host1", 9000)
        .unwrap()
        .address("host2", 9001u16)
        .unwrap()
        .address("host3", 9002u16)
        .unwrap();
    assert_eq!(builder.addresses.len(), 3);
    assert_eq!(builder.addresses[0], ("host1".to_string(), "9000".to_string()));
    assert_eq!(builder.addresses[1], ("host2".to_string(), "9001".to_string()));
    assert_eq!(builder.addresses[2], ("host3".to_string(), "9002".to_string()));
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_programmatic_address_with_string_port() {
    let builder = SenderBuilder::new(Protocol::Http, "host1", "9000")
        .unwrap()
        .address("host2", "9001")
        .unwrap();
    assert_eq!(builder.addresses.len(), 2);
    assert_eq!(builder.addresses[1], ("host2".to_string(), "9001".to_string()));
}

#[cfg(all(feature = "sync-sender-tcp", feature = "sync-sender-http"))]
#[test]
fn multi_url_programmatic_tcp_rejects_address() {
    let builder = SenderBuilder::new(Protocol::Tcp, "host1", 9009).unwrap();
    assert_conf_err(
        builder.address("host2", 9009u16),
        "Multiple addresses are only supported for HTTP/HTTPS protocols.",
    );
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_many_addresses() {
    let mut builder = SenderBuilder::new(Protocol::Http, "host0", 9000).unwrap();
    for i in 1..20 {
        builder = builder
            .address(format!("host{i}"), (9000 + i) as u16)
            .unwrap();
    }
    assert_eq!(builder.addresses.len(), 20);
    for i in 0..20 {
        assert_eq!(builder.addresses[i].0, format!("host{i}"));
    }
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_duplicate_addresses_allowed() {
    let builder = SenderBuilder::from_conf(
        "http::addr=host1:9000;addr=host1:9000;addr=host1:9000;",
    )
    .unwrap();
    assert_eq!(builder.addresses.len(), 3);
    assert_eq!(builder.addresses[0], builder.addresses[1]);
    assert_eq!(builder.addresses[1], builder.addresses[2]);
}

// ==================== Fuzz-like Config Parsing Tests ====================

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_fuzz_random_addr_combinations() {
    // Test various valid multi-addr configurations.
    let test_cases = vec![
        "http::addr=a:1;",
        "http::addr=a:1;addr=b:2;",
        "http::addr=a:1;addr=b:2;addr=c:3;",
        "http::addr=localhost;addr=127.0.0.1:8080;",
        "http::addr=my-host.example.com:9000;addr=other-host.example.com;",
        "https::addr=secure1:443;addr=secure2:443;",
        "http::addr=a:1;addr=b:2;addr=c:3;addr=d:4;addr=e:5;",
        "http::addr=h:1;addr=h:2;addr=h:3;addr=h:4;addr=h:5;addr=h:6;addr=h:7;addr=h:8;addr=h:9;addr=h:10;",
    ];

    for conf_str in test_cases {
        let builder = SenderBuilder::from_conf(conf_str);
        assert!(
            builder.is_ok(),
            "Failed to parse config: {conf_str}: {:?}",
            builder.err()
        );
    }
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_fuzz_addr_with_all_params() {
    let conf = "http::addr=h1:9000;addr=h2:9001;username=u;password=p;request_timeout=5000;retry_timeout=3000;request_min_throughput=1024;max_buf_size=2048;";
    let builder = SenderBuilder::from_conf(conf).unwrap();
    assert_eq!(builder.addresses.len(), 2);
    let http = builder.http.as_ref().unwrap();
    assert_specified_eq(&http.request_timeout, Duration::from_millis(5000));
    assert_specified_eq(&http.retry_timeout, Duration::from_millis(3000));
    assert_specified_eq(&http.request_min_throughput, 1024u64);
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_addr_ordering_matters() {
    // Ensure the first addr is the primary.
    let builder = SenderBuilder::from_conf(
        "http::addr=primary:9000;addr=secondary:9001;addr=tertiary:9002;",
    )
    .unwrap();
    assert_eq!(builder.addresses[0].0, "primary");
    assert_eq!(builder.addresses[1].0, "secondary");
    assert_eq!(builder.addresses[2].0, "tertiary");
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_addr_interleaved_with_other_params() {
    // addr params interleaved with other params should still work.
    let builder = SenderBuilder::from_conf(
        "http::addr=h1:9000;username=u;addr=h2:9001;password=p;addr=h3:9002;",
    )
    .unwrap();
    assert_eq!(builder.addresses.len(), 3);
    assert_eq!(builder.addresses[0].0, "h1");
    assert_eq!(builder.addresses[1].0, "h2");
    assert_eq!(builder.addresses[2].0, "h3");
    let auth = builder.build_auth().unwrap();
    assert!(matches!(auth, Some(conf::AuthParams::Basic(_))));
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

// === IPv6 address parsing tests (Fix #12) ===

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_ipv6_bracket_notation_with_port() {
    let builder = SenderBuilder::from_conf("http::addr=[::1]:9000;").unwrap();
    assert_eq!(builder.addresses.len(), 1);
    assert_eq!(builder.addresses[0].0, "::1");
    assert_eq!(builder.addresses[0].1, "9000");
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_ipv6_bracket_notation_default_port() {
    let builder = SenderBuilder::from_conf("http::addr=[::1];").unwrap();
    assert_eq!(builder.addresses.len(), 1);
    assert_eq!(builder.addresses[0].0, "::1");
    assert_eq!(builder.addresses[0].1, Protocol::Http.default_port());
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_ipv6_multiple_addrs() {
    let builder = SenderBuilder::from_conf(
        "http::addr=[::1]:9000;addr=[2001:db8::1]:9001;addr=host3:9002;",
    )
    .unwrap();
    assert_eq!(builder.addresses.len(), 3);
    assert_eq!(builder.addresses[0], ("::1".to_string(), "9000".to_string()));
    assert_eq!(
        builder.addresses[1],
        ("2001:db8::1".to_string(), "9001".to_string())
    );
    assert_eq!(
        builder.addresses[2],
        ("host3".to_string(), "9002".to_string())
    );
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_ipv6_full_address() {
    let builder =
        SenderBuilder::from_conf("http::addr=[2001:0db8:85a3::8a2e:0370:7334]:9000;").unwrap();
    assert_eq!(builder.addresses[0].0, "2001:0db8:85a3::8a2e:0370:7334");
    assert_eq!(builder.addresses[0].1, "9000");
}

// === Empty host/port validation tests (Fix #13) ===

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_empty_addr_rejected() {
    let result = SenderBuilder::from_conf("http::addr=;");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_empty_port_rejected() {
    let result = SenderBuilder::from_conf("http::addr=host:;");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("Empty port"), "Error: {}", err.msg());
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_empty_host_rejected() {
    let result = SenderBuilder::from_conf("http::addr=:9000;");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("Empty host"), "Error: {}", err.msg());
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_ipv6_unterminated_bracket() {
    let result = SenderBuilder::from_conf("http::addr=[::1:9000;");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(
        err.msg().contains("Unterminated bracket"),
        "Error: {}",
        err.msg()
    );
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_ipv6_empty_bracket_host() {
    let result = SenderBuilder::from_conf("http::addr=[]:9000;");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("Empty host"), "Error: {}", err.msg());
}

// === split_addr with rsplit_once preserves backward compat (Fix #12) ===

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_regular_hostname_with_port() {
    // Standard host:port still works with rsplit_once
    let builder = SenderBuilder::from_conf("http::addr=myhost.example.com:9000;").unwrap();
    assert_eq!(builder.addresses[0].0, "myhost.example.com");
    assert_eq!(builder.addresses[0].1, "9000");
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_hostname_no_port_default() {
    let builder = SenderBuilder::from_conf("http::addr=myhost;").unwrap();
    assert_eq!(builder.addresses[0].0, "myhost");
    assert_eq!(builder.addresses[0].1, Protocol::Http.default_port());
}

// === Dead code removal verification (Fix #11) ===
// The `first_addr_seen` variable has been removed. If it returns, this test
// will still pass, but verifying that multiple addr keys are correctly skipped
// in the params loop (the behavior first_addr_seen was trying to support).
#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_addr_params_skipped_correctly() {
    // Three addr keys plus other params - all addr entries should be skipped in the loop,
    // and other params applied correctly.
    let builder = SenderBuilder::from_conf(
        "http::addr=host1:9000;addr=host2:9001;addr=host3:9002;retry_timeout=5000;",
    )
    .unwrap();
    assert_eq!(builder.addresses.len(), 3);
    let http = builder.http.as_ref().unwrap();
    assert_eq!(*http.retry_timeout, Duration::from_millis(5000));
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_ipv6_bracket_empty_port_after_colon() {
    // [::1]: — bracket notation with trailing colon but no port value.
    let result = SenderBuilder::from_conf("http::addr=[::1]:;");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("Empty port"), "Error: {}", err.msg());
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_bare_ipv6_rejected() {
    // Bare IPv6 without brackets should be rejected with a helpful message.
    let result = SenderBuilder::from_conf("http::addr=::1;");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(
        err.msg().contains("bracket notation"),
        "Error should mention bracket notation: {}",
        err.msg()
    );
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn multi_url_bare_ipv6_full_rejected() {
    // Full bare IPv6 address like fe80::1 should also be rejected.
    let result = SenderBuilder::from_conf("http::addr=fe80::1;");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(
        err.msg().contains("bracket notation"),
        "Error should mention bracket notation: {}",
        err.msg()
    );
}

#[test]
fn multi_url_address_rejects_empty_host() {
    let result = SenderBuilder::new(Protocol::Http, "localhost", "9000")
        .unwrap()
        .address("", "9001");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("Empty host"));
}

#[test]
fn multi_url_address_rejects_empty_port() {
    let result = SenderBuilder::new(Protocol::Http, "localhost", "9000")
        .unwrap()
        .address("host2", "");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("Empty port"));
}

#[test]
fn new_rejects_empty_host() {
    let result = SenderBuilder::new(Protocol::Http, "", "9000");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("Empty host"));
}

#[test]
fn new_rejects_empty_port() {
    let result = SenderBuilder::new(Protocol::Http, "localhost", "");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("Empty port"));
}
