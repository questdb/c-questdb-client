use super::*;
use crate::ErrorCode;
use tempfile::TempDir;

#[cfg(feature = "ilp-over-http")]
#[test]
fn http_simple() {
    let builder = SenderBuilder::from_conf("http::addr=localhost;").unwrap();
    assert_eq!(builder.protocol, SenderProtocol::IlpOverHttp);
    assert_specified_eq(&builder.host, "localhost");
    assert_specified_eq(&builder.port, SenderProtocol::IlpOverHttp.default_port());
    assert_specified_eq(&builder.tls_enabled, false);
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn https_simple() {
    let builder = SenderBuilder::from_conf("https::addr=localhost;").unwrap();
    assert_eq!(builder.protocol, SenderProtocol::IlpOverHttp);
    assert_specified_eq(&builder.host, "localhost");
    assert_specified_eq(&builder.port, SenderProtocol::IlpOverHttp.default_port());
    assert_specified_eq(&builder.tls_enabled, true);
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);
}

#[test]
fn tcp_simple() {
    let builder = SenderBuilder::from_conf("tcp::addr=localhost;").unwrap();
    assert_eq!(builder.protocol, SenderProtocol::IlpOverTcp);
    assert_specified_eq(&builder.port, SenderProtocol::IlpOverTcp.default_port());
    assert_specified_eq(&builder.host, "localhost");
    assert_specified_eq(&builder.tls_enabled, false);
}

#[test]
fn tcps_simple() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;").unwrap();
    assert_eq!(builder.protocol, SenderProtocol::IlpOverTcp);
    assert_specified_eq(&builder.host, "localhost");
    assert_specified_eq(&builder.port, SenderProtocol::IlpOverTcp.default_port());
    assert_specified_eq(&builder.tls_enabled, true);
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);
}

#[test]
fn invalid_value() {
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost\n;"),
        "Config parse error: invalid char '\\n' in value at position 19",
    );
}

#[test]
fn specified_cant_change() {
    let mut builder = SenderBuilder::from_conf("tcp::addr=localhost;").unwrap();
    builder = builder.bind_interface("1.1.1.1").unwrap();
    assert_conf_err(
        builder.bind_interface("1.1.1.2"),
        "\"bind_interface\" is already specified",
    );
}

#[test]
fn missing_addr() {
    assert_conf_err(
        SenderBuilder::from_conf("tcp::"),
        "Missing \"addr\" parameter in config string",
    );
}

#[test]
fn unsupported_service() {
    assert_conf_err(
        SenderBuilder::from_conf("xaxa::addr=localhost;"),
        "Unsupported service: xaxa",
    );
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn http_basic_auth() {
    let builder =
        SenderBuilder::from_conf("http::addr=localhost;username=user123;password=pass321;")
            .unwrap();
    let auth = builder.build_auth().unwrap();
    match auth.unwrap() {
        AuthParams::Basic(BasicAuthParams { username, password }) => {
            assert_eq!(username, "user123");
            assert_eq!(password, "pass321");
        }
        _ => {
            panic!("Expected AuthParams::Basic");
        }
    }
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn http_token_auth() {
    let builder = SenderBuilder::from_conf("http::addr=localhost:9000;token=token123;").unwrap();
    let auth = builder.build_auth().unwrap();
    match auth.unwrap() {
        AuthParams::Token(TokenAuthParams { token }) => {
            assert_eq!(token, "token123");
        }
        _ => {
            panic!("Expected AuthParams::Token");
        }
    }
}

#[cfg(feature = "ilp-over-http")]
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

#[cfg(feature = "ilp-over-http")]
#[test]
fn misspelled_basic_auth() {
    assert_conf_err(
        Sender::from_conf("http::addr=localhost;username=user123;password=pass321;"),
        r##"Basic authentication parameter "username" is present, but "password" is missing."##,
    );
    assert_conf_err(
        Sender::from_conf("http::addr=localhost;username=user123;password=pass321;"),
        r##"Basic authentication parameter "password" is present, but "username" is missing."##,
    );
}

#[cfg(feature = "ilp-over-http")]
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

#[cfg(feature = "ilp-over-http")]
#[test]
fn cant_use_basic_auth_with_tcp() {
    let builder = SenderBuilder::new_tcp("localhost", 9000)
        .username("user123")
        .unwrap()
        .password("pass321")
        .unwrap();
    assert_conf_err(
        builder.build_auth(),
        "The \"basic_auth\" setting can only be used with the ILP/HTTP protocol.",
    );
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn cant_use_token_auth_with_tcp() {
    let builder = SenderBuilder::new_tcp("localhost", 9000)
        .token("token123")
        .unwrap();
    assert_conf_err(
        builder.build_auth(),
        "Token authentication only be used with the ILP/HTTP protocol.",
    );
}

#[cfg(feature = "ilp-over-http")]
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

#[test]
fn set_auth_specifies_tcp() {
    let mut builder = SenderBuilder::new_tcp("localhost", 9000);
    assert_eq!(builder.protocol, SenderProtocol::IlpOverTcp);
    builder = builder
        .username("key_id123")
        .unwrap()
        .token("priv_key123")
        .unwrap()
        .token_x("pub_key1")
        .unwrap()
        .token_y("pub_key2")
        .unwrap();
    assert_eq!(builder.protocol, SenderProtocol::IlpOverTcp);
}

#[test]
fn set_net_interface_specifies_tcp() {
    let builder = SenderBuilder::new_tcp("localhost", 9000);
    assert_eq!(builder.protocol, SenderProtocol::IlpOverTcp);
    builder.bind_interface("55.88.0.4").unwrap();
}

#[test]
fn tcp_ecdsa_auth() {
    let builder = SenderBuilder::from_conf(
        "tcp::addr=localhost:9000;username=user123;token=token123;token_x=xtok123;token_y=ytok123;",
    )
    .unwrap();
    let auth = builder.build_auth().unwrap();
    match auth.unwrap() {
        AuthParams::Ecdsa(EcdsaAuthParams {
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
        #[cfg(feature = "ilp-over-http")]
        _ => {
            panic!("Expected AuthParams::Ecdsa");
        }
    }
}

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

#[test]
fn misspelled_tcp_ecdsa_auth() {
    assert_conf_err(
        Sender::from_conf("tcp::addr=localhost;username=user123;tokenx=123;"),
        "Incomplete ECDSA authentication parameters. Specify either all or none of: \"username\", \"token\", \"token_x\", \"token_y\"."
    );
}

#[test]
fn tcps_tls_verify_on() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;tls_verify=on;").unwrap();
    assert_specified_eq(&builder.tls_enabled, true);
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);
}

#[cfg(feature = "insecure-skip-verify")]
#[test]
fn tcps_tls_verify_unsafe_off() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;tls_verify=unsafe_off;").unwrap();
    assert_specified_eq(&builder.tls_enabled, true);
    assert_defaulted_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);
    assert_specified_eq(&builder.tls_verify, false);
}

#[test]
fn tcps_tls_verify_invalid() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;tls_verify=off;"),
        r##"Config parameter "tls_verify" must be either "on" or "unsafe_off".'"##,
    );
}

#[test]
fn tcps_tls_roots_webpki() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;tls_ca=webpki_roots;").unwrap();
    assert_specified_eq(&builder.tls_enabled, true);
    assert_specified_eq(&builder.tls_ca, CertificateAuthority::WebpkiRoots);
    assert_defaulted_eq(&builder.tls_roots, None);
}

#[cfg(feature = "tls-native-certs")]
#[test]
fn tcps_tls_roots_os() {
    let builder = SenderBuilder::from_conf("tcps::addr=localhost;tls_ca=os_roots;").unwrap();
    assert_specified_eq(&builder.tls_enabled, true);
    assert_specified_eq(&builder.tls_ca, CertificateAuthority::OsRoots);
    assert_defaulted_eq(&builder.tls_roots, None);
}

#[test]
fn tcps_tls_roots_file() {
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

#[test]
fn tcps_tls_roots_file_missing() {
    let err =
        SenderBuilder::from_conf("tcps::addr=localhost;tls_roots=/some/invalid/path/cacerts.pem;")
            .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err
        .msg()
        .contains("Could not open root certificate file from path"));
}

#[test]
fn tcps_tls_roots_file_with_password() {
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

#[cfg(feature = "ilp-over-http")]
#[test]
fn http_request_min_throughput() {
    let builder =
        SenderBuilder::from_conf("http::addr=localhost;request_min_throughput=100;").unwrap();
    let Some(http_config) = builder.http else {
        panic!("Expected Some(HttpConfig)");
    };
    assert_specified_eq(&http_config.request_min_throughput, 100u64);
    assert_defaulted_eq(&http_config.request_timeout, Duration::from_millis(5000));
    assert_defaulted_eq(&http_config.retry_timeout, Duration::from_millis(10000));
}

#[cfg(feature = "ilp-over-http")]
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

#[cfg(feature = "ilp-over-http")]
#[test]
fn http_retry_timeout() {
    let builder = SenderBuilder::from_conf("http::addr=localhost;retry_timeout=100;").unwrap();
    let Some(http_config) = builder.http else {
        panic!("Expected Some(HttpConfig)");
    };
    assert_defaulted_eq(&http_config.request_min_throughput, 102400u64);
    assert_defaulted_eq(&http_config.request_timeout, Duration::from_millis(5000));
    assert_specified_eq(&http_config.retry_timeout, Duration::from_millis(100));
}

#[test]
fn auto_flush_off() {
    SenderBuilder::from_conf("tcps::addr=localhost;auto_flush=off;").unwrap();
}

#[test]
fn auto_flush_unsupported() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;auto_flush=on;"),
        "Invalid auto_flush value 'on'. This client does not support \
            auto-flush, so the only accepted value is 'off'",
    );
}

#[test]
fn auto_flush_rows_unsupported() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;auto_flush_rows=100;"),
        "Invalid configuration parameter \"auto_flush_rows\". This client does not support auto-flush",
    );
}

#[test]
fn auto_flush_bytes_unsupported() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;auto_flush_bytes=100;"),
        "Invalid configuration parameter \"auto_flush_bytes\". This client does not support auto-flush",
    );
}

fn assert_specified_eq<V: PartialEq + Debug, IntoV: Into<V>>(
    actual: &ConfigSetting<V>,
    expected: IntoV,
) {
    let expected = expected.into();
    if let ConfigSetting::Specified(actual_value) = actual {
        assert_eq!(actual_value, &expected);
    } else {
        panic!("Expected Specified({:?}), but got {:?}", expected, actual);
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
        panic!("Expected Defaulted({:?}), but got {:?}", expected, actual);
    }
}

fn assert_conf_err<T, M: AsRef<str>>(result: Result<T>, expect_msg: M) {
    let Err(err) = result else {
        panic!("Got Ok, expected ConfigError: {}", expect_msg.as_ref());
    };
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert_eq!(err.msg(), expect_msg.as_ref());
}
