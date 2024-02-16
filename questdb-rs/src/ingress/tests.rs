use super::*;
use crate::{error::Result, ErrorCode};

#[cfg(feature = "ilp-over-http")]
#[test]
fn http_simple() {
    let builder = assert_ok(SenderBuilder::from_conf("http::addr=localhost;"));
    assert_specified_eq(&builder.protocol, SenderProtocol::IlpOverHttp);
    assert_specified_eq(&builder.host, "localhost");
    assert_specified_eq(&builder.port, SenderProtocol::IlpOverHttp.default_port());
    assert_specified_eq(&builder.tls, Tls::Disabled);
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn https_simple() {
    let builder = assert_ok(SenderBuilder::from_conf("https::addr=localhost;"));
    assert_specified_eq(&builder.protocol, SenderProtocol::IlpOverHttp);
    assert_specified_eq(&builder.host, "localhost");
    assert_specified_eq(&builder.port, SenderProtocol::IlpOverHttp.default_port());
    assert_specified_eq(
        &builder.tls,
        Tls::Enabled(CertificateAuthority::WebpkiRoots),
    );
}

#[test]
fn tcp_simple() {
    let builder = assert_ok(SenderBuilder::from_conf("tcp::addr=localhost;"));
    assert_specified_eq(&builder.protocol, SenderProtocol::IlpOverTcp);
    assert_specified_eq(&builder.port, SenderProtocol::IlpOverTcp.default_port());
    assert_specified_eq(&builder.host, "localhost");
    assert_specified_eq(&builder.tls, Tls::Disabled);
}

#[test]
fn tcps_simple() {
    let builder = assert_ok(SenderBuilder::from_conf("tcps::addr=localhost;"));
    assert_specified_eq(&builder.protocol, SenderProtocol::IlpOverTcp);
    assert_specified_eq(&builder.host, "localhost");
    assert_specified_eq(&builder.port, SenderProtocol::IlpOverTcp.default_port());
    assert_specified_eq(
        &builder.tls,
        Tls::Enabled(CertificateAuthority::WebpkiRoots),
    );
}

#[test]
fn invalid_value() {
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost\n;"),
        "Config parse error: invalid char '\\n' in value at position 19",
    );
}

#[test]
fn unrecognized_param() {
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost;quest=db;"),
        "Configuration string contains unrecognized parameters: [\"quest\"]",
    );
}

#[test]
fn specified_is_idempotent() {
    let builder = assert_ok(SenderBuilder::from_conf("tcp::addr=localhost;"));
    assert_ok(builder.tcp());
}

#[test]
fn specified_cant_change() {
    let mut builder = assert_ok(SenderBuilder::from_conf("tcp::addr=localhost;"));
    builder = assert_ok(builder.net_interface("1.1.1.1"));
    assert_conf_err(
        builder.net_interface("1.1.1.2"),
        "net_interface is already specified",
    );
}

#[test]
fn missing_addr() {
    assert_conf_err(
        SenderBuilder::from_conf("tcp::"),
        "Missing 'addr' parameter in config string",
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
    let builder = assert_ok(SenderBuilder::from_conf(
        "http::addr=localhost;user=user123;pass=pass321;",
    ));
    let auth = assert_specified(builder.auth).expect("builder.auth was set to None");
    match auth {
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
    let builder = assert_ok(SenderBuilder::from_conf(
        "http::addr=localhost:9000;token=token123;",
    ));
    let auth = assert_specified(builder.auth).expect("builder.auth was set to None");
    match auth {
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
        SenderBuilder::from_conf("http::addr=localhost;user=user123;"),
        "Authentication parameter 'user' is present, but 'pass' is missing",
    );
    assert_conf_err(
        SenderBuilder::from_conf("http::addr=localhost;pass=pass321;"),
        "Authentication parameter 'pass' is present, but 'user' is missing",
    );
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn misspelled_basic_auth() {
    assert_conf_err(
        SenderBuilder::from_conf("http::addr=localhost;user=user123;password=pass321;"),
        "Authentication parameter 'user' is present, but 'pass' is missing. \
            Hint: check the spelling of the parameters. These parameters weren't recognized: [\"password\"]",
    );
    assert_conf_err(
        SenderBuilder::from_conf("http::addr=localhost;username=user123;pass=pass321;"),
        "Authentication parameter 'pass' is present, but 'user' is missing. \
            Hint: check the spelling of the parameters. These parameters weren't recognized: [\"username\"]",
    );
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn inconsistent_http_auth() {
    let expected_err_msg = "Inconsistent HTTP authentication parameters. \
    Specify either 'user' and 'pass', or just 'token'";
    assert_conf_err(
        SenderBuilder::from_conf("http::addr=localhost;user=user123;token=token123;"),
        expected_err_msg,
    );
    assert_conf_err(
        SenderBuilder::from_conf("http::addr=localhost;pass=pass321;token=token123;"),
        expected_err_msg,
    );
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn cant_use_basic_auth_with_tcp() {
    let builder = assert_ok(SenderBuilder::new("localhost", 9000));
    assert_conf_err(
        builder.basic_auth("user123", "pass321"),
        "in order to set basic_auth, you must first select protocol IlpOverHttp",
    );
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn cant_use_token_auth_with_tcp() {
    let builder = assert_ok(SenderBuilder::new("localhost", 9000));
    assert_conf_err(
        builder.token_auth("token123"),
        "in order to set token_auth, you must first select protocol IlpOverHttp",
    );
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn cant_use_ecdsa_auth_with_http() {
    let builder = assert_ok(SenderBuilder::from_conf("http::addr=localhost;"));
    assert_conf_err(
        builder.auth("key_id123", "priv_key123", "pub_key1", "pub_key2"),
        "in order to set auth, you must first select protocol IlpOverTcp",
    );
}

#[test]
fn set_auth_specifies_tcp() {
    let mut builder = assert_ok(SenderBuilder::new("localhost", 9000));
    assert_defaulted_eq(&builder.protocol, SenderProtocol::IlpOverTcp);
    builder = assert_ok(builder.auth("key_id123", "priv_key123", "pub_key1", "pub_key2"));
    assert_specified_eq(&builder.protocol, SenderProtocol::IlpOverTcp);
}

#[test]
fn set_net_interface_specifies_tcp() {
    let mut builder = assert_ok(SenderBuilder::new("localhost", 9000));
    assert_defaulted_eq(&builder.protocol, SenderProtocol::IlpOverTcp);
    builder = assert_ok(builder.net_interface("55.88.0.4"));
    assert_specified_eq(&builder.protocol, SenderProtocol::IlpOverTcp);
}

#[test]
fn tcp_ecdsa_auth() {
    let builder = assert_ok(SenderBuilder::from_conf(
        "tcp::addr=localhost:9000;user=user123;token=token123;token_x=xtok123;token_y=ytok123;",
    ));
    let auth = assert_specified(builder.auth).expect("builder.auth was set to None");
    match auth {
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
        _ => {
            panic!("Expected AuthParams::Ecdsa");
        }
    }
}

#[test]
fn incomplete_tcp_ecdsa_auth() {
    let expected_err_msg = "Incomplete ECDSA authentication parameters. \
            Specify either all or none of: 'user', 'token', 'token_x', 'token_y'";
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost;user=user123;"),
        expected_err_msg,
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost;user=user123;token=token123;"),
        expected_err_msg,
    );
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost;user=user123;token=token123;token_x=123;"),
        expected_err_msg,
    );
}

#[test]
fn misspelled_tcp_ecdsa_auth() {
    assert_conf_err(
        SenderBuilder::from_conf("tcp::addr=localhost;user=user123;tokenx=123;"),
        "Incomplete ECDSA authentication parameters. \
            Specify either all or none of: 'user', 'token', 'token_x', 'token_y'. \
            Hint: check the spelling of the parameters. These parameters weren't recognized: [\"tokenx\"]"
    );
}

#[test]
fn tcps_tls_verify_on() {
    let builder = assert_ok(SenderBuilder::from_conf(
        "tcps::addr=localhost;tls_verify=on;",
    ));
    assert_specified_eq(
        &builder.tls,
        Tls::Enabled(CertificateAuthority::WebpkiRoots),
    );
}

#[cfg(feature = "insecure-skip-verify")]
#[test]
fn tcps_tls_verify_unsafe_off() {
    let builder = assert_ok(SenderBuilder::from_conf(
        "tcps::addr=localhost;tls_verify=unsafe_off;",
    ));
    assert_specified_eq(&builder.tls, Tls::InsecureSkipVerify);
}

#[test]
fn tcps_tls_verify_invalid() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;tls_verify=off;"),
        "Config parameter 'tls_verify' must be either 'on' or 'unsafe_off'",
    );
}

#[test]
fn tcps_tls_roots_webpki() {
    let builder = assert_ok(SenderBuilder::from_conf(
        "tcps::addr=localhost;tls_roots=webpki;",
    ));
    assert_specified_eq(
        &builder.tls,
        Tls::Enabled(CertificateAuthority::WebpkiRoots),
    );
}

#[cfg(feature = "tls-native-certs")]
#[test]
fn tcps_tls_roots_os() {
    let builder = assert_ok(SenderBuilder::from_conf(
        "tcps::addr=localhost;tls_roots=os-certs;",
    ));
    assert_specified_eq(&builder.tls, Tls::Enabled(CertificateAuthority::OsRoots));
}

#[test]
fn tcps_tls_roots_file() {
    let builder = assert_ok(SenderBuilder::from_conf(
        "tcps::addr=localhost;tls_roots=/home/questuser/cacerts.pem;",
    ));
    let path = PathBuf::from_str("/home/questuser/cacerts.pem").unwrap();
    assert_specified_eq(
        &builder.tls,
        Tls::Enabled(CertificateAuthority::File {
            path,
            password: None,
        }),
    );
}

#[test]
fn tcps_tls_roots_file_with_password() {
    let builder = assert_ok(SenderBuilder::from_conf(
        "tcps::addr=localhost;tls_roots=/home/questuser/cacerts.pem;tls_roots_password=extremely_secure;",
    ));
    let path = PathBuf::from_str("/home/questuser/cacerts.pem").unwrap();
    assert_specified_eq(
        &builder.tls,
        Tls::Enabled(CertificateAuthority::File {
            path,
            password: Some("extremely_secure".to_string()),
        }),
    );
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn http_min_throughput() {
    let builder = assert_ok(SenderBuilder::from_conf(
        "http::addr=localhost;min_throughput=100;",
    ));
    let Some(http_config) = builder.http else {
        panic!("Expected Some(HttpConfig)");
    };
    assert_specified_eq(&http_config.min_throughput, 100u64);
    assert_defaulted_eq(&http_config.grace_timeout, Duration::from_millis(5000));
    assert_defaulted_eq(&http_config.retry_timeout, Duration::from_millis(10000));
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn http_grace_timeout() {
    let builder = assert_ok(SenderBuilder::from_conf(
        "http::addr=localhost;grace_timeout=100;",
    ));
    let Some(http_config) = builder.http else {
        panic!("Expected Some(HttpConfig)");
    };
    assert_defaulted_eq(&http_config.min_throughput, 102400u64);
    assert_specified_eq(&http_config.grace_timeout, Duration::from_millis(100));
    assert_defaulted_eq(&http_config.retry_timeout, Duration::from_millis(10000));
}

#[cfg(feature = "ilp-over-http")]
#[test]
fn http_retry_timeout() {
    let builder = assert_ok(SenderBuilder::from_conf(
        "http::addr=localhost;retry_timeout=100;",
    ));
    let Some(http_config) = builder.http else {
        panic!("Expected Some(HttpConfig)");
    };
    assert_defaulted_eq(&http_config.min_throughput, 102400u64);
    assert_defaulted_eq(&http_config.grace_timeout, Duration::from_millis(5000));
    assert_specified_eq(&http_config.retry_timeout, Duration::from_millis(100));
}

#[test]
fn auto_flush_off() {
    assert_ok(SenderBuilder::from_conf(
        "tcps::addr=localhost;auto_flush=off;",
    ));
}

#[test]
fn auto_flush_unsupported() {
    assert_conf_err(
        SenderBuilder::from_conf("tcps::addr=localhost;auto_flush=on;"),
        "Invalid auto_flush value 'on'. This client does not support \
            auto-flush, so the only accepted value is 'off'",
    );
}

fn assert_ok(result: Result<SenderBuilder>) -> SenderBuilder {
    if let Err(err) = result {
        panic!("Expected an Ok result, but got {:?}", err);
    }
    result.unwrap()
}

fn assert_specified<V: std::fmt::Debug>(actual: ConfigSetting<V>) -> V {
    if let ConfigSetting::Specified(actual_value) = actual {
        actual_value
    } else {
        panic!("Expected Specified(_), but got {:?}", actual);
    }
}

fn assert_specified_eq<V: PartialEq + std::fmt::Debug, IntoV: Into<V>>(
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

fn assert_conf_err<M: AsRef<str>>(result: Result<SenderBuilder>, expect_msg: M) {
    let Err(err) = result else {
        panic!("Got Ok, expected ConfigError: {}", expect_msg.as_ref());
    };
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert_eq!(err.msg(), expect_msg.as_ref());
}
