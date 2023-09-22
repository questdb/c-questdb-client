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

use crate::{
    ingress::{
        Buffer, CertificateAuthority, Sender, TableName, Timestamp, TimestampMicros,
        TimestampNanos, Tls,
    },
    Error, ErrorCode,
};

use crate::tests::{
    mock::{certs_dir, MockServer},
    TestResult,
};

use core::time::Duration;
use std::{io, time::SystemTime};

#[test]
fn test_basics() -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server.lsb().connect()?;
    assert!(!sender.must_close());
    server.accept()?;

    assert_eq!(server.recv_q()?, 0);

    let ts = std::time::SystemTime::now();
    let ts_micros_num = ts
        .duration_since(std::time::SystemTime::UNIX_EPOCH)?
        .as_micros() as i64;
    let ts_nanos_num = ts
        .duration_since(std::time::SystemTime::UNIX_EPOCH)?
        .as_nanos() as i64;
    let ts_micros = TimestampMicros::from_systemtime(ts)?;
    assert_eq!(ts_micros.as_i64(), ts_micros_num);
    let ts_nanos = TimestampNanos::from_systemtime(ts)?;
    assert_eq!(ts_nanos.as_i64(), ts_nanos_num);

    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .column_ts("ts1", TimestampMicros::new(12345))?
        .column_ts("ts2", ts_micros)?
        .column_ts("ts3", ts_nanos)?
        .at(ts_nanos)?;

    assert_eq!(server.recv_q()?, 0);
    let exp = format!(
        "test,t1=v1 f1=0.5,ts1=12345t,ts2={}t,ts3={}t {}\n",
        ts_micros_num,
        ts_nanos_num / 1000i64,
        ts_nanos_num
    );
    assert_eq!(buffer.as_str(), exp);
    assert_eq!(buffer.len(), exp.len());
    sender.flush(&mut buffer)?;
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.as_str(), "");
    assert_eq!(server.recv_q()?, 1);
    assert_eq!(server.msgs[0].as_str(), exp);
    Ok(())
}

#[test]
fn test_table_name_too_long() -> TestResult {
    let mut buffer = Buffer::with_max_name_len(4);
    let name = "a name too long";
    let err = buffer.table(name).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidName);
    assert_eq!(
        err.msg(),
        r#"Bad name: "a name too long": Too long (max 4 characters)"#
    );
    Ok(())
}

#[test]
fn test_timestamp_overloads() -> TestResult {
    let tbl_name = TableName::new("tbl_name")?;

    let mut buffer = Buffer::new();
    buffer
        .table(tbl_name)?
        .column_ts("a", TimestampMicros::new(12345))?
        .column_ts("b", TimestampMicros::new(-100000000))?
        .column_ts("c", TimestampNanos::new(12345678))?
        .column_ts("d", TimestampNanos::new(-12345678))?
        .column_ts("e", Timestamp::Micros(TimestampMicros::new(-1)))?
        .column_ts("f", Timestamp::Nanos(TimestampNanos::new(-10000)))?
        .at(TimestampMicros::new(1))?;
    buffer
        .table(tbl_name)?
        .column_ts(
            "a",
            TimestampMicros::from_systemtime(
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(1))
                    .unwrap(),
            )?,
        )?
        .at(TimestampNanos::from_systemtime(
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(5))
                .unwrap(),
        )?)?;

    let exp = concat!(
        "tbl_name a=12345t,b=-100000000t,c=12345t,d=-12345t,e=-1t,f=-10t 1000\n",
        "tbl_name a=1000000t 5000000000\n"
    );
    assert_eq!(buffer.as_str(), exp);

    Ok(())
}

#[cfg(feature = "chrono_timestamp")]
#[test]
fn test_chrono_timestamp() -> TestResult {
    use chrono::{DateTime, TimeZone, Utc};

    let tbl_name = TableName::new("tbl_name")?;
    let ts: DateTime<Utc> = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 1).unwrap();
    let ts = TimestampNanos::from_datetime(ts)?;

    let mut buffer = Buffer::new();
    buffer.table(tbl_name)?.column_ts("a", ts)?.at(ts)?;

    let exp = "tbl_name a=1000000t 1000000000\n";
    assert_eq!(buffer.as_str(), exp);

    Ok(())
}

macro_rules! column_name_too_long_test_impl {
    ($column_fn:ident, $value:expr) => {{
        let mut buffer = Buffer::with_max_name_len(4);
        let name = "a name too long";
        let err = buffer.table("tbl")?.$column_fn(name, $value).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidName);
        assert_eq!(
            err.msg(),
            r#"Bad name: "a name too long": Too long (max 4 characters)"#
        );
        Ok(())
    }};
}

#[test]
fn test_symbol_column_name_too_long() -> TestResult {
    column_name_too_long_test_impl!(symbol, "v1")
}

#[test]
fn test_bool_column_name_too_long() -> TestResult {
    column_name_too_long_test_impl!(column_bool, true)
}

#[test]
fn test_i64_column_name_too_long() -> TestResult {
    column_name_too_long_test_impl!(column_i64, 1)
}

#[test]
fn test_f64_column_name_too_long() -> TestResult {
    column_name_too_long_test_impl!(column_f64, 0.5)
}

#[test]
fn test_str_column_name_too_long() -> TestResult {
    column_name_too_long_test_impl!(column_str, "value")
}

#[test]
fn test_tls_with_file_ca() -> TestResult {
    let mut ca_path = certs_dir();
    ca_path.push("server_rootCA.pem");

    let server = MockServer::new()?;
    let lsb = server
        .lsb()
        .tls(Tls::Enabled(CertificateAuthority::File(ca_path)));
    let server_jh = server.accept_tls();
    let mut sender = lsb.connect()?;
    let mut server: MockServer = server_jh.join().unwrap()?;

    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;

    assert_eq!(server.recv_q()?, 0);
    let exp = "test,t1=v1 f1=0.5 10000000\n";
    assert_eq!(buffer.as_str(), exp);
    assert_eq!(buffer.len(), exp.len());
    sender.flush(&mut buffer)?;
    assert_eq!(server.recv_q()?, 1);
    assert_eq!(server.msgs[0].as_str(), exp);
    Ok(())
}

#[test]
fn test_tls_to_plain_server() -> TestResult {
    let mut ca_path = certs_dir();
    ca_path.push("server_rootCA.pem");

    let mut server = MockServer::new()?;
    let lsb = server
        .lsb()
        .read_timeout(Duration::from_millis(500))
        .tls(Tls::Enabled(CertificateAuthority::File(ca_path)));
    let server_jh = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        Ok(server)
    });
    let maybe_sender = lsb.connect();
    let _server: MockServer = server_jh.join().unwrap()?;
    let err = maybe_sender.unwrap_err();
    assert_eq!(
        err,
        Error::new(
            ErrorCode::TlsError,
            "Failed to complete TLS handshake: \
         Timed out waiting for server response after 500ms."
                .to_owned()
        )
    );
    Ok(())
}

fn expect_eventual_disconnect(sender: &mut Sender) {
    let mut retry = || {
        for _ in 0..1000 {
            std::thread::sleep(Duration::from_millis(100));
            let mut buffer = Buffer::new();
            buffer.table("test_table")?.symbol("s1", "v1")?.at_now()?;
            sender.flush(&mut buffer)?;
        }
        Ok(())
    };

    let err: Error = retry().unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError);
}

#[test]
fn test_plain_to_tls_server() -> TestResult {
    let server = MockServer::new()?;
    let lsb = server
        .lsb()
        .read_timeout(Duration::from_millis(500))
        .tls(Tls::Disabled);
    let server_jh = server.accept_tls();
    let maybe_sender = lsb.connect();
    let server_err = server_jh.join().unwrap().unwrap_err();

    // The server failed to handshake, so disconnected the client.
    assert!(
        (server_err.kind() == io::ErrorKind::TimedOut)
            || (server_err.kind() == io::ErrorKind::WouldBlock)
    );

    // The client nevertheless connected successfully.
    let mut sender = maybe_sender.unwrap();

    // Eventually, the client fail to flush.
    expect_eventual_disconnect(&mut sender);
    Ok(())
}

#[cfg(feature = "insecure-skip-verify")]
#[test]
fn test_tls_insecure_skip_verify() -> TestResult {
    let server = MockServer::new()?;
    let lsb = server.lsb().tls(Tls::InsecureSkipVerify);
    let server_jh = server.accept_tls();
    let mut sender = lsb.connect()?;
    let mut server: MockServer = server_jh.join().unwrap()?;

    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;

    assert_eq!(server.recv_q()?, 0);
    let exp = "test,t1=v1 f1=0.5 10000000\n";
    assert_eq!(buffer.as_str(), exp);
    assert_eq!(buffer.len(), exp.len());
    sender.flush(&mut buffer)?;
    assert_eq!(server.recv_q()?, 1);
    assert_eq!(server.msgs[0].as_str(), exp);
    Ok(())
}
