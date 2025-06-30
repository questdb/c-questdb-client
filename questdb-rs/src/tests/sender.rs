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

use crate::{
    ingress::{
        Buffer, F64Serializer, Sender, TableName, Timestamp, TimestampMicros, TimestampNanos,
        DOUBLE_BINARY_FORMAT_TYPE,
    },
    ErrorCode,
};

use crate::ingress::ProtocolVersion;
use crate::tests::TestResult;
use core::time::Duration;

#[cfg(feature = "ndarray")]
use crate::ingress::ndarr::write_array_data;

#[cfg(feature = "ndarray")]
use ndarray::{arr2, ArrayD};

#[cfg(feature = "sync-sender-tcp")]
use crate::tests::{
    assert_err_contains,
    mock::{certs_dir, MockServer},
    ndarr::ArrayColumnTypeTag,
};

#[cfg(feature = "sync-sender-tcp")]
use rstest::rstest;

#[cfg(feature = "sync-sender-tcp")]
use crate::ingress::{CertificateAuthority, ARRAY_BINARY_FORMAT_TYPE};

#[cfg(feature = "sync-sender-tcp")]
#[rstest]
fn test_basics(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
) -> TestResult {
    use std::time::SystemTime;

    let mut server = MockServer::new()?;
    let mut sender = server.lsb_tcp().protocol_version(version)?.build()?;
    assert!(!sender.must_close());
    server.accept()?;

    assert_eq!(server.recv_q()?, 0);

    let ts = SystemTime::now();
    let ts_micros_num = ts.duration_since(SystemTime::UNIX_EPOCH)?.as_micros() as i64;
    let ts_nanos_num = ts.duration_since(SystemTime::UNIX_EPOCH)?.as_nanos() as i64;
    let ts_micros = TimestampMicros::from_systemtime(ts)?;
    assert_eq!(ts_micros.as_i64(), ts_micros_num);
    let ts_nanos = TimestampNanos::from_systemtime(ts)?;
    assert_eq!(ts_nanos.as_i64(), ts_nanos_num);

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .column_ts("ts1", TimestampMicros::new(12345))?
        .column_ts("ts2", ts_micros)?
        .column_ts("ts3", ts_nanos)?
        .at(ts_nanos)?;

    assert_eq!(server.recv_q()?, 0);
    let exp = &[
        "test,t1=v1 ".as_bytes(),
        f64_to_bytes("f1", 0.5, version).as_slice(),
        format!(
            ",ts1=12345t,ts2={}t,ts3={}t {}\n",
            ts_micros_num,
            ts_nanos_num / 1000i64,
            ts_nanos_num
        )
        .as_bytes(),
    ]
    .concat();
    assert_eq!(buffer.as_bytes(), exp);
    assert_eq!(buffer.len(), exp.len());
    sender.flush(&mut buffer)?;
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.as_bytes(), b"");
    assert_eq!(server.recv_q()?, 1);
    assert_eq!(server.msgs[0], *exp);
    Ok(())
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn test_array_f64_basic() -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_tcp()
        .protocol_version(ProtocolVersion::V2)?
        .build()?;
    server.accept()?;

    let ts = TimestampNanos::now();
    let mut buffer = sender.new_buffer();
    buffer
        .table("my_table")?
        .symbol("device", "A001")?
        .column_f64("f1", 25.5)?
        .column_arr("arr1d", &[1.0, 2.0, 3.0])?
        .at(ts)?;

    assert_eq!(server.recv_q()?, 0);

    let exp = &[
        b"my_table,device=A001 ",
        f64_to_bytes("f1", 25.5, ProtocolVersion::V2).as_slice(),
        b",arr1d=",
        b"=", // binary field
        &[ARRAY_BINARY_FORMAT_TYPE],
        &[ArrayColumnTypeTag::Double.into()],
        &[1u8],              // 1D array
        &3u32.to_le_bytes(), // 3 elements
        &1.0f64.to_le_bytes(),
        &2.0f64.to_le_bytes(),
        &3.0f64.to_le_bytes(),
        format!(" {}\n", ts.as_i64()).as_bytes(),
    ]
    .concat();

    assert_eq!(buffer.as_bytes(), exp);
    assert_eq!(buffer.len(), exp.len());
    sender.flush(&mut buffer)?;
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.as_bytes(), b"");
    assert_eq!(server.recv_q()?, 1);
    assert_eq!(server.msgs[0].as_slice(), exp);
    Ok(())
}

#[cfg(feature = "sync-sender-tcp")]
#[cfg(feature = "ndarray")]
#[test]
fn test_array_f64_for_ndarray() -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_tcp()
        .protocol_version(ProtocolVersion::V2)?
        .build()?;
    server.accept()?;

    let ts = TimestampNanos::now();
    let array_2d = arr2(&[[1.1, 2.2], [3.3, 4.4]]);
    let array_3d = ArrayD::<f64>::ones(vec![2, 3, 4]);

    let mut buffer = sender.new_buffer();
    buffer
        .table("my_table")?
        .symbol("device", "A001")?
        .column_f64("f1", 25.5)?
        .column_arr("arr2d", &array_2d.view())?
        .column_arr("arr3d", &array_3d.view())?
        .at(ts)?;

    assert_eq!(server.recv_q()?, 0);

    let array_header2d = &[
        &[b'='][..],
        &[ARRAY_BINARY_FORMAT_TYPE],
        &[ArrayColumnTypeTag::Double.into()],
        &[2u8],
        &2i32.to_le_bytes(),
        &2i32.to_le_bytes(),
    ]
    .concat();
    let mut array_data2d = vec![0u8; 4 * size_of::<f64>()];
    write_array_data(&array_2d.view(), &mut array_data2d[0..], 32)?;

    let array_header3d = &[
        &[b'='][..],
        &[ARRAY_BINARY_FORMAT_TYPE],
        &[ArrayColumnTypeTag::Double.into()],
        &[3u8],
        &2i32.to_le_bytes(),
        &3i32.to_le_bytes(),
        &4i32.to_le_bytes(),
    ]
    .concat();
    let mut array_data3d = vec![0u8; 24 * size_of::<f64>()];
    write_array_data(
        &array_3d.view(),
        &mut array_data3d[0..],
        24 * size_of::<f64>(),
    )?;

    let exp = &[
        "my_table,device=A001 ".as_bytes(),
        f64_to_bytes("f1", 25.5, ProtocolVersion::V2).as_slice(),
        ",arr2d=".as_bytes(),
        array_header2d,
        array_data2d.as_slice(),
        ",arr3d=".as_bytes(),
        array_header3d,
        array_data3d.as_slice(),
        format!(" {}\n", ts.as_i64()).as_bytes(),
    ]
    .concat();

    assert_eq!(buffer.as_bytes(), exp);
    assert_eq!(buffer.len(), exp.len());
    sender.flush(&mut buffer)?;
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.as_bytes(), b"");
    assert_eq!(server.recv_q()?, 1);
    assert_eq!(server.msgs[0].as_slice(), exp);
    Ok(())
}

#[cfg(feature = "sync-sender-tcp")]
#[rstest]
fn test_max_buf_size(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
) -> TestResult {
    let max = 1024;
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_tcp()
        .protocol_version(version)?
        .max_buf_size(max)?
        .build()?;
    assert!(!sender.must_close());
    server.accept()?;
    let mut buffer = sender.new_buffer();

    while buffer.len() < max {
        buffer
            .table("test")?
            .symbol("t1", "v1")?
            .column_f64("f1", 0.5)?
            .at_now()?;
    }

    let err = sender.flush(&mut buffer).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    match version {
        ProtocolVersion::V1 => {
            assert_eq!(
                err.msg(),
                "Could not flush buffer: Buffer size of 1026 exceeds maximum configured allowed size of 1024 bytes."
            );
        }
        ProtocolVersion::V2 => {
            assert_eq!(
                err.msg(),
                "Could not flush buffer: Buffer size of 1025 exceeds maximum configured allowed size of 1024 bytes."
            );
        }
    }
    Ok(())
}

#[test]
fn test_table_name_too_long() -> TestResult {
    let mut buffer = Buffer::with_max_name_len(ProtocolVersion::V2, 4);
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
fn test_row_count() -> TestResult {
    let mut buffer = Buffer::new(ProtocolVersion::V2);
    assert_eq!(buffer.row_count(), 0);

    buffer.table("x")?.symbol("y", "z1")?.at_now()?;
    buffer
        .table("x")?
        .symbol("y", "z2")?
        .at(TimestampNanos::now())?;
    assert_eq!(buffer.row_count(), 2);

    buffer.set_marker()?;

    buffer.table("x")?.symbol("y", "z3")?.at_now()?;
    buffer
        .table("x")?
        .symbol("y", "z4")?
        .at(TimestampNanos::now())?;
    buffer.table("x")?.symbol("y", "z5")?.at_now()?;
    assert_eq!(buffer.row_count(), 5);

    buffer.rewind_to_marker()?;
    assert_eq!(buffer.row_count(), 2);

    buffer.clear();
    assert_eq!(buffer.row_count(), 0);
    Ok(())
}

#[test]
fn test_transactional() -> TestResult {
    let mut buffer = Buffer::new(ProtocolVersion::V2);

    // transactional since there are no recorded tables yet
    assert_eq!(buffer.row_count(), 0);
    assert!(buffer.transactional());

    buffer.set_marker()?;
    buffer.table("table 1.test")?.symbol("a", "b")?.at_now()?;
    assert_eq!(buffer.row_count(), 1); // tables={'table 1.test'}

    // still transactional since there is only one single table.
    assert!(buffer.transactional());

    buffer.table("table 2.test")?.symbol("c", "d")?.at_now()?;

    // not transactional since we have both tables "x" and "y".
    assert_eq!(buffer.row_count(), 2); // tables={'table 1.test', 'table 2.test'}
    assert!(!buffer.transactional());

    buffer.rewind_to_marker()?;
    // no tables, so we're transactional again
    assert_eq!(buffer.row_count(), 0); // tables=[]
    assert!(buffer.transactional());
    assert!(buffer.is_empty());

    // We add another new and different table, so we are still transactional.
    buffer.table("test=table=3")?.symbol("e", "f")?.at_now()?;
    assert_eq!(buffer.row_count(), 1); // tables={'test=table=3'}
    assert!(buffer.transactional());

    // Same table again, so we are still transactional.
    buffer.table("test=table=3")?.symbol("g", "h")?.at_now()?;
    assert_eq!(buffer.row_count(), 2); // tables={'test=table=3'}
    assert!(buffer.transactional());

    buffer.set_marker()?;
    // We add a new different table: Name differs in length.
    buffer.table("test=table=3 ")?.symbol("i", "j")?.at_now()?;
    assert_eq!(buffer.row_count(), 3); // tables={'test=table=3', 'test=table=3 '}
    assert!(!buffer.transactional());

    buffer.rewind_to_marker()?;
    assert_eq!(buffer.row_count(), 2); // tables={'test=table=3'}
    assert!(buffer.transactional());

    buffer.set_marker()?;
    // We add a new different table: Name differs in content, but not in length.
    buffer.table("test=table=4")?.symbol("k", "l")?.at_now()?;
    assert_eq!(buffer.row_count(), 3); // tables={'test=table=3', 'test=table=4'}
    assert!(!buffer.transactional());

    buffer.rewind_to_marker()?;
    assert_eq!(buffer.row_count(), 2); // tables={'test=table=3'}
    assert!(buffer.transactional());

    buffer.clear();
    assert_eq!(buffer.row_count(), 0); // tables=[]
    assert!(buffer.transactional());
    assert!(buffer.is_empty());

    // We add three rows of the same new table, so we are still transactional.
    buffer.table("test=table=5")?.symbol("m", "n")?.at_now()?;
    buffer.table("test=table=5")?.symbol("o", "p")?.at_now()?;
    buffer.table("test=table=5")?.symbol("q", "r")?.at_now()?;
    assert_eq!(buffer.row_count(), 3); // tables={'test=table=5'}
    assert!(buffer.transactional());

    Ok(())
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn test_auth_inconsistent_keys() -> TestResult {
    test_bad_key("fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU", // d
                 "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU", // x
                 "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac",
                 "Misconfigured ILP authentication keys: InconsistentComponents. Hint: Check the keys for a possible typo."
    )
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn test_auth_bad_base64_private_key() -> TestResult {
    test_bad_key(
        "bad key",                                     // d
        "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU", // x
        "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac", // y
        "Misconfigured ILP authentication keys. Could not decode private authentication key: invalid Base64 encoding. Hint: Check the keys for a possible typo."
    )
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn test_auth_private_key_too_long() -> TestResult {
    #[cfg(feature = "aws-lc-crypto")]    
    let expected = "Misconfigured ILP authentication keys: InvalidEncoding. Hint: Check the keys for a possible typo.";

    #[cfg(feature = "ring-crypto")]
    let expected = "Misconfigured ILP authentication keys: InvalidComponent. Hint: Check the keys for a possible typo.";

    test_bad_key(
        "ZkxLWUVhb0ViOWxybjNua3dMREEtTV94bnVGT2RTdDl5MFo3X3ZXU0hMVWZMS1lFYW9FYjlscm4zbmt3TERBLU1feG51Rk9kU3Q5eTBaN192V1NITFU",
        "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU", // x
        "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac", // y
        expected
    )
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn test_auth_public_key_x_too_long() -> TestResult {
    test_bad_key(
        "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",
        "ZkxLWUVhb0ViOWxybjNua3dMREEtTV94bnVGT2RTdDl5MFo3X3ZXU0hMVWZMS1lFYW9FYjlscm4zbmt3TERBLU1feG51Rk9kU3Q5eTBaN192V1NITFU", // x
        "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac", // y
        "Misconfigured ILP authentication keys. Public key x is too long. Hint: Check the keys for a possible typo."
    )
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn test_auth_public_key_y_too_long() -> TestResult {
    test_bad_key(
        "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",
        "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac", // x
        "ZkxLWUVhb0ViOWxybjNua3dMREEtTV94bnVGT2RTdDl5MFo3X3ZXU0hMVWZMS1lFYW9FYjlscm4zbmt3TERBLU1feG51Rk9kU3Q5eTBaN192V1NITFU", // y
        "Misconfigured ILP authentication keys. Public key y is too long. Hint: Check the keys for a possible typo."
    )
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn test_auth_bad_base64_public_key_x() -> TestResult {
    test_bad_key(
        "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU", // d
        "bad base64 encoding",                       // x
        "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac", // y
        "Misconfigured ILP authentication keys. Could not decode public key x: invalid Base64 encoding. Hint: Check the keys for a possible typo."
    )
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn test_auth_bad_base64_public_key_y() -> TestResult {
    test_bad_key(
        "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU", // d
        "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac", // x
        "bad base64 encoding", // y
        "Misconfigured ILP authentication keys. Could not decode public key y: invalid Base64 encoding. Hint: Check the keys for a possible typo."
    )
}

#[cfg(feature = "sync-sender-tcp")]
fn test_bad_key(
    priv_key: &str,
    pub_key_x: &str,
    pub_key_y: &str,
    expected_error_msg: &str,
) -> TestResult {
    let server = MockServer::new()?;
    let lsb = server
        .lsb_tcp()
        .username("admin")?
        .token(priv_key)?
        .token_x(pub_key_x)?
        .token_y(pub_key_y)?;
    let sender = lsb.build();

    match sender {
        Ok(_) => panic!("Expected an error due to bad key, but connect succeeded."),
        Err(err) => {
            assert_eq!(
                err.code(),
                ErrorCode::AuthError,
                "Expected an ErrorCode::AuthError"
            );
            assert_eq!(
                err.msg(),
                expected_error_msg,
                "Error message did not match expected message."
            );
        }
    }
    Ok(())
}

#[test]
fn test_timestamp_overloads() -> TestResult {
    use std::time::SystemTime;

    let tbl_name = TableName::new("tbl_name")?;

    let mut buffer = Buffer::new(ProtocolVersion::V2);
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
    )
    .as_bytes();
    assert_eq!(buffer.as_bytes(), exp);

    Ok(())
}

#[cfg(feature = "chrono_timestamp")]
#[test]
fn test_chrono_timestamp() -> TestResult {
    use chrono::{DateTime, TimeZone, Utc};

    let tbl_name = TableName::new("tbl_name")?;
    let ts: DateTime<Utc> = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 1).unwrap();
    let ts = TimestampNanos::from_datetime(ts)?;

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table(tbl_name)?.column_ts("a", ts)?.at(ts)?;

    let exp = b"tbl_name a=1000000t 1000000000\n";
    assert_eq!(buffer.as_bytes(), exp);

    Ok(())
}

macro_rules! column_name_too_long_test_impl {
    ($column_fn:ident, $value:expr) => {{
        let mut buffer = Buffer::with_max_name_len(ProtocolVersion::V2, 4);
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
fn test_arr_column_name_too_long() -> TestResult {
    column_name_too_long_test_impl!(column_arr, &[1.0, 2.0, 3.0])
}

#[cfg(feature = "sync-sender-tcp")]
#[rstest]
fn test_tls_with_file_ca(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
) -> TestResult {
    let mut ca_path = certs_dir();
    ca_path.push("server_rootCA.pem");

    let server = MockServer::new()?;
    let lsb = server
        .lsb_tcps()
        .protocol_version(version)?
        .tls_roots(ca_path)?;
    let server_jh = server.accept_tls();
    let mut sender = lsb.build()?;
    let mut server: MockServer = server_jh.join().unwrap()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;

    assert_eq!(server.recv_q()?, 0);
    let exp = &[
        "test,t1=v1 ".as_bytes(),
        f64_to_bytes("f1", 0.5, version).as_slice(),
        " 10000000\n".as_bytes(),
    ]
    .concat();
    assert_eq!(buffer.as_bytes(), exp);
    assert_eq!(buffer.len(), exp.len());
    sender.flush(&mut buffer)?;
    assert_eq!(server.recv_q()?, 1);
    assert_eq!(server.msgs[0].as_slice(), exp);
    Ok(())
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn test_tls_to_plain_server() -> TestResult {
    let mut ca_path = certs_dir();
    ca_path.push("server_rootCA.pem");

    let mut server = MockServer::new()?;
    let lsb = server
        .lsb_tcps()
        .auth_timeout(Duration::from_millis(500))?
        .tls_ca(CertificateAuthority::PemFile)?
        .tls_roots(ca_path)?;
    let server_jh = std::thread::spawn(move || -> std::io::Result<MockServer> {
        server.accept()?;
        Ok(server)
    });
    let maybe_sender = lsb.build();
    let _server: MockServer = server_jh.join().unwrap()?;
    let err = maybe_sender.unwrap_err();
    assert_eq!(
        err,
        crate::error::Error::new(
            ErrorCode::TlsError,
            "Failed to complete TLS handshake: \
         Timed out waiting for server response after 500ms."
                .to_owned()
        )
    );
    Ok(())
}

#[cfg(feature = "sync-sender-tcp")]
fn expect_eventual_disconnect(sender: &mut Sender) {
    let mut retry = || {
        for _ in 0..1000 {
            std::thread::sleep(Duration::from_millis(100));
            let mut buffer = Buffer::new(ProtocolVersion::V2);
            buffer.table("test_table")?.symbol("s1", "v1")?.at_now()?;
            sender.flush(&mut buffer)?;
        }
        Ok(())
    };

    let err: crate::error::Error = retry().unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError);
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn test_plain_to_tls_server() -> TestResult {
    let server = MockServer::new()?;
    let lsb = server.lsb_tcp().auth_timeout(Duration::from_millis(500))?;
    let server_jh = server.accept_tls();
    let maybe_sender = lsb.protocol_version(ProtocolVersion::V2)?.build();
    let server_err = server_jh.join().unwrap().unwrap_err();

    // The server failed to handshake, so disconnected the client.
    assert!(
        (server_err.kind() == std::io::ErrorKind::TimedOut)
            || (server_err.kind() == std::io::ErrorKind::WouldBlock)
    );

    // The client nevertheless connected successfully.
    let mut sender = maybe_sender.unwrap();

    // Eventually, the client fail to flush.
    expect_eventual_disconnect(&mut sender);
    Ok(())
}

#[cfg(feature = "insecure-skip-verify")]
#[rstest]
fn test_tls_insecure_skip_verify(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
) -> TestResult {
    let server = MockServer::new()?;
    let lsb = server
        .lsb_tcps()
        .protocol_version(version)?
        .tls_verify(false)?;
    let server_jh = server.accept_tls();
    let mut sender = lsb.build()?;
    let mut server: MockServer = server_jh.join().unwrap()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;

    assert_eq!(server.recv_q()?, 0);
    let exp = &[
        "test,t1=v1 ".as_bytes(),
        f64_to_bytes("f1", 0.5, version).as_slice(),
        " 10000000\n".as_bytes(),
    ]
    .concat();
    assert_eq!(buffer.as_bytes(), exp);
    assert_eq!(buffer.len(), exp.len());
    sender.flush(&mut buffer)?;
    assert_eq!(server.recv_q()?, 1);
    assert_eq!(server.msgs[0].as_slice(), exp);
    Ok(())
}

#[test]
fn bad_uppercase_protocol() {
    let res = Sender::from_conf("TCP::addr=localhost:9009;");
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.code() == ErrorCode::ConfigError);
    assert!(err.msg() == "Unsupported protocol: TCP");
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn bad_uppercase_addr() {
    let res = Sender::from_conf("tcp::ADDR=localhost:9009;");
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.code() == ErrorCode::ConfigError);
    assert!(err.msg() == "Missing \"addr\" parameter in config string");
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn tcp_mismatched_buffer_and_sender_version() -> TestResult {
    let server = MockServer::new()?;
    let mut sender = server
        .lsb_tcp()
        .protocol_version(ProtocolVersion::V2)?
        .build()?;
    let mut buffer = Buffer::new(ProtocolVersion::V1);
    buffer.table("test")?.symbol("t1", "v1")?.at_now()?;
    assert_err_contains(
        sender.flush(&mut buffer),
        ErrorCode::ProtocolVersionError,
        "Attempting to send with protocol version v1 \
        but the sender is configured to use protocol version v2",
    );
    Ok(())
}

pub(crate) fn f64_to_bytes(name: &str, value: f64, version: ProtocolVersion) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(name.as_bytes());
    buf.push(b'=');

    match version {
        ProtocolVersion::V1 => {
            let mut ser = F64Serializer::new(value);
            buf.extend_from_slice(ser.as_str().as_bytes());
        }
        ProtocolVersion::V2 => {
            buf.push(b'=');
            buf.push(DOUBLE_BINARY_FORMAT_TYPE);
            buf.extend_from_slice(&value.to_le_bytes());
        }
    }
    buf
}
