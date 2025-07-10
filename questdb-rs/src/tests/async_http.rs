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
use crate::ingress::ProtocolVersion;
use crate::tests::mock::HttpResponse;
use crate::{
    ingress::{SenderBuilder, TimestampNanos},
    tests::{mock::MockServer, TestResult},
};
use std::io;

async fn _test_sender_auto_detect_protocol_version(
    supported_versions: Option<Vec<u16>>,
    expect_version: ProtocolVersion,
    max_name_len: usize,
    expect_max_name_len: usize,
) -> TestResult {
    let supported_versions1 = supported_versions.clone();
    let mut server = MockServer::new()?
        .configure_settings_response(supported_versions.as_deref().unwrap_or(&[]), max_name_len);
    let sender_builder = server.lsb_http();

    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        match supported_versions1 {
            None => server.send_http_response_q(
                HttpResponse::empty()
                    .with_status(404, "Not Found")
                    .with_header("content-type", "text/plain")
                    .with_body_str("Not Found"),
            )?,
            Some(_) => server.send_settings_response()?,
        }
        let exp = &[
            b"test,t1=v1 ",
            crate::tests::f64_to_bytes("f1", 0.5, expect_version).as_slice(),
            b" 10000000\n",
        ]
        .concat();
        let req = server.recv_http_q()?;
        assert_eq!(req.body(), exp);
        server.send_http_response_q(HttpResponse::empty())?;
        Ok(server)
    });

    let mut sender = sender_builder.build_async().await?;
    // assert_eq!(sender.protocol_version(), expect_version);
    // assert_eq!(sender.max_name_len(), expect_max_name_len);
    let mut txn = sender.new_transaction("test")?;
    txn.row()?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    txn.commit().await?;
    _ = server_thread.join().unwrap()?;
    Ok(())
}

#[tokio::test]
async fn test_sender_auto_protocol_version_basic() -> TestResult {
    _test_sender_auto_detect_protocol_version(Some(vec![1, 2]), ProtocolVersion::V2, 130, 130).await
}

#[tokio::test]
async fn test_sender_auto_protocol_version_old_server1() -> TestResult {
    _test_sender_auto_detect_protocol_version(Some(vec![]), ProtocolVersion::V1, 0, 127).await
}

#[tokio::test]
async fn test_sender_auto_protocol_version_old_server2() -> TestResult {
    _test_sender_auto_detect_protocol_version(None, ProtocolVersion::V1, 0, 127).await
}

#[tokio::test]
async fn test_sender_auto_protocol_version_only_v1() -> TestResult {
    _test_sender_auto_detect_protocol_version(Some(vec![1]), ProtocolVersion::V1, 127, 127).await
}

#[tokio::test]
async fn test_sender_auto_protocol_version_only_v2() -> TestResult {
    _test_sender_auto_detect_protocol_version(Some(vec![2]), ProtocolVersion::V2, 127, 127).await
}

// #[tokio::test]
// async fn test_two_lines() -> TestResult {
//     let mut server = MockServer::new()?;
//     let sender_builder = server.lsb_http();
//
//     let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
//         server.accept()?;
//         let req = server.recv_http_q()?;
//         assert_eq!(req.method(), "GET");
//         assert_eq!(req.path(), "/settings");
//         // match supported_versions1 {
//         //     None => server.send_http_response_q(
//         //         HttpResponse::empty()
//         //             .with_status(404, "Not Found")
//         //             .with_header("content-type", "text/plain")
//         //             .with_body_str("Not Found"),
//         //     )?,
//         //     Some(_) => server.send_settings_response()?,
//         // }
//         server.send_settings_response()?;
//         // let exp = &[
//         //     b"test,t1=v1 ",
//         //     crate::tests::sync_sender::f64_to_bytes("f1", 0.5, expect_version).as_slice(),
//         //     b" 10000000\n",
//         // ]
//         //     .concat();
//         // let req = server.recv_http_q()?;
//         // assert_eq!(req.body(), exp);
//         // server.send_http_response_q(HttpResponse::empty())?;
//         Ok(server)
//     });
//
//     let mut sender = sender_builder
//         .build_async()
//         .await?;
//     let mut txn = sender.new_transaction("table1")?;
//     txn.row()?
//         .symbol("a", "B")?
//         .column_f64("b", 10.25)?
//         .at(TimestampNanos::now())?;
//     txn.commit().await?;
//     Ok(())
// }
