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

use http::StatusCode;
use crate::error::Result;
use crate::ingress::DebugBytes;
use crate::{fmt, ingress::ProtocolVersion};

pub(crate) fn is_retriable_status_code(status: http::status::StatusCode) -> bool {
    status.is_server_error()
        && matches!(
            status.as_u16(),
            // Official HTTP codes
            500 | // Internal Server Error
            503 | // Service Unavailable
            504 | // Gateway Timeout

            // Unofficial extensions
            507 | // Insufficient Storage
            509 | // Bandwidth Limit Exceeded
            523 | // Origin is Unreachable
            524 | // A Timeout Occurred
            529 | // Site is overloaded
            599 // Network Connect Timeout Error
        )
}

pub(crate) fn check_status_code(
    status: StatusCode,
    url: &str,
) -> Result<()> {
    let code = status.as_u16();
    match status.as_u16() {
        404 => Err(fmt!(
            HttpNotSupported,
            "Could not flush buffer: HTTP endpoint does not support ILP."
        )),
        401 | 403 => Err(fmt!(
            AuthError,
            "Could not flush buffer: HTTP endpoint authentication error [code: {code}]",
        )),
        _ if status.is_client_error() || status.is_server_error() => Err(fmt!(
            SocketError,
            "Could not flush buffer: {}: {}", url, status.as_str()
        )),
        _ => Ok(())
    }
}

fn parse_server_settings(
    response: &str,
    settings_url: &str,
    default_protocol_version: crate::ingress::ProtocolVersion,
    default_max_name_len: usize,
) -> Result<(Vec<crate::ingress::ProtocolVersion>, usize)> {
    let json: serde_json::Value = serde_json::from_str(response).map_err(|_| {
        crate::error::fmt!(
            ProtocolVersionError,
            "Malformed server response, settings url: {}, err: response is not valid JSON.",
            settings_url,
        )
    })?;

    let mut support_versions: Vec<ProtocolVersion> = vec![];
    if let Some(serde_json::Value::Array(ref values)) = json
        .get("config")
        .and_then(|v| v.get("line.proto.support.versions"))
    {
        for value in values.iter() {
            if let Some(v) = value.as_u64() {
                match v {
                    1 => support_versions.push(ProtocolVersion::V1),
                    2 => support_versions.push(ProtocolVersion::V2),
                    _ => {}
                }
            }
        }
    } else {
        support_versions.push(default_protocol_version);
    }

    let max_name_length = json
        .get("config")
        .and_then(|v| v.get("cairo.max.file.name.length"))
        .and_then(|v| v.as_u64())
        .unwrap_or(default_max_name_len as u64) as usize;
    Ok((support_versions, max_name_length))
}

pub(crate) fn process_settings_response<P: AsRef<[u8]>>(
    response: Result<(StatusCode, P)>,
    settings_url: &str,
    default_protocol_version: ProtocolVersion,
    default_max_name_len: usize,
) -> Result<(Vec<ProtocolVersion>, usize)> {
    let body = match &response {
        Ok((status, body)) => {
            if status.is_client_error() || status.is_server_error() {
                if status.as_u16() == 404 {
                    return Ok((vec![default_protocol_version], default_max_name_len));        
                }
                return Err(fmt!(
                    ProtocolVersionError,
                    "Could not detect server's line protocol version, settings url: {settings_url}, status code: {status}."
                ));
            }
            body.as_ref()
        },
        Err(e) => return Err(
            fmt!(
                ProtocolVersionError,
                "Could not read the server's protocol version from the server: {e}",
            )
        )
    };

    let body_str = std::str::from_utf8(body)
        .map_err(|utf8_error| fmt!(
            ProtocolVersionError,
            "Could not read the server's response as a string: {:?}: {utf8_error}",
            DebugBytes(body)
        ))?;

    parse_server_settings(
        body_str,
        settings_url,
        default_protocol_version,
        default_max_name_len)
}