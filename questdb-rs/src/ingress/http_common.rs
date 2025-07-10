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

#[cfg(feature = "_sender-http")]
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
