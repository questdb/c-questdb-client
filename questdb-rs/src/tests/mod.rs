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

mod f64_serializer;

#[cfg(feature = "ilp-over-http")]
mod http;

mod mock;
mod sender;

mod ndarr;

#[cfg(feature = "json_tests")]
mod json_tests {
    include!(concat!(env!("OUT_DIR"), "/json_tests.rs"));
}

pub type TestError = Box<dyn std::error::Error>;
pub type TestResult = std::result::Result<(), TestError>;

pub fn assert_err_contains<T: std::fmt::Debug>(
    result: crate::Result<T>,
    expected_code: crate::ErrorCode,
    expected_msg_contained: &str,
) {
    match result {
        Ok(_) => {
            panic!("Expected error containing '{expected_msg_contained}', but got Ok({result:?})")
        }
        Err(e) => {
            assert_eq!(
                e.code(),
                expected_code,
                "Expected error code {:?}, but got {:?}",
                expected_code,
                e.code()
            );
            assert!(
                e.msg().contains(expected_msg_contained),
                "Expected error message to contain {:?}, but got {:?}",
                expected_msg_contained,
                e.msg()
            );
        }
    }
}
