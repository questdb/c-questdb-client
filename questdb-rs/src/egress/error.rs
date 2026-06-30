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

//! Egress-facing view of the crate-wide error type.
//!
//! Error handling is unified: there is a single [`crate::Error`] /
//! [`crate::ErrorCode`] for both ingestion and queries, because a
//! `QuestDb` pool spans both directions and must speak one
//! error vocabulary. This module re-exports those types (and the crate `fmt!`
//! constructor) under the `crate::egress::error` path that the reader code and
//! the `Result` alias already use, so no read-path call site needs to know the
//! definition moved.

pub use crate::error::{Error, ErrorCode, Result};

// `UpgradeReject` (a `SERVER_INFO` / `421` topology concept) lives next to
// `ServerInfo` in `server_event`; re-export it here so the reader/transport
// code keeps importing it from `crate::egress::error`.
pub use crate::egress::server_event::UpgradeReject;

pub(crate) use crate::error::fmt;
