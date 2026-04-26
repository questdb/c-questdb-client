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

//! QuestDB Wire Protocol (QWP) egress reader.
//!
//! Implements the client side of the QWP egress extension: a binary,
//! columnar, WebSocket-based read protocol for streaming query results
//! from QuestDB. This module currently contains the wire codec foundation
//! (frame header, varint, message kinds, column type codes, errors).
//! Transport, decoder, and `Reader`/`Cursor`/`Batch` types land in
//! follow-up changes.

pub mod binds;
pub mod column;
pub mod column_kind;
pub mod decoder;
pub mod error;
pub mod query_request;
pub mod schema;
pub mod server_event;
pub mod symbol_dict;
pub mod wire;

pub use binds::Bind;
pub use column::{
    BinaryColumn, ColumnView, Decimal64Column, FixedBytesColumn, FixedColumn, FixedWidth,
    Long256Column, SymbolColumn, UuidColumn, Validity, VarcharColumn,
};
pub use column_kind::ColumnKind;
pub use decoder::{ColumnBuffer, DecodedBatch, DecodedColumn, decode_result_batch};
pub use error::{Error, ErrorCode, Result};
pub use query_request::{QueryRequest, QueryRequestBuilder};
pub use schema::{DecodedSchema, Schema, SchemaColumn, SchemaMode, SchemaRegistry};
pub use server_event::{ServerEvent, ServerInfo, ServerRole, decode_frame};
pub use symbol_dict::SymbolDict;
pub use wire::{FrameHeader, MsgKind, RESET_MASK_DICT, RESET_MASK_SCHEMAS, StatusCode};
