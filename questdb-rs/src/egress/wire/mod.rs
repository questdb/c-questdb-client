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

//! QWP wire codec primitives: frame header, varint, message kinds.

pub mod bit_reader;
pub mod byte_reader;
pub mod cache_reset;
pub mod header;
pub mod msg_kind;
pub mod varint;

pub(crate) use byte_reader::ByteReader;

pub use cache_reset::{RESET_MASK_DICT, RESET_MASK_SCHEMAS};
pub use header::{FrameHeader, HEADER_LEN, MAGIC, flags};
pub use msg_kind::{MsgKind, StatusCode};
pub use varint::{MAX_VARINT_LEN_U64, decode_u64, decode_usize, encode_u64};
