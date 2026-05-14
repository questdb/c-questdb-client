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

//! Replay encoder for the pipelined QWP/WebSocket sender.

use crate::error;
use crate::ingress::buffer::{QwpWsColumnarBuffer, QwpWsEncodeScratch, SymbolGlobalDict};

pub(crate) struct QwpWsReplayEncoder {
    scratch: QwpWsEncodeScratch,
    global_dict: SymbolGlobalDict,
    version: u8,
}

impl QwpWsReplayEncoder {
    pub(crate) fn new(version: u8) -> Self {
        Self {
            scratch: QwpWsEncodeScratch::new(),
            global_dict: SymbolGlobalDict::new(),
            version,
        }
    }

    fn encode_to_scratch(&mut self, buffer: &QwpWsColumnarBuffer) -> crate::Result<()> {
        if buffer.is_empty() {
            return Err(error::fmt!(
                InvalidApiCall,
                "Cannot submit an empty QWP/WebSocket buffer."
            ));
        }
        buffer.encode_ws_replay_message(&mut self.scratch, &mut self.global_dict, self.version)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn encode(&mut self, buffer: &QwpWsColumnarBuffer) -> crate::Result<&[u8]> {
        self.encode_to_scratch(buffer)?;
        Ok(&self.scratch.message)
    }

    pub(crate) fn encode_with_max_size(
        &mut self,
        buffer: &QwpWsColumnarBuffer,
        max_buf_size: usize,
    ) -> crate::Result<&[u8]> {
        let global_dict_mark = self.global_dict.mark();
        if let Err(err) = self.encode_to_scratch(buffer) {
            self.global_dict.rollback(global_dict_mark);
            return Err(err);
        }
        let encoded_len = self.scratch.message.len();
        if encoded_len > max_buf_size {
            self.global_dict.rollback(global_dict_mark);
            return Err(qwp_ws_encoded_message_size_error(encoded_len, max_buf_size));
        }
        Ok(&self.scratch.message)
    }
}

pub(crate) fn qwp_ws_encoded_message_size_error(
    encoded_len: usize,
    max_buf_size: usize,
) -> crate::Error {
    error::fmt!(
        InvalidApiCall,
        "Could not flush buffer: QWP/WebSocket encoded message size of {} exceeds maximum configured allowed size of {} bytes.",
        encoded_len,
        max_buf_size
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    fn one_symbol_buffer(symbol: &str) -> QwpWsColumnarBuffer {
        let mut buffer = QwpWsColumnarBuffer::new(127);
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", symbol)
            .unwrap()
            .at_now()
            .unwrap();
        buffer
    }

    #[test]
    fn replay_encoder_max_size_accounts_for_connection_global_symbol_prefix() {
        let mut encoder = QwpWsReplayEncoder::new(1);
        for idx in 0..130 {
            let seed = one_symbol_buffer(format!("seed{idx}").as_str());
            encoder.encode_with_max_size(&seed, usize::MAX).unwrap();
        }
        let seeded_symbols = encoder.global_dict.len();

        let buffer = one_symbol_buffer("fresh");
        let local_hint = buffer.len();
        let err = encoder
            .encode_with_max_size(&buffer, local_hint)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("QWP/WebSocket encoded message size"));
        assert_eq!(encoder.global_dict.len(), seeded_symbols);

        let encoded_len = encoder
            .encode_with_max_size(&buffer, usize::MAX)
            .unwrap()
            .len();
        assert!(encoded_len > local_hint);
        assert_eq!(encoder.global_dict.len(), seeded_symbols + 1);
    }
}
