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

#![allow(dead_code)]

//! Shared QWP/WebSocket publication receipt and outbound-frame types.

use std::sync::Arc;

use super::qwp_ws_sfa_segment::SfaMappedPayload;

pub(crate) struct PendingPayload {
    storage: PendingPayloadStorage,
}

enum PendingPayloadStorage {
    Owned(Arc<[u8]>),
    SfaMapped(SfaMappedPayload),
}

impl PendingPayload {
    pub(crate) fn owned(payload: Arc<[u8]>) -> Self {
        Self {
            storage: PendingPayloadStorage::Owned(payload),
        }
    }

    pub(crate) fn sfa_mapped(payload: SfaMappedPayload) -> Self {
        Self {
            storage: PendingPayloadStorage::SfaMapped(payload),
        }
    }

    pub(crate) fn len(&self) -> usize {
        match &self.storage {
            PendingPayloadStorage::Owned(payload) => payload.len(),
            PendingPayloadStorage::SfaMapped(payload) => payload.len(),
        }
    }

    pub(crate) fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        match &self.storage {
            PendingPayloadStorage::Owned(payload) => f(payload.as_ref()),
            PendingPayloadStorage::SfaMapped(payload) => payload.with_bytes(f),
        }
    }
}

impl std::fmt::Debug for PendingPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingPayload")
            .field("len", &self.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QwpReceipt {
    pub(crate) fsn: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QwpReceiptStatus {
    Unknown { fsn: u64 },
    Published { fsn: u64 },
    Sent { fsn: u64, wire_seq: u64 },
    Completed { fsn: u64 },
    Terminal { fsn: u64 },
}

impl QwpReceiptStatus {
    pub(crate) fn is_pending(&self) -> bool {
        matches!(
            self,
            QwpReceiptStatus::Published { .. } | QwpReceiptStatus::Sent { .. }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SentFrame {
    pub(crate) fsn: u64,
    pub(crate) wire_seq: u64,
    pub(crate) payload_len: usize,
}

#[derive(Debug)]
pub(crate) struct OutboundFrame {
    pub(crate) fsn: u64,
    pub(crate) wire_seq: u64,
    pub(crate) payload: PendingPayload,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct OutboundFrameView<'a> {
    pub(crate) fsn: u64,
    pub(crate) wire_seq: u64,
    pub(crate) payload: &'a [u8],
}

impl OutboundFrame {
    pub(crate) fn sent_frame(&self) -> SentFrame {
        SentFrame {
            fsn: self.fsn,
            wire_seq: self.wire_seq,
            payload_len: self.payload.len(),
        }
    }

    pub(crate) fn with_view<R>(&self, f: impl FnOnce(OutboundFrameView<'_>) -> R) -> R {
        self.payload.with_bytes(|payload| {
            f(OutboundFrameView {
                fsn: self.fsn,
                wire_seq: self.wire_seq,
                payload,
            })
        })
    }
}

impl OutboundFrameView<'_> {
    pub(crate) fn sent_frame(&self) -> SentFrame {
        SentFrame {
            fsn: self.fsn,
            wire_seq: self.wire_seq,
            payload_len: self.payload.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueError {
    InvalidCapacity,
    EmptyPayload,
    FrameCapacityFull {
        max_frames: usize,
    },
    PayloadExceedsByteCapacity {
        payload_len: usize,
        max_bytes: usize,
    },
    ByteCapacityFull {
        payload_len: usize,
        bytes_used: usize,
        max_bytes: usize,
    },
    StorageSpareNotReady {
        segment_size_bytes: u64,
        allocated_segment_bytes: u64,
        max_total_bytes: u64,
    },
    StorageSegmentCapFull {
        segment_size_bytes: u64,
        allocated_segment_bytes: u64,
        max_total_bytes: u64,
    },
    MaxInFlightReached {
        max_in_flight: usize,
    },
    NoUnsentFrame,
    ProtocolAckWithoutConnection,
    ProtocolAckBeyondSent {
        wire_seq: u64,
        last_sent_wire_seq: Option<u64>,
    },
    ProtocolAckedUnsentFrame {
        fsn: u64,
    },
    ProtocolRejectWithoutConnection,
    ProtocolRejectBeyondSent {
        wire_seq: u64,
        last_sent_wire_seq: Option<u64>,
    },
    ProtocolRejectedUnsentFrame {
        fsn: u64,
    },
    OutboundFrameUnavailable {
        fsn: u64,
        wire_seq: u64,
    },
    SequenceOverflow,
}
