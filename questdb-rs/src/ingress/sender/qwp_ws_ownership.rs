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

//! Native QWP/WebSocket progress ownership.
//!
//! The manual sender owns the publication queue and transport driver. Future
//! threaded or async adapters should consume it instead of sharing a separate
//! progress owner.

use std::fmt::{Debug, Formatter};

use crate::error;
use crate::ingress::Buffer;

#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::SenderBuilder;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::buffer::QwpBuffer;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::sender::qwp_ws_driver::{
    CloseOutcome, DeliveryOutcome, DriveOutcome, QwpRejectedFrame, ReconnectReason,
};
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::sender::qwp_ws_queue::{
    QwpReceipt, QwpReceiptStatus as InternalQwpReceiptStatus,
};
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::sender::{
    SyncQwpWsPublisher, driver_error_to_error, publication_error_to_error,
};

/// Handle returned when a QWP/WebSocket batch is locally published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QwpWsReceipt {
    fsn: u64,
}

impl QwpWsReceipt {
    /// The frame sequence number assigned by this sender.
    pub fn fsn(self) -> u64 {
        self.fsn
    }
}

/// Current status of a locally published QWP/WebSocket receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QwpWsReceiptStatus {
    Unknown { fsn: u64 },
    Published { fsn: u64 },
    Sent { fsn: u64, wire_sequence: u64 },
    Acked { fsn: u64 },
    Rejected { fsn: u64 },
    Terminal { fsn: u64 },
}

/// Result of waiting for a QWP/WebSocket receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QwpWsDeliveryOutcome {
    Acked,
    Rejected(QwpWsRejection),
    Timeout,
}

/// Server rejection details for a locally published QWP/WebSocket frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QwpWsRejection {
    pub fsn: u64,
    pub wire_sequence: u64,
    pub status: u8,
    pub message: String,
}

/// Reason a QWP/WebSocket sender reconnected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QwpWsReconnectReason {
    Disconnect,
    RetryableFailure,
}

/// Result of one manual QWP/WebSocket progress step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QwpWsDriveOutcome {
    Idle,
    Sent { fsn: u64, wire_sequence: u64 },
    Acked { wire_sequence: u64 },
    Rejected { fsn: u64, wire_sequence: u64 },
    Reconnected { reason: QwpWsReconnectReason },
    Terminal,
}

/// Result of draining a QWP/WebSocket sender before close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QwpWsCloseOutcome {
    Drained,
    Timeout,
    Terminal,
}

/// Threadless QWP/WebSocket sender core.
pub struct QwpWsSender {
    max_drive_steps: usize,
    max_buf_size: usize,
    max_name_len: usize,

    #[cfg(feature = "sync-sender-qwp-ws")]
    publisher: SyncQwpWsPublisher,
}

impl Debug for QwpWsSender {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("QwpWsSender");
        debug
            .field("max_drive_steps", &self.max_drive_steps)
            .field("max_buf_size", &self.max_buf_size)
            .field("max_name_len", &self.max_name_len);
        debug.finish()
    }
}

impl QwpWsSender {
    /// Create a manual QWP/WebSocket sender from the same configuration string
    /// accepted by [`crate::ingress::Sender::from_conf`].
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn from_conf<T: AsRef<str>>(conf: T) -> crate::Result<Self> {
        SenderBuilder::from_conf(conf)?.build_qwp_ws()
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    pub(crate) fn from_publisher(
        publisher: SyncQwpWsPublisher,
        max_drive_steps: usize,
        max_buf_size: usize,
        max_name_len: usize,
    ) -> Self {
        Self {
            max_drive_steps,
            max_buf_size,
            max_name_len,
            publisher,
        }
    }

    /// Creates a QWP row buffer using this sender's protocol settings.
    pub fn new_buffer(&self) -> Buffer {
        Buffer::qwp_with_max_name_len(self.max_name_len)
    }

    /// Publish a buffer into the sender queue and clear it on success.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn submit(&mut self, buf: &mut Buffer) -> crate::Result<QwpWsReceipt> {
        let receipt = self.submit_and_keep(buf)?;
        buf.clear();
        Ok(receipt)
    }

    /// Publish a buffer into the sender queue while preserving the buffer.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn submit_and_keep(&mut self, buf: &Buffer) -> crate::Result<QwpWsReceipt> {
        let qwp = self.qwp_buffer(buf)?;
        match self.publisher.try_submit_qwp(qwp).map(QwpWsReceipt::from) {
            Ok(receipt) => Ok(receipt),
            Err(err) => Err(publication_error_to_error(err)),
        }
    }

    /// Drive one send/receive/reconnect step.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn drive_once(&mut self) -> crate::Result<QwpWsDriveOutcome> {
        match self.publisher.drive_once() {
            Ok(outcome) => Ok(outcome.into()),
            Err(err) => Err(driver_error_to_error(&self.publisher, err)),
        }
    }

    /// Wait using this sender's configured bounded progress budget.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn wait(&mut self, receipt: QwpWsReceipt) -> crate::Result<QwpWsDeliveryOutcome> {
        self.wait_steps(receipt, self.max_drive_steps)
    }

    /// Wait using an explicit maximum number of progress steps.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn wait_steps(
        &mut self,
        receipt: QwpWsReceipt,
        max_drive_steps: usize,
    ) -> crate::Result<QwpWsDeliveryOutcome> {
        let receipt = receipt.into();
        match self.publisher.wait_steps(receipt, max_drive_steps) {
            Ok(DeliveryOutcome::Acked) => Ok(QwpWsDeliveryOutcome::Acked),
            Ok(DeliveryOutcome::Rejected) => {
                let rejection = self.publisher.rejected_frame(receipt).ok_or_else(|| {
                    error::fmt!(
                        SocketError,
                        "QWP/WebSocket frame was rejected, but rejection details are unavailable"
                    )
                })?;
                Ok(QwpWsDeliveryOutcome::Rejected(rejection.into()))
            }
            Ok(DeliveryOutcome::Terminal) => {
                Err(self.publisher.terminal_error().cloned().unwrap_or_else(|| {
                    error::fmt!(SocketError, "QWP/WebSocket sender is terminal")
                }))
            }
            Ok(DeliveryOutcome::Timeout) => Ok(QwpWsDeliveryOutcome::Timeout),
            Err(err) => Err(driver_error_to_error(&self.publisher, err)),
        }
    }

    /// Return the current local status for a receipt.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn receipt_status(&self, receipt: QwpWsReceipt) -> crate::Result<QwpWsReceiptStatus> {
        Ok(self.publisher.receipt_status(receipt.into()).into())
    }

    /// Drain all locally published frames before closing the queue.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn close_drain(&mut self) -> crate::Result<QwpWsCloseOutcome> {
        self.close_drain_steps(self.max_drive_steps)
    }

    /// Drain all locally published frames using an explicit progress budget.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn close_drain_steps(
        &mut self,
        max_drive_steps: usize,
    ) -> crate::Result<QwpWsCloseOutcome> {
        match self.publisher.close_drain_steps(max_drive_steps) {
            Ok(outcome) => Ok(outcome.into()),
            Err(err) => Err(driver_error_to_error(&self.publisher, err)),
        }
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn qwp_buffer<'a>(&self, buf: &'a Buffer) -> crate::Result<&'a QwpBuffer> {
        let qwp = buf.as_qwp().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/WebSocket sender requires a QWP buffer created by `QwpWsSender::new_buffer()`."
            )
        })?;
        qwp.check_can_flush()?;
        if qwp.len() > self.max_buf_size {
            return Err(error::fmt!(
                InvalidApiCall,
                "Could not publish buffer: QWP buffer size hint of {} exceeds maximum configured allowed size of {} bytes.",
                qwp.len(),
                self.max_buf_size
            ));
        }
        Ok(qwp)
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl From<QwpReceipt> for QwpWsReceipt {
    fn from(value: QwpReceipt) -> Self {
        Self { fsn: value.fsn }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl From<QwpWsReceipt> for QwpReceipt {
    fn from(value: QwpWsReceipt) -> Self {
        Self { fsn: value.fsn }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl From<InternalQwpReceiptStatus> for QwpWsReceiptStatus {
    fn from(value: InternalQwpReceiptStatus) -> Self {
        match value {
            InternalQwpReceiptStatus::Unknown { fsn } => Self::Unknown { fsn },
            InternalQwpReceiptStatus::Published { fsn } => Self::Published { fsn },
            InternalQwpReceiptStatus::Sent { fsn, wire_seq } => Self::Sent {
                fsn,
                wire_sequence: wire_seq,
            },
            InternalQwpReceiptStatus::Acked { fsn } => Self::Acked { fsn },
            InternalQwpReceiptStatus::Rejected { fsn } => Self::Rejected { fsn },
            InternalQwpReceiptStatus::Terminal { fsn } => Self::Terminal { fsn },
        }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl From<&QwpRejectedFrame> for QwpWsRejection {
    fn from(value: &QwpRejectedFrame) -> Self {
        Self {
            fsn: value.fsn,
            wire_sequence: value.wire_seq,
            status: value.error.status,
            message: value.error.message.clone(),
        }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl From<ReconnectReason> for QwpWsReconnectReason {
    fn from(value: ReconnectReason) -> Self {
        match value {
            ReconnectReason::Disconnect => Self::Disconnect,
            ReconnectReason::RetryableFailure => Self::RetryableFailure,
        }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl From<DriveOutcome> for QwpWsDriveOutcome {
    fn from(value: DriveOutcome) -> Self {
        match value {
            DriveOutcome::Idle => Self::Idle,
            DriveOutcome::Sent(frame) => Self::Sent {
                fsn: frame.fsn,
                wire_sequence: frame.wire_seq,
            },
            DriveOutcome::Acked { wire_seq } => Self::Acked {
                wire_sequence: wire_seq,
            },
            DriveOutcome::Rejected { fsn, wire_seq } => Self::Rejected {
                fsn,
                wire_sequence: wire_seq,
            },
            DriveOutcome::Reconnected { reason } => Self::Reconnected {
                reason: reason.into(),
            },
            DriveOutcome::Terminal => Self::Terminal,
        }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl From<CloseOutcome> for QwpWsCloseOutcome {
    fn from(value: CloseOutcome) -> Self {
        match value {
            CloseOutcome::Drained => Self::Drained,
            CloseOutcome::Timeout => Self::Timeout,
            CloseOutcome::Terminal => Self::Terminal,
        }
    }
}
