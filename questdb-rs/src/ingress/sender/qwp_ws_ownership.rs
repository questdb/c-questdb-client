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
//! The manual sender owns the publication queue and transport driver. Threaded
//! and async adapters consume it instead of sharing a separate progress owner.

use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};

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

static NEXT_PROTOTYPE_ID: AtomicU64 = AtomicU64::new(1);

/// Placeholder options for the FFI ownership prototype.
#[doc(hidden)]
#[derive(Debug, Default, Clone)]
pub struct QwpWsOptions {
    _private: (),
}

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
    prototype_id: u64,
    max_drive_steps: usize,
    max_buf_size: usize,
    max_name_len: usize,

    #[cfg(feature = "sync-sender-qwp-ws")]
    publisher: Option<SyncQwpWsPublisher>,
}

impl Debug for QwpWsSender {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("QwpWsSender");
        debug
            .field("prototype_id", &self.prototype_id)
            .field("max_drive_steps", &self.max_drive_steps)
            .field("max_buf_size", &self.max_buf_size)
            .field("max_name_len", &self.max_name_len);
        #[cfg(feature = "sync-sender-qwp-ws")]
        debug.field("connected", &self.publisher.is_some());
        debug.finish()
    }
}

impl QwpWsSender {
    /// Construct a type-only sender prototype for FFI ownership tests.
    #[doc(hidden)]
    pub fn open(_opts: QwpWsOptions) -> crate::Result<Self> {
        Ok(Self {
            prototype_id: NEXT_PROTOTYPE_ID.fetch_add(1, Ordering::Relaxed),
            max_drive_steps: 0,
            max_buf_size: usize::MAX,
            max_name_len: 127,
            #[cfg(feature = "sync-sender-qwp-ws")]
            publisher: None,
        })
    }

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
            prototype_id: NEXT_PROTOTYPE_ID.fetch_add(1, Ordering::Relaxed),
            max_drive_steps,
            max_buf_size,
            max_name_len,
            publisher: Some(publisher),
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
        match self
            .publisher_mut()?
            .try_submit_qwp(qwp)
            .map(QwpWsReceipt::from)
        {
            Ok(receipt) => Ok(receipt),
            Err(err) => Err(publication_error_to_error(err)),
        }
    }

    /// Drive one send/receive/reconnect step.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn drive_once(&mut self) -> crate::Result<QwpWsDriveOutcome> {
        let publisher = self.publisher_mut()?;
        match publisher.drive_once() {
            Ok(outcome) => Ok(outcome.into()),
            Err(err) => Err(driver_error_to_error(publisher, err)),
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
        let publisher = self.publisher_mut()?;
        match publisher.wait_steps(receipt, max_drive_steps) {
            Ok(DeliveryOutcome::Acked) => Ok(QwpWsDeliveryOutcome::Acked),
            Ok(DeliveryOutcome::Rejected) => {
                let rejection = publisher.rejected_frame(receipt).ok_or_else(|| {
                    error::fmt!(
                        SocketError,
                        "QWP/WebSocket frame was rejected, but rejection details are unavailable"
                    )
                })?;
                Ok(QwpWsDeliveryOutcome::Rejected(rejection.into()))
            }
            Ok(DeliveryOutcome::Terminal) => Err(publisher
                .terminal_error()
                .cloned()
                .unwrap_or_else(|| error::fmt!(SocketError, "QWP/WebSocket sender is terminal"))),
            Ok(DeliveryOutcome::Timeout) => Ok(QwpWsDeliveryOutcome::Timeout),
            Err(err) => Err(driver_error_to_error(publisher, err)),
        }
    }

    /// Return the current local status for a receipt.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn receipt_status(&self, receipt: QwpWsReceipt) -> crate::Result<QwpWsReceiptStatus> {
        Ok(self.publisher_ref()?.receipt_status(receipt.into()).into())
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
        let publisher = self.publisher_mut()?;
        match publisher.close_drain_steps(max_drive_steps) {
            Ok(outcome) => Ok(outcome.into()),
            Err(err) => Err(driver_error_to_error(publisher, err)),
        }
    }

    /// Test/debug identifier preserved when ownership moves into adapters.
    #[doc(hidden)]
    pub fn prototype_id(&self) -> u64 {
        self.prototype_id
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn publisher_ref(&self) -> crate::Result<&SyncQwpWsPublisher> {
        self.publisher.as_ref().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/WebSocket sender was not opened from a connection configuration"
            )
        })
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn publisher_mut(&mut self) -> crate::Result<&mut SyncQwpWsPublisher> {
        self.publisher.as_mut().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/WebSocket sender was not opened from a connection configuration"
            )
        })
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

/// Explicit background-thread ownership adapter.
///
/// The adapter owns the sender core. Stopping or dropping this value does not
/// return the manual sender.
#[derive(Debug)]
pub struct QwpWsThreadedSender {
    inner: QwpWsSender,
}

impl QwpWsThreadedSender {
    /// Consume a manual sender and make this value the sole progress owner.
    pub fn start(sender: QwpWsSender) -> crate::Result<Self> {
        Ok(Self::from_sender_type_only(sender))
    }

    #[doc(hidden)]
    pub fn from_sender_type_only(sender: QwpWsSender) -> Self {
        Self { inner: sender }
    }

    /// Stop the prototype runner without returning the manual sender.
    pub fn stop(self) {}

    /// Test/debug identifier preserved from the consumed manual sender.
    #[doc(hidden)]
    pub fn prototype_id(&self) -> u64 {
        self.inner.prototype_id()
    }
}

/// Explicit async ownership adapter.
///
/// This is runtime-neutral in the type-only prototype. A later async adapter can
/// build on the same ownership conversion without exposing a runtime through C.
#[derive(Debug)]
pub struct QwpWsAsyncSender {
    inner: QwpWsSender,
}

impl QwpWsAsyncSender {
    /// Consume a manual sender and make this value the sole progress owner.
    pub fn from_sender(sender: QwpWsSender) -> crate::Result<Self> {
        Ok(Self { inner: sender })
    }

    /// Test/debug identifier preserved from the consumed manual sender.
    #[doc(hidden)]
    pub fn prototype_id(&self) -> u64 {
        self.inner.prototype_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threaded_adapter_consumes_manual_sender() {
        let sender = QwpWsSender::open(QwpWsOptions::default()).unwrap();
        let id = sender.prototype_id();

        let threaded = QwpWsThreadedSender::start(sender).unwrap();

        assert_eq!(threaded.prototype_id(), id);
        threaded.stop();
    }

    #[test]
    fn async_adapter_consumes_manual_sender() {
        let sender = QwpWsSender::open(QwpWsOptions::default()).unwrap();
        let id = sender.prototype_id();

        let async_sender = QwpWsAsyncSender::from_sender(sender).unwrap();

        assert_eq!(async_sender.prototype_id(), id);
    }

    #[test]
    fn prototype_sender_is_not_a_connected_progress_owner() {
        let mut sender = QwpWsSender::open(QwpWsOptions::default()).unwrap();

        let err = sender.drive_once().unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
    }
}
