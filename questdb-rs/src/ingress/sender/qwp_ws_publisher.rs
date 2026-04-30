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

//! Replay-publication shell for the pipelined QWP/WebSocket prototype.
//!
//! The manual driver is intentionally payload-opaque. This module sits one level
//! above it: the replay encoder turns a QWP buffer into a self-sufficient replay
//! payload, and the publication driver publishes those bytes to the driver's
//! queue.

use crate::error;
use crate::ingress::buffer::{QwpBuffer, QwpWsEncodeScratch, SymbolGlobalDict};

use super::qwp_ws_driver::{
    CloseOutcome, DeliveryOutcome, DetachedReceive, DetachedSend, DriveOutcome, DriverError,
    DriverEvent, ManualDriverPrototype, ManualDriverTransport, PublicationLog, QwpRejectedFrame,
    QwpServerError, TransportFailure, TransportResponse, TransportSendResult,
};
use super::qwp_ws_queue::{QwpReceipt, QwpReceiptStatus, SentFrame};

pub(crate) struct QwpWsPublicationDriver<Q, T> {
    driver: ManualDriverPrototype<Q, T>,
    encoder: QwpWsReplayEncoder,
}

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

    pub(crate) fn version(&self) -> u8 {
        self.version
    }

    pub(crate) fn encode(&mut self, buffer: &QwpBuffer) -> crate::Result<&[u8]> {
        if buffer.is_empty() {
            return Err(error::fmt!(
                InvalidApiCall,
                "Cannot submit an empty QWP/WebSocket buffer."
            ));
        }
        buffer.encode_ws_replay_message(&mut self.scratch, &mut self.global_dict, self.version)?;
        Ok(&self.scratch.message)
    }
}

impl<Q: PublicationLog, T: ManualDriverTransport> QwpWsPublicationDriver<Q, T> {
    pub(crate) fn new(driver: ManualDriverPrototype<Q, T>, version: u8) -> Self {
        Self {
            driver,
            encoder: QwpWsReplayEncoder::new(version),
        }
    }

    pub(crate) fn version(&self) -> u8 {
        self.encoder.version()
    }

    pub(crate) fn try_submit_qwp(
        &mut self,
        buffer: &QwpBuffer,
    ) -> Result<QwpReceipt, QwpWsPublicationError> {
        let payload = self
            .encoder
            .encode(buffer)
            .map_err(QwpWsPublicationError::Encode)?;
        Ok(self.driver.try_submit(payload)?)
    }

    pub(crate) fn try_submit_replay_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<QwpReceipt, DriverError> {
        self.driver.try_submit(payload)
    }

    pub(crate) fn submit_qwp_with_drive_limit(
        &mut self,
        buffer: &QwpBuffer,
        max_drive_steps: usize,
    ) -> Result<QwpReceipt, QwpWsPublicationError> {
        let payload = self
            .encoder
            .encode(buffer)
            .map_err(QwpWsPublicationError::Encode)?;
        Ok(self
            .driver
            .submit_with_drive_limit(payload, max_drive_steps)?)
    }

    pub(crate) fn drive_once(&mut self) -> Result<DriveOutcome, DriverError> {
        self.driver.drive_once()
    }

    pub(crate) fn drive_send_once(&mut self) -> Result<DriveOutcome, DriverError> {
        self.driver.drive_send_once()
    }

    pub(crate) fn drive_receive_once(&mut self) -> Result<DriveOutcome, DriverError> {
        self.driver.drive_receive_once()
    }

    pub(crate) fn drive_receive_ready_once(&mut self) -> Result<DriveOutcome, DriverError> {
        self.driver.drive_receive_ready_once()
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.driver.is_terminal()
    }

    pub(crate) fn detach_send_available(&mut self) -> Result<Option<DetachedSend<T>>, DriverError> {
        self.driver.detach_send_available()
    }

    pub(crate) fn finish_detached_send(
        &mut self,
        transport: T,
        frame: SentFrame,
        send_result: Result<TransportSendResult, TransportFailure>,
    ) -> Result<DriveOutcome, DriverError> {
        self.driver
            .finish_detached_send(transport, frame, send_result)
    }

    pub(crate) fn detach_receive_ready(&mut self) -> Option<DetachedReceive<T>> {
        self.driver.detach_receive_ready()
    }

    pub(crate) fn finish_detached_receive(
        &mut self,
        transport: T,
        response: Result<Option<TransportResponse>, TransportFailure>,
    ) -> Result<DriveOutcome, DriverError> {
        self.driver.finish_detached_receive(transport, response)
    }

    pub(crate) fn wait_steps(
        &mut self,
        receipt: QwpReceipt,
        max_drive_steps: usize,
    ) -> Result<DeliveryOutcome, DriverError> {
        self.driver.wait_steps(receipt, max_drive_steps)
    }

    pub(crate) fn close_drain_steps(
        &mut self,
        max_drive_steps: usize,
    ) -> Result<CloseOutcome, DriverError> {
        self.driver.close_drain_steps(max_drive_steps)
    }

    pub(crate) fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        self.driver.receipt_status(receipt)
    }

    pub(crate) fn sent_frames(&self) -> &[SentFrame] {
        self.driver.sent_frames()
    }

    pub(crate) fn poll_event(&mut self) -> Option<DriverEvent> {
        self.driver.poll_event()
    }

    pub(crate) fn events_dropped_total(&self) -> u64 {
        self.driver.events_dropped_total()
    }

    pub(crate) fn terminal_error(&self) -> Option<&crate::Error> {
        self.driver.terminal_error()
    }

    pub(crate) fn last_server_error(&self) -> Option<&QwpServerError> {
        self.driver.last_server_error()
    }

    pub(crate) fn rejected_frame(&self, receipt: QwpReceipt) -> Option<&QwpRejectedFrame> {
        self.driver.rejected_frame(receipt)
    }

    pub(crate) fn into_driver(self) -> ManualDriverPrototype<Q, T> {
        self.driver
    }
}

#[derive(Debug)]
pub(crate) enum QwpWsPublicationError {
    Encode(crate::Error),
    Driver(DriverError),
}

impl From<DriverError> for QwpWsPublicationError {
    fn from(value: DriverError) -> Self {
        Self::Driver(value)
    }
}
