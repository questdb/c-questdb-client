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

//! Replay-publication shell for the pipelined QWP/WebSocket sender.
//!
//! The manual driver is intentionally payload-opaque. This module sits one level
//! above it: the replay encoder turns a QWP buffer into a self-sufficient replay
//! payload, and the publication driver publishes those bytes to the driver's
//! queue.

use std::time::Duration;

use crate::error;
use crate::ingress::buffer::{QwpBuffer, QwpWsEncodeScratch, SymbolGlobalDict};

#[cfg(test)]
use super::qwp_ws_driver::DeliveryOutcome;
use super::qwp_ws_driver::{
    CloseOutcome, DriveOutcome, DriverError, ManualDriverPrototype, ManualDriverTransport,
    PublicationLog, QwpWsPublicationStore, QwpWsSendCore,
};
use super::qwp_ws_ownership::QwpWsSenderError;
use super::qwp_ws_queue::QwpReceipt;
#[cfg(test)]
use super::qwp_ws_queue::SentFrame;

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

    #[cfg(test)]
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

    pub(crate) fn submit_qwp_with_append_deadline(
        &mut self,
        buffer: &QwpBuffer,
        append_deadline: Duration,
    ) -> Result<QwpReceipt, QwpWsPublicationError> {
        let payload = self
            .encoder
            .encode(buffer)
            .map_err(QwpWsPublicationError::Encode)?;
        Ok(self
            .driver
            .submit_with_drive_deadline(payload, append_deadline)?)
    }

    #[cfg(test)]
    pub(crate) fn drive_once(&mut self) -> Result<DriveOutcome, DriverError> {
        self.driver.drive_once()
    }

    pub(crate) fn drive_ready_once(&mut self) -> Result<DriveOutcome, DriverError> {
        self.driver.drive_ready_once()
    }

    #[cfg(test)]
    pub(crate) fn wait_steps(
        &mut self,
        receipt: QwpReceipt,
        max_drive_steps: usize,
    ) -> Result<DeliveryOutcome, DriverError> {
        self.driver.wait_steps(receipt, max_drive_steps)
    }

    #[cfg(test)]
    pub(crate) fn close_drain_steps(
        &mut self,
        max_drive_steps: usize,
    ) -> Result<CloseOutcome, DriverError> {
        self.driver.close_drain_steps(max_drive_steps)
    }

    pub(crate) fn close_drain_ready_once(&mut self) -> Result<CloseOutcome, DriverError> {
        self.driver.close_drain_ready_once()
    }

    #[cfg(test)]
    pub(crate) fn sent_frames(&self) -> &[SentFrame] {
        self.driver.sent_frames()
    }

    pub(crate) fn terminal_error(&self) -> Option<&crate::Error> {
        self.driver.terminal_error()
    }

    pub(crate) fn terminal_sender_error(&self) -> Option<&QwpWsSenderError> {
        self.driver.terminal_sender_error()
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.driver.is_terminal()
    }

    pub(crate) fn published_fsn(&self) -> Option<u64> {
        self.driver.published_fsn()
    }

    pub(crate) fn acked_fsn(&self) -> Option<u64> {
        self.driver.acked_fsn()
    }

    pub(crate) fn poll_sender_error(&mut self) -> Option<QwpWsSenderError> {
        self.driver.poll_sender_error()
    }

    pub(crate) fn sender_errors_dropped_total(&self) -> u64 {
        self.driver.sender_errors_dropped_total()
    }

    #[cfg(test)]
    pub(crate) fn into_driver(self) -> ManualDriverPrototype<Q, T> {
        self.driver
    }

    pub(crate) fn into_runner_parts(self) -> (QwpWsPublicationStore<Q>, QwpWsSendCore<T>) {
        self.driver.into_parts()
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
