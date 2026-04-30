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

//! Type-only QWP/WebSocket progress ownership prototype.
//!
//! This module intentionally has no transport, queue, or encoder logic. It
//! exists to validate the Step 2 design rule: a sender core has exactly one
//! progress owner, and adapters consume the manual sender instead of sharing it
//! through runtime "runner active" checks.

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_PROTOTYPE_ID: AtomicU64 = AtomicU64::new(1);

/// Placeholder options for the type-only QWP/WebSocket prototype.
#[derive(Debug, Default, Clone)]
pub struct QwpWsOptions {
    _private: (),
}

/// Threadless QWP/WebSocket sender core.
///
/// Progress-driving methods on the future implementation should live on this
/// type and take `&mut self`.
#[derive(Debug)]
pub struct QwpWsSender {
    prototype_id: u64,
}

impl QwpWsSender {
    /// Construct a type-only sender prototype.
    pub fn open(_opts: QwpWsOptions) -> crate::Result<Self> {
        Ok(Self {
            prototype_id: NEXT_PROTOTYPE_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// Placeholder manual progress method.
    ///
    /// Its `&mut self` receiver is the important part of this prototype.
    pub fn drive_once(&mut self) -> crate::Result<()> {
        Ok(())
    }

    /// Test/debug identifier preserved when ownership moves into adapters.
    #[doc(hidden)]
    pub fn prototype_id(&self) -> u64 {
        self.prototype_id
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
    fn manual_progress_requires_mutable_sender() {
        let mut sender = QwpWsSender::open(QwpWsOptions::default()).unwrap();

        sender.drive_once().unwrap();
    }
}
