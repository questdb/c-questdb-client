//! Server-rejection events for pooled QWP/WebSocket senders.
//!
//! Mirrors the Java client's `SenderErrorHandler` contract: every server
//! rejection recorded by a pooled connection's runner is pushed to one
//! pool-wide handler, decoupled from the `wait()` ack barrier. With a
//! user handler the delivery runs on a dedicated dispatcher thread through
//! a bounded drop-oldest inbox; without one every rejection is logged, so
//! silence is never the default. A terminal diagnostic is published only
//! after the connection's terminal latch and pollable diagnostics have been
//! committed, so handler code can immediately observe the terminal state.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use super::conn_events::EventDispatcher;
use super::{QwpWsErrorHandler, QwpWsSenderError};

pub(crate) struct RejectionEventSource {
    dispatcher: Mutex<Option<EventDispatcher<QwpWsSenderError>>>,
    fallback: Option<QwpWsErrorHandler>,
    fallback_delivered: AtomicU64,
    closed_delivered: AtomicU64,
    closed_dropped: AtomicU64,
}

impl std::fmt::Debug for RejectionEventSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RejectionEventSource")
            .field("delivered", &self.delivered())
            .field("dropped", &self.dropped())
            .finish()
    }
}

impl RejectionEventSource {
    pub(crate) fn with_handler(handler: QwpWsErrorHandler, inbox_capacity: usize) -> Self {
        let listener = std::sync::Arc::new(move |error: &QwpWsSenderError| handler.handle(error));
        Self {
            dispatcher: Mutex::new(Some(EventDispatcher::named(
                "rejections",
                listener,
                inbox_capacity,
            ))),
            fallback: None,
            fallback_delivered: AtomicU64::new(0),
            closed_delivered: AtomicU64::new(0),
            closed_dropped: AtomicU64::new(0),
        }
    }

    /// A source with no user handler: every rejection is logged inline at
    /// the publish site (warn for retriable policies, error for terminal),
    /// with no dispatcher thread.
    pub(crate) fn logging_default() -> Self {
        Self {
            dispatcher: Mutex::new(None),
            fallback: Some(QwpWsErrorHandler::log_default()),
            fallback_delivered: AtomicU64::new(0),
            closed_delivered: AtomicU64::new(0),
            closed_dropped: AtomicU64::new(0),
        }
    }

    /// Test-only synchronous delivery for asserting publication ordering at
    /// the exact call site, without scheduler timing in the assertion.
    #[cfg(test)]
    pub(crate) fn inline_for_test(handler: QwpWsErrorHandler) -> Self {
        Self {
            dispatcher: Mutex::new(None),
            fallback: Some(handler),
            fallback_delivered: AtomicU64::new(0),
            closed_delivered: AtomicU64::new(0),
            closed_dropped: AtomicU64::new(0),
        }
    }

    fn lock_dispatcher(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<EventDispatcher<QwpWsSenderError>>> {
        match self.dispatcher.lock() {
            Ok(dispatcher) => dispatcher,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(crate) fn publish(&self, error: QwpWsSenderError) {
        if let Some(dispatcher) = self.lock_dispatcher().as_ref() {
            dispatcher.offer(error);
            return;
        }
        if let Some(fallback) = &self.fallback {
            fallback.handle(&error);
            self.fallback_delivered.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Detach and join the dispatcher, preserving its counters. `publish`
    /// holds the same mutex while it queues an event, so after this returns
    /// no emitter can reach the user handler, even if an FFI-owned sender
    /// outlives its pool handle. The logging fallback has no user resources
    /// and stays active.
    pub(crate) fn close(&self) {
        let dispatcher = self.lock_dispatcher().take();
        if let Some(dispatcher) = dispatcher {
            let (delivered, dropped) = dispatcher.shutdown();
            self.closed_delivered.store(delivered, Ordering::Relaxed);
            self.closed_dropped.store(dropped, Ordering::Relaxed);
        }
    }

    pub(crate) fn delivered(&self) -> u64 {
        let live = self
            .lock_dispatcher()
            .as_ref()
            .map(EventDispatcher::delivered)
            .unwrap_or(0);
        self.closed_delivered.load(Ordering::Relaxed)
            + self.fallback_delivered.load(Ordering::Relaxed)
            + live
    }

    pub(crate) fn dropped(&self) -> u64 {
        let live = self
            .lock_dispatcher()
            .as_ref()
            .map(EventDispatcher::dropped)
            .unwrap_or(0);
        self.closed_dropped.load(Ordering::Relaxed) + live
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::{QwpWsErrorCategory, QwpWsErrorPolicy};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn rejection(from_fsn: u64) -> QwpWsSenderError {
        QwpWsSenderError {
            category: QwpWsErrorCategory::WriteError,
            applied_policy: QwpWsErrorPolicy::Retriable,
            status: Some(0x09),
            message: Some("boom".to_string()),
            message_sequence: Some(from_fsn),
            from_fsn,
            to_fsn: from_fsn,
        }
    }

    #[test]
    fn handler_mode_delivers_on_dispatcher_thread() {
        let seen: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_in_handler = Arc::clone(&seen);
        let publishing_thread = std::thread::current().id();
        let source = RejectionEventSource::with_handler(
            QwpWsErrorHandler::new(move |error: &QwpWsSenderError| {
                assert_ne!(std::thread::current().id(), publishing_thread);
                seen_in_handler.lock().unwrap().push(error.from_fsn);
            }),
            8,
        );
        source.publish(rejection(1));
        source.publish(rejection(2));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while source.delivered() < 2 {
            assert!(std::time::Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(*seen.lock().unwrap(), vec![1, 2]);
        assert_eq!(source.dropped(), 0);
    }

    #[test]
    fn close_fences_handler_and_keeps_counters() {
        let seen: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_in_handler = Arc::clone(&seen);
        let source = RejectionEventSource::with_handler(
            QwpWsErrorHandler::new(move |error: &QwpWsSenderError| {
                seen_in_handler.lock().unwrap().push(error.from_fsn);
            }),
            8,
        );
        source.publish(rejection(1));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while source.delivered() < 1 {
            assert!(std::time::Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
        source.close();
        source.publish(rejection(2));
        assert_eq!(source.delivered(), 1);
        assert_eq!(source.dropped(), 0);
        assert_eq!(*seen.lock().unwrap(), vec![1]);
    }

    #[test]
    fn logging_default_counts_deliveries() {
        let source = RejectionEventSource::logging_default();
        source.publish(rejection(1));
        source.publish(rejection(2));
        assert_eq!(source.delivered(), 2);
        assert_eq!(source.dropped(), 0);
    }
}
