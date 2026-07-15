//! Connection lifecycle events.
//!
//! Mirrors the Java client's `SenderConnectionListener` contract: a
//! user-supplied listener receives [`ConnectionEvent`]s describing
//! connection-state transitions (initial connect, endpoint attempt
//! failures, failover, terminal auth rejection). Events are delivered on
//! a dedicated dispatcher thread through a bounded inbox with a
//! drop-oldest overflow policy, so a slow listener can never stall
//! connect, publish, or reconnect paths. Success events fire once per
//! transition; failure events may be coalesced (dropped) under inbox
//! pressure — observable via [`ConnectionEventDispatcher::dropped`].

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default bounded-inbox capacity, matching the Java dispatcher.
pub const DEFAULT_CONNECTION_EVENT_INBOX_CAPACITY: usize = 64;

/// The set of connection-state transitions that fire as discrete events.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConnectionEventKind {
    /// The very first successful connect observed by this event source.
    /// Fired once, before any data has been sent on the connection.
    Connected,
    /// An active wire connection died. Fired once per detected loss,
    /// before any reconnect attempt.
    Disconnected,
    /// A subsequent connect succeeded against the same endpoint that was
    /// previously active. Mutually exclusive with [`Self::FailedOver`].
    Reconnected,
    /// A subsequent connect succeeded against a different endpoint than
    /// the previously-active one.
    FailedOver,
    /// A single endpoint connect/upgrade attempt failed; the walk moves
    /// to the next endpoint. Fired once per failed endpoint per sweep.
    EndpointAttemptFailed,
    /// Every configured endpoint was attempted and none accepted the
    /// connection in this sweep.
    AllEndpointsUnreachable,
    /// Terminal: the server rejected credentials. The owning
    /// sender/pool operation surfaces the error to the caller.
    AuthFailed,
}

/// One connection-state transition. All `Option` fields are `None` when
/// not applicable to the [`kind`](Self::kind).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectionEvent {
    pub kind: ConnectionEventKind,
    /// Endpoint involved in this event.
    pub host: Option<String>,
    pub port: Option<String>,
    /// For [`ConnectionEventKind::FailedOver`], the previously-active
    /// endpoint.
    pub previous_host: Option<String>,
    pub previous_port: Option<String>,
    /// Monotonic per-source connect-attempt counter at the time this
    /// event fired.
    pub attempt_number: Option<u64>,
    /// Error code classification for failure events.
    pub cause_code: Option<crate::ErrorCode>,
    /// Human-readable cause for failure events.
    pub cause_msg: Option<String>,
    /// Wall-clock time of the event, milliseconds since the Unix epoch.
    pub timestamp_millis: i64,
}

impl ConnectionEvent {
    pub(crate) fn new(kind: ConnectionEventKind) -> Self {
        let timestamp_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Self {
            kind,
            host: None,
            port: None,
            previous_host: None,
            previous_port: None,
            attempt_number: None,
            cause_code: None,
            cause_msg: None,
            timestamp_millis,
        }
    }

    pub(crate) fn at(mut self, host: &str, port: &str) -> Self {
        self.host = Some(host.to_string());
        self.port = Some(port.to_string());
        self
    }

    pub(crate) fn previously_at(mut self, host: &str, port: &str) -> Self {
        self.previous_host = Some(host.to_string());
        self.previous_port = Some(port.to_string());
        self
    }

    pub(crate) fn attempt(mut self, attempt: u64) -> Self {
        self.attempt_number = Some(attempt);
        self
    }

    pub(crate) fn caused_by(mut self, err: &crate::Error) -> Self {
        self.cause_code = Some(err.code());
        self.cause_msg = Some(err.msg().to_string());
        self
    }
}

/// User-supplied listener. Invoked on the dispatcher thread, never on an
/// I/O or producer thread. Panics are caught and logged; the dispatcher
/// keeps running.
pub type ConnectionListener = Arc<dyn Fn(&ConnectionEvent) + Send + Sync>;

struct DispatcherInner {
    inbox: Mutex<VecDeque<ConnectionEvent>>,
    available: Condvar,
    capacity: usize,
    listener: ConnectionListener,
    closed: AtomicBool,
    dropped: AtomicU64,
    delivered: AtomicU64,
}

impl DispatcherInner {
    fn lock_inbox(&self) -> std::sync::MutexGuard<'_, VecDeque<ConnectionEvent>> {
        match self.inbox.lock() {
            Ok(inbox) => inbox,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Bounded inbox plus a dedicated dispatcher thread delivering
/// [`ConnectionEvent`]s to one [`ConnectionListener`].
///
/// `offer` never blocks: when the inbox is full the oldest undelivered
/// event is discarded (drop-oldest) and counted in [`Self::dropped`].
/// Dropping the dispatcher discards undelivered events and **joins** the
/// dispatcher thread, waiting for at most the one in-flight listener
/// invocation — after drop returns, the listener is guaranteed to never
/// run again, so FFI callers may release listener resources (e.g. a
/// Python callable behind `user_data`) immediately afterwards.
pub struct ConnectionEventDispatcher {
    inner: Arc<DispatcherInner>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ConnectionEventDispatcher {
    pub fn new(listener: ConnectionListener, capacity: usize) -> Self {
        let capacity = if capacity == 0 {
            DEFAULT_CONNECTION_EVENT_INBOX_CAPACITY
        } else {
            capacity
        };
        let inner = Arc::new(DispatcherInner {
            inbox: Mutex::new(VecDeque::with_capacity(capacity)),
            available: Condvar::new(),
            capacity,
            listener,
            closed: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
        });
        let thread_inner = Arc::clone(&inner);
        let thread = match std::thread::Builder::new()
            .name("questdb-conn-events".to_string())
            .spawn(move || dispatch_loop(thread_inner))
        {
            Ok(handle) => Some(handle),
            Err(err) => {
                log::warn!("connection-event dispatcher thread failed to spawn: {err}");
                inner.closed.store(true, Ordering::Release);
                None
            }
        };
        Self { inner, thread }
    }

    /// Queue one event for delivery. Non-blocking; drop-oldest on a full
    /// inbox; discarded outright after close.
    pub fn offer(&self, event: ConnectionEvent) {
        if self.inner.closed.load(Ordering::Acquire) {
            self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        {
            let mut inbox = self.inner.lock_inbox();
            if inbox.len() >= self.inner.capacity {
                inbox.pop_front();
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            }
            inbox.push_back(event);
        }
        self.inner.available.notify_one();
    }

    /// Total events discarded by the drop-oldest policy (or offered after
    /// close) since startup.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// Total events handed to the listener since startup, counting ones
    /// whose listener invocation panicked.
    pub fn delivered(&self) -> u64 {
        self.inner.delivered.load(Ordering::Relaxed)
    }
}

impl Drop for ConnectionEventDispatcher {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.available.notify_one();
        if let Some(handle) = self.thread.take()
            && handle.thread().id() != std::thread::current().id()
        {
            let _ = handle.join();
        }
    }
}

fn dispatch_loop(inner: Arc<DispatcherInner>) {
    loop {
        let event = {
            let mut inbox = inner.lock_inbox();
            loop {
                // Once closed, discard the backlog (counted as dropped)
                // so the joining drop waits for at most the in-flight
                // listener invocation, not the whole queue.
                if inner.closed.load(Ordering::Acquire) {
                    let discarded = inbox.len() as u64;
                    if discarded > 0 {
                        inbox.clear();
                        inner.dropped.fetch_add(discarded, Ordering::Relaxed);
                    }
                    break None;
                }
                if let Some(event) = inbox.pop_front() {
                    break Some(event);
                }
                inbox = match inner.available.wait(inbox) {
                    Ok(inbox) => inbox,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
        };
        let Some(event) = event else {
            return;
        };
        let listener = &inner.listener;
        if catch_unwind(AssertUnwindSafe(|| listener(&event))).is_err() {
            log::warn!("connection-event listener panicked; event: {event:?}");
        }
        inner.delivered.fetch_add(1, Ordering::Relaxed);
    }
}

/// Per-source event context: one dispatcher (fixed at construction — either
/// present for the source's whole life or absent, never attached later) plus
/// the state needed to classify successes. `connect_succeeded` fires:
///
/// - [`ConnectionEventKind::Connected`] for the source's first-ever
///   success;
/// - [`ConnectionEventKind::Reconnected`] for a same-endpoint success
///   after an observed failure;
/// - [`ConnectionEventKind::FailedOver`] for a success against a
///   different endpoint than the previous one;
/// - nothing for a same-endpoint success with no intervening failure
///   (e.g. pool growth opening additional connections).
impl std::fmt::Debug for ConnectionEventSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionEventSource")
            .field("delivered", &self.delivered())
            .field("dropped", &self.dropped())
            .finish()
    }
}

pub(crate) struct ConnectionEventSource {
    dispatcher: Mutex<Option<ConnectionEventDispatcher>>,
    attempts: AtomicU64,
    last_endpoint: Mutex<Option<(String, String)>>,
    failed_since_success: AtomicBool,
}

impl ConnectionEventSource {
    pub(crate) fn new(listener: ConnectionListener, inbox_capacity: usize) -> Self {
        Self::with_dispatcher(Some(ConnectionEventDispatcher::new(
            listener,
            inbox_capacity,
        )))
    }

    /// A source with no listener: emissions are discarded, but the attempt
    /// counter and classification state still track. Lets pool emitters hold
    /// one source unconditionally instead of threading `Option` everywhere.
    pub(crate) fn disabled() -> Self {
        Self::with_dispatcher(None)
    }

    fn with_dispatcher(dispatcher: Option<ConnectionEventDispatcher>) -> Self {
        Self {
            dispatcher: Mutex::new(dispatcher),
            attempts: AtomicU64::new(0),
            last_endpoint: Mutex::new(None),
            failed_since_success: AtomicBool::new(false),
        }
    }

    fn lock_dispatcher(&self) -> std::sync::MutexGuard<'_, Option<ConnectionEventDispatcher>> {
        match self.dispatcher.lock() {
            Ok(dispatcher) => dispatcher,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Detach and join the dispatcher. `offer` holds the same mutex while it
    /// queues an event, so after this returns no emitter can reach the user
    /// listener, even if an FFI-owned sender outlives its pool handle.
    pub(crate) fn close(&self) {
        let dispatcher = self.lock_dispatcher().take();
        drop(dispatcher);
    }

    fn offer(&self, event: ConnectionEvent) {
        if let Some(dispatcher) = self.lock_dispatcher().as_ref() {
            dispatcher.offer(event);
        }
    }

    pub(crate) fn next_attempt(&self) -> u64 {
        self.attempts.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn connect_attempt_failed(
        &self,
        host: &str,
        port: &str,
        err: &crate::Error,
        attempt: u64,
    ) {
        self.failed_since_success.store(true, Ordering::Relaxed);
        self.offer(
            ConnectionEvent::new(ConnectionEventKind::EndpointAttemptFailed)
                .at(host, port)
                .attempt(attempt)
                .caused_by(err),
        );
    }

    pub(crate) fn auth_failed(&self, host: &str, port: &str, err: &crate::Error, attempt: u64) {
        self.failed_since_success.store(true, Ordering::Relaxed);
        self.offer(
            ConnectionEvent::new(ConnectionEventKind::AuthFailed)
                .at(host, port)
                .attempt(attempt)
                .caused_by(err),
        );
    }

    pub(crate) fn all_endpoints_unreachable(&self, err: &crate::Error) {
        self.failed_since_success.store(true, Ordering::Relaxed);
        self.offer(
            ConnectionEvent::new(ConnectionEventKind::AllEndpointsUnreachable).caused_by(err),
        );
    }

    pub(crate) fn disconnected(&self, host: &str, port: &str) {
        self.failed_since_success.store(true, Ordering::Relaxed);
        self.offer(ConnectionEvent::new(ConnectionEventKind::Disconnected).at(host, port));
    }

    pub(crate) fn connect_succeeded(&self, host: &str, port: &str) {
        let mut last = match self.last_endpoint.lock() {
            Ok(last) => last,
            Err(poisoned) => poisoned.into_inner(),
        };
        let failed = self.failed_since_success.swap(false, Ordering::Relaxed);
        let event = match last.as_ref() {
            None => Some(ConnectionEvent::new(ConnectionEventKind::Connected).at(host, port)),
            Some((prev_host, prev_port)) if prev_host == host && prev_port == port => {
                if failed {
                    Some(ConnectionEvent::new(ConnectionEventKind::Reconnected).at(host, port))
                } else {
                    None
                }
            }
            Some((prev_host, prev_port)) => Some(
                ConnectionEvent::new(ConnectionEventKind::FailedOver)
                    .at(host, port)
                    .previously_at(prev_host, prev_port),
            ),
        };
        *last = Some((host.to_string(), port.to_string()));
        drop(last);
        if let Some(event) = event {
            self.offer(event);
        }
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.lock_dispatcher()
            .as_ref()
            .map(ConnectionEventDispatcher::dropped)
            .unwrap_or(0)
    }

    pub(crate) fn delivered(&self) -> u64 {
        self.lock_dispatcher()
            .as_ref()
            .map(ConnectionEventDispatcher::delivered)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn wait_for(mut cond: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    type SeenKindsAndHosts = Arc<Mutex<Vec<(ConnectionEventKind, Option<String>)>>>;

    #[test]
    fn delivers_in_order_on_dispatcher_thread() {
        let seen: SeenKindsAndHosts = Arc::new(Mutex::new(Vec::new()));
        let seen_in_listener = Arc::clone(&seen);
        let offering_thread = std::thread::current().id();
        let dispatcher = ConnectionEventDispatcher::new(
            Arc::new(move |event: &ConnectionEvent| {
                assert_ne!(std::thread::current().id(), offering_thread);
                seen_in_listener
                    .lock()
                    .unwrap()
                    .push((event.kind, event.host.clone()));
            }),
            8,
        );
        dispatcher.offer(ConnectionEvent::new(ConnectionEventKind::Connected).at("a", "1"));
        dispatcher.offer(
            ConnectionEvent::new(ConnectionEventKind::FailedOver)
                .at("b", "2")
                .previously_at("a", "1"),
        );
        wait_for(|| dispatcher.delivered() == 2);
        let seen = seen.lock().unwrap();
        assert_eq!(
            *seen,
            vec![
                (ConnectionEventKind::Connected, Some("a".to_string())),
                (ConnectionEventKind::FailedOver, Some("b".to_string())),
            ]
        );
        assert_eq!(dispatcher.dropped(), 0);
    }

    #[test]
    fn drop_oldest_when_full() {
        let gate = Arc::new(Mutex::new(()));
        let seen: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_in_listener = Arc::clone(&seen);
        let gate_in_listener = Arc::clone(&gate);
        let dispatcher = ConnectionEventDispatcher::new(
            Arc::new(move |event: &ConnectionEvent| {
                drop(gate_in_listener.lock().unwrap());
                seen_in_listener
                    .lock()
                    .unwrap()
                    .push(event.attempt_number.unwrap());
            }),
            2,
        );
        {
            // Hold the gate so the dispatcher stalls on event 0 while the
            // inbox overflows behind it.
            let _held = gate.lock().unwrap();
            dispatcher
                .offer(ConnectionEvent::new(ConnectionEventKind::EndpointAttemptFailed).attempt(0));
            wait_for(|| dispatcher.inner.inbox.lock().unwrap().is_empty());
            for attempt in 1..=4u64 {
                dispatcher.offer(
                    ConnectionEvent::new(ConnectionEventKind::EndpointAttemptFailed)
                        .attempt(attempt),
                );
            }
        }
        wait_for(|| dispatcher.delivered() == 3);
        assert_eq!(*seen.lock().unwrap(), vec![0, 3, 4]);
        assert_eq!(dispatcher.dropped(), 2);
    }

    #[test]
    fn listener_panic_does_not_kill_dispatcher() {
        let seen: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_in_listener = Arc::clone(&seen);
        let dispatcher = ConnectionEventDispatcher::new(
            Arc::new(move |event: &ConnectionEvent| {
                let attempt = event.attempt_number.unwrap();
                if attempt == 0 {
                    panic!("listener bug");
                }
                seen_in_listener.lock().unwrap().push(attempt);
            }),
            8,
        );
        dispatcher.offer(ConnectionEvent::new(ConnectionEventKind::Disconnected).attempt(0));
        dispatcher.offer(ConnectionEvent::new(ConnectionEventKind::Reconnected).attempt(1));
        wait_for(|| dispatcher.delivered() == 2);
        assert_eq!(*seen.lock().unwrap(), vec![1]);
    }

    #[test]
    fn drop_joins_in_flight_delivery_and_discards_backlog() {
        // FFI callers (e.g. the Python binding) release listener
        // resources right after the owning pool closes; drop() must
        // therefore wait for the in-flight invocation and guarantee no
        // delivery ever runs afterwards.
        let release = Arc::new(AtomicBool::new(false));
        let delivered_after_drop = Arc::new(AtomicBool::new(false));
        let dropped_flag = Arc::new(AtomicBool::new(false));
        let release_in_listener = Arc::clone(&release);
        let delivered_after_drop_in_listener = Arc::clone(&delivered_after_drop);
        let dropped_flag_in_listener = Arc::clone(&dropped_flag);
        let dispatcher = ConnectionEventDispatcher::new(
            Arc::new(move |_: &ConnectionEvent| {
                while !release_in_listener.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                if dropped_flag_in_listener.load(Ordering::Acquire) {
                    delivered_after_drop_in_listener.store(true, Ordering::Release);
                }
            }),
            8,
        );
        dispatcher.offer(ConnectionEvent::new(ConnectionEventKind::Connected).attempt(0));
        wait_for(|| dispatcher.inner.inbox.lock().unwrap().is_empty());
        // Backlog behind the stalled in-flight event: must be discarded.
        for attempt in 1..=3u64 {
            dispatcher
                .offer(ConnectionEvent::new(ConnectionEventKind::Disconnected).attempt(attempt));
        }
        let inner = Arc::clone(&dispatcher.inner);
        let releaser = {
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                release.store(true, Ordering::Release);
            })
        };
        drop(dispatcher);
        dropped_flag.store(true, Ordering::Release);
        releaser.join().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!delivered_after_drop.load(Ordering::Acquire));
        assert_eq!(inner.delivered.load(Ordering::Relaxed), 1);
        assert_eq!(inner.dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn drop_signals_thread_exit_and_discards_late_offers() {
        let dispatcher = ConnectionEventDispatcher::new(Arc::new(|_: &ConnectionEvent| {}), 4);
        let inner = Arc::clone(&dispatcher.inner);
        drop(dispatcher);
        wait_for(|| Arc::strong_count(&inner) == 1);
        assert!(inner.closed.load(Ordering::Acquire));
    }

    #[test]
    fn source_close_fences_listener() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_in_listener = Arc::clone(&seen);
        let source = ConnectionEventSource::new(
            Arc::new(move |event: &ConnectionEvent| {
                seen_in_listener.lock().unwrap().push(event.kind);
            }),
            8,
        );

        source.connect_succeeded("a", "1");
        source.disconnected("a", "1");
        source.connect_succeeded("a", "1");
        wait_for(|| seen.lock().unwrap().len() == 3);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                ConnectionEventKind::Connected,
                ConnectionEventKind::Disconnected,
                ConnectionEventKind::Reconnected
            ]
        );

        source.close();
        source.disconnected("a", "1");
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(seen.lock().unwrap().len(), 3);
    }

    #[test]
    fn disabled_source_discards_events() {
        let source = ConnectionEventSource::disabled();
        source.connect_succeeded("a", "1");
        source.disconnected("a", "1");
        assert_eq!(source.delivered(), 0);
        assert_eq!(source.dropped(), 0);
    }
}
