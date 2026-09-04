//! Connection lifecycle events.
//!
//! Mirrors the Java client's `SenderConnectionListener` contract: a
//! user-supplied listener receives [`ConnectionEvent`]s describing
//! connection-state transitions (initial connect, endpoint attempt
//! failures, failover, terminal auth rejection). Events are delivered on
//! a dedicated dispatcher thread through a bounded inbox with a
//! drop-oldest overflow policy, so a slow listener can never stall
//! connect, publish, or reconnect paths. Success events fire once per
//! transition and are queued only after negotiated connection state,
//! including the server-advertised frame cap, is committed. They are not
//! data-delivery or acknowledgement barriers. Failure events may be
//! coalesced (dropped) under inbox pressure — observable via
//! [`ConnectionEventDispatcher::dropped`].

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
    /// Fired once, after negotiated state is committed and before any data
    /// has been sent on the connection.
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
    /// A credential was rejected or could not be obtained.
    ///
    /// Terminal **only when `host` is set**: the server rejected the
    /// credential it was offered, and the owning sender/pool operation
    /// surfaces the error to the caller.
    ///
    /// When `host` and `port` are `None` the credential was never offered to
    /// anyone -- a token provider failed before any endpoint was dialled (see
    /// [`ConnectionEvents::token_provider_failed`]). That is **retryable**:
    /// `classify_provider_error` keeps such a failure a `SocketError` so the
    /// store-and-forward drainer holds queued frames while a human signs in,
    /// and the sender goes on reconnecting. A listener that pages, tears down
    /// the pool, or exits on `AuthFailed` must gate on `host.is_some()`, or it
    /// will fire on an ordinary silent-refresh blip. The `cause_code` tells the
    /// two apart as well: `AuthError` for a rejection, `SocketError` for a
    /// provider failure.
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

struct DispatcherInner<T> {
    inbox: Mutex<VecDeque<T>>,
    available: Condvar,
    capacity: usize,
    listener: Arc<dyn Fn(&T) + Send + Sync>,
    name: &'static str,
    closed: AtomicBool,
    dropped: AtomicU64,
    delivered: AtomicU64,
    /// Set by the worker as it enters `dispatch_loop`, so a test can tell
    /// a running worker from one that never spawned.
    #[cfg(test)]
    worker_started: (Mutex<bool>, Condvar),
}

impl<T> DispatcherInner<T> {
    fn lock_inbox(&self) -> std::sync::MutexGuard<'_, VecDeque<T>> {
        match self.inbox.lock() {
            Ok(inbox) => inbox,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[cfg(test)]
    fn signal_worker_start(&self) {
        let (started, signal) = &self.worker_started;
        let mut started = match started.lock() {
            Ok(started) => started,
            Err(poisoned) => poisoned.into_inner(),
        };
        *started = true;
        signal.notify_all();
    }

    #[cfg(test)]
    fn wait_for_worker_start(&self, timeout: std::time::Duration) -> bool {
        let (started, signal) = &self.worker_started;
        let deadline = std::time::Instant::now() + timeout;
        let mut started = match started.lock() {
            Ok(started) => started,
            Err(poisoned) => poisoned.into_inner(),
        };
        while !*started {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            started = match signal.wait_timeout(started, deadline - now) {
                Ok((started, _)) => started,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        true
    }
}

/// Bounded inbox plus a dedicated dispatcher thread delivering events of
/// one type to one listener.
///
/// `offer` never blocks: when the inbox is full the oldest undelivered
/// event is discarded (drop-oldest) and counted in [`Self::dropped`].
/// Dropping the dispatcher discards undelivered events and **joins** the
/// dispatcher thread, waiting for at most the one in-flight listener
/// invocation — after drop returns, the listener is guaranteed to never
/// run again, so FFI callers may release listener resources (e.g. a
/// Python callable behind `user_data`) immediately afterwards.
pub struct EventDispatcher<T> {
    inner: Arc<DispatcherInner<T>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// [`EventDispatcher`] delivering [`ConnectionEvent`]s to one
/// [`ConnectionListener`].
pub type ConnectionEventDispatcher = EventDispatcher<ConnectionEvent>;

impl<T: std::fmt::Debug + Send + 'static> EventDispatcher<T> {
    pub fn new(listener: Arc<dyn Fn(&T) + Send + Sync>, capacity: usize) -> Self {
        Self::named("conn-events", listener, capacity)
    }

    pub(crate) fn named(
        name: &'static str,
        listener: Arc<dyn Fn(&T) + Send + Sync>,
        capacity: usize,
    ) -> Self {
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
            name,
            closed: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            #[cfg(test)]
            worker_started: (Mutex::new(false), Condvar::new()),
        });
        let thread_inner = Arc::clone(&inner);
        let thread = match std::thread::Builder::new()
            .name(format!("questdb-{name}"))
            .spawn(move || dispatch_loop(thread_inner))
        {
            Ok(handle) => Some(handle),
            Err(err) => {
                log::warn!("{name} dispatcher thread failed to spawn: {err}");
                inner.closed.store(true, Ordering::Release);
                None
            }
        };
        Self { inner, thread }
    }

    /// Queue one event for delivery. Non-blocking; drop-oldest on a full
    /// inbox; discarded outright after close.
    pub fn offer(&self, event: T) {
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

    /// Test-only: block until the worker thread has entered its dispatch
    /// loop, returning `false` on timeout or when the spawn failed. Lets a
    /// test that exercises the close/join path prove there was a worker to
    /// join, rather than passing because no thread was ever created.
    #[cfg(test)]
    pub(crate) fn wait_for_worker_start(&self, timeout: std::time::Duration) -> bool {
        self.thread.is_some() && self.inner.wait_for_worker_start(timeout)
    }

    /// Drop the dispatcher (joining its thread, so any in-flight listener
    /// invocation completes) and return the final `(delivered, dropped)`.
    pub(crate) fn shutdown(self) -> (u64, u64) {
        let inner = Arc::clone(&self.inner);
        drop(self);
        (
            inner.delivered.load(Ordering::Relaxed),
            inner.dropped.load(Ordering::Relaxed),
        )
    }
}

impl<T> Drop for EventDispatcher<T> {
    fn drop(&mut self) {
        // The inbox mutex is required for the wakeup to reach the
        // dispatcher: `dispatch_loop` reads `closed` and parks while
        // holding that same mutex, so publishing the close under it means
        // the loop either sees the store before parking or is already
        // registered as a waiter when the notify lands. The loop re-reads
        // `closed` under the mutex before each park, so only this notify
        // has to arrive; a surplus one is harmless.
        //
        // Keeping events from arriving after the close is what makes every
        // offered event either delivered or counted in `dropped`, and that
        // comes from the holders rather than from `offer`, whose `closed`
        // check runs outside the inbox mutex and is not ordered against
        // this store: `ConnectionEventSource::offer` and
        // `RejectionEventSource::publish` hold their own dispatcher mutex
        // across the whole `offer` call, and `close` takes that same mutex
        // to remove the dispatcher.
        {
            let _inbox = self.inner.lock_inbox();
            self.inner.closed.store(true, Ordering::Release);
            self.inner.available.notify_one();
        }
        if let Some(handle) = self.thread.take()
            && handle.thread().id() != std::thread::current().id()
        {
            let _ = handle.join();
        }
    }
}

fn dispatch_loop<T: std::fmt::Debug>(inner: Arc<DispatcherInner<T>>) {
    #[cfg(test)]
    inner.signal_worker_start();
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
            log::warn!("{} listener panicked; event: {event:?}", inner.name);
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

    /// A token provider (e.g. OIDC) failed before any endpoint was dialled, so
    /// the round ends without a connection.
    ///
    /// Reported as an `AuthFailed` carrying no endpoint: the failure is the
    /// credential, not a host, and nothing was contacted. Without this the
    /// whole round is silent — the provider is resolved above the endpoint
    /// loop, so neither `auth_failed` nor `all_endpoints_unreachable` is ever
    /// reached, and a listener sees no event at all for a sender that is in
    /// fact reconnecting indefinitely.
    pub(crate) fn token_provider_failed(&self, err: &crate::Error, attempt: u64) {
        self.failed_since_success.store(true, Ordering::Relaxed);
        self.offer(
            ConnectionEvent::new(ConnectionEventKind::AuthFailed)
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
    fn drop_immediately_after_new_never_hangs() {
        // Regression: dropping a dispatcher right after construction — before
        // its freshly spawned worker has parked on the condvar — must not lose
        // the shutdown wakeup and hang the join in Drop. This is the create-
        // then-close race that surfaced as a `questdb_db_close` hang when a
        // pool was closed immediately after connect. Runs on a helper thread so
        // a regression fails fast with a message instead of wedging the suite.
        let done = Arc::new(AtomicBool::new(false));
        let done_in_thread = Arc::clone(&done);
        let runner = std::thread::spawn(move || {
            for _ in 0..2000 {
                let dispatcher =
                    ConnectionEventDispatcher::new(Arc::new(|_: &ConnectionEvent| {}), 8);
                drop(dispatcher);
            }
            done_in_thread.store(true, Ordering::Release);
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !done.load(Ordering::Acquire) {
            assert!(
                std::time::Instant::now() < deadline,
                "EventDispatcher::drop hung joining a not-yet-parked worker (lost wakeup)"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        runner.join().unwrap();
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
    fn drop_joins_a_dispatcher_thread_that_never_saw_an_event() {
        // A dispatcher dropped right after construction races its own
        // thread's first trip through the inbox lock: the thread reads
        // `closed`, finds the inbox empty and parks. The close is
        // published under that mutex, so the park stays reachable and
        // every drop joins. Run the cycle often enough to cover the
        // window; a stalled join shows up as the recv timeout.
        //
        // Against a dispatcher that publishes the close without the inbox
        // mutex the stall lands within the first few hundred rounds, so
        // this count carries a wide margin over the window it sweeps.
        //
        // The cycle runs on its own thread and reports over a channel so a
        // stalled join fails this test rather than hanging the suite:
        // libtest joins the test's own thread, so the same loop written
        // inline would block `cargo test` with no output at all.
        const ROUNDS: u32 = 5_000;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let completed = Arc::new(AtomicU64::new(0));
        let completed_in_thread = Arc::clone(&completed);
        std::thread::spawn(move || {
            for round in 0..ROUNDS {
                let dispatcher =
                    ConnectionEventDispatcher::new(Arc::new(|_: &ConnectionEvent| {}), 4);
                // A round covers the race only if the thread started:
                // `named` logs and gives up on a spawn failure, which would
                // leave every drop a no-op and pass this test vacuously.
                assert!(
                    dispatcher.thread.is_some(),
                    "dispatcher thread failed to spawn"
                );
                // Sweep the gap so drops land across the whole startup
                // window, including the instant the thread holds the inbox
                // lock and is about to park.
                for _ in 0..(round % 400) {
                    std::hint::spin_loop();
                }
                drop(dispatcher);
                completed_in_thread.store(u64::from(round + 1), Ordering::Relaxed);
            }
            let _ = done_tx.send(());
        });
        match done_rx.recv_timeout(Duration::from_secs(60)) {
            Ok(()) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                "only {} of {ROUNDS} drop/join cycles finished in 60s; a stalled \
                 join reports a few hundred, an overloaded machine reports most \
                 of them",
                completed.load(Ordering::Relaxed),
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("the drop/join worker panicked")
            }
        }
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
