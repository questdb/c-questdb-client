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

//! C ABI for rotating Bearer-token providers (`include/questdb/token_provider.h`).
//!
//! A `questdb_token_provider` is either a refreshing provider -- a proactively
//! refreshing cache in front of a C token source -- or a provider implemented
//! by the application through a small function table. Either attaches to a
//! sender, a reader or a pool.

use std::ffi::{c_char, c_void};
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc::size_t;
use questdb::token_provider::{
    BearerTokenProvider, ExpiringToken, RefreshingTokenProvider, TokenSource,
};
use questdb::{Error, ErrorCode, TokenProviderIsolation};
use zeroize::Zeroizing;

use crate::oidc::{versioned_output_capacity, write_versioned_output};
use crate::{line_sender_opts, questdb_error, set_err_out_from_error};

/// Fetch a new token for a refreshing provider: call exactly one of
/// `questdb_token_sink_set_token` or `questdb_token_sink_set_error`.
pub type questdb_token_source_fn =
    unsafe extern "C" fn(user_data: *mut c_void, sink: *mut questdb_token_sink);

/// The current token of an application-implemented provider: call exactly one
/// of `questdb_token_sink_set_token` or `questdb_token_sink_set_error`.
pub type questdb_token_get_fn =
    unsafe extern "C" fn(user_data: *mut c_void, sink: *mut questdb_token_sink);

/// A server rejected `token` with `http_status` (401).
pub type questdb_token_rejected_fn = unsafe extern "C" fn(
    user_data: *mut c_void,
    token: *const c_char,
    token_len: size_t,
    http_status: u16,
);

/// Release `user_data` once the provider no longer needs it.
pub type questdb_token_release_fn = unsafe extern "C" fn(user_data: *mut c_void);

/// Function table of an application-implemented provider.
#[repr(C)]
pub struct questdb_token_provider_vtable {
    pub struct_size: size_t,
    pub get_token: Option<questdb_token_get_fn>,
    pub on_rejected: Option<questdb_token_rejected_fn>,
    pub release: Option<questdb_token_release_fn>,
}

const QUESTDB_TOKEN_PROVIDER_VTABLE_V1_SIZE: usize =
    std::mem::size_of::<questdb_token_provider_vtable>();

/// Parameters of a refreshing provider (spec §5.1). Initialize with
/// `questdb_refreshing_token_provider_options_init`, which fills in the
/// defaults, then override the fields you need.
#[repr(C)]
pub struct questdb_refreshing_token_provider_options {
    pub struct_size: size_t,
    pub name: *const c_char,
    pub name_len: size_t,
    pub refresh_margin_ms: u64,
    pub min_refresh_interval_ms: u64,
    pub handout_floor_ms: u64,
    pub cold_wait_ms: u64,
    pub backoff_initial_ms: u64,
    pub backoff_max_ms: u64,
    pub retry_after_max_ms: u64,
    pub forced_min_interval_ms: u64,
    pub forced_wait_ms: u64,
}

const QUESTDB_REFRESHING_TOKEN_PROVIDER_OPTIONS_V1_SIZE: usize =
    std::mem::size_of::<questdb_refreshing_token_provider_options>();

impl Default for questdb_refreshing_token_provider_options {
    fn default() -> Self {
        let ms = |d: Duration| d.as_millis() as u64;
        Self {
            struct_size: std::mem::size_of::<Self>(),
            name: ptr::null(),
            name_len: 0,
            refresh_margin_ms: ms(RefreshingTokenProvider::DEFAULT_REFRESH_MARGIN),
            min_refresh_interval_ms: ms(RefreshingTokenProvider::DEFAULT_MIN_REFRESH_INTERVAL),
            handout_floor_ms: ms(RefreshingTokenProvider::DEFAULT_HANDOUT_FLOOR),
            cold_wait_ms: ms(RefreshingTokenProvider::DEFAULT_COLD_WAIT),
            backoff_initial_ms: ms(RefreshingTokenProvider::DEFAULT_BACKOFF_INITIAL),
            backoff_max_ms: ms(RefreshingTokenProvider::DEFAULT_BACKOFF_MAX),
            retry_after_max_ms: ms(RefreshingTokenProvider::DEFAULT_RETRY_AFTER_MAX),
            forced_min_interval_ms: ms(RefreshingTokenProvider::DEFAULT_FORCED_MIN_INTERVAL),
            forced_wait_ms: ms(RefreshingTokenProvider::DEFAULT_FORCED_WAIT),
        }
    }
}

/// A snapshot of a refreshing provider (spec §5.7). Never contains the token.
#[repr(C)]
pub struct questdb_token_provider_status {
    pub struct_size: size_t,
    pub closed: bool,
    pub has_last_failure: bool,
    pub last_failure_retryable: bool,
    pub consecutive_failures: u32,
    pub token_expires_at_ms: i64,
    pub last_success_at_ms: i64,
    pub last_failure_retry_after_ms: i64,
    pub last_failure_at_ms: i64,
    pub last_failure_msg: *mut c_char,
    pub last_failure_msg_capacity: size_t,
    pub last_failure_msg_len: size_t,
}

const QUESTDB_TOKEN_PROVIDER_STATUS_V1_SIZE: usize =
    std::mem::size_of::<questdb_token_provider_status>();

/// The token-unavailable classification of an error.
#[repr(C)]
pub struct questdb_token_unavailable_view {
    pub struct_size: size_t,
    pub retryable: bool,
    pub retry_after_ms: i64,
}

const QUESTDB_TOKEN_UNAVAILABLE_VIEW_V1_SIZE: usize =
    std::mem::size_of::<questdb_token_unavailable_view>();

// ---------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------

/// Where a source or provider callback reports its result. Valid only for the
/// duration of the callback.
pub struct questdb_token_sink {
    outcome: SinkOutcome,
}

enum SinkOutcome {
    Empty,
    Token {
        token: Zeroizing<String>,
        expires_at_ms: i64,
        refresh_at_ms: i64,
    },
    Error(Error),
}

impl questdb_token_sink {
    fn new() -> Self {
        Self {
            outcome: SinkOutcome::Empty,
        }
    }

    fn take(self, who: &str) -> questdb::Result<(Zeroizing<String>, i64, i64)> {
        match self.outcome {
            SinkOutcome::Token {
                token,
                expires_at_ms,
                refresh_at_ms,
            } => Ok((token, expires_at_ms, refresh_at_ms)),
            SinkOutcome::Error(err) => Err(err),
            SinkOutcome::Empty => Err(Error::token_unavailable(
                true,
                None,
                format!("the {who} callback reported neither a token nor an error"),
            )),
        }
    }
}

/// Report a token from a source or provider callback. The token is copied.
///
/// `expires_at_ms` is the token's expiry in epoch milliseconds; a source must
/// give it, a provider may pass 0. `refresh_at_ms` is the platform's suggested
/// refresh time, or 0 for none. Returns false, setting nothing, when `sink` is
/// NULL, a result was already reported, or the token is not UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_sink_set_token(
    sink: *mut questdb_token_sink,
    token: *const c_char,
    token_len: size_t,
    expires_at_ms: i64,
    refresh_at_ms: i64,
) -> bool {
    let Some(sink) = (unsafe { sink.as_mut() }) else {
        return false;
    };
    if !matches!(sink.outcome, SinkOutcome::Empty) || (token.is_null() && token_len != 0) {
        return false;
    }
    let bytes = if token_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(token.cast::<u8>(), token_len) }
    };
    let Ok(token) = std::str::from_utf8(bytes) else {
        return false;
    };
    sink.outcome = SinkOutcome::Token {
        token: Zeroizing::new(token.to_string()),
        expires_at_ms,
        refresh_at_ms,
    };
    true
}

/// Report a failure from a source or provider callback. `retryable` says
/// whether retrying can succeed (network failures, timeouts, throttling and
/// 5xx are retryable; missing or wrong configuration is not).
/// `retry_after_ms` is a suggested wait, or a negative value for none. The
/// message (UTF-8, copied) must not contain a token or a response body.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_sink_set_error(
    sink: *mut questdb_token_sink,
    retryable: bool,
    retry_after_ms: i64,
    msg: *const c_char,
    msg_len: size_t,
) -> bool {
    let Some(sink) = (unsafe { sink.as_mut() }) else {
        return false;
    };
    if !matches!(sink.outcome, SinkOutcome::Empty) {
        return false;
    }
    let message = if msg.is_null() || msg_len == 0 {
        String::from("the token callback failed without a message")
    } else {
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(msg.cast::<u8>(), msg_len) })
            .into_owned()
    };
    let retry_after = (retry_after_ms >= 0).then(|| Duration::from_millis(retry_after_ms as u64));
    sink.outcome = SinkOutcome::Error(Error::token_unavailable(retryable, retry_after, message));
    true
}

// ---------------------------------------------------------------------------
// Callback adapters
// ---------------------------------------------------------------------------

struct CallbackSource {
    fetch: questdb_token_source_fn,
    release: Option<questdb_token_release_fn>,
    user_data: *mut c_void,
}

// The C contract: the callbacks and `user_data` are usable from any thread.
unsafe impl Send for CallbackSource {}
unsafe impl Sync for CallbackSource {}

impl TokenSource for CallbackSource {
    fn fetch_token(&self) -> questdb::Result<ExpiringToken> {
        let mut sink = questdb_token_sink::new();
        unsafe { (self.fetch)(self.user_data, &mut sink) };
        let (token, expires_at_ms, refresh_at_ms) = sink.take("token source")?;
        let mut result = ExpiringToken::new(token.as_str(), system_time(expires_at_ms));
        if refresh_at_ms > 0 {
            result = result.with_refresh_at(system_time(refresh_at_ms));
        }
        Ok(result)
    }
}

impl Drop for CallbackSource {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            unsafe { release(self.user_data) };
        }
    }
}

struct CallbackTarget {
    get_token: questdb_token_get_fn,
    on_rejected: Option<questdb_token_rejected_fn>,
    release: Option<questdb_token_release_fn>,
    user_data: *mut c_void,
}

unsafe impl Send for CallbackTarget {}
unsafe impl Sync for CallbackTarget {}

impl Drop for CallbackTarget {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            unsafe { release(self.user_data) };
        }
    }
}

/// An application-implemented provider. Clones share the function table.
#[derive(Clone)]
pub(crate) struct CallbackProvider(Arc<CallbackTarget>);

impl BearerTokenProvider for CallbackProvider {
    fn token(&self) -> questdb::Result<String> {
        let mut sink = questdb_token_sink::new();
        unsafe { (self.0.get_token)(self.0.user_data, &mut sink) };
        let (token, _, _) = sink.take("token provider")?;
        Ok(token.as_str().to_string())
    }

    fn on_rejected(&self, token: &str, http_status: u16) {
        if let Some(on_rejected) = self.0.on_rejected {
            unsafe {
                on_rejected(
                    self.0.user_data,
                    token.as_ptr().cast::<c_char>(),
                    token.len(),
                    http_status,
                )
            };
        }
    }
}

fn system_time(epoch_ms: i64) -> SystemTime {
    let offset = Duration::from_millis(epoch_ms.unsigned_abs());
    let t = if epoch_ms >= 0 {
        UNIX_EPOCH.checked_add(offset)
    } else {
        UNIX_EPOCH.checked_sub(offset)
    };
    t.unwrap_or(UNIX_EPOCH)
}

fn epoch_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

/// A rotating Bearer-token provider: a refreshing provider or an
/// application-implemented one. Attaching it to a client shares it; freeing
/// this handle does not affect clients it was attached to.
pub struct questdb_token_provider {
    kind: ProviderKind,
    /// One isolated-acquisition identity for every attachment of an
    /// application provider, so a blocked callback cannot take one worker per
    /// attached client.
    isolation: TokenProviderIsolation,
    creator_pid: u32,
}

#[derive(Clone)]
enum ProviderKind {
    Refreshing(RefreshingTokenProvider),
    Callbacks(CallbackProvider),
}

impl questdb_token_provider {
    fn is_inherited(&self) -> bool {
        std::process::id() != self.creator_pid
    }

    /// Attach this provider to a sender builder.
    fn attach_to_sender(
        &self,
        builder: questdb::ingress::SenderBuilder,
    ) -> questdb::Result<questdb::ingress::SenderBuilder> {
        match &self.kind {
            ProviderKind::Refreshing(provider) => builder.bearer_token_provider(provider.clone()),
            ProviderKind::Callbacks(provider) => builder
                .bearer_token_provider_with_isolation(provider.clone(), self.isolation.clone()),
        }
    }

    /// Attach this provider to a reader configuration.
    pub(crate) fn attach_to_reader(
        &self,
        config: questdb::egress::ReaderConfig,
    ) -> questdb::Result<questdb::egress::ReaderConfig> {
        match &self.kind {
            ProviderKind::Refreshing(provider) => config.token_provider(provider.clone()),
            ProviderKind::Callbacks(provider) => {
                config.token_provider_with_isolation(provider.clone(), self.isolation.clone())
            }
        }
    }

    /// Open a pool whose senders and readers share this provider.
    pub(crate) fn connect_pool(
        &self,
        conf: &str,
        handlers: questdb::ConnectHandlers,
    ) -> questdb::Result<questdb::QuestDb> {
        match &self.kind {
            ProviderKind::Refreshing(provider) => {
                questdb::QuestDb::connect_with_handlers_and_token_provider(
                    conf,
                    handlers,
                    provider.clone(),
                )
            }
            ProviderKind::Callbacks(provider) => {
                questdb::QuestDb::connect_with_handlers_and_token_provider_with_isolation(
                    conf,
                    handlers,
                    provider.clone(),
                    self.isolation.clone(),
                )
            }
        }
    }
}

fn inherited_error() -> Error {
    Error::new(
        ErrorCode::InvalidApiCall,
        "This token provider was inherited across fork and cannot be used in this \
         process; create a new provider in the child.",
    )
}

/// Borrow a provider handle for use, failing for NULL or an inherited one.
pub(crate) unsafe fn provider_ref<'a>(
    provider: *const questdb_token_provider,
    err_out: *mut *mut questdb_error,
) -> Option<&'a questdb_token_provider> {
    let Some(provider) = (unsafe { provider.as_ref() }) else {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(ErrorCode::InvalidApiCall, "token provider must not be NULL"),
            )
        };
        return None;
    };
    if provider.is_inherited() {
        unsafe { set_err_out_from_error(err_out, inherited_error()) };
        return None;
    }
    Some(provider)
}

fn new_handle(kind: ProviderKind) -> *mut questdb_token_provider {
    Box::into_raw(Box::new(questdb_token_provider {
        kind,
        isolation: TokenProviderIsolation::default(),
        creator_pid: std::process::id(),
    }))
}

/// Fill `options` with the specification's defaults. `struct_size` is the
/// caller's allocation size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_refreshing_token_provider_options_init(
    options: *mut questdb_refreshing_token_provider_options,
    struct_size: size_t,
) {
    if options.is_null() || struct_size < std::mem::size_of::<size_t>() {
        return;
    }
    let mut value = questdb_refreshing_token_provider_options::default();
    let written = struct_size.min(std::mem::size_of::<questdb_refreshing_token_provider_options>());
    value.struct_size = written;
    unsafe { write_versioned_output(options, written, &value) };
}

/// Create a refreshing provider around a C token source.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_refreshing_token_provider_new(
    source: Option<questdb_token_source_fn>,
    user_data: *mut c_void,
    release: Option<questdb_token_release_fn>,
    options: *const questdb_refreshing_token_provider_options,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_token_provider {
    let fail = |err_out: *mut *mut questdb_error, msg: String| {
        unsafe { set_err_out_from_error(err_out, Error::new(ErrorCode::InvalidApiCall, msg)) };
        ptr::null_mut()
    };
    let Some(fetch) = source else {
        return fail(
            err_out,
            "token source callback must not be NULL".to_string(),
        );
    };
    // Own `user_data` from here on: every exit releases it exactly once.
    let source = CallbackSource {
        fetch,
        release,
        user_data,
    };
    let options = if options.is_null() {
        questdb_refreshing_token_provider_options::default()
    } else {
        let size = unsafe { options.cast::<size_t>().read() };
        if size < QUESTDB_REFRESHING_TOKEN_PROVIDER_OPTIONS_V1_SIZE {
            return fail(
                err_out,
                format!(
                    "questdb_refreshing_token_provider_options.struct_size is {size}, expected \
                     at least {QUESTDB_REFRESHING_TOKEN_PROVIDER_OPTIONS_V1_SIZE}"
                ),
            );
        }
        unsafe { options.read() }
    };
    let ms = Duration::from_millis;
    let mut builder = RefreshingTokenProvider::builder(source)
        .refresh_margin(ms(options.refresh_margin_ms))
        .min_refresh_interval(ms(options.min_refresh_interval_ms))
        .handout_floor(ms(options.handout_floor_ms))
        .cold_wait(ms(options.cold_wait_ms))
        .backoff_initial(ms(options.backoff_initial_ms))
        .backoff_max(ms(options.backoff_max_ms))
        .retry_after_max(ms(options.retry_after_max_ms))
        .forced_min_interval(ms(options.forced_min_interval_ms))
        .forced_wait(ms(options.forced_wait_ms));
    if !options.name.is_null() && options.name_len > 0 {
        let bytes =
            unsafe { std::slice::from_raw_parts(options.name.cast::<u8>(), options.name_len) };
        match std::str::from_utf8(bytes) {
            Ok(name) => builder = builder.name(name),
            Err(_) => return fail(err_out, "token provider name is not UTF-8".to_string()),
        }
    }
    match builder.build() {
        Ok(provider) => new_handle(ProviderKind::Refreshing(provider)),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            ptr::null_mut()
        }
    }
}

/// Create a provider from an application-implemented function table. Once
/// the vtable is readable the provider owns `user_data`, failed calls
/// included: `release` runs once when it is no longer needed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_provider_new(
    vtable: *const questdb_token_provider_vtable,
    user_data: *mut c_void,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_token_provider {
    let invalid = |err_out: *mut *mut questdb_error, msg: String| {
        unsafe { set_err_out_from_error(err_out, Error::new(ErrorCode::InvalidApiCall, msg)) };
        ptr::null_mut()
    };
    if vtable.is_null() {
        return invalid(
            err_out,
            "token provider vtable must not be NULL".to_string(),
        );
    }
    let size = unsafe { vtable.cast::<size_t>().read() };
    if size < QUESTDB_TOKEN_PROVIDER_VTABLE_V1_SIZE {
        return invalid(
            err_out,
            format!(
                "questdb_token_provider_vtable.struct_size is {size}, expected at least \
                 {QUESTDB_TOKEN_PROVIDER_VTABLE_V1_SIZE}"
            ),
        );
    }
    let vtable = unsafe { vtable.read() };
    let Some(get_token) = vtable.get_token else {
        // The provider owns `user_data` once the vtable is readable, failed
        // calls included, like `questdb_refreshing_token_provider_new`.
        if let Some(release) = vtable.release {
            unsafe { release(user_data) };
        }
        return invalid(
            err_out,
            "token provider vtable.get_token must not be NULL".to_string(),
        );
    };
    let target = CallbackTarget {
        get_token,
        on_rejected: vtable.on_rejected,
        release: vtable.release,
        user_data,
    };
    new_handle(ProviderKind::Callbacks(CallbackProvider(Arc::new(target))))
}

/// Another handle to the same provider. NULL for NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_provider_clone(
    provider: *const questdb_token_provider,
) -> *mut questdb_token_provider {
    let Some(provider) = (unsafe { provider.as_ref() }) else {
        return ptr::null_mut();
    };
    if provider.is_inherited() {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(questdb_token_provider {
        kind: provider.kind.clone(),
        isolation: provider.isolation.clone(),
        creator_pid: provider.creator_pid,
    }))
}

/// Release this handle. Clients the provider is attached to keep using it, and
/// a refreshing provider keeps refreshing until it is closed or every handle
/// and client is gone. NULL-tolerant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_provider_free(provider: *mut questdb_token_provider) {
    if provider.is_null() {
        return;
    }
    let provider = unsafe { Box::from_raw(provider) };
    if provider.is_inherited() {
        // The parent's threads are gone in the child: dropping could block on
        // a lock one of them held, or run a release callback. Leak instead.
        std::mem::forget(provider);
    }
}

/// Close a refreshing provider: stop its refresher and fail every later token
/// request, ending every client that uses it. No-op for an
/// application-implemented provider and for NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_provider_close(provider: *const questdb_token_provider) {
    if let Some(provider) = unsafe { provider.as_ref() }
        && !provider.is_inherited()
        && let ProviderKind::Refreshing(refreshing) = &provider.kind
    {
        refreshing.close();
    }
}

/// Wait up to `timeout_ms` for a refreshing provider to hold a usable token.
/// True at once for an application-implemented provider.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_provider_await_ready(
    provider: *const questdb_token_provider,
    timeout_ms: u64,
) -> bool {
    let Some(provider) = (unsafe { provider.as_ref() }) else {
        return false;
    };
    if provider.is_inherited() {
        return false;
    }
    match &provider.kind {
        ProviderKind::Refreshing(refreshing) => {
            refreshing.await_ready(Duration::from_millis(timeout_ms))
        }
        ProviderKind::Callbacks(_) => true,
    }
}

/// An owned token, zeroized when freed.
pub struct questdb_token {
    value: Zeroizing<String>,
}

/// The provider's current token, for a client of your own (PG-wire, say). A
/// refreshing provider may wait up to its `cold_wait` for one. Returns NULL
/// and sets `*err_out` on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_provider_token(
    provider: *const questdb_token_provider,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_token {
    let Some(provider) = (unsafe { provider_ref(provider, err_out) }) else {
        return ptr::null_mut();
    };
    let result = match &provider.kind {
        ProviderKind::Refreshing(refreshing) => refreshing.token(),
        ProviderKind::Callbacks(callbacks) => callbacks.token(),
    };
    match result {
        Ok(value) => Box::into_raw(Box::new(questdb_token {
            value: Zeroizing::new(value),
        })),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            ptr::null_mut()
        }
    }
}

/// The token bytes (UTF-8, not NUL-terminated). NULL for NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_data(token: *const questdb_token) -> *const c_char {
    match unsafe { token.as_ref() } {
        Some(token) => token.value.as_ptr().cast::<c_char>(),
        None => ptr::null(),
    }
}

/// The token length in bytes. 0 for NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_len(token: *const questdb_token) -> size_t {
    match unsafe { token.as_ref() } {
        Some(token) => token.value.len(),
        None => 0,
    }
}

/// Zeroize and free a token. NULL-tolerant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_free(token: *mut questdb_token) {
    if !token.is_null() {
        drop(unsafe { Box::from_raw(token) });
    }
}

/// Tell the provider a server rejected `token` with `http_status`, for a client
/// of your own. A refreshing provider refreshes early on a 401 for its current
/// token, waiting up to its `forced_wait`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_provider_on_rejected(
    provider: *const questdb_token_provider,
    token: *const c_char,
    token_len: size_t,
    http_status: u16,
) {
    let Some(provider) = (unsafe { provider.as_ref() }) else {
        return;
    };
    if provider.is_inherited() || (token.is_null() && token_len != 0) {
        return;
    }
    let bytes = if token_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(token.cast::<u8>(), token_len) }
    };
    let Ok(token) = std::str::from_utf8(bytes) else {
        return;
    };
    match &provider.kind {
        ProviderKind::Refreshing(refreshing) => refreshing.on_rejected(token, http_status),
        ProviderKind::Callbacks(callbacks) => callbacks.on_rejected(token, http_status),
    }
}

/// Read a refreshing provider's status (spec §5.7). Initialize
/// `out->struct_size` to `sizeof *out`, and point `last_failure_msg` at a
/// buffer of `last_failure_msg_capacity` bytes to receive the last failure's
/// message (UTF-8, not NUL-terminated, truncated at a character boundary to
/// fit; `last_failure_msg_len` reports its length before truncation). Returns
/// false for NULL, an application-implemented provider, or an undersized
/// `out`, whose `struct_size` is then set to the size this library requires.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_token_provider_get_status(
    provider: *const questdb_token_provider,
    out: *mut questdb_token_provider_status,
) -> bool {
    let Some(provider) = (unsafe { provider.as_ref() }) else {
        return false;
    };
    let ProviderKind::Refreshing(refreshing) = &provider.kind else {
        return false;
    };
    let Some(capacity) =
        (unsafe { versioned_output_capacity(out, QUESTDB_TOKEN_PROVIDER_STATUS_V1_SIZE) })
    else {
        return false;
    };
    let status = if provider.is_inherited() {
        None
    } else {
        Some(refreshing.status())
    };
    let msg_buf = unsafe { (*out).last_failure_msg };
    let msg_capacity = unsafe { (*out).last_failure_msg_capacity };
    let mut value = questdb_token_provider_status {
        struct_size: capacity.min(std::mem::size_of::<questdb_token_provider_status>()),
        closed: true,
        has_last_failure: false,
        last_failure_retryable: false,
        consecutive_failures: 0,
        token_expires_at_ms: -1,
        last_success_at_ms: -1,
        last_failure_retry_after_ms: -1,
        last_failure_at_ms: -1,
        last_failure_msg: msg_buf,
        last_failure_msg_capacity: msg_capacity,
        last_failure_msg_len: 0,
    };
    if let Some(status) = status {
        value.closed = status.closed;
        value.consecutive_failures = status.consecutive_failures;
        value.token_expires_at_ms = status.token_expires_at.map_or(-1, epoch_ms);
        value.last_success_at_ms = status.last_success_at.map_or(-1, epoch_ms);
        if let Some(failure) = &status.last_failure {
            value.has_last_failure = true;
            value.last_failure_retryable = failure.retryable();
            value.last_failure_retry_after_ms = failure
                .retry_after()
                .map_or(-1, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
            value.last_failure_at_ms = epoch_ms(failure.at());
            let message = failure.message();
            value.last_failure_msg_len = message.len();
            if !msg_buf.is_null() && msg_capacity > 0 {
                let mut cut = message.len().min(msg_capacity);
                while !message.is_char_boundary(cut) {
                    cut -= 1;
                }
                unsafe { ptr::copy_nonoverlapping(message.as_ptr(), msg_buf.cast::<u8>(), cut) };
            }
        }
    }
    unsafe { write_versioned_output(out, capacity, &value) };
    true
}

/// The token-unavailable classification of `error`, when a token source or
/// provider reported one: whether retrying can succeed, and its suggested
/// wait. Returns false when the error carries none, or for an undersized
/// `out`, whose `struct_size` is then set to the size this library requires.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_error_token_unavailable_get_view(
    error: *const questdb_error,
    out: *mut questdb_token_unavailable_view,
) -> bool {
    let Some(error) = (unsafe { error.as_ref() }) else {
        return false;
    };
    let Some(capacity) =
        (unsafe { versioned_output_capacity(out, QUESTDB_TOKEN_UNAVAILABLE_VIEW_V1_SIZE) })
    else {
        return false;
    };
    let Some(classification) = error.error.as_token_unavailable() else {
        return false;
    };
    let value = questdb_token_unavailable_view {
        struct_size: capacity.min(std::mem::size_of::<questdb_token_unavailable_view>()),
        retryable: classification.retryable(),
        retry_after_ms: classification
            .retry_after()
            .map_or(-1, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)),
    };
    unsafe { write_versioned_output(out, capacity, &value) };
    true
}

/// Attach a token provider to HTTP(S) or QWP/WebSocket sender options. The
/// options keep their own reference: `provider` may be freed afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_token_provider(
    opts: *mut line_sender_opts,
    provider: *const questdb_token_provider,
    err_out: *mut *mut questdb_error,
) -> bool {
    if opts.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "line_sender_opts_token_provider requires non-NULL opts",
                ),
            )
        };
        return false;
    }
    let Some(provider) = (unsafe { provider_ref(provider, err_out) }) else {
        return false;
    };
    let current = unsafe { (*opts).0.clone() };
    match provider.attach_to_sender(current) {
        Ok(updated) => {
            unsafe { (*opts).0 = updated };
            true
        }
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::header_abi::c_struct_fields;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TOKEN_PROVIDER_H: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../include/questdb/token_provider.h"
    ));

    #[test]
    fn the_structs_match_the_header() {
        #[allow(dead_code)]
        fn exhaustive(
            options: &questdb_refreshing_token_provider_options,
            vtable: &questdb_token_provider_vtable,
            status: &questdb_token_provider_status,
            view: &questdb_token_unavailable_view,
        ) {
            let questdb_refreshing_token_provider_options {
                struct_size: _,
                name: _,
                name_len: _,
                refresh_margin_ms: _,
                min_refresh_interval_ms: _,
                handout_floor_ms: _,
                cold_wait_ms: _,
                backoff_initial_ms: _,
                backoff_max_ms: _,
                retry_after_max_ms: _,
                forced_min_interval_ms: _,
                forced_wait_ms: _,
            } = options;
            let questdb_token_provider_vtable {
                struct_size: _,
                get_token: _,
                on_rejected: _,
                release: _,
            } = vtable;
            let questdb_token_provider_status {
                struct_size: _,
                closed: _,
                has_last_failure: _,
                last_failure_retryable: _,
                consecutive_failures: _,
                token_expires_at_ms: _,
                last_success_at_ms: _,
                last_failure_retry_after_ms: _,
                last_failure_at_ms: _,
                last_failure_msg: _,
                last_failure_msg_capacity: _,
                last_failure_msg_len: _,
            } = status;
            let questdb_token_unavailable_view {
                struct_size: _,
                retryable: _,
                retry_after_ms: _,
            } = view;
        }
        assert_eq!(
            c_struct_fields(
                TOKEN_PROVIDER_H,
                "questdb_refreshing_token_provider_options"
            ),
            [
                "struct_size",
                "name",
                "name_len",
                "refresh_margin_ms",
                "min_refresh_interval_ms",
                "handout_floor_ms",
                "cold_wait_ms",
                "backoff_initial_ms",
                "backoff_max_ms",
                "retry_after_max_ms",
                "forced_min_interval_ms",
                "forced_wait_ms",
            ]
        );
        assert_eq!(
            c_struct_fields(TOKEN_PROVIDER_H, "questdb_token_provider_vtable"),
            ["struct_size", "get_token", "on_rejected", "release"]
        );
        assert_eq!(
            c_struct_fields(TOKEN_PROVIDER_H, "questdb_token_provider_status"),
            [
                "struct_size",
                "closed",
                "has_last_failure",
                "last_failure_retryable",
                "consecutive_failures",
                "token_expires_at_ms",
                "last_success_at_ms",
                "last_failure_retry_after_ms",
                "last_failure_at_ms",
                "last_failure_msg",
                "last_failure_msg_capacity",
                "last_failure_msg_len",
            ]
        );
        assert_eq!(
            c_struct_fields(TOKEN_PROVIDER_H, "questdb_token_unavailable_view"),
            ["struct_size", "retryable", "retry_after_ms"]
        );
    }

    fn now_ms() -> i64 {
        epoch_ms(SystemTime::now())
    }

    /// State shared with the C callbacks below through `user_data`.
    #[derive(Default)]
    struct Probe {
        fetches: AtomicUsize,
        released: AtomicUsize,
        rejected: std::sync::Mutex<Vec<(String, u16)>>,
        fail: bool,
    }

    unsafe extern "C" fn source(user_data: *mut c_void, sink: *mut questdb_token_sink) {
        let probe = unsafe { &*user_data.cast::<Probe>() };
        let n = probe.fetches.fetch_add(1, Ordering::SeqCst) + 1;
        if probe.fail {
            let msg = "identity not assigned";
            assert!(unsafe {
                questdb_token_sink_set_error(sink, false, 2_500, msg.as_ptr().cast(), msg.len())
            });
            return;
        }
        let token = format!("T{n}");
        assert!(unsafe {
            questdb_token_sink_set_token(
                sink,
                token.as_ptr().cast(),
                token.len(),
                now_ms() + 3_600_000,
                0,
            )
        });
        // A second report is refused.
        assert!(!unsafe { questdb_token_sink_set_token(sink, token.as_ptr().cast(), 1, 0, 0) });
    }

    unsafe extern "C" fn get_token(user_data: *mut c_void, sink: *mut questdb_token_sink) {
        let probe = unsafe { &*user_data.cast::<Probe>() };
        probe.fetches.fetch_add(1, Ordering::SeqCst);
        let token = if probe.rejected.lock().unwrap().is_empty() {
            "stale"
        } else {
            "fresh"
        };
        assert!(unsafe {
            questdb_token_sink_set_token(sink, token.as_ptr().cast(), token.len(), 0, 0)
        });
    }

    unsafe extern "C" fn on_rejected(
        user_data: *mut c_void,
        token: *const c_char,
        token_len: size_t,
        http_status: u16,
    ) {
        let probe = unsafe { &*user_data.cast::<Probe>() };
        let token = unsafe { std::slice::from_raw_parts(token.cast::<u8>(), token_len) };
        probe
            .rejected
            .lock()
            .unwrap()
            .push((String::from_utf8(token.to_vec()).unwrap(), http_status));
    }

    unsafe extern "C" fn release(user_data: *mut c_void) {
        let probe = unsafe { &*user_data.cast::<Probe>() };
        probe.released.fetch_add(1, Ordering::SeqCst);
    }

    fn token_text(token: *mut questdb_token) -> String {
        assert!(!token.is_null());
        let bytes = unsafe {
            std::slice::from_raw_parts(
                questdb_token_data(token).cast::<u8>(),
                questdb_token_len(token),
            )
        };
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        unsafe { questdb_token_free(token) };
        text
    }

    fn await_count(counter: &AtomicUsize, expected: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while counter.load(Ordering::SeqCst) != expected {
            assert!(std::time::Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn a_refreshing_provider_serves_its_sources_token_and_releases_it_once() {
        let probe = Box::leak(Box::new(Probe::default()));
        let user_data = ptr::from_mut(probe).cast::<c_void>();
        let mut options =
            unsafe { std::mem::zeroed::<questdb_refreshing_token_provider_options>() };
        unsafe {
            questdb_refreshing_token_provider_options_init(&mut options, size_of_val(&options))
        };
        assert_eq!(options.cold_wait_ms, 30_000);
        assert_eq!(options.handout_floor_ms, 60_000);
        let name = "c-test";
        options.name = name.as_ptr().cast();
        options.name_len = name.len();
        let mut err: *mut questdb_error = ptr::null_mut();
        let provider = unsafe {
            questdb_refreshing_token_provider_new(
                Some(source),
                user_data,
                Some(release),
                &options,
                &mut err,
            )
        };
        assert!(!provider.is_null() && err.is_null());
        assert!(unsafe { questdb_token_provider_await_ready(provider, 10_000) });
        let token = unsafe { questdb_token_provider_token(provider, &mut err) };
        assert_eq!(token_text(token), "T1");

        let mut status = unsafe { std::mem::zeroed::<questdb_token_provider_status>() };
        status.struct_size = size_of_val(&status);
        assert!(unsafe { questdb_token_provider_get_status(provider, &mut status) });
        assert!(!status.closed && !status.has_last_failure);
        assert!(status.token_expires_at_ms > now_ms());

        // A clone keeps the provider alive after the original handle is freed.
        let clone = unsafe { questdb_token_provider_clone(provider) };
        unsafe { questdb_token_provider_free(provider) };
        let token = unsafe { questdb_token_provider_token(clone, &mut err) };
        assert_eq!(token_text(token), "T1");
        assert_eq!(probe.released.load(Ordering::SeqCst), 0);
        unsafe { questdb_token_provider_free(clone) };
        // The refresher drops the source, releasing user_data, once.
        await_count(&probe.released, 1);
    }

    #[test]
    fn a_refreshing_providers_failure_carries_its_classification() {
        let probe = Box::leak(Box::new(Probe {
            fail: true,
            ..Probe::default()
        }));
        let mut options =
            unsafe { std::mem::zeroed::<questdb_refreshing_token_provider_options>() };
        unsafe {
            questdb_refreshing_token_provider_options_init(&mut options, size_of_val(&options))
        };
        options.cold_wait_ms = 50;
        let mut err: *mut questdb_error = ptr::null_mut();
        let provider = unsafe {
            questdb_refreshing_token_provider_new(
                Some(source),
                ptr::from_mut(probe).cast(),
                None,
                &options,
                &mut err,
            )
        };
        assert!(!provider.is_null());
        await_count(&probe.fetches, 1);
        let token = unsafe { questdb_token_provider_token(provider, &mut err) };
        assert!(token.is_null() && !err.is_null());
        let mut view = unsafe { std::mem::zeroed::<questdb_token_unavailable_view>() };
        view.struct_size = size_of_val(&view);
        assert!(unsafe { questdb_error_token_unavailable_get_view(err, &mut view) });
        assert!(!view.retryable);
        assert!(view.retry_after_ms > 0);
        unsafe { crate::questdb_error_free(err) };

        let mut buffer = [0u8; 8];
        let mut status = unsafe { std::mem::zeroed::<questdb_token_provider_status>() };
        status.struct_size = size_of_val(&status);
        status.last_failure_msg = buffer.as_mut_ptr().cast();
        status.last_failure_msg_capacity = buffer.len();
        assert!(unsafe { questdb_token_provider_get_status(provider, &mut status) });
        assert!(status.has_last_failure && !status.last_failure_retryable);
        assert_eq!(status.last_failure_msg_len, "identity not assigned".len());
        assert_eq!(&buffer, b"identity");

        unsafe { questdb_token_provider_close(provider) };
        assert!(!unsafe { questdb_token_provider_await_ready(provider, 100) });
        unsafe { questdb_token_provider_free(provider) };
    }

    #[test]
    fn an_application_provider_hears_rejections_and_is_released_once() {
        let probe = Box::leak(Box::new(Probe::default()));
        let vtable = questdb_token_provider_vtable {
            struct_size: size_of::<questdb_token_provider_vtable>(),
            get_token: Some(get_token),
            on_rejected: Some(on_rejected),
            release: Some(release),
        };
        let mut err: *mut questdb_error = ptr::null_mut();
        let provider =
            unsafe { questdb_token_provider_new(&vtable, ptr::from_mut(probe).cast(), &mut err) };
        assert!(!provider.is_null());
        let token = unsafe { questdb_token_provider_token(provider, &mut err) };
        assert_eq!(token_text(token), "stale");
        unsafe { questdb_token_provider_on_rejected(provider, "stale".as_ptr().cast(), 5, 401) };
        let token = unsafe { questdb_token_provider_token(provider, &mut err) };
        assert_eq!(token_text(token), "fresh");
        assert_eq!(
            *probe.rejected.lock().unwrap(),
            vec![("stale".to_string(), 401)]
        );
        // Not a refreshing provider: no status, and await_ready is immediate.
        let mut status = unsafe { std::mem::zeroed::<questdb_token_provider_status>() };
        status.struct_size = size_of_val(&status);
        assert!(!unsafe { questdb_token_provider_get_status(provider, &mut status) });
        assert!(unsafe { questdb_token_provider_await_ready(provider, 0) });
        unsafe { questdb_token_provider_free(provider) };
        assert_eq!(probe.released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn invalid_arguments_are_rejected() {
        let mut err: *mut questdb_error = ptr::null_mut();
        let provider = unsafe {
            questdb_refreshing_token_provider_new(
                None,
                ptr::null_mut(),
                None,
                ptr::null(),
                &mut err,
            )
        };
        assert!(provider.is_null() && !err.is_null());
        unsafe { crate::questdb_error_free(err) };
        err = ptr::null_mut();
        let vtable = questdb_token_provider_vtable {
            struct_size: size_of::<questdb_token_provider_vtable>(),
            get_token: None,
            on_rejected: None,
            release: None,
        };
        let provider = unsafe { questdb_token_provider_new(&vtable, ptr::null_mut(), &mut err) };
        assert!(provider.is_null() && !err.is_null());
        unsafe { crate::questdb_error_free(err) };
        assert!(unsafe { questdb_token_provider_clone(ptr::null()) }.is_null());
        unsafe { questdb_token_provider_free(ptr::null_mut()) };
        assert!(!unsafe { questdb_token_sink_set_token(ptr::null_mut(), ptr::null(), 0, 0, 0) });
    }

    #[test]
    fn a_provider_attaches_to_http_and_websocket_options_only() {
        let probe = Box::leak(Box::new(Probe::default()));
        let vtable = questdb_token_provider_vtable {
            struct_size: size_of::<questdb_token_provider_vtable>(),
            get_token: Some(get_token),
            on_rejected: None,
            release: None,
        };
        let mut err: *mut questdb_error = ptr::null_mut();
        let provider =
            unsafe { questdb_token_provider_new(&vtable, ptr::from_mut(probe).cast(), &mut err) };
        for (conf, accepted) in [
            ("http::addr=localhost:9000;", true),
            ("ws::addr=localhost:9000;", true),
            ("tcp::addr=localhost:9009;", false),
            ("ws::addr=localhost:9000;token=static;", false),
        ] {
            let utf8 = unsafe { crate::line_sender_utf8_assert(conf.len(), conf.as_ptr().cast()) };
            let opts = unsafe { crate::line_sender_opts_from_conf(utf8, &mut err) };
            assert!(!opts.is_null(), "{conf}");
            let attached = unsafe { line_sender_opts_token_provider(opts, provider, &mut err) };
            assert_eq!(attached, accepted, "{conf}");
            if !attached {
                assert!(!err.is_null());
                unsafe { crate::questdb_error_free(err) };
                err = ptr::null_mut();
            }
            unsafe { crate::line_sender_opts_free(opts) };
        }
        unsafe { questdb_token_provider_free(provider) };
    }
}
