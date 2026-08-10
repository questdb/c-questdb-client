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

//! C ABI for the OIDC device authorization flow.
//!
//! The ABI owns opaque `Arc<OidcDeviceAuth>` handles so one authentication
//! state can safely feed sender, reader, and pooled connections. All input
//! pointers are validated before allocation or Rust string construction: the
//! enclosing FFI crate ships with `panic = "abort"`.

use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::str;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use libc::{c_char, c_void, size_t};
use questdb::oidc::{
    DeviceCodeChallenge, FileTokenStore, OidcDeviceAuth, OidcErrorKind, Renderer,
    sanitize_display_text,
};
use questdb::{Error, ErrorCode};
use zeroize::Zeroizing;

use crate::{line_sender_error, line_sender_opts, questdb_error, set_err_out_from_error};

/// Hard cap for every caller-provided OIDC string. Real endpoint URLs, scopes,
/// and filesystem paths are tiny; the cap prevents an attacker-controlled C
/// length from becoming an abort-on-OOM allocation in this `panic = "abort"`
/// crate.
const MAX_OIDC_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
enum BuilderSource {
    Explicit,
    QuestDb(String),
}

#[derive(Clone)]
enum FileStoreConfig {
    None,
    Directory(PathBuf),
    DefaultLocation,
}

#[derive(Clone)]
struct OidcBuilderConfig {
    source: BuilderSource,
    client_id: Option<String>,
    scope: Option<String>,
    audience: Option<String>,
    groups_in_token: Option<bool>,
    issuer: Option<String>,
    token_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
    allow_insecure_transport: bool,
    ca_bundle: Option<PathBuf>,
    open_browser: Option<bool>,
    interactive: Option<bool>,
    default_interval: Option<u64>,
    timeout_ms: Option<u64>,
    renderer: Option<Arc<CEventHandler>>,
    file_store: FileStoreConfig,
}

impl OidcBuilderConfig {
    fn new(source: BuilderSource) -> Self {
        Self {
            source,
            client_id: None,
            scope: None,
            audience: None,
            groups_in_token: None,
            issuer: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            allow_insecure_transport: false,
            ca_bundle: None,
            open_browser: None,
            interactive: None,
            default_interval: None,
            timeout_ms: None,
            renderer: None,
            file_store: FileStoreConfig::None,
        }
    }

    fn build(&self) -> Result<OidcDeviceAuth, Error> {
        let mut builder = match &self.source {
            BuilderSource::Explicit => OidcDeviceAuth::builder(),
            BuilderSource::QuestDb(url) => OidcDeviceAuth::from_questdb(url.clone()),
        };
        if let Some(value) = &self.client_id {
            builder = builder.client_id(value.clone());
        }
        if let Some(value) = &self.scope {
            builder = builder.scope(value.clone());
        }
        if let Some(value) = &self.audience {
            builder = builder.audience(value.clone());
        }
        if let Some(value) = self.groups_in_token {
            builder = builder.groups_in_token(value);
        }
        if let Some(value) = &self.issuer {
            builder = builder.issuer(value.clone());
        }
        if let Some(value) = &self.token_endpoint {
            builder = builder.token_endpoint(value.clone());
        }
        if let Some(value) = &self.device_authorization_endpoint {
            builder = builder.device_authorization_endpoint(value.clone());
        }
        builder = builder.allow_insecure_transport(self.allow_insecure_transport);
        if let Some(value) = &self.ca_bundle {
            builder = builder.ca_bundle(value.clone());
        }
        if let Some(value) = self.open_browser {
            builder = builder.open_browser(value);
        }
        if let Some(value) = self.interactive {
            builder = builder.interactive(value);
        }
        if let Some(value) = self.default_interval {
            builder = builder.default_interval(value);
        }
        if let Some(value) = self.timeout_ms {
            builder = builder.timeout(Duration::from_millis(value));
        }
        if let Some(renderer) = &self.renderer {
            builder = builder.renderer(CEventRenderer(Arc::clone(renderer)));
        }
        match &self.file_store {
            FileStoreConfig::None => {}
            FileStoreConfig::Directory(directory) => {
                builder = builder.token_store(FileTokenStore::at(directory.clone()));
            }
            FileStoreConfig::DefaultLocation => {
                let store = FileTokenStore::at_default_location().map_err(|err| {
                    Error::new(
                        ErrorCode::ConfigError,
                        format!("Could not resolve the default OIDC token-store directory: {err}"),
                    )
                })?;
                builder = builder.token_store(store);
            }
        }
        builder.build().map_err(Into::into)
    }
}

/// Reusable OIDC builder. Its Rust builder is reconstructed from this cloneable
/// configuration for each build, so a failed build does not consume the C
/// handle and one configuration can build multiple independent auth states.
pub struct questdb_oidc_builder {
    config: OidcBuilderConfig,
}

/// Thread-safe OIDC authentication state. Transport attachment clones the Arc;
/// freeing this C handle does not invalidate already-configured clients.
pub struct questdb_oidc_auth {
    shared: SharedOidcAuth,
}

/// The Rust auth state plus the C callback identity installed on it.
///
/// Transport providers retain this complete value so a token request made
/// indirectly by a sender, reader, or pool observes the same callback
/// reentrancy guard as the direct C auth functions.
#[derive(Clone)]
pub(crate) struct SharedOidcAuth {
    inner: Arc<OidcDeviceAuth>,
    event_handler: Option<Arc<CEventHandler>>,
}

impl SharedOidcAuth {
    fn reject_callback_reentry(&self) -> Result<(), Error> {
        if self
            .event_handler
            .as_deref()
            .is_some_and(CEventHandler::is_active)
        {
            return Err(Error::new(
                ErrorCode::InvalidApiCall,
                "OIDC authentication cannot be re-entered from its event callback; return from \
                 the callback before calling sign_in, token, clear, or an attached transport"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn sign_in(&self) -> Result<(), Error> {
        self.reject_callback_reentry()?;
        self.inner.sign_in().map_err(Into::into)
    }

    pub(crate) fn token(&self) -> Result<String, Error> {
        self.reject_callback_reentry()?;
        // OidcDeviceAuth::token is deliberately non-interactive. Every attached
        // transport shares this path, so flush/connect/reconnect can refresh
        // silently but can never start a device-flow prompt.
        self.inner.token().map_err(Into::into)
    }

    fn clear(&self) -> Result<(), Error> {
        self.reject_callback_reentry()?;
        self.inner.try_clear().map_err(Into::into)
    }
}

/// Owned token copy. `Zeroizing` overwrites its allocation when released.
pub struct questdb_oidc_token {
    value: Zeroizing<String>,
}

/// Device-flow renderer event kind.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum questdb_oidc_event_kind {
    QUESTDB_OIDC_EVENT_PROMPT = 0,
    QUESTDB_OIDC_EVENT_WAITING = 1,
    QUESTDB_OIDC_EVENT_SUCCESS = 2,
    QUESTDB_OIDC_EVENT_FAILURE = 3,
}

/// Borrowed event view. Every string is valid only for the callback duration.
#[repr(C)]
pub struct questdb_oidc_event {
    pub struct_size: size_t,
    pub kind: questdb_oidc_event_kind,
    pub user_code: *const c_char,
    pub user_code_len: size_t,
    pub verification_uri: *const c_char,
    pub verification_uri_len: size_t,
    pub verification_uri_complete: *const c_char,
    pub verification_uri_complete_len: size_t,
    pub identity: *const c_char,
    pub identity_len: size_t,
    pub message: *const c_char,
    pub message_len: size_t,
    pub seconds_left: f64,
    pub expires_in_seconds: f64,
    pub browser_target: *const c_char,
    pub browser_target_len: size_t,
}

pub type questdb_oidc_event_cb =
    Option<unsafe extern "C" fn(user_data: *mut c_void, event: *const questdb_oidc_event)>;
/// Releases callback state after its final owner is dropped. It may run on any
/// thread and must return normally without unwinding or performing a non-local
/// jump (for example, C `longjmp`) across the Rust FFI frame.
pub type questdb_oidc_user_data_release_cb = Option<unsafe extern "C" fn(user_data: *mut c_void)>;

struct CEventHandler {
    callback: unsafe extern "C" fn(*mut c_void, *const questdb_oidc_event),
    user_data: usize,
    release: questdb_oidc_user_data_release_cb,
    /// One handler is shared by every auth built from a reusable builder.
    /// Serialize those sibling auths before entering caller-owned state.
    callback_gate: std::sync::Mutex<()>,
    /// Callback reentry can arrive from a different thread, so this state must
    /// be shared with every auth that uses the handler rather than thread-local.
    active: AtomicBool,
}

struct ActiveEventHandler<'a> {
    handler: &'a CEventHandler,
}

impl<'a> ActiveEventHandler<'a> {
    fn enter(handler: &'a CEventHandler) -> Self {
        let was_active = handler.active.swap(true, Ordering::AcqRel);
        debug_assert!(!was_active, "callback gate must serialize handler entry");
        Self { handler }
    }
}

impl Drop for ActiveEventHandler<'_> {
    fn drop(&mut self) {
        let was_active = self.handler.active.swap(false, Ordering::AcqRel);
        debug_assert!(was_active, "active callback guard must be balanced");
    }
}

impl CEventHandler {
    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

impl Drop for CEventHandler {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            // SAFETY: registration transfers ownership of `user_data` and
            // requires `release` to return normally across this FFI boundary.
            unsafe { release(self.user_data as *mut c_void) };
        }
    }
}

#[derive(Clone)]
struct CEventRenderer(Arc<CEventHandler>);

impl CEventRenderer {
    fn invoke(&self, event: &questdb_oidc_event) {
        let _serialized = self
            .0
            .callback_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _active = ActiveEventHandler::enter(&self.0);
        unsafe { (self.0.callback)(self.0.user_data as *mut c_void, event) };
    }
}

impl Renderer for CEventRenderer {
    fn on_prompt(&self, challenge: &DeviceCodeChallenge) {
        // Never expose the raw IdP response through a presentation callback.
        // Display fields are inert single-line ASCII; the independently vetted
        // browser target is the only URL consumers may make clickable or open.
        let display_user_code = challenge.display_user_code();
        let display_verification_uri = challenge.display_verification_uri();
        let display_verification_uri_complete = challenge.display_verification_uri_complete();
        let browser_target_value = challenge.browser_target();
        let (user_code, user_code_len) = str_or_null(Some(&display_user_code));
        let (verification_uri, verification_uri_len) = str_or_null(Some(&display_verification_uri));
        let (verification_uri_complete, verification_uri_complete_len) =
            str_or_null(display_verification_uri_complete.as_deref());
        let (browser_target, browser_target_len) = str_or_null(browser_target_value.as_deref());
        self.invoke(&questdb_oidc_event {
            struct_size: std::mem::size_of::<questdb_oidc_event>(),
            kind: questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_PROMPT,
            user_code,
            user_code_len,
            verification_uri,
            verification_uri_len,
            verification_uri_complete,
            verification_uri_complete_len,
            identity: ptr::null(),
            identity_len: 0,
            message: ptr::null(),
            message_len: 0,
            seconds_left: 0.0,
            expires_in_seconds: 0.0,
            browser_target,
            browser_target_len,
        });
    }

    fn on_waiting(&self, seconds_left: f64) {
        let mut event = empty_event(questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING);
        event.seconds_left = seconds_left;
        self.invoke(&event);
    }

    fn on_success(&self, identity: Option<&str>, expires_in_secs: f64) {
        let mut event = empty_event(questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_SUCCESS);
        let display_identity = identity.map(sanitize_display_text);
        (event.identity, event.identity_len) = str_or_null(display_identity.as_deref());
        event.expires_in_seconds = expires_in_secs;
        self.invoke(&event);
    }

    fn on_failure(&self, message: &str) {
        let mut event = empty_event(questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_FAILURE);
        let display_message = sanitize_display_text(message);
        (event.message, event.message_len) = str_or_null(Some(&display_message));
        self.invoke(&event);
    }
}

fn empty_event(kind: questdb_oidc_event_kind) -> questdb_oidc_event {
    questdb_oidc_event {
        struct_size: std::mem::size_of::<questdb_oidc_event>(),
        kind,
        user_code: ptr::null(),
        user_code_len: 0,
        verification_uri: ptr::null(),
        verification_uri_len: 0,
        verification_uri_complete: ptr::null(),
        verification_uri_complete_len: 0,
        identity: ptr::null(),
        identity_len: 0,
        message: ptr::null(),
        message_len: 0,
        seconds_left: 0.0,
        expires_in_seconds: 0.0,
        browser_target: ptr::null(),
        browser_target_len: 0,
    }
}

/// Return a borrowed pointer-plus-length span. Non-NULL data is not
/// NUL-terminated and callers must use the returned length.
fn str_or_null(value: Option<&str>) -> (*const c_char, size_t) {
    value.map_or((ptr::null(), 0), |value| {
        (value.as_ptr() as *const c_char, value.len())
    })
}

unsafe fn set_input_error(
    err_out: *mut *mut questdb_error,
    code: ErrorCode,
    message: impl Into<String>,
) {
    unsafe { set_err_out_from_error(err_out, Error::new(code, message.into())) };
}

unsafe fn input_str<'a>(
    input: *const c_char,
    input_len: size_t,
    label: &str,
    err_out: *mut *mut questdb_error,
) -> Option<&'a str> {
    if input.is_null() && input_len != 0 {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{label} pointer is NULL with non-zero length"),
            )
        };
        return None;
    }
    if input_len > MAX_OIDC_INPUT_BYTES {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                format!(
                    "{label} length {input_len} exceeds the OIDC input cap of {MAX_OIDC_INPUT_BYTES} bytes"
                ),
            )
        };
        return None;
    }
    let bytes = if input_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(input as *const u8, input_len) }
    };
    match str::from_utf8(bytes) {
        Ok(value) => Some(value),
        Err(_) => {
            unsafe {
                set_input_error(
                    err_out,
                    ErrorCode::InvalidUtf8,
                    format!("{label} is not valid UTF-8"),
                )
            };
            None
        }
    }
}

unsafe fn builder_mut<'a>(
    builder: *mut questdb_oidc_builder,
    err_out: *mut *mut questdb_error,
) -> Option<&'a mut questdb_oidc_builder> {
    if builder.is_null() {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                "OIDC builder pointer is NULL",
            )
        };
        None
    } else {
        Some(unsafe { &mut *builder })
    }
}

pub(crate) unsafe fn clone_auth(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> Option<SharedOidcAuth> {
    if auth.is_null() {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                "OIDC auth pointer is NULL",
            )
        };
        None
    } else {
        Some(unsafe { (*auth).shared.clone() })
    }
}

/// Create an explicit OIDC builder. The caller must set client id, token
/// endpoint, and device-authorization endpoint before building.
#[unsafe(no_mangle)]
pub extern "C" fn questdb_oidc_builder_new() -> *mut questdb_oidc_builder {
    Box::into_raw(Box::new(questdb_oidc_builder {
        config: OidcBuilderConfig::new(BuilderSource::Explicit),
    }))
}

/// Create a builder that discovers OIDC configuration from QuestDB `/settings`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_from_questdb(
    url: *const c_char,
    url_len: size_t,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_oidc_builder {
    let Some(url) = (unsafe { input_str(url, url_len, "QuestDB URL", err_out) }) else {
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(questdb_oidc_builder {
        config: OidcBuilderConfig::new(BuilderSource::QuestDb(url.to_owned())),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_free(builder: *mut questdb_oidc_builder) {
    if !builder.is_null() {
        unsafe { drop(Box::from_raw(builder)) };
    }
}

macro_rules! string_setter {
    ($name:ident, $field:ident, $label:literal) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            builder: *mut questdb_oidc_builder,
            value: *const c_char,
            value_len: size_t,
            err_out: *mut *mut questdb_error,
        ) -> bool {
            let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
                return false;
            };
            let Some(value) = (unsafe { input_str(value, value_len, $label, err_out) }) else {
                return false;
            };
            builder.config.$field = Some(value.to_owned());
            true
        }
    };
}

string_setter!(questdb_oidc_builder_client_id, client_id, "OIDC client id");
string_setter!(questdb_oidc_builder_scope, scope, "OIDC scope");
string_setter!(questdb_oidc_builder_audience, audience, "OIDC audience");
string_setter!(questdb_oidc_builder_issuer, issuer, "OIDC issuer");
string_setter!(
    questdb_oidc_builder_token_endpoint,
    token_endpoint,
    "OIDC token endpoint"
);
string_setter!(
    questdb_oidc_builder_device_authorization_endpoint,
    device_authorization_endpoint,
    "OIDC device-authorization endpoint"
);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_groups_in_token(
    builder: *mut questdb_oidc_builder,
    enabled: bool,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.groups_in_token = Some(enabled);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_allow_insecure_transport(
    builder: *mut questdb_oidc_builder,
    enabled: bool,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.allow_insecure_transport = enabled;
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_open_browser(
    builder: *mut questdb_oidc_builder,
    enabled: bool,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.open_browser = Some(enabled);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_interactive(
    builder: *mut questdb_oidc_builder,
    enabled: bool,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.interactive = Some(enabled);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_default_interval_seconds(
    builder: *mut questdb_oidc_builder,
    seconds: u64,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.default_interval = Some(seconds);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_timeout_ms(
    builder: *mut questdb_oidc_builder,
    timeout_ms: u64,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.timeout_ms = Some(timeout_ms);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_ca_bundle(
    builder: *mut questdb_oidc_builder,
    path: *const c_char,
    path_len: size_t,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    let Some(path) = (unsafe { input_str(path, path_len, "OIDC CA-bundle path", err_out) }) else {
        return false;
    };
    builder.config.ca_bundle = Some(PathBuf::from(path));
    true
}

/// Explicitly enable plaintext token persistence in `directory`.
///
/// Access, ID, and long-lived refresh tokens are stored as unencrypted JSON.
/// Unix uses owner-only file/directory modes; other platforms depend on the
/// directory's default ACL. Without this opt-in, credentials remain in memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_file_token_store(
    builder: *mut questdb_oidc_builder,
    directory: *const c_char,
    directory_len: size_t,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    let Some(directory) = (unsafe {
        input_str(
            directory,
            directory_len,
            "OIDC token-store directory",
            err_out,
        )
    }) else {
        return false;
    };
    builder.config.file_store = FileStoreConfig::Directory(PathBuf::from(directory));
    true
}

/// Explicitly enable plaintext token persistence at the configured default
/// location. Access, ID, and long-lived refresh tokens are stored as
/// unencrypted JSON; see the public C header for the platform security contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_default_file_token_store(
    builder: *mut questdb_oidc_builder,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.file_store = FileStoreConfig::DefaultLocation;
    true
}

/// Install a renderer callback. `user_data` ownership transfers to the builder
/// and is released exactly once through `release` after the builder and every
/// auth object/transport built from it have dropped their last reference. The
/// callback may run on any token-acquisition thread, is serialized with its
/// sibling invocations, and must not unwind. Auth reentry from the callback is
/// rejected before reaching the core acquisition mutex. Final `release` has no
/// thread-affinity guarantee and must return normally without unwinding or
/// performing a non-local jump across the Rust FFI frame.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_event_handler(
    builder: *mut questdb_oidc_builder,
    callback: questdb_oidc_event_cb,
    user_data: *mut c_void,
    release: questdb_oidc_user_data_release_cb,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    let Some(callback) = callback else {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                "OIDC event callback is NULL",
            )
        };
        return false;
    };
    builder.config.renderer = Some(Arc::new(CEventHandler {
        callback,
        user_data: user_data as usize,
        release,
        callback_gate: std::sync::Mutex::new(()),
        active: AtomicBool::new(false),
    }));
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_build(
    builder: *const questdb_oidc_builder,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_oidc_auth {
    if builder.is_null() {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                "OIDC builder pointer is NULL",
            )
        };
        return ptr::null_mut();
    }
    let config = unsafe { &(*builder).config };
    let event_handler = config.renderer.clone();
    match config.build() {
        Ok(auth) => Box::into_raw(Box::new(questdb_oidc_auth {
            shared: SharedOidcAuth {
                inner: Arc::new(auth),
                event_handler,
            },
        })),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_clone(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_oidc_auth {
    let Some(shared) = (unsafe { clone_auth(auth, err_out) }) else {
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(questdb_oidc_auth { shared }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_free(auth: *mut questdb_oidc_auth) {
    if !auth.is_null() {
        unsafe { drop(Box::from_raw(auth)) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_sign_in(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(auth) = (unsafe { clone_auth(auth, err_out) }) else {
        return false;
    };
    match auth.sign_in() {
        Ok(()) => true,
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_token(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_oidc_token {
    let Some(auth) = (unsafe { clone_auth(auth, err_out) }) else {
        return ptr::null_mut();
    };
    match auth.token() {
        Ok(value) => Box::into_raw(Box::new(questdb_oidc_token {
            value: Zeroizing::new(value),
        })),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            ptr::null_mut()
        }
    }
}

/// Clear in-memory credentials and delete any persisted local entry.
///
/// Memory is cleared even if deletion fails. Such a failure is returned because
/// a new auth object or process may still load the persisted credential. This
/// does not revoke tokens at the identity provider.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_clear(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(auth) = (unsafe { clone_auth(auth, err_out) }) else {
        return false;
    };
    match auth.clear() {
        Ok(()) => true,
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_token_data(
    token: *const questdb_oidc_token,
) -> *const c_char {
    if token.is_null() {
        return ptr::null();
    }
    unsafe { (*token).value.as_ptr() as *const c_char }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_token_len(token: *const questdb_oidc_token) -> size_t {
    if token.is_null() {
        return 0;
    }
    let token = unsafe { &*token };
    token.value.len()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_token_free(token: *mut questdb_oidc_token) {
    if !token.is_null() {
        unsafe { drop(Box::from_raw(token)) };
    }
}

/// Resolved OIDC configuration. Strings borrow from the auth handle.
#[repr(C)]
pub struct questdb_oidc_config_view {
    pub struct_size: size_t,
    pub groups_in_token: bool,
    pub client_id: *const c_char,
    pub client_id_len: size_t,
    pub token_endpoint: *const c_char,
    pub token_endpoint_len: size_t,
    pub device_authorization_endpoint: *const c_char,
    pub device_authorization_endpoint_len: size_t,
    pub scope: *const c_char,
    pub scope_len: size_t,
    pub audience: *const c_char,
    pub audience_len: size_t,
    pub issuer: *const c_char,
    pub issuer_len: size_t,
}

// Pin the initial output layouts independently of future appended fields.
// Both v1 structs deliberately end in a naturally aligned integer so adding a
// field cannot hide inside trailing padding without increasing struct_size.
const QUESTDB_OIDC_CONFIG_VIEW_V1_SIZE: usize =
    std::mem::offset_of!(questdb_oidc_config_view, issuer_len) + std::mem::size_of::<size_t>();

unsafe fn versioned_output_capacity<T>(out: *mut T, minimum_size: usize) -> Option<usize> {
    if out.is_null() {
        return None;
    }
    let capacity = unsafe { out.cast::<size_t>().read() };
    if capacity < minimum_size {
        // The pointer contract requires storage for at least struct_size even
        // when its value is invalid, so report the required v1 capacity there.
        unsafe { out.cast::<size_t>().write(minimum_size) };
        return None;
    }
    Some(capacity)
}

unsafe fn write_versioned_output<T>(out: *mut T, capacity: usize, value: &T) {
    unsafe {
        std::ptr::copy_nonoverlapping(
            (value as *const T).cast::<u8>(),
            out.cast::<u8>(),
            capacity.min(std::mem::size_of::<T>()),
        )
    };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_get_config(
    auth: *const questdb_oidc_auth,
    out: *mut questdb_oidc_config_view,
) -> bool {
    if auth.is_null() {
        return false;
    }
    let Some(capacity) =
        (unsafe { versioned_output_capacity(out, QUESTDB_OIDC_CONFIG_VIEW_V1_SIZE) })
    else {
        return false;
    };
    let config = unsafe { (*auth).shared.inner.config() };
    let (client_id, client_id_len) = str_or_null(Some(&config.client_id));
    let (token_endpoint, token_endpoint_len) = str_or_null(Some(&config.token_endpoint));
    let (device_authorization_endpoint, device_authorization_endpoint_len) =
        str_or_null(Some(&config.device_authorization_endpoint));
    let (scope, scope_len) = str_or_null(Some(&config.scope));
    let (audience, audience_len) = str_or_null(config.audience.as_deref());
    let (issuer, issuer_len) = str_or_null(config.issuer.as_deref());
    let written_size = capacity.min(std::mem::size_of::<questdb_oidc_config_view>());
    let mut value = unsafe { std::mem::zeroed::<questdb_oidc_config_view>() };
    value.struct_size = written_size;
    value.groups_in_token = config.groups_in_token;
    value.client_id = client_id;
    value.client_id_len = client_id_len;
    value.token_endpoint = token_endpoint;
    value.token_endpoint_len = token_endpoint_len;
    value.device_authorization_endpoint = device_authorization_endpoint;
    value.device_authorization_endpoint_len = device_authorization_endpoint_len;
    value.scope = scope;
    value.scope_len = scope_len;
    value.audience = audience;
    value.audience_len = audience_len;
    value.issuer = issuer;
    value.issuer_len = issuer_len;
    unsafe { write_versioned_output(out, capacity, &value) };
    true
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum questdb_oidc_error_kind {
    QUESTDB_OIDC_ERROR_CONFIG = 0,
    QUESTDB_OIDC_ERROR_NETWORK = 1,
    QUESTDB_OIDC_ERROR_DEVICE_FLOW = 2,
    QUESTDB_OIDC_ERROR_TIMEOUT = 3,
    QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED = 4,
    QUESTDB_OIDC_ERROR_UNKNOWN = 255,
}

#[repr(C)]
pub struct questdb_oidc_error_view {
    pub struct_size: size_t,
    pub kind: questdb_oidc_error_kind,
    pub idp_error: *const c_char,
    pub idp_error_len: size_t,
    pub idp_error_description: *const c_char,
    pub idp_error_description_len: size_t,
    pub has_status: bool,
    pub status: u16,
    pub has_retry_after: bool,
    pub retry_after_seconds: u64,
}

const QUESTDB_OIDC_ERROR_VIEW_V1_SIZE: usize =
    std::mem::offset_of!(questdb_oidc_error_view, retry_after_seconds) + std::mem::size_of::<u64>();

fn error_kind(kind: OidcErrorKind) -> questdb_oidc_error_kind {
    match kind {
        OidcErrorKind::Config => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_CONFIG,
        OidcErrorKind::Network => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_NETWORK,
        OidcErrorKind::DeviceFlow => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_DEVICE_FLOW,
        OidcErrorKind::Timeout => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_TIMEOUT,
        OidcErrorKind::InteractionRequired => {
            questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED
        }
        _ => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_UNKNOWN,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_error_oidc_get_view(
    error: *const questdb_error,
    out: *mut questdb_oidc_error_view,
) -> bool {
    if error.is_null() {
        return false;
    }
    let Some(capacity) =
        (unsafe { versioned_output_capacity(out, QUESTDB_OIDC_ERROR_VIEW_V1_SIZE) })
    else {
        return false;
    };
    let Some(oidc) = (unsafe { (*error).error.oidc_error() }) else {
        return false;
    };
    let (idp_error, idp_error_len) = str_or_null(oidc.idp_error());
    let (idp_error_description, idp_error_description_len) =
        str_or_null(oidc.idp_error_description());
    let status = oidc.status();
    let retry_after = oidc.retry_after_secs();
    let written_size = capacity.min(std::mem::size_of::<questdb_oidc_error_view>());
    let mut value = unsafe { std::mem::zeroed::<questdb_oidc_error_view>() };
    value.struct_size = written_size;
    value.kind = error_kind(oidc.kind());
    value.idp_error = idp_error;
    value.idp_error_len = idp_error_len;
    value.idp_error_description = idp_error_description;
    value.idp_error_description_len = idp_error_description_len;
    value.has_status = status.is_some();
    value.status = status.unwrap_or(0);
    value.has_retry_after = retry_after.is_some();
    value.retry_after_seconds = retry_after.unwrap_or(0);
    unsafe { write_versioned_output(out, capacity, &value) };
    true
}

/// Attach this OIDC state as a rotating, non-prompting provider to an HTTP(S)
/// or QWP/WebSocket sender builder. Explicit sign-in must happen before a
/// transport needs a token that cannot be loaded or silently refreshed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_oidc_auth(
    opts: *mut line_sender_opts,
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if opts.is_null() {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_opts_oidc_auth requires non-NULL opts",
            )
        };
        return false;
    }
    let Some(auth) = (unsafe { clone_auth(auth, err_out) }) else {
        return false;
    };
    let current = unsafe { (*opts).0.clone() };
    match current.bearer_token_provider(move || auth.token()) {
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
    use questdb::oidc::{PersistedToken, TokenStore, TokenStoreKey, TokenStoreResult};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    // Frozen copies of the first published output prefixes. They deliberately
    // remain unchanged when fields are appended to the public Rust structs.
    #[repr(C)]
    struct OidcConfigViewV1 {
        struct_size: size_t,
        groups_in_token: bool,
        client_id: *const c_char,
        client_id_len: size_t,
        token_endpoint: *const c_char,
        token_endpoint_len: size_t,
        device_authorization_endpoint: *const c_char,
        device_authorization_endpoint_len: size_t,
        scope: *const c_char,
        scope_len: size_t,
        audience: *const c_char,
        audience_len: size_t,
        issuer: *const c_char,
        issuer_len: size_t,
    }

    #[repr(C)]
    struct GuardedOidcConfigViewV1 {
        view: OidcConfigViewV1,
        canary: [u8; 16],
    }

    #[repr(C)]
    struct OidcErrorViewV1 {
        struct_size: size_t,
        kind: questdb_oidc_error_kind,
        idp_error: *const c_char,
        idp_error_len: size_t,
        idp_error_description: *const c_char,
        idp_error_description_len: size_t,
        has_status: bool,
        status: u16,
        has_retry_after: bool,
        retry_after_seconds: u64,
    }

    #[repr(C)]
    struct GuardedOidcErrorViewV1 {
        view: OidcErrorViewV1,
        canary: [u8; 16],
    }

    unsafe fn set_string(
        setter: unsafe extern "C" fn(
            *mut questdb_oidc_builder,
            *const c_char,
            size_t,
            *mut *mut questdb_error,
        ) -> bool,
        builder: *mut questdb_oidc_builder,
        value: &str,
    ) {
        let mut error = ptr::null_mut();
        assert!(unsafe {
            setter(
                builder,
                value.as_ptr() as *const c_char,
                value.len(),
                &mut error,
            )
        });
        assert!(error.is_null());
    }

    unsafe fn explicit_builder() -> *mut questdb_oidc_builder {
        let builder = questdb_oidc_builder_new();
        unsafe {
            set_string(questdb_oidc_builder_client_id, builder, "questdb-c");
            set_string(questdb_oidc_builder_scope, builder, "openid profile");
            set_string(
                questdb_oidc_builder_token_endpoint,
                builder,
                "https://idp.example/token",
            );
            set_string(
                questdb_oidc_builder_device_authorization_endpoint,
                builder,
                "https://idp.example/device",
            );
        }
        builder
    }

    #[test]
    fn null_token_is_an_empty_null_span() {
        let token = ptr::null();
        assert!(unsafe { questdb_oidc_token_data(token) }.is_null());
        assert_eq!(unsafe { questdb_oidc_token_len(token) }, 0);
    }

    unsafe extern "C" fn ignore_event(_user_data: *mut c_void, _event: *const questdb_oidc_event) {}

    struct FailingClearStore;

    impl TokenStore for FailingClearStore {
        fn load(&self, _key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
            Ok(None)
        }

        fn save(&self, _key: &TokenStoreKey, _token: &PersistedToken) -> TokenStoreResult<()> {
            Ok(())
        }

        fn clear(&self, _key: &TokenStoreKey) -> TokenStoreResult<()> {
            Err(Box::new(std::io::Error::other(
                "injected persisted clear failure",
            )))
        }

        fn in_lock(
            &self,
            _key: &TokenStoreKey,
            action: &mut dyn FnMut() -> TokenStoreResult<()>,
        ) -> TokenStoreResult<()> {
            action()
        }
    }

    unsafe extern "C" fn release_counter(user_data: *mut c_void) {
        let counter = unsafe { Box::from_raw(user_data as *mut Arc<AtomicUsize>) };
        counter.fetch_add(1, Ordering::SeqCst);
    }

    #[derive(Default)]
    struct EventLog {
        kinds: Vec<questdb_oidc_event_kind>,
        user_code: String,
        verification_uri: String,
        verification_uri_complete: String,
        browser_target: String,
        identity: String,
        message: String,
    }

    unsafe fn copy_event_text(value: *const c_char, value_len: size_t) -> String {
        if value.is_null() || value_len == 0 {
            return String::new();
        }
        String::from_utf8_lossy(unsafe { slice::from_raw_parts(value as *const u8, value_len) })
            .into_owned()
    }

    unsafe extern "C" fn record_event(user_data: *mut c_void, event: *const questdb_oidc_event) {
        let events = unsafe { &*(user_data as *const Arc<Mutex<EventLog>>) };
        let event = unsafe { &*event };
        let mut events = events.lock().unwrap();
        events.kinds.push(event.kind);
        match event.kind {
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_PROMPT => {
                events.user_code = unsafe { copy_event_text(event.user_code, event.user_code_len) };
                events.verification_uri =
                    unsafe { copy_event_text(event.verification_uri, event.verification_uri_len) };
                events.verification_uri_complete = unsafe {
                    copy_event_text(
                        event.verification_uri_complete,
                        event.verification_uri_complete_len,
                    )
                };
                events.browser_target =
                    unsafe { copy_event_text(event.browser_target, event.browser_target_len) };
            }
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_SUCCESS => {
                events.identity = unsafe { copy_event_text(event.identity, event.identity_len) };
            }
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_FAILURE => {
                events.message = unsafe { copy_event_text(event.message, event.message_len) };
            }
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING => {}
        }
    }

    unsafe extern "C" fn release_events(user_data: *mut c_void) {
        unsafe { drop(Box::from_raw(user_data as *mut Arc<Mutex<EventLog>>)) };
    }

    #[derive(Default)]
    struct SerializedCallbackState {
        active: AtomicUsize,
        overlaps: AtomicUsize,
        calls: AtomicUsize,
    }

    unsafe extern "C" fn record_serialized_callback(
        user_data: *mut c_void,
        _event: *const questdb_oidc_event,
    ) {
        let state = unsafe { &*(user_data as *const Arc<SerializedCallbackState>) };
        if state.active.fetch_add(1, Ordering::SeqCst) != 0 {
            state.overlaps.fetch_add(1, Ordering::SeqCst);
        }
        // Widen the overlap window so this reliably catches a missing callback
        // gate even under a heavily loaded test runner.
        std::thread::sleep(Duration::from_millis(2));
        state.calls.fetch_add(1, Ordering::SeqCst);
        state.active.fetch_sub(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn release_serialized_callback(user_data: *mut c_void) {
        unsafe {
            drop(Box::from_raw(
                user_data as *mut Arc<SerializedCallbackState>,
            ))
        };
    }

    #[derive(Default)]
    struct ReentrantCallState {
        auth: AtomicPtr<questdb_oidc_auth>,
        rejected: AtomicUsize,
        unexpected: AtomicUsize,
    }

    unsafe fn record_reentrant_result(
        state: &ReentrantCallState,
        succeeded: bool,
        error: *mut questdb_error,
    ) {
        let is_guard_error = !succeeded
            && !error.is_null()
            && unsafe { crate::questdb_error_get_code(error) } as i32
                == crate::line_sender_error_code::line_sender_error_invalid_api_call as i32
            && {
                let mut len = 0;
                let message = unsafe { crate::questdb_error_msg(error, &mut len) };
                let message = unsafe { slice::from_raw_parts(message as *const u8, len) };
                String::from_utf8_lossy(message).contains("cannot be re-entered")
            };
        if is_guard_error {
            state.rejected.fetch_add(1, Ordering::SeqCst);
        } else {
            state.unexpected.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { crate::questdb_error_free(error) };
    }

    unsafe fn perform_reentrant_auth_calls(state: &ReentrantCallState) {
        let auth = state.auth.load(Ordering::SeqCst);

        let mut error = ptr::null_mut();
        let signed_in = unsafe { questdb_oidc_auth_sign_in(auth, &mut error) };
        unsafe { record_reentrant_result(state, signed_in, error) };

        error = ptr::null_mut();
        let token = unsafe { questdb_oidc_auth_token(auth, &mut error) };
        unsafe { record_reentrant_result(state, !token.is_null(), error) };
        unsafe { questdb_oidc_token_free(token) };

        error = ptr::null_mut();
        let cleared = unsafe { questdb_oidc_auth_clear(auth, &mut error) };
        unsafe { record_reentrant_result(state, cleared, error) };
    }

    unsafe extern "C" fn attempt_reentrant_auth_calls(
        user_data: *mut c_void,
        _event: *const questdb_oidc_event,
    ) {
        let state = unsafe { &*(user_data as *const Arc<ReentrantCallState>) };
        unsafe { perform_reentrant_auth_calls(state) };
    }

    unsafe extern "C" fn attempt_cross_thread_reentrant_auth_calls(
        user_data: *mut c_void,
        _event: *const questdb_oidc_event,
    ) {
        let state = unsafe { &*(user_data as *const Arc<ReentrantCallState>) };
        let state = Arc::clone(state);
        std::thread::spawn(move || unsafe { perform_reentrant_auth_calls(&state) })
            .join()
            .unwrap();
    }

    unsafe extern "C" fn release_reentrant_state(user_data: *mut c_void) {
        unsafe { drop(Box::from_raw(user_data as *mut Arc<ReentrantCallState>)) };
    }

    fn write_json_response(mut stream: TcpStream, body: &str) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        let headers_end = loop {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                return;
            }
            request.extend_from_slice(&chunk[..read]);
            if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = String::from_utf8_lossy(&request[..headers_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while request.len() < headers_end + content_length {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    #[test]
    fn builder_is_reusable_and_config_view_borrows_from_auth() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            let first = questdb_oidc_builder_build(builder, &mut error);
            assert!(!first.is_null());
            assert!(error.is_null());
            let second = questdb_oidc_builder_build(builder, &mut error);
            assert!(!second.is_null());
            assert!(error.is_null());

            assert_eq!(
                std::mem::size_of::<OidcConfigViewV1>(),
                QUESTDB_OIDC_CONFIG_VIEW_V1_SIZE
            );
            let mut guarded = std::mem::zeroed::<GuardedOidcConfigViewV1>();
            guarded.canary = [0xA5; 16];
            guarded.view.struct_size = std::mem::size_of::<OidcConfigViewV1>();
            assert!(questdb_oidc_auth_get_config(
                first,
                (&mut guarded.view as *mut OidcConfigViewV1).cast::<questdb_oidc_config_view>(),
            ));
            let view = &guarded.view;
            assert_eq!(view.struct_size, QUESTDB_OIDC_CONFIG_VIEW_V1_SIZE);
            assert_eq!(
                slice::from_raw_parts(view.client_id as *const u8, view.client_id_len),
                b"questdb-c"
            );
            assert_eq!(
                slice::from_raw_parts(view.scope as *const u8, view.scope_len),
                b"openid profile"
            );
            assert_eq!(guarded.canary, [0xA5; 16]);

            let mut undersized = std::mem::size_of::<size_t>();
            assert!(!questdb_oidc_auth_get_config(
                first,
                (&mut undersized as *mut size_t).cast::<questdb_oidc_config_view>(),
            ));
            assert_eq!(undersized, QUESTDB_OIDC_CONFIG_VIEW_V1_SIZE);

            questdb_oidc_builder_free(builder);
            questdb_oidc_auth_free(first);
            questdb_oidc_auth_free(second);
        }
    }

    #[test]
    fn config_failures_retain_structured_oidc_details() {
        unsafe {
            let builder = questdb_oidc_builder_new();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_build(builder, &mut error).is_null());
            assert!(!error.is_null());
            assert_eq!(
                std::mem::size_of::<OidcErrorViewV1>(),
                QUESTDB_OIDC_ERROR_VIEW_V1_SIZE
            );
            let mut guarded = std::mem::zeroed::<GuardedOidcErrorViewV1>();
            guarded.canary = [0x5A; 16];
            guarded.view.struct_size = std::mem::size_of::<OidcErrorViewV1>();
            assert!(questdb_error_oidc_get_view(
                error,
                (&mut guarded.view as *mut OidcErrorViewV1).cast::<questdb_oidc_error_view>(),
            ));
            let view = &guarded.view;
            assert_eq!(view.struct_size, QUESTDB_OIDC_ERROR_VIEW_V1_SIZE);
            assert_eq!(
                view.kind,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_CONFIG
            );
            assert_eq!(guarded.canary, [0x5A; 16]);

            let mut undersized = std::mem::size_of::<size_t>();
            assert!(!questdb_error_oidc_get_view(
                error,
                (&mut undersized as *mut size_t).cast::<questdb_oidc_error_view>(),
            ));
            assert_eq!(undersized, QUESTDB_OIDC_ERROR_VIEW_V1_SIZE);
            crate::questdb_error_free(error);
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn attached_reader_failure_retains_structured_oidc_details() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            // The reader connects before constructing its upgrade headers. The
            // provider then fails locally and drops this socket without sending
            // a request or starting an interactive device flow.
            let _ = listener.accept().unwrap();
        });

        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_interactive(builder, true, &mut error));
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            assert!(error.is_null());

            let conf = format!("ws::addr={address};failover=off;");
            let config = crate::line_sender_utf8 {
                len: conf.len(),
                buf: conf.as_ptr() as *const c_char,
            };
            let reader = crate::egress::qwp_reader_from_conf_with_oidc(config, &*auth, &mut error);
            assert!(reader.is_null());
            assert!(!error.is_null());

            let mut view = std::mem::zeroed::<questdb_oidc_error_view>();
            view.struct_size = std::mem::size_of_val(&view);
            assert!(questdb_error_oidc_get_view(error, &mut view));
            assert_eq!(
                view.kind,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED
            );

            crate::questdb_error_free(error);
            questdb_oidc_auth_free(auth);
            questdb_oidc_builder_free(builder);
        }
        server.join().unwrap();
    }

    #[test]
    fn renderer_user_data_lives_until_builder_and_auth_are_released() {
        unsafe {
            let releases = Arc::new(AtomicUsize::new(0));
            let user_data = Box::into_raw(Box::new(Arc::clone(&releases))) as *mut c_void;
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(ignore_event),
                user_data,
                Some(release_counter),
                &mut error,
            ));
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            questdb_oidc_builder_free(builder);
            assert_eq!(releases.load(Ordering::SeqCst), 0);
            questdb_oidc_auth_free(auth);
            assert_eq!(releases.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn callbacks_shared_by_renderer_clones_are_serialized() {
        const THREADS: usize = 8;
        const CALLS_PER_THREAD: usize = 4;

        let state = Arc::new(SerializedCallbackState::default());
        let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
        let handler = Arc::new(CEventHandler {
            callback: record_serialized_callback,
            user_data: user_data as usize,
            release: Some(release_serialized_callback),
            callback_gate: std::sync::Mutex::new(()),
            active: AtomicBool::new(false),
        });
        let start = Arc::new(std::sync::Barrier::new(THREADS + 1));
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let renderer = CEventRenderer(Arc::clone(&handler));
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    for _ in 0..CALLS_PER_THREAD {
                        renderer.on_waiting(30.0);
                    }
                })
            })
            .collect();
        start.wait();
        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            THREADS * CALLS_PER_THREAD
        );
        assert_eq!(state.active.load(Ordering::SeqCst), 0);
        assert_eq!(state.overlaps.load(Ordering::SeqCst), 0);
        drop(handler);
    }

    #[test]
    fn auth_operations_from_its_event_callback_are_rejected() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_interactive(builder, false, &mut error));
            let state = Arc::new(ReentrantCallState::default());
            let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(attempt_reentrant_auth_calls),
                user_data,
                Some(release_reentrant_state),
                &mut error,
            ));
            let handler = Arc::clone((*builder).config.renderer.as_ref().unwrap());
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            assert!(error.is_null());
            state.auth.store(auth, Ordering::SeqCst);

            // Enter through the same renderer used by the auth. All three
            // calls must fail before attempting to acquire the core mutex.
            CEventRenderer(handler).on_waiting(30.0);

            assert_eq!(state.rejected.load(Ordering::SeqCst), 3);
            assert_eq!(state.unexpected.load(Ordering::SeqCst), 0);
            questdb_oidc_auth_free(auth);
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn auth_operations_from_another_thread_during_event_callback_are_rejected() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_interactive(builder, false, &mut error));
            let state = Arc::new(ReentrantCallState::default());
            let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(attempt_cross_thread_reentrant_auth_calls),
                user_data,
                Some(release_reentrant_state),
                &mut error,
            ));
            let handler = Arc::clone((*builder).config.renderer.as_ref().unwrap());
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            assert!(error.is_null());
            state.auth.store(auth, Ordering::SeqCst);

            // The callback waits for another thread that tries all three auth
            // operations. They must fail before trying the core mutex held by
            // a real interactive flow.
            CEventRenderer(handler).on_waiting(30.0);

            assert_eq!(state.rejected.load(Ordering::SeqCst), 3);
            assert_eq!(state.unexpected.load(Ordering::SeqCst), 0);
            questdb_oidc_auth_free(auth);
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn device_flow_returns_owned_token_and_renderer_events() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (device, _) = listener.accept().unwrap();
            write_json_response(
                device,
                r#"{"device_code":"DEV-CODE","user_code":"AB\u001b[31m\u202e\u0430","verification_uri":"https://exa\u0430mple.com/\nactivate","verification_uri_complete":"https://idp.example.com/activate?code=ABCD\n","expires_in":600,"interval":5}"#,
            );
            let (token, _) = listener.accept().unwrap();
            write_json_response(
                token,
                r#"{"access_token":"ffi-access-token","token_type":"Bearer","expires_in":300}"#,
            );
        });

        unsafe {
            let builder = questdb_oidc_builder_new();
            set_string(questdb_oidc_builder_client_id, builder, "questdb-c");
            set_string(questdb_oidc_builder_scope, builder, "openid");
            set_string(
                questdb_oidc_builder_device_authorization_endpoint,
                builder,
                &format!("http://{address}/device"),
            );
            set_string(
                questdb_oidc_builder_token_endpoint,
                builder,
                &format!("http://{address}/token"),
            );
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_interactive(builder, true, &mut error));
            assert!(questdb_oidc_builder_open_browser(
                builder, false, &mut error
            ));
            let events = Arc::new(Mutex::new(EventLog::default()));
            let user_data = Box::into_raw(Box::new(Arc::clone(&events))) as *mut c_void;
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(record_event),
                user_data,
                Some(release_events),
                &mut error,
            ));
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());

            // Token retrieval is safe for transport callbacks even when the
            // auth permits interaction: it reports InteractionRequired without
            // touching the device endpoint. Only sign_in starts the mock server
            // sequence below.
            let token = questdb_oidc_auth_token(auth, &mut error);
            assert!(token.is_null());
            assert!(!error.is_null());
            let mut view = std::mem::zeroed::<questdb_oidc_error_view>();
            view.struct_size = std::mem::size_of_val(&view);
            assert!(questdb_error_oidc_get_view(error, &mut view));
            assert_eq!(
                view.kind,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED
            );
            crate::questdb_error_free(error);
            error = ptr::null_mut();

            assert!(questdb_oidc_auth_sign_in(auth, &mut error));
            assert!(error.is_null());
            let token = questdb_oidc_auth_token(auth, &mut error);
            assert!(!token.is_null());
            assert!(error.is_null());
            assert_eq!(
                slice::from_raw_parts(
                    questdb_oidc_token_data(token) as *const u8,
                    questdb_oidc_token_len(token),
                ),
                b"ffi-access-token"
            );
            let events = events.lock().unwrap();
            assert_eq!(
                events.kinds,
                vec![
                    questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_PROMPT,
                    questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_SUCCESS,
                ]
            );
            assert_eq!(events.user_code, "AB[31m\\u{0430}");
            assert_eq!(
                events.verification_uri,
                "https://exa\\u{0430}mple.com/activate"
            );
            assert_eq!(
                events.verification_uri_complete,
                "https://idp.example.com/activate?code=ABCD"
            );
            assert_eq!(
                events.browser_target,
                "https://idp.example.com/activate?code=ABCD"
            );
            drop(events);
            questdb_oidc_token_free(token);
            questdb_oidc_auth_free(auth);
            questdb_oidc_builder_free(builder);
        }
        server.join().unwrap();
    }

    #[test]
    fn clear_propagates_persisted_deletion_failure() {
        let inner = OidcDeviceAuth::builder()
            .client_id("questdb-c")
            .scope("openid")
            .token_endpoint("https://idp.example/token")
            .device_authorization_endpoint("https://idp.example/device")
            .token_store(FailingClearStore)
            .build()
            .unwrap();
        let auth = Box::into_raw(Box::new(questdb_oidc_auth {
            shared: SharedOidcAuth {
                inner: Arc::new(inner),
                event_handler: None,
            },
        }));

        unsafe {
            let mut error = ptr::null_mut();
            assert!(!questdb_oidc_auth_clear(auth, &mut error));
            assert!(!error.is_null());
            let mut view = std::mem::zeroed::<questdb_oidc_error_view>();
            view.struct_size = std::mem::size_of_val(&view);
            assert!(questdb_error_oidc_get_view(error, &mut view));
            assert_eq!(
                view.kind,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_NETWORK
            );
            let mut message_len = 0;
            let message = crate::questdb_error_msg(error, &mut message_len);
            let message = slice::from_raw_parts(message as *const u8, message_len);
            assert!(String::from_utf8_lossy(message).contains("injected persisted clear failure"));
            crate::questdb_error_free(error);
            questdb_oidc_auth_free(auth);
        }
    }

    #[test]
    fn renderer_sanitizes_identity_and_failure_message() {
        let events = Arc::new(Mutex::new(EventLog::default()));
        let user_data = Box::into_raw(Box::new(Arc::clone(&events))) as *mut c_void;
        let renderer = CEventRenderer(Arc::new(CEventHandler {
            callback: record_event,
            user_data: user_data as usize,
            release: Some(release_events),
            callback_gate: std::sync::Mutex::new(()),
            active: AtomicBool::new(false),
        }));

        renderer.on_success(Some("alice\x1b[31m\u{202e}"), 300.0);
        renderer.on_failure("failed\n\u{200b}try again");
        drop(renderer);

        let events = events.lock().unwrap();
        assert_eq!(
            events.kinds,
            vec![
                questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_SUCCESS,
                questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_FAILURE,
            ]
        );
        assert_eq!(events.identity, "alice[31m");
        assert_eq!(events.message, "failedtry again");
    }

    #[test]
    fn sender_attachment_keeps_shared_auth_state_alive() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            let host = crate::line_sender_utf8 {
                len: "localhost".len(),
                buf: c"localhost".as_ptr(),
            };
            let opts = crate::line_sender_opts_new(
                crate::line_sender_protocol::line_sender_protocol_https,
                host,
                9000,
            );
            assert!(!opts.is_null());
            assert!(line_sender_opts_oidc_auth(opts, auth, &mut error));
            assert!(error.is_null());

            questdb_oidc_auth_free(auth);
            crate::line_sender_opts_free(opts);
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn lazy_pool_retains_auth_without_running_device_flow() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());

            let mut options = crate::column_sender::questdb_db_connect_options::default();
            let options_size = std::mem::size_of_val(&options);
            crate::column_sender::questdb_db_connect_options_init(&mut options, options_size);
            options.oidc_auth = auth;
            let conf = "ws::addr=127.0.0.1:1;lazy_connect=true;";
            let db = crate::column_sender::questdb_db_connect_ex(
                conf.as_ptr() as *const c_char,
                conf.len(),
                &options,
                &mut error,
            );
            assert!(!db.is_null());
            assert!(error.is_null());

            questdb_oidc_auth_free(auth);
            crate::column_sender::questdb_db_close(db);
            questdb_oidc_builder_free(builder);
        }
    }
}
