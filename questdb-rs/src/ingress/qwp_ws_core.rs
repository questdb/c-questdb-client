//! Transport-neutral QWP/WebSocket sender core used by browser WebAssembly.
//!
//! The native sender owns an OS socket, a background thread and file-backed
//! store-and-forward slots. Browser WASM reuses the same delivery driver and
//! in-memory SFA queue while supplying WebSocket events from JavaScript.

#![allow(dead_code)]

#[path = "sender/qwp_ws_codec.rs"]
pub(crate) mod qwp_ws_codec;
#[path = "sender/qwp_ws_driver.rs"]
pub(crate) mod qwp_ws_driver;
#[path = "sender/qwp_ws_ownership.rs"]
mod qwp_ws_ownership;
#[path = "sender/qwp_ws_queue.rs"]
pub(crate) mod qwp_ws_queue;
#[path = "sender/qwp_ws_sfa_catchup.rs"]
mod qwp_ws_sfa_catchup;
#[path = "sender/qwp_ws_sfa_manifest.rs"]
mod qwp_ws_sfa_manifest;
#[path = "sender/qwp_ws_sfa_queue.rs"]
pub(crate) mod qwp_ws_sfa_queue;
#[path = "sender/qwp_ws_sfa_segment.rs"]
mod qwp_ws_sfa_segment;
#[path = "sender/qwp_ws_sfa_symbol_dict.rs"]
mod qwp_ws_sfa_symbol_dict;

pub(crate) use qwp_ws_ownership::{QwpWsRoleReject, QwpWsSenderError};
