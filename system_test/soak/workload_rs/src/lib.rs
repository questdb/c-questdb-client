//! Soak / stress workload library.
//!
//! The pieces here are shared by the workload binary (`src/main.rs`) and its
//! tests. The load-bearing module is [`gen`]: the deterministic, cross-language
//! data generator that lets the soak oracle regenerate every expected
//! read-back value from `(seed, worker_id, seq)` alone.

pub mod column_leg;
#[cfg(feature = "dataframe")]
pub mod dataframe_leg;
pub mod egress_leg;
pub mod gen;
pub mod journal;
pub mod legs;
pub mod stats;

use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

/// True once the orchestrator has asked the leg to stop (SIGTERM/SIGINT). Leg
/// loops poll this so a graceful stop lets them exit the loop and release their
/// pooled sender/reader instead of being killed mid-flight (I4 pool drain).
pub fn stop_requested() -> bool {
    STOP.load(Ordering::Relaxed)
}

/// Install the SIGTERM/SIGINT handlers that flip [`stop_requested`].
pub fn install_stop_handler() {
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        // SAFETY: the action only stores into a static AtomicBool, which is
        // async-signal-safe.
        let _ = unsafe {
            signal_hook::low_level::register(signal, || STOP.store(true, Ordering::SeqCst))
        };
    }
}
