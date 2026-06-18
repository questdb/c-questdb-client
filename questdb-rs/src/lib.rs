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
#![doc = include_str!("../README.md")]

mod error;

#[cfg(any(feature = "sync-sender-tcp", feature = "sync-sender-qwp-udp"))]
mod gai;

// Shared RFC 6455 WebSocket plumbing. Compiled whenever either side
// needs it (ingress QWP/WS sender or egress QWP/WS reader). Each side
// keeps its own transport-specific state machine on top of these
// primitives.
#[cfg(any(feature = "_sender-qwp-ws", feature = "_egress"))]
mod ws;

// JKS / PKCS#12 trust-store loader for `tls_roots_password`. Pulled
// in only for the QWP transports — matches the Java reference's
// `KeyStore.getInstance(...)` surface there. Other ILP transports
// keep using rustls' native PEM input.
#[cfg(feature = "_keystore-roots")]
mod keystore_roots;

pub mod ingress;

#[cfg(feature = "_egress")]
pub mod egress;

// Custom high-performance connection pooling + the `Db` facade. Gated on
// `pool`, which pulls in both the egress reader and the sender transports the
// facade needs.
#[cfg(feature = "pool")]
pub mod pool;

#[cfg(feature = "pool")]
pub mod db;

pub use error::*;

#[cfg(test)]
mod alloc_counter {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub static COUNTING: AtomicBool = AtomicBool::new(false);
    pub static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

    pub struct CountingAllocator;

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if COUNTING.load(Ordering::Relaxed) {
                ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            if COUNTING.load(Ordering::Relaxed) {
                ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    /// Begin counting allocations made through the global allocator.
    ///
    /// The counter and the enable flag are process-global, so *any* allocation
    /// on *any* thread between [`start_counting`] and [`stop_counting`] is
    /// included. Tests that assert on the result must therefore run
    /// single-threaded: mark them `#[ignore]` and run with `--test-threads=1`
    /// (see the existing `qwp_zero_alloc_*` tests for the convention).
    pub fn start_counting() -> usize {
        ALLOC_COUNT.store(0, Ordering::SeqCst);
        COUNTING.store(true, Ordering::SeqCst);
        0
    }

    /// Stop counting and return the number of allocations observed since
    /// [`start_counting`]. Same single-thread constraint as `start_counting`.
    pub fn stop_counting() -> usize {
        COUNTING.store(false, Ordering::SeqCst);
        ALLOC_COUNT.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
#[global_allocator]
static GLOBAL: alloc_counter::CountingAllocator = alloc_counter::CountingAllocator;

#[cfg(test)]
mod tests;
