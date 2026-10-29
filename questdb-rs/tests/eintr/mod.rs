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

//! Signal-driven `EINTR` injection for the egress `interrupt_on_eintr` tests.
//!
//! Hosts such as Ruby install signal handlers without `SA_RESTART`, so a
//! blocking `recv` on the reading thread fails with `EINTR` whenever a
//! signal lands on it. [`Pelter`] reproduces that: it installs a no-op
//! `SIGUSR2` handler without `SA_RESTART` and `pthread_kill`s the thread
//! that started it until dropped.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

extern "C" fn noop_handler(_: libc::c_int) {}

fn install_handler_without_sa_restart() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = noop_handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
        sa.sa_flags = 0; // deliberately no SA_RESTART
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut()),
            0,
            "sigaction"
        );
    });
}

/// Repeatedly signals the thread that created it until dropped.
pub struct Pelter {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Pelter {
    /// Signal the creating thread every `every`. Must be dropped on the
    /// creating thread (it is joined before that thread can exit).
    pub fn start(every: Duration) -> Self {
        install_handler_without_sa_restart();
        // `pthread_t` is a pointer on some platforms; carry it as an
        // integer so the closure is `Send`.
        let target = unsafe { libc::pthread_self() } as usize;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop2.load(Ordering::Acquire) {
                unsafe { libc::pthread_kill(target as libc::pthread_t, libc::SIGUSR2) };
                thread::sleep(every);
            }
        });
        Pelter {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Pelter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
