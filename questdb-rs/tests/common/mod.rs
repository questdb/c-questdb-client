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

//! Shared launch fixture for live-server integration tests.
//!
//! Spawns the `questdb` submodule's built jar via the same JVM
//! invocation as `system_test/fixture.py`, polls `/ping` until ready,
//! exposes its HTTP / ILP / PostgreSQL ports, and SIGKILLs the process
//! on `Drop`.
//!
//! A process-wide [`OnceLock`] in callers can amortise the boot cost
//! across all tests in a single `cargo test` invocation.
//!
//! Built only when the `live-server-tests` feature is enabled.

#![cfg(feature = "live-server-tests")]
// `tests/common/mod.rs` is compiled once per integration-test binary
// (Rust's "tests/<name>.rs each is a separate crate" model). Helpers
// that only some binaries need surface as `dead_code` in the others.
// Mark the module as such to keep `clippy -D warnings` quiet without
// peppering individual fns with `#[allow]`.
#![allow(dead_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PING_PATH: &str = "/ping";
const PING_TIMEOUT: Duration = Duration::from_secs(45);
const PING_INTERVAL: Duration = Duration::from_millis(100);

/// Serialises the allocate-then-spawn critical section across `#[test]`
/// threads in this `cargo test` binary. `allocate_ports` releases its
/// bound listeners before the JVM gets a chance to rebind, so without
/// this mutex two concurrent tests can be handed the same port by the
/// kernel: thread A drops the listener, thread B's `allocate_ports` is
/// assigned the freshly-freed port, and thread A's JVM then loses the
/// race when it tries to bind. Held only until `/ping` returns 204 — by
/// that point the JVM owns its three sockets and other tests can boot in
/// parallel.
static STARTUP: Mutex<()> = Mutex::new(());

/// Locate the QuestDB jar built from the `questdb/` submodule. We walk up
/// from `questdb-rs/` to the workspace root and look for the jar there.
fn locate_jar() -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let target_dir = crate_dir
        .parent()
        .expect("workspace root above questdb-rs")
        .join("questdb")
        .join("core")
        .join("target");
    let entries = std::fs::read_dir(&target_dir).unwrap_or_else(|e| {
        panic!(
            "Could not read {}: {}\n\nHint: build the jar first:\n  cd questdb && mvn -pl core -am -DskipTests package",
            target_dir.display(),
            e
        )
    });
    let mut candidates: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with("questdb-")
                && name.ends_with("-SNAPSHOT.jar")
                && !name.ends_with("-tests.jar")
                && !name.ends_with("-sources.jar")
        })
        .collect();
    candidates.sort();
    candidates.pop().unwrap_or_else(|| {
        panic!(
            "No questdb-*-SNAPSHOT.jar in {}.\n\nBuild it first:\n  cd questdb && mvn -pl core -am -DskipTests package",
            target_dir.display()
        )
    })
}

/// Allocate `n` free TCP ports on 127.0.0.1 by binding briefly to port 0.
/// `start_with_config` serialises the allocate-then-spawn critical
/// section via a process-local mutex ([`STARTUP`]), so the
/// close→rebind window cannot collide with another test thread in this
/// same `cargo test` binary. Externally visible parallelism (test
/// bodies running after `/ping` returns 204) is unaffected.
fn allocate_ports(n: usize) -> Vec<u16> {
    let mut listeners = Vec::with_capacity(n);
    let mut ports = Vec::with_capacity(n);
    for _ in 0..n {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        ports.push(l.local_addr().unwrap().port());
        listeners.push(l);
    }
    drop(listeners);
    ports
}

/// Locate a `java` binary, preferring `JAVA_HOME` if set.
fn locate_java() -> PathBuf {
    if let Some(home) = std::env::var_os("JAVA_HOME") {
        let candidate = PathBuf::from(home).join("bin").join("java");
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from("java")
}

fn poll_until<F: FnMut() -> bool>(mut probe: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(PING_INTERVAL);
    }
    false
}

fn http_status(host: &str, port: u16, path: &str) -> u16 {
    let url = format!("http://{}:{}{}", host, port, path);
    match ureq::get(&url).call() {
        Ok(resp) => resp.status().as_u16(),
        // QuestDB returns 204 for /ping which `ureq` surfaces via the
        // Ok branch; non-2xx come through Err in `ureq::Error::StatusCode`.
        Err(ureq::Error::StatusCode(code)) => code,
        Err(_) => 0,
    }
}

/// Run a SQL statement via the QuestDB HTTP `/exec` endpoint. Used for
/// DDL / setup queries; result body is not parsed.
///
/// ureq's default request-prelude buffer is 128 KB, which is too small
/// for wide-schema `INSERT ... VALUES (...)` strings the fuzz tests
/// generate; bump to 4 MiB to match the server-side
/// `http.request.header.buffer.size` we set in `start_fragmented`.
pub fn http_exec(host: &str, port: u16, sql: &str) -> u16 {
    let url = format!("http://{}:{}/exec", host, port);
    let agent = ureq::Agent::config_builder()
        .output_buffer_size(4 * 1024 * 1024)
        .build()
        .new_agent();
    match agent.get(&url).query("query", sql).call() {
        Ok(resp) => resp.status().as_u16(),
        Err(ureq::Error::StatusCode(code)) => code,
        Err(e) => {
            eprintln!(
                "[live-server] http_exec error: {} (sql len={})",
                e,
                sql.len()
            );
            0
        }
    }
}

/// Running QuestDB instance scoped to one process.
#[allow(dead_code)] // ilp_port / pg_port exposed for future tests
pub struct QuestDbServer {
    child: Child,
    pub host: String,
    pub http_port: u16,
    pub ilp_port: u16,
    pub pg_port: u16,
    pub log_path: PathBuf,
    _data_dir: tempfile::TempDir,
}

impl QuestDbServer {
    /// Dump the last `n` log lines to stderr — for diagnostics in tests.
    pub fn dump_recent_log(&self, n: usize) {
        let log = std::fs::read_to_string(&self.log_path).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        let start = lines.len().saturating_sub(n);
        eprintln!(
            "--- jvm.log tail ({} of {}) ---",
            lines.len() - start,
            lines.len()
        );
        for line in &lines[start..] {
            eprintln!("{}", line);
        }
        eprintln!("--- end jvm.log tail ---");
    }
}

impl QuestDbServer {
    // dump_recent_log defined in the impl block above; this is the boot
    // path.

    /// Boot a fresh server with no extra server-conf keys. Convenience
    /// wrapper around [`Self::start_with_config`].
    ///
    /// Used by the shared singleton in `egress_live_server.rs` so dozens
    /// of pinned-value smoke tests can amortise the ~15 s JVM boot.
    pub fn start() -> Self {
        Self::start_with_config(&[])
    }

    /// Boot a fresh server and append `extra_conf` to its `server.conf`.
    /// Each `(key, value)` produces one line `key=value` after the
    /// fixture's default port / telemetry block. Blocks until `/ping`
    /// responds 204 or the 45 s timeout fires; on failure dumps the JVM
    /// log to stderr.
    ///
    /// Use this constructor for tests that need per-instance debug
    /// knobs (e.g. `debug.http.force.recv.fragmentation.chunk.size`
    /// for fragmentation fuzz). The returned `QuestDbServer` owns its
    /// JVM — `Drop` kills it at end of test, so each per-test instance
    /// costs one ~15 s boot.
    pub fn start_with_config(extra_conf: &[(&str, &str)]) -> Self {
        // Hold the startup mutex across allocate_ports + spawn +
        // wait_for_ping so the port triple we picked is still ours when
        // the JVM finally binds. `into_inner` defuses mutex poisoning
        // from a panicking earlier test — the lock guards no shared
        // state, only ordering. See [`STARTUP`] for the full rationale.
        let _startup_guard = STARTUP.lock().unwrap_or_else(|e| e.into_inner());

        let jar = locate_jar();
        let java = locate_java();
        let ports = allocate_ports(3);
        let (http_port, ilp_port, pg_port) = (ports[0], ports[1], ports[2]);

        let data_dir = tempfile::tempdir().expect("tempdir");
        let conf_dir = data_dir.path().join("conf");
        std::fs::create_dir_all(&conf_dir).expect("conf dir");
        let mut conf = format!(
            "http.bind.to=127.0.0.1:{http}\n\
             line.tcp.net.bind.to=127.0.0.1:{ilp}\n\
             pg.net.bind.to=127.0.0.1:{pg}\n\
             http.min.enabled=false\n\
             line.udp.enabled=false\n\
             line.http.enabled=true\n\
             telemetry.enabled=false\n",
            http = http_port,
            ilp = ilp_port,
            pg = pg_port,
        );
        for (k, v) in extra_conf {
            conf.push_str(k);
            conf.push('=');
            conf.push_str(v);
            conf.push('\n');
        }
        std::fs::write(conf_dir.join("server.conf"), conf).expect("server.conf");

        let log_path = data_dir.path().join("jvm.log");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("open jvm.log");
        let log_file_clone = log_file.try_clone().expect("clone log handle");

        let mut cmd = Command::new(&java);
        cmd.args([
            "-DQuestDB-Runtime-0",
            "-ea",
            "-Dnoebug",
            "-XX:+UnlockExperimentalVMOptions",
            "-XX:+AlwaysPreTouch",
            "-p",
        ])
        .arg(&jar)
        .args(["-m", "io.questdb/io.questdb.ServerMain", "-d"])
        .arg(data_dir.path())
        .current_dir(data_dir.path())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_clone));

        eprintln!(
            "[live-server] launching {} -p {} ... (data={}, http={})",
            java.display(),
            jar.display(),
            data_dir.path().display(),
            http_port
        );
        let child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn QuestDB JVM: {e}"));

        let host = "127.0.0.1".to_string();
        let server = Self {
            child,
            host,
            http_port,
            ilp_port,
            pg_port,
            log_path: log_path.clone(),
            _data_dir: data_dir,
        };
        server.wait_for_ping(&log_path);
        eprintln!("[live-server] /ping is up on {}:{}", server.host, http_port);
        server
    }

    fn wait_for_ping(&self, log_path: &Path) {
        let host = self.host.clone();
        let port = self.http_port;
        let up = poll_until(|| http_status(&host, port, PING_PATH) == 204, PING_TIMEOUT);
        if !up {
            eprintln!(
                "[live-server] /ping did not respond on http://{}:{} within {:?}; dumping JVM log:",
                self.host, self.http_port, PING_TIMEOUT
            );
            if let Ok(log) = std::fs::read_to_string(log_path) {
                eprintln!("--- begin jvm.log ---\n{}\n--- end jvm.log ---", log);
            } else {
                eprintln!("(jvm.log unreadable at {})", log_path.display());
            }
        }
        assert!(
            up,
            "QuestDB did not respond on http://{}:{}{} within {:?}",
            self.host, self.http_port, PING_PATH, PING_TIMEOUT
        );
    }

    /// `ws::` connect string for the egress reader. The function name
    /// is a historical artefact — the connect-string scheme is now
    /// `ws`/`wss`, but the helper kept its older name for source
    /// stability across call sites.
    pub fn qwp_conf(&self) -> String {
        format!("ws::addr={}:{}", self.host, self.http_port)
    }

    /// `http::` connect string for the ingress sender.
    pub fn http_conf(&self) -> String {
        format!("http::addr={}:{}", self.host, self.http_port)
    }

    pub fn http_exec(&self, sql: &str) -> u16 {
        http_exec(&self.host, self.http_port, sql)
    }
}

impl Drop for QuestDbServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
