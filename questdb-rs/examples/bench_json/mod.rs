//! Shared JSON metric contract (QWP_DATAFRAME_BENCH_PLAN.md §3.2) for the
//! Rust Polars ingress/egress examples. Emits the **same** field names as
//! the Python harness (`py-questdb-client/test/benchmark_pandas_columnar.py`:
//! `summarize` + `add_rates` + `_path_summary` + the top-level report) so a
//! Step 4 aggregator consumes Python (`py-pandas`) and Rust (`rust-polars`)
//! JSON uniformly.
//!
//! Kept dependency-light (hand-rolled JSON, no serde) and outside Cargo's
//! example auto-discovery (it lives in a subdirectory, referenced by each
//! example via `mod bench_json;`).

#![allow(dead_code)] // each example uses a subset of the surface.

use std::fmt::Write as _;

const MIB: f64 = 1024.0 * 1024.0;

// ---------------------------------------------------------------------------
// Process CPU time (the Python harness reports process_cpu via
// time.process_time_ns()).
// ---------------------------------------------------------------------------

/// User+system CPU nanoseconds consumed by this process so far.
#[cfg(unix)]
pub fn process_cpu_ns() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if rc != 0 {
        return 0;
    }
    let tv_ns =
        |tv: &libc::timeval| (tv.tv_sec as u64) * 1_000_000_000 + (tv.tv_usec as u64) * 1_000;
    tv_ns(&usage.ru_utime) + tv_ns(&usage.ru_stime)
}

/// User+system CPU nanoseconds consumed by this process so far.
#[cfg(windows)]
pub fn process_cpu_ns() -> u64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    fn filetime_100ns(ft: FILETIME) -> u64 {
        ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
    }

    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return 0;
    }
    filetime_100ns(kernel)
        .saturating_add(filetime_100ns(user))
        .saturating_mul(100)
}

/// User+system CPU nanoseconds consumed by this process so far.
#[cfg(not(any(unix, windows)))]
pub fn process_cpu_ns() -> u64 {
    0
}

// ---------------------------------------------------------------------------
// JSON building (minimal, ordered, sorted keys for deterministic output).
// ---------------------------------------------------------------------------

/// A JSON object as ordered key→value pairs (values already serialised).
pub struct Obj(Vec<(String, String)>);

impl Obj {
    pub fn new() -> Self {
        Obj(Vec::new())
    }
    pub fn str(&mut self, k: &str, v: &str) -> &mut Self {
        self.0.push((k.to_string(), json_str(v)));
        self
    }
    pub fn opt_str(&mut self, k: &str, v: Option<&str>) -> &mut Self {
        self.0
            .push((k.to_string(), v.map_or("null".to_string(), json_str)));
        self
    }
    pub fn int(&mut self, k: &str, v: u64) -> &mut Self {
        self.0.push((k.to_string(), v.to_string()));
        self
    }
    pub fn float(&mut self, k: &str, v: f64) -> &mut Self {
        self.0.push((k.to_string(), json_f64(v)));
        self
    }
    pub fn opt_float(&mut self, k: &str, v: Option<f64>) -> &mut Self {
        self.0
            .push((k.to_string(), v.map_or("null".to_string(), json_f64)));
        self
    }
    pub fn bool(&mut self, k: &str, v: bool) -> &mut Self {
        self.0.push((k.to_string(), v.to_string()));
        self
    }
    pub fn raw(&mut self, k: &str, v: String) -> &mut Self {
        self.0.push((k.to_string(), v));
        self
    }
    /// Serialise to compact, single-line JSON with keys sorted (matches
    /// the Python harness's `json.dumps(..., sort_keys=True)` shape; the
    /// aggregator parses JSON, so whitespace is irrelevant and compact
    /// output sidesteps nested-indent bookkeeping when objects are
    /// embedded as raw values). The `_indent` argument is accepted for
    /// call-site symmetry and ignored.
    pub fn to_json(&self, _indent: usize) -> String {
        let mut entries: Vec<&(String, String)> = self.0.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut s = String::from("{");
        for (i, (k, v)) in entries.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(s, "{}:{}", json_str(k), v);
        }
        s.push('}');
        s
    }
}

impl Default for Obj {
    fn default() -> Self {
        Self::new()
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_f64(v: f64) -> String {
    if v.is_finite() {
        // Enough precision to round-trip; trims trailing zeros.
        let s = format!("{v:.12}");
        let s = s.trim_end_matches('0').trim_end_matches('.');
        if s.is_empty() || s == "-" {
            "0".to_string()
        } else {
            s.to_string()
        }
    } else {
        "null".to_string()
    }
}

// ---------------------------------------------------------------------------
// summarize() — mirrors the Python harness field-for-field.
// ---------------------------------------------------------------------------

/// Percentile of an ascending slice, Python-harness convention
/// (`round((n-1)*p)`).
fn percentile(sorted_s: &[f64], p: f64) -> f64 {
    if sorted_s.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_s.len() as f64 - 1.0) * p).round() as usize;
    sorted_s[idx.min(sorted_s.len() - 1)]
}

/// `summarize(samples_ns)` — seconds-domain stats matching the Python
/// harness (`iterations`, `median_s`, `mean_s`, `min_s`, `max_s`,
/// `p95_s`, `stdev_s`, `cov`), optionally with rates folded in.
fn summarize(
    obj: &mut Obj,
    samples_ns: &[u64],
    rows: usize,
    columns: usize,
    wire_bytes: Option<u64>,
) {
    let secs: Vec<f64> = samples_ns.iter().map(|&n| n as f64 / 1e9).collect();
    let mut sorted = secs.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = secs.len();
    let mean = if n > 0 {
        secs.iter().sum::<f64>() / n as f64
    } else {
        0.0
    };
    let median = if n == 0 {
        0.0
    } else if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    };
    let stdev = if n > 1 {
        let var = secs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0);
        var.sqrt()
    } else {
        0.0
    };
    obj.int("iterations", n as u64);
    obj.float("median_s", median);
    obj.float("mean_s", mean);
    obj.float("min_s", *sorted.first().unwrap_or(&0.0));
    obj.float("max_s", *sorted.last().unwrap_or(&0.0));
    obj.float("p95_s", percentile(&sorted, 0.95));
    obj.float("stdev_s", stdev);
    obj.float("cov", if mean != 0.0 { stdev / mean } else { 0.0 });
    add_rates(obj, median, rows, columns, wire_bytes);
}

/// `add_rates(summary, rows, columns, wire_bytes)` — rows/cells per second
/// off the median, plus MiB/s when bytes crossed the wire (floor paths
/// leave `mib_per_s` null, exactly like the Python harness).
fn add_rates(obj: &mut Obj, median_s: f64, rows: usize, columns: usize, wire_bytes: Option<u64>) {
    let rows_per_s = if median_s != 0.0 {
        Some(rows as f64 / median_s)
    } else {
        None
    };
    let cells_per_s = if median_s != 0.0 {
        Some((rows * columns) as f64 / median_s)
    } else {
        None
    };
    obj.opt_float("rows_per_s_median", rows_per_s);
    obj.opt_float("cells_per_s_median", cells_per_s);
    let mib_per_s = match (wire_bytes, median_s) {
        (Some(b), m) if m != 0.0 => Some((b as f64 / MIB) / m),
        _ => None,
    };
    obj.opt_float("mib_per_s", mib_per_s);
}

/// One contract-conformant per-path summary block (plan §3.2):
/// `summarize` + rates + `process_cpu` (its own summarize+rates) + `phase`
/// + `warm` + `wire_bytes`.
pub struct PathSummary {
    obj: Obj,
    pub median_s: f64,
    pub rows_per_s_median: Option<f64>,
    pub mib_per_s: Option<f64>,
}

impl PathSummary {
    pub fn new(
        wall_ns: &[u64],
        cpu_ns: &[u64],
        rows: usize,
        columns: usize,
        phase: &str,
        warm: bool,
        wire_bytes: Option<u64>,
    ) -> Self {
        // `mib_per_s` is only meaningful for e2e paths (bytes on wire); the
        // floor leaves it null, matching `_path_summary`'s
        // `rate_wire_bytes = wire_bytes if phase == "e2e" else None`.
        let rate_wire_bytes = if phase == "e2e" { wire_bytes } else { None };
        let mut obj = Obj::new();
        summarize(&mut obj, wall_ns, rows, columns, rate_wire_bytes);

        // Recompute the headline fields we expose to the caller.
        let secs: Vec<f64> = wall_ns.iter().map(|&n| n as f64 / 1e9).collect();
        let mut sorted = secs.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let nn = sorted.len();
        let median_s = if nn == 0 {
            0.0
        } else if nn % 2 == 1 {
            sorted[nn / 2]
        } else {
            (sorted[nn / 2 - 1] + sorted[nn / 2]) / 2.0
        };
        let rows_per_s_median = if median_s != 0.0 {
            Some(rows as f64 / median_s)
        } else {
            None
        };
        let mib_per_s = match (rate_wire_bytes, median_s) {
            (Some(b), m) if m != 0.0 => Some((b as f64 / MIB) / m),
            _ => None,
        };

        let mut cpu = Obj::new();
        summarize(&mut cpu, cpu_ns, rows, columns, rate_wire_bytes);
        obj.raw("process_cpu", cpu.to_json(0));

        obj.str("phase", phase);
        obj.bool("warm", warm);
        // `wire_bytes` records the schema's per-flush payload on every path
        // (the Python harness records it even on floor paths).
        match wire_bytes {
            Some(b) => obj.int("wire_bytes", b),
            None => obj.opt_str("wire_bytes", None),
        };

        PathSummary {
            obj,
            median_s,
            rows_per_s_median,
            mib_per_s,
        }
    }

    fn into_json(self) -> String {
        self.obj.to_json(0)
    }
}

// ---------------------------------------------------------------------------
// Environment / machine block.
// ---------------------------------------------------------------------------

pub struct Env {
    obj: Obj,
}

impl Env {
    /// Collect the machine block (plan §3.7). `extra` carries any
    /// language-specific library versions (e.g. polars) the example wants
    /// recorded alongside platform + rustc.
    pub fn collect(extra: &[(&str, &str)]) -> Self {
        let mut obj = Obj::new();
        obj.str("platform", std::env::consts::OS);
        obj.str("arch", std::env::consts::ARCH);
        // An example binary has no compiler version at runtime; the
        // build/run harness can inject the exact toolchain via
        // `RUSTC_VERSION` (e.g. `rustc --version`). Falls back to "unknown".
        obj.str(
            "rustc",
            std::env::var("RUSTC_VERSION")
                .ok()
                .as_deref()
                .unwrap_or("unknown"),
        );
        obj.str("questdb_rs", env!("CARGO_PKG_VERSION"));
        for (k, v) in extra {
            obj.str(k, v);
        }
        Env { obj }
    }
}

// ---------------------------------------------------------------------------
// Top-level report.
// ---------------------------------------------------------------------------

pub struct RowCountCheck {
    pub expected: u64,
    pub actual: u64,
    pub ok: bool,
    pub inflated: bool,
}

pub struct Report {
    schema: String,
    rows: usize,
    columns: usize,
    direction: String,
    client: String,
    run_mode: String,
    pub warmups: usize,
    pub wire_bytes: u64,
    pub env: Env,
    paths: Vec<(String, PathSummary)>,
    headline: Obj,
    pub row_count_check: Option<RowCountCheck>,
    pub real_conf: Option<String>,
    pub http_base: Option<String>,
}

impl Report {
    pub fn new(
        schema: &str,
        rows: usize,
        columns: usize,
        direction: &str,
        client: &str,
        run_mode: &str,
    ) -> Self {
        Report {
            schema: schema.to_string(),
            rows,
            columns,
            direction: direction.to_string(),
            client: client.to_string(),
            run_mode: run_mode.to_string(),
            warmups: 0,
            wire_bytes: 0,
            env: Env::collect(&[]),
            paths: Vec::new(),
            headline: Obj::new(),
            row_count_check: None,
            real_conf: None,
            http_base: None,
        }
    }

    pub fn add_path(&mut self, name: &str, summary: PathSummary) {
        self.paths.push((name.to_string(), summary));
    }

    fn path(&self, name: &str) -> Option<&PathSummary> {
        self.paths.iter().find(|(n, _)| n == name).map(|(_, s)| s)
    }

    /// Ingress headline (plan §3.6): pair the encode floor with the e2e
    /// `flush_polars_dataframe` and report the e2e (the honest
    /// `populate_plus_encode`-style sum) + the marginal DataFrame
    /// overhead on top of the floor.
    pub fn compute_ingress_headline(&mut self) {
        let (Some(floor), Some(e2e)) = (
            self.path("encode-floor"),
            self.path("flush-polars-dataframe"),
        ) else {
            return;
        };
        let floor_s = floor.median_s;
        let e2e_s = e2e.median_s;
        let mut h = Obj::new();
        h.float("encode_floor_s", floor_s);
        h.float("flush_polars_dataframe_s", e2e_s);
        h.float("dataframe_overhead_s", (e2e_s - floor_s).max(0.0));
        h.opt_float("encode_floor_rows_per_s", floor.rows_per_s_median);
        h.opt_float("flush_polars_dataframe_rows_per_s", e2e.rows_per_s_median);
        h.opt_float("flush_polars_dataframe_mib_per_s", e2e.mib_per_s);
        self.headline = h;
    }

    /// Egress headline (plan §3.6): `decode_plus_assemble` is the
    /// `fetch_all_polars` e2e (decode + assemble); `decode-only` is the
    /// floor; the marginal assemble is the difference. Headline the sum.
    pub fn compute_egress_headline(&mut self) {
        let (Some(decode), Some(assemble)) =
            (self.path("decode-only"), self.path("fetch-all-polars"))
        else {
            return;
        };
        let decode_s = decode.median_s;
        let assemble_s = assemble.median_s;
        let mut h = Obj::new();
        h.float("decode_floor_s", decode_s);
        h.float("assemble_plus_io_s", (assemble_s - decode_s).max(0.0));
        h.float("decode_plus_assemble_s", assemble_s);
        h.opt_float(
            "decode_plus_assemble_rows_per_s",
            assemble.rows_per_s_median,
        );
        h.opt_float("decode_plus_assemble_mib_per_s", assemble.mib_per_s);
        self.headline = h;
    }

    pub fn into_json(self) -> String {
        let mut top = Obj::new();
        top.str("schema", &self.schema);
        top.int("rows", self.rows as u64);
        top.int("columns", self.columns as u64);
        top.str("direction", &self.direction);
        top.str("client", &self.client);
        top.str("run_mode", &self.run_mode);
        top.int("warmups", self.warmups as u64);
        top.int("wire_bytes", self.wire_bytes);
        top.raw("machine", self.env.obj.to_json(0));
        top.raw("commits", commits_block().to_json(0));
        if !self.headline.0.is_empty() {
            top.raw("headline", self.headline.to_json(0));
        }
        // paths: a nested object keyed by path name.
        let mut paths = Obj::new();
        for (name, summary) in self.paths {
            paths.raw(&name, summary.into_json());
        }
        top.raw("paths", paths.to_json(0));
        if let Some(rc) = &self.row_count_check {
            let mut o = Obj::new();
            o.int("expected", rc.expected);
            o.int("actual", rc.actual);
            o.bool("ok", rc.ok);
            o.bool("inflated", rc.inflated);
            top.raw("row_count_check", o.to_json(0));
        }
        if let Some(c) = &self.real_conf {
            top.str("real_conf", c);
        }
        if let Some(h) = &self.http_base {
            top.str("http_base", h);
        }
        top.to_json(0)
    }
}

/// `commits` block (plan §3.2 / §3.7). Reads `C_QUESTDB_CLIENT_COMMIT`
/// from the environment if set (the build/run harness can inject it);
/// otherwise null, since an example binary has no repo access at runtime.
fn commits_block() -> Obj {
    let mut o = Obj::new();
    o.opt_str(
        "c_questdb_client",
        std::env::var("C_QUESTDB_CLIENT_COMMIT").ok().as_deref(),
    );
    o.opt_str(
        "py_questdb_client",
        std::env::var("PY_QUESTDB_CLIENT_COMMIT").ok().as_deref(),
    );
    o
}
