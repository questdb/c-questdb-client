//! Per-leg stats emitter (§S1). Writes one JSON line per sampling tick with the
//! **internal** signals the orchestrator can't see from outside: the pool
//! counts (via the S0 `dbg_pool_counts` surface) and the sender's own
//! published / acked frame watermarks plus row counters. The orchestrator
//! merges these with the externally-sampled RSS / FD and stamps `t` + `leg`
//! (see `soak.py` `_read_latest_internal`).

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

use questdb::{DbgPoolCount, QuestDb};

/// Appends JSON-line stats samples for one workload leg.
pub struct StatsWriter {
    out: BufWriter<File>,
}

impl StatsWriter {
    /// Create/truncate the stats file for this leg.
    pub fn create<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            out: BufWriter::new(file),
        })
    }

    /// Emit one sample. `published` / `acked` are the sender's frame watermarks
    /// (`published_fsn` / `acked_fsn`); `rows_sent` / `rows_acked` are the
    /// leg's own row counters.
    pub fn emit(
        &mut self,
        db: &QuestDb,
        rows_sent: u64,
        rows_acked: u64,
        published: Option<u64>,
        acked: Option<u64>,
    ) -> io::Result<()> {
        let p = db.dbg_pool_counts();
        writeln!(
            self.out,
            concat!(
                "{{\"pool\":{{",
                "\"column_sf\":{},\"column_direct\":{},",
                "\"row_sender\":{},\"reader\":{}}},",
                "\"rows_sent\":{},\"rows_acked\":{},",
                "\"published_fsn\":{},\"acked_fsn\":{}}}"
            ),
            triple(p.column_sf),
            triple(p.column_direct),
            triple(p.row_sender),
            triple(p.reader),
            rows_sent,
            rows_acked,
            opt(published),
            opt(acked),
        )?;
        // Flush the line so the orchestrator's tail read always sees whole
        // records; the OS buffers the write, this is not an fsync.
        self.out.flush()
    }
}

fn triple(c: DbgPoolCount) -> String {
    format!("[{},{},{}]", c.free, c.in_use, c.closing)
}

fn opt(v: Option<u64>) -> String {
    match v {
        Some(x) => x.to_string(),
        None => "null".to_string(),
    }
}
