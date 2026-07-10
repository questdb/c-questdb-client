//! Fsync'd ack journal — the "gap-free by construction" mechanism (§S1).
//!
//! Every ingest leg appends its highest **durably-acked** `seq` to a per-worker
//! journal after each ack watermark advance, and `fsync`s it. Two guarantees
//! fall out:
//!
//! * **Recovery point.** After a client kill/restart the leg resumes at
//!   `watermark + 1`, so it never re-sends already-acked rows on the direct /
//!   SF-mem paths, and never skips a row on any path.
//! * **Oracle lower bound.** The journal is the authoritative "every `seq` up
//!   to here must be readable back" watermark the completeness invariant (I1)
//!   checks against — independent of the client under test.
//!
//! Crash safety: records are newline-terminated and the file is `fsync`'d after
//! each append. A process killed mid-append can leave a torn trailing line with
//! no newline; [`AckJournal::recover`] ignores it and trusts only fully written
//! (newline-terminated) records, so recovery never reads a half-written number.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// An append-only, fsync'd log of monotonically increasing acked-`seq`
/// watermarks for one worker.
#[derive(Debug)]
pub struct AckJournal {
    file: File,
    path: PathBuf,
    last: Option<u64>,
}

impl AckJournal {
    /// Open (creating if absent) the journal at `path`, positioning at its end
    /// for appends. The current watermark is recovered from any existing
    /// content — so opening an existing journal resumes it.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let last = Self::recover(&path)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { file, path, last })
    }

    /// The highest watermark recorded so far, or `None` for a fresh journal.
    pub fn watermark(&self) -> Option<u64> {
        self.last
    }

    /// The `seq` to resume ingest from: `watermark + 1`, or 0 for a fresh
    /// journal.
    pub fn resume_seq(&self) -> u64 {
        self.last.map_or(0, |w| w + 1)
    }

    /// Append `watermark` and `fsync`. Must be monotonically non-decreasing:
    /// an attempt to record a lower watermark is a bug (an ack watermark never
    /// goes backwards) and returns an error rather than corrupting the log.
    pub fn record(&mut self, watermark: u64) -> io::Result<()> {
        if let Some(prev) = self.last {
            if watermark < prev {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("ack watermark went backwards: {watermark} < {prev}"),
                ));
            }
            if watermark == prev {
                return Ok(()); // no-op: nothing new acked
            }
        }
        writeln!(self.file, "{watermark}")?;
        self.file.flush()?;
        self.file.sync_all()?;
        self.last = Some(watermark);
        Ok(())
    }

    /// Read the recovery watermark from `path` without opening a live journal:
    /// the last **newline-terminated** record, ignoring a torn trailing line.
    /// Returns `None` if the file is absent or has no complete record.
    pub fn recover<P: AsRef<Path>>(path: P) -> io::Result<Option<u64>> {
        let mut file = match File::open(path.as_ref()) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        // Only trust records followed by a newline. `split('\n')` yields the
        // trailing (possibly torn / empty) segment as its last element; skip it.
        let mut segments: Vec<&str> = content.split('\n').collect();
        segments.pop(); // drop the trailing partial / empty segment

        let mut last = None;
        for seg in segments {
            let seg = seg.trim();
            if seg.is_empty() {
                continue;
            }
            match seg.parse::<u64>() {
                Ok(v) => last = Some(v),
                // A corrupt complete line is unexpected; surface it rather than
                // silently skipping, since it means the journal is untrustworthy.
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("corrupt journal record: {seg:?}"),
                    ))
                }
            }
        }
        Ok(last)
    }

    /// The journal's path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*; // brings in `Write` (used by write!/writeln! in the tests)

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "soak_journal_{}_{}_{}.log",
            std::process::id(),
            name,
            // Cheap uniqueness without rand/time crates.
            name.len()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn records_and_reopens_at_watermark() {
        let path = temp_path("reopen");
        {
            let mut j = AckJournal::open(&path).unwrap();
            assert_eq!(j.watermark(), None);
            assert_eq!(j.resume_seq(), 0);
            j.record(0).unwrap();
            j.record(15).unwrap();
            j.record(16383).unwrap();
            assert_eq!(j.watermark(), Some(16383));
            assert_eq!(j.resume_seq(), 16384);
        }
        // Reopen recovers the last watermark.
        let j2 = AckJournal::open(&path).unwrap();
        assert_eq!(j2.watermark(), Some(16383));
        assert_eq!(j2.resume_seq(), 16384);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rejects_backwards_watermark_and_ignores_repeat() {
        let path = temp_path("monotonic");
        let mut j = AckJournal::open(&path).unwrap();
        j.record(100).unwrap();
        // Repeat is a harmless no-op (nothing new acked).
        j.record(100).unwrap();
        assert_eq!(j.watermark(), Some(100));
        // Backwards is a bug and must be rejected.
        let err = j.record(99).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(j.watermark(), Some(100));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn recovery_ignores_torn_trailing_line() {
        let path = temp_path("torn");
        {
            let mut j = AckJournal::open(&path).unwrap();
            j.record(7).unwrap();
            j.record(42).unwrap();
        }
        // Simulate a crash mid-append: a trailing record with no newline.
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            write!(f, "9999").unwrap(); // no '\n' — torn
            f.sync_all().unwrap();
        }
        // Recovery must trust only the last complete (newline-terminated) record.
        assert_eq!(AckJournal::recover(&path).unwrap(), Some(42));
        let j = AckJournal::open(&path).unwrap();
        assert_eq!(j.watermark(), Some(42));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn recover_absent_file_is_none() {
        let path = temp_path("absent");
        assert_eq!(AckJournal::recover(&path).unwrap(), None);
    }

    #[test]
    fn corrupt_complete_line_surfaces_error() {
        let path = temp_path("corrupt");
        {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(f, "12").unwrap();
            writeln!(f, "not_a_number").unwrap();
            f.sync_all().unwrap();
        }
        let err = AckJournal::recover(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        std::fs::remove_file(&path).unwrap();
    }
}
