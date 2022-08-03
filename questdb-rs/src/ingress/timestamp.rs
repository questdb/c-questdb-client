use crate::error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TIMESTAMP_MAX: i64 = i64::MAX - 1;

#[derive(Copy, Clone, Debug)]
pub struct TimestampMicros(i64);

impl TimestampMicros {
    pub fn new(micros: i64) -> crate::Result<Self> {
        if micros >= 0 {
            Ok(Self(micros))
        } else {
            Err(error::fmt!(
                InvalidTimestamp,
                "Timestamp {} is negative. It must be >= 0.",
                micros))
        }
    }

    pub fn as_i64(&self) -> i64 {
        self.0
    }
}

impl TryFrom<SystemTime> for TimestampMicros {
    type Error = crate::Error;

    fn try_from(time: SystemTime) -> crate::Result<Self> {
        let duration = time.duration_since(UNIX_EPOCH)
            .map_err(|e| error::fmt!(
                // This will fail if before UNIX_EPOCH,
                // so this check also guarantees that the
                // eventual micros result will be >= 0.
                InvalidTimestamp,
                concat!(
                    "Could not calulate duration since UNIX_EPOCH",
                    " for timestamp {:?}: {}"),
                time,
                e))?;
        let micros: u128 = duration.as_micros();
        if micros <= (TIMESTAMP_MAX as u128) {
            Ok(Self(micros as i64))
        } else {
            Err(error::fmt!(
                InvalidTimestamp,
                concat!(
                    "Timestamp {:?} is too large to fit in a ",
                    "64-bit signed integer."),
                time))
        }
    }
}

impl From<TimestampMicros> for SystemTime {
    fn from(timestamp: TimestampMicros) -> Self {
        UNIX_EPOCH + Duration::from_micros(timestamp.0 as u64)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct TimestampNanos(i64);

impl TimestampNanos {
    pub fn new(nanos: i64) -> crate::Result<Self> {
        if nanos >= 0 {
            Ok(Self(nanos))
        } else {
            Err(error::fmt!(
                InvalidTimestamp,
                "Timestamp {} is negative. It must be >= 0.",
                nanos))
        }
    }

    pub fn as_i64(&self) -> i64 {
        self.0
    }
}

impl TryFrom<SystemTime> for TimestampNanos {
    type Error = crate::Error;

    fn try_from(time: SystemTime) -> crate::Result<Self> {
        let duration = time.duration_since(UNIX_EPOCH)
            .map_err(|e| error::fmt!(
                // This will fail if before UNIX_EPOCH,
                // so this check also guarantees that the
                // eventual nanos result will be >= 0.
                InvalidTimestamp,
                concat!(
                    "Could not calulate duration since UNIX_EPOCH",
                    " for timestamp {:?}: {}"),
                time,
                e))?;
        let nanos: u128 = duration.as_nanos();
        if nanos <= (TIMESTAMP_MAX as u128) {
            Ok(Self(nanos as i64))
        } else {
            Err(error::fmt!(
                InvalidTimestamp,
                concat!(
                    "Timestamp {:?} is too large to fit in a ",
                    "64-bit signed integer."),
                time))
        }
    }
}
