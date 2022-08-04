use crate::error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TIMESTAMP_MAX: i64 = i64::MAX - 1;

/// A `i64` timestamp expressed as microseconds since the UNIX epoch (UTC).
/// 
/// The number can't be negative (i.e. can't be before 1970-01-01 00:00:00).
/// 
/// # Examples
/// 
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampMicros;
/// 
/// # fn main() -> Result<()> {
/// let ts = TimestampMicros::new(1659548204354448)?;
/// # Ok(())
/// # }
/// ```
/// 
/// or
/// 
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampMicros;
/// use std::convert::TryInto;
/// 
/// # fn main() -> Result<()> {
/// let ts: TimestampMicros = std::time::SystemTime::now().try_into()?;
/// # Ok(())
/// # }
/// ```
#[derive(Copy, Clone, Debug)]
pub struct TimestampMicros(i64);

impl TimestampMicros {
    /// Create a new timestamp from the given number of microseconds
    /// since the UNIX epoch (UTC).
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

    /// Get the numeric value of the timestamp.
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

/// A `i64` timestamp expressed as nanoseconds since the UNIX epoch (UTC).
/// 
/// The number can't be negative (i.e. can't be before 1970-01-01 00:00:00).
/// 
/// # Examples
/// 
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampNanos;
/// 
/// # fn main() -> Result<()> {
/// let ts = TimestampNanos::new(1659548315647406592)?;
/// # Ok(())
/// # }
/// ```
/// 
/// or
/// 
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampNanos;
/// use std::convert::TryInto;
/// 
/// # fn main() -> Result<()> {
/// let ts: TimestampNanos = std::time::SystemTime::now().try_into()?;
/// # Ok(())
/// # }
/// ```
#[derive(Copy, Clone, Debug)]
pub struct TimestampNanos(i64);

impl TimestampNanos {
    /// Create a new timestamp from the given number of nanoseconds
    /// since the UNIX epoch (UTC).
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

    /// Get the numeric value of the timestamp.
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
