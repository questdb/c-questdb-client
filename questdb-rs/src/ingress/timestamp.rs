use crate::error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TIMESTAMP_NEG_BOUND: i128 = -9223372036854775808i128; // (i64::MIN * -1i64) as u128;
const TIMESTAMP_POS_BOUND: i128 = i64::MAX as i128;

/// Convert a `SystemTime` to a `Duration` to/from the UNIX epoch.
/// Returns a tuple of (is_negative, duration).
fn sys_time_to_duration(time: SystemTime, extract_fn: impl FnOnce(Duration) -> u128) -> i128 {
    if time >= UNIX_EPOCH {
        extract_fn(time.duration_since(UNIX_EPOCH).expect("time >= UNIX_EPOCH")) as i128
    } else {
        -1i128 * extract_fn(UNIX_EPOCH.duration_since(time).expect("time < UNIX_EPOCH")) as i128
    }
}

fn sys_time_convert(
    time: SystemTime,
    extract_fn: impl FnOnce(Duration) -> u128,
) -> crate::Result<i64> {
    let number = sys_time_to_duration(time, extract_fn);
    if number >= TIMESTAMP_NEG_BOUND && number <= TIMESTAMP_POS_BOUND {
        Ok(number as i64)
    } else {
        Err(error::fmt!(
            InvalidTimestamp,
            "Timestamp {:?} is out of range",
            time
        ))
    }
}

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
        Ok(Self(micros))
    }

    /// Get the numeric value of the timestamp.
    pub fn as_i64(&self) -> i64 {
        self.0
    }
}

impl TryFrom<SystemTime> for TimestampMicros {
    type Error = crate::Error;

    fn try_from(time: SystemTime) -> crate::Result<Self> {
        sys_time_convert(time, |d| d.as_micros()).map(Self)
    }
}

impl From<TimestampMicros> for SystemTime {
    fn from(timestamp: TimestampMicros) -> Self {
        UNIX_EPOCH + Duration::from_micros(timestamp.0 as u64)
    }
}

/// A `i64` timestamp expressed as nanoseconds since the UNIX epoch (UTC).
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
        Ok(Self(nanos))
    }

    /// Get the numeric value of the timestamp.
    pub fn as_i64(&self) -> i64 {
        self.0
    }
}

impl TryFrom<SystemTime> for TimestampNanos {
    type Error = crate::Error;

    fn try_from(time: SystemTime) -> crate::Result<Self> {
        sys_time_convert(time, |d| d.as_nanos()).map(Self)
    }
}

impl TryFrom<TimestampMicros> for TimestampNanos {
    type Error = crate::Error;

    fn try_from(ts: TimestampMicros) -> crate::Result<Self> {
        let nanos = ts.as_i64().checked_mul(1000i64);
        match nanos {
            Some(nanos) => Ok(Self(nanos)),
            None => Err(error::fmt!(
                InvalidTimestamp,
                "Timestamp {:?} is out of range",
                ts
            )),
        }
    }
}

impl From<TimestampNanos> for TimestampMicros {
    fn from(ts: TimestampNanos) -> Self {
        Self(ts.as_i64() / 1000i64)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Timestamp {
    Micros(TimestampMicros),
    Nanos(TimestampNanos),
}

impl From<TimestampMicros> for Timestamp {
    fn from(ts: TimestampMicros) -> Self {
        Self::Micros(ts)
    }
}

impl From<TimestampNanos> for Timestamp {
    fn from(ts: TimestampNanos) -> Self {
        Self::Nanos(ts)
    }
}

impl TryFrom<SystemTime> for Timestamp {
    type Error = crate::Error;

    fn try_from(time: SystemTime) -> crate::Result<Self> {
        Ok(Self::Nanos(time.try_into()?))
    }
}

impl TryFrom<Timestamp> for TimestampMicros {
    type Error = crate::Error;

    fn try_from(ts: Timestamp) -> crate::Result<Self> {
        match ts {
            Timestamp::Micros(ts) => Ok(ts),
            Timestamp::Nanos(ts) => Ok(ts.into()),
        }
    }
}

impl TryFrom<Timestamp> for TimestampNanos {
    type Error = crate::Error;

    fn try_from(ts: Timestamp) -> crate::Result<Self> {
        match ts {
            Timestamp::Micros(ts) => Ok(ts.try_into()?),
            Timestamp::Nanos(ts) => Ok(ts),
        }
    }
}
