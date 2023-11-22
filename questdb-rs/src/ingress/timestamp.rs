use crate::error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "chrono_timestamp")]
use chrono::{DateTime, TimeZone};

/// Convert a `SystemTime` to a `Duration` to/from the UNIX epoch.
/// Returns a tuple of (is_negative, duration).
#[inline]
fn sys_time_to_duration(time: SystemTime, extract_fn: impl FnOnce(Duration) -> u128) -> i128 {
    if time >= UNIX_EPOCH {
        extract_fn(time.duration_since(UNIX_EPOCH).expect("time >= UNIX_EPOCH")) as i128
    } else {
        -(extract_fn(UNIX_EPOCH.duration_since(time).expect("time < UNIX_EPOCH")) as i128)
    }
}

#[inline]
fn sys_time_convert(
    time: SystemTime,
    extract_fn: impl FnOnce(Duration) -> u128,
) -> crate::Result<i64> {
    let number = sys_time_to_duration(time, extract_fn);
    match i64::try_from(number) {
        Ok(number) => Ok(number),
        Err(_) => Err(error::fmt!(
            InvalidTimestamp,
            "Timestamp {:?} is out of range",
            time
        )),
    }
}

#[inline]
fn extract_current_timestamp(extract_fn: impl FnOnce(Duration) -> u128) -> crate::Result<i64> {
    let time = SystemTime::now();
    sys_time_convert(time, extract_fn)
}

/// A `i64` timestamp expressed as microseconds since the UNIX epoch (UTC).
///
/// # Examples
///
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampMicros;
///
/// # fn main() -> Result<()> {
/// let ts = TimestampMicros::now();
/// # Ok(())
/// # }
/// ```
///
/// or
///
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampMicros;
///
/// # fn main() -> Result<()> {
/// let ts = TimestampMicros::new(1695312859886554);
/// # Ok(())
/// # }
/// ```
///
/// or
///
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampMicros;
///
/// # fn main() -> Result<()> {
/// let ts = TimestampMicros::from_systemtime(std::time::SystemTime::now())?;
/// # Ok(())
/// # }
/// ```
///
/// or
///
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampMicros;
///
/// # fn main() -> Result<()> {
/// #[cfg(feature = "chrono_timestamp")]
/// let ts = TimestampMicros::from_datetime(chrono::Utc::now());
/// # Ok(())
/// # }
/// ```
#[derive(Copy, Clone, Debug)]
pub struct TimestampMicros(i64);

impl TimestampMicros {
    /// Current UTC timestamp in microseconds.
    pub fn now() -> Self {
        Self(extract_current_timestamp(|d| d.as_micros()).expect("now in range of micros"))
    }

    /// Create a new timestamp from the given number of microseconds
    /// since the UNIX epoch (UTC).
    pub fn new(micros: i64) -> Self {
        Self(micros)
    }

    #[cfg(feature = "chrono_timestamp")]
    pub fn from_datetime<T: TimeZone>(dt: DateTime<T>) -> Self {
        Self::new(dt.timestamp_micros())
    }

    pub fn from_systemtime(time: SystemTime) -> crate::Result<Self> {
        sys_time_convert(time, |d| d.as_micros()).map(Self)
    }

    /// Get the numeric value of the timestamp.
    pub fn as_i64(&self) -> i64 {
        self.0
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
/// let ts = TimestampNanos::now();
/// # Ok(())
/// # }
/// ```
///
/// or
///
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampNanos;
///
/// # fn main() -> Result<()> {
/// let ts = TimestampNanos::new(1659548315647406592);
/// # Ok(())
/// # }
/// ```
///
/// or
///
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampNanos;
///
/// # fn main() -> Result<()> {
/// let ts = TimestampNanos::from_systemtime(std::time::SystemTime::now())?;
/// # Ok(())
/// # }
/// ```
///
/// or
///
/// ```
/// # use questdb::Result;
/// use questdb::ingress::TimestampNanos;
///
/// # fn main() -> Result<()> {
/// # #[cfg(feature = "chrono_timestamp")]
/// let ts = TimestampNanos::from_datetime(chrono::Utc::now());
/// # Ok(())
/// # }
/// ```
///
#[derive(Copy, Clone, Debug)]
pub struct TimestampNanos(i64);

impl TimestampNanos {
    /// Current UTC timestamp in nanoseconds.
    pub fn now() -> Self {
        Self(extract_current_timestamp(|d| d.as_nanos()).expect("now in range of nanos"))
    }

    /// Create a new timestamp from the given number of nanoseconds
    /// since the UNIX epoch (UTC).
    pub fn new(nanos: i64) -> Self {
        Self(nanos)
    }

    #[cfg(feature = "chrono_timestamp")]
    pub fn from_datetime<T: TimeZone>(dt: DateTime<T>) -> crate::Result<Self> {
        match dt.timestamp_nanos_opt() {
            Some(nanos) => Ok(Self::new(nanos)),
            None => Err(error::fmt!(
                InvalidTimestamp,
                "Timestamp {:?} is out of range",
                dt
            )),
        }
    }

    pub fn from_systemtime(time: SystemTime) -> crate::Result<Self> {
        sys_time_convert(time, |d| d.as_nanos()).map(Self)
    }

    /// Get the numeric value of the timestamp.
    pub fn as_i64(&self) -> i64 {
        self.0
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

/// A timestamp expressed as micros or nanos.
/// You should seldom use this directly. Instead use one of:
///   * `TimestampNanos`
///   * `TimestampMicros`
///
/// Both of these types can `try_into()` the `Timestamp` type.
///
/// Both of these can be constructed from `std::time::SystemTime`,
/// or from `chrono::DateTime`.
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
