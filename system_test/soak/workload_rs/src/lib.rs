//! Soak / stress workload library.
//!
//! The pieces here are shared by the workload binary (`src/main.rs`) and its
//! tests. The load-bearing module is [`gen`]: the deterministic, cross-language
//! data generator that lets the soak oracle regenerate every expected
//! read-back value from `(seed, worker_id, seq)` alone.

pub mod column_leg;
#[cfg(feature = "dataframe")]
pub mod dataframe_leg;
pub mod egress_leg;
pub mod gen;
pub mod journal;
pub mod legs;
pub mod stats;
