/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2022 QuestDB
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

//! # QuestDB Client Library for Rust
//! 
//! To start using `questdb-rs` add it to your `Cargo.toml`:
//! 
//! ```toml
//! [dependencies]
//! questdb-rs = "0.0.1"
//! ```
//! 
//! See the [ingress] module to insert data into QuestDB via the ILP protocol.
//!
//! # C, C++ and Python APIs
//! 
//! This crate is also exposed as a C and C++ API and in turn exposed to Python.
//! 
//! * This project's [GitHub page](https://github.com/questdb/c-questdb-client)
//!   for the C and C++ API.
//! * [Python bindings](https://github.com/questdb/py-questdb-client).
//! 
//! # Community
//! 
//! If you need help, have additional questions or want to provide feedback, you
//! may find us on [Slack](https://slack.questdb.io/).
//! 
//! You can also sign up to our [mailing list](https://questdb.io/community/) to
//! get notified of new releases.
//!

mod error;
pub mod ingress;
mod gai;
 
pub use error::*;

#[cfg(test)]
mod tests;