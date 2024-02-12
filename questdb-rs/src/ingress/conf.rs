/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2024 QuestDB
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

use std::ops::Deref;

use crate::{Error, ErrorCode, Result};

/// Wraps a SenderBuilder config setting with the intent of tracking
/// whether the value was user-specified or defaulted.
/// The API then ensures the following rules:
/// * A defaulted value can be changed to another defaulted value,
///   or to a user-specified value.
/// * A user-specified value can't be changed once set.
#[derive(Debug, Clone)]
pub(crate) enum ConfigSetting<T> {
    Defaulted(T),
    Specified(T),
}

impl<T> ConfigSetting<T> {
    pub(crate) fn new_default(value: T) -> Self {
        ConfigSetting::Defaulted(value)
    }

    pub(crate) fn new_specified(value: T) -> Self {
        ConfigSetting::Specified(value)
    }

    /// Update the default value, usually because
    /// another setting was triggered.
    /// Does nothing if the value was already specified.
    /// Returns true if the value was updated.
    pub(crate) fn set_default(&mut self, value: T) -> Result<()> {
        if let ConfigSetting::Defaulted(_) = self {
            *self = ConfigSetting::Defaulted(value);
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::ConfigError,
                "set_default() called on a specified value",
            ))
        }
    }

    /// Set the user-defined value.
    /// Note that it can't be changed once set.
    /// Returns true if the value was updated, false if already specified.
    pub(crate) fn set_specified(&mut self, setting_name: &str, value: T) -> Result<()> {
        if let ConfigSetting::Defaulted(_) = self {
            *self = ConfigSetting::Specified(value);
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::ConfigError,
                format!("{setting_name} is already specified"),
            ))
        }
    }
}

impl<T> Deref for ConfigSetting<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            ConfigSetting::Defaulted(v) => v,
            ConfigSetting::Specified(v) => v,
        }
    }
}
