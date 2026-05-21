/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
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

//! Bit masks carried by the `CACHE_RESET` (`0x17`) message's `reset_mask` byte.

/// Clear the connection-scoped symbol dictionary. After processing this
/// reset, the next batch carrying `FLAG_DELTA_SYMBOL_DICT` must have
/// `delta_start = 0`.
pub const RESET_MASK_DICT: u8 = 0x01;

/// Clear the connection-scoped schema registry. All previously assigned
/// `schema_id` values are discarded; post-reset ids may collide with
/// pre-reset ids.
pub const RESET_MASK_SCHEMAS: u8 = 0x02;

/// Convenience: returns true if the dict bit is set.
pub fn resets_dict(mask: u8) -> bool {
    mask & RESET_MASK_DICT != 0
}

/// Convenience: returns true if the schemas bit is set.
pub fn resets_schemas(mask: u8) -> bool {
    mask & RESET_MASK_SCHEMAS != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicates() {
        assert!(resets_dict(0x01));
        assert!(!resets_dict(0x02));
        assert!(resets_schemas(0x02));
        assert!(!resets_schemas(0x01));
        assert!(resets_dict(0x03));
        assert!(resets_schemas(0x03));
    }
}
