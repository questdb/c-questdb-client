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

use crate::error;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum Op {
    Table,
    Symbol,
    Column,
    At,
    Flush,
}

impl Op {
    const fn bit(self) -> u8 {
        match self {
            Op::Table => 1,
            Op::Symbol => 1 << 1,
            Op::Column => 1 << 2,
            Op::At => 1 << 3,
            Op::Flush => 1 << 4,
        }
    }

    const fn descr(self) -> &'static str {
        match self {
            Op::Table => "table",
            Op::Symbol => "symbol",
            Op::Column => "column",
            Op::At => "at",
            Op::Flush => "flush",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum OpCase {
    Init,
    TableWritten,
    SymbolWritten,
    ColumnWritten,
    MayFlushOrTable,
}

impl OpCase {
    const fn allowed_ops(self) -> u8 {
        match self {
            OpCase::Init => Op::Table.bit(),
            OpCase::TableWritten => Op::Symbol.bit() | Op::Column.bit(),
            OpCase::SymbolWritten => Op::Symbol.bit() | Op::Column.bit() | Op::At.bit(),
            OpCase::ColumnWritten => Op::Column.bit() | Op::At.bit(),
            OpCase::MayFlushOrTable => Op::Flush.bit() | Op::Table.bit(),
        }
    }

    const fn allows(self, op: Op) -> bool {
        self.allowed_ops() & op.bit() != 0
    }

    fn next_op_descr(self) -> &'static str {
        match self {
            OpCase::Init => "should have called `table` instead",
            OpCase::TableWritten => "should have called `symbol` or `column` instead",
            OpCase::SymbolWritten => "should have called `symbol`, `column` or `at` instead",
            OpCase::ColumnWritten => "should have called `column` or `at` instead",
            OpCase::MayFlushOrTable => "should have called `flush` or `table` instead",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) struct OpState {
    op_case: OpCase,
}

impl OpState {
    pub(super) const fn new() -> Self {
        Self {
            op_case: OpCase::Init,
        }
    }

    pub(super) fn check(self, op: Op) -> crate::Result<()> {
        if self.op_case.allows(op) {
            Ok(())
        } else {
            Err(error::fmt!(
                InvalidApiCall,
                "State error: Bad call to `{}`, {}.",
                op.descr(),
                self.op_case.next_op_descr()
            ))
        }
    }

    pub(super) const fn can_set_marker(self) -> bool {
        self.op_case.allows(Op::Table)
    }

    pub(super) const fn allows_symbol(self) -> bool {
        self.op_case.allows(Op::Symbol)
    }

    pub(super) fn record_table(&mut self) {
        self.op_case = OpCase::TableWritten;
    }

    pub(super) fn record_symbol(&mut self) {
        self.op_case = OpCase::SymbolWritten;
    }

    pub(super) fn record_column(&mut self) {
        self.op_case = OpCase::ColumnWritten;
    }

    pub(super) fn finish_row(&mut self) {
        self.op_case = OpCase::MayFlushOrTable;
    }
}

#[cfg(test)]
mod tests {
    use super::{Op, OpState};
    use crate::ErrorCode;

    #[test]
    fn op_state_reports_exact_error_messages() {
        let mut state = OpState::new();

        let err = state.check(Op::Flush).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            "State error: Bad call to `flush`, should have called `table` instead."
        );

        state.record_table();
        let err = state.check(Op::Flush).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            "State error: Bad call to `flush`, should have called `symbol` or `column` instead."
        );

        state.record_symbol();
        let err = state.check(Op::Flush).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            "State error: Bad call to `flush`, should have called `symbol`, `column` or `at` instead."
        );

        state.record_column();
        let err = state.check(Op::Flush).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            "State error: Bad call to `flush`, should have called `column` or `at` instead."
        );

        state.finish_row();
        let err = state.check(Op::Symbol).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            "State error: Bad call to `symbol`, should have called `flush` or `table` instead."
        );
    }

    #[test]
    fn op_state_tracks_marker_and_field_separator_rules() {
        let mut state = OpState::new();
        assert!(state.can_set_marker());
        assert!(!state.allows_symbol());

        state.record_table();
        assert!(!state.can_set_marker());
        assert!(state.allows_symbol());

        state.record_symbol();
        assert!(!state.can_set_marker());
        assert!(state.allows_symbol());

        state.record_column();
        assert!(!state.can_set_marker());
        assert!(!state.allows_symbol());

        state.finish_row();
        assert!(state.can_set_marker());
        assert!(!state.allows_symbol());
    }
}
