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
            OpCase::Init => Op::Table.bit() | Op::Flush.bit(),
            OpCase::TableWritten => Op::Symbol.bit() | Op::Column.bit(),
            OpCase::SymbolWritten => Op::Symbol.bit() | Op::Column.bit() | Op::At.bit(),
            OpCase::ColumnWritten => Op::Column.bit() | Op::At.bit(),
            OpCase::MayFlushOrTable => Op::Flush.bit() | Op::Table.bit(),
        }
    }

    #[inline(always)]
    const fn allows(self, op: Op) -> bool {
        self.allowed_ops() & op.bit() != 0
    }

    fn next_op_descr(self) -> &'static str {
        match self {
            OpCase::Init => "should have called `table` or `flush` instead",
            OpCase::TableWritten => "should have called `symbol` or `column` instead",
            OpCase::SymbolWritten => "should have called `symbol`, `column` or `at` instead",
            OpCase::ColumnWritten => "should have called `column` or `at` instead",
            OpCase::MayFlushOrTable => "should have called `flush` or `table` instead",
        }
    }

    /// Advice tail for an op this case rejects.
    ///
    /// Usually just the per-case "what to call instead", but `symbol` after a
    /// non-symbol column earns its own message: the constraint belongs to ILP
    /// alone, and the substitute the generic advice points at (`column_str`)
    /// silently writes a different column type.
    fn rejected_op_descr(self, op: Op) -> &'static str {
        match (self, op) {
            (OpCase::ColumnWritten, Op::Symbol) => {
                "ILP requires all symbols before the row's first `column`; \
                 move the symbol earlier, or use a QWP buffer, where symbols \
                 may follow columns. `column_str` is not equivalent: it writes \
                 a VARCHAR, not a SYMBOL"
            }
            _ => self.next_op_descr(),
        }
    }

    /// The equivalent case for protocols where symbols are ordinary typed
    /// columns: a row that has written a non-symbol column is then in exactly
    /// the same position as one that has written a symbol.
    ///
    /// Both [`OpState::check_symbols_as_columns`] and its error message are
    /// derived from this single mapping, so the allowed-op set and the advice
    /// text cannot drift apart.
    #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
    const fn symbols_as_columns(self) -> Self {
        match self {
            OpCase::ColumnWritten => OpCase::SymbolWritten,
            other => other,
        }
    }
}

#[cold]
#[inline(never)]
fn bad_op_error(op_case: OpCase, op: Op) -> crate::Error {
    error::fmt!(
        InvalidApiCall,
        "State error: Bad call to `{}`, {}.",
        op.descr(),
        op_case.rejected_op_descr(op)
    )
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

    #[inline(always)]
    pub(super) fn check(self, op: Op) -> crate::Result<()> {
        if self.op_case.allows(op) {
            Ok(())
        } else {
            Err(self.bad_op_error(op))
        }
    }

    /// Checks a write for protocols where symbols are ordinary typed columns
    /// and may therefore follow non-symbol columns in the same row.
    ///
    /// Only that one edge is relaxed: a row still has to start with `table`
    /// and still has to end with `at`.
    #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
    #[inline(always)]
    pub(super) fn check_symbols_as_columns(self, op: Op) -> crate::Result<()> {
        let op_case = self.op_case.symbols_as_columns();
        if op_case.allows(op) {
            Ok(())
        } else {
            Err(bad_op_error(op_case, op))
        }
    }

    #[inline(always)]
    fn bad_op_error(self, op: Op) -> crate::Error {
        bad_op_error(self.op_case, op)
    }

    pub(super) const fn can_set_marker(self) -> bool {
        self.op_case.allows(Op::Table)
    }

    pub(super) fn ensure_marker_can_be_set(self) -> crate::Result<()> {
        self.ensure_rewind_point_can_be_set("marker")
    }

    pub(super) fn ensure_bookmark_can_be_set(self) -> crate::Result<()> {
        self.ensure_rewind_point_can_be_set("bookmark")
    }

    fn ensure_rewind_point_can_be_set(self, what: &'static str) -> crate::Result<()> {
        if self.can_set_marker() {
            Ok(())
        } else {
            Err(error::fmt!(
                InvalidApiCall,
                "Can't set the {} whilst constructing a line. \
                A {} may only be set on an empty buffer or after `at` or \
                `at_now` is called.",
                what,
                what
            ))
        }
    }

    pub(super) fn missing_marker_error() -> crate::Error {
        error::fmt!(InvalidApiCall, "Can't rewind to the marker: No marker set.")
    }

    /// ILP only: whether the next ILP field separator must be a space (the
    /// symbol section is still open) rather than a comma.
    ///
    /// This deliberately answers from the *strict* op set, so it disagrees
    /// with [`check_symbols_as_columns`](Self::check_symbols_as_columns) once
    /// a non-symbol column has been written. That is not a contradiction: the
    /// relaxed check governs QWP, which has no ILP field separator, while this
    /// predicate governs ILP line syntax, which is unchanged.
    pub(super) const fn ilp_symbol_section_is_open(self) -> bool {
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

        // Flush is allowed on an empty buffer (no-op).
        state.check(Op::Flush).unwrap();

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
        assert!(!state.ilp_symbol_section_is_open());

        state.record_table();
        assert!(!state.can_set_marker());
        assert!(state.ilp_symbol_section_is_open());

        state.record_symbol();
        assert!(!state.can_set_marker());
        assert!(state.ilp_symbol_section_is_open());

        state.record_column();
        assert!(!state.can_set_marker());
        assert!(!state.ilp_symbol_section_is_open());

        state.finish_row();
        assert!(state.can_set_marker());
        assert!(!state.ilp_symbol_section_is_open());
    }

    #[test]
    fn op_state_reports_ilp_symbol_ordering_in_its_own_message() {
        let mut state = OpState::new();
        state.record_table();
        state.record_column();

        let err = state.check(Op::Symbol).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            concat!(
                "State error: Bad call to `symbol`, ILP requires all symbols before ",
                "the row's first `column`; move the symbol earlier, or use a QWP ",
                "buffer, where symbols may follow columns. `column_str` is not ",
                "equivalent: it writes a VARCHAR, not a SYMBOL."
            )
        );

        // The advice for the *other* ops rejected in this state is unchanged.
        assert_eq!(
            state.check(Op::Flush).unwrap_err().msg(),
            "State error: Bad call to `flush`, should have called `column` or `at` instead."
        );
    }

    /// Unit test of [`OpState::check_symbols_as_columns`] in isolation. The
    /// end-to-end claim that ILP `Buffer`s still reject a symbol after a
    /// column is pinned by `ilp_buffer_rejects_symbol_after_column` in
    /// `crate::tests::sender`.
    #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
    #[test]
    fn op_state_symbols_as_columns_relaxes_only_symbol_after_column() {
        let mut state = OpState::new();
        state.record_table();
        state.record_column();

        assert!(state.check(Op::Symbol).is_err());
        state.check_symbols_as_columns(Op::Symbol).unwrap();

        state.record_symbol();
        state.check_symbols_as_columns(Op::Symbol).unwrap();
        state.check_symbols_as_columns(Op::Column).unwrap();
        state.check_symbols_as_columns(Op::At).unwrap();

        state.record_column();
        let err = state.check_symbols_as_columns(Op::Flush).unwrap_err();
        assert_eq!(
            err.msg(),
            "State error: Bad call to `flush`, should have called `symbol`, `column` or `at` instead."
        );

        // Narrowness: a row must still open with `table` and close with `at`.
        let mut state = OpState::new();
        assert!(state.check_symbols_as_columns(Op::Symbol).is_err());
        assert!(state.check_symbols_as_columns(Op::Column).is_err());
        assert!(state.check_symbols_as_columns(Op::At).is_err());

        state.record_table();
        let err = state.check_symbols_as_columns(Op::At).unwrap_err();
        assert_eq!(
            err.msg(),
            "State error: Bad call to `at`, should have called `symbol` or `column` instead."
        );

        state.record_column();
        state.finish_row();
        let err = state.check_symbols_as_columns(Op::Symbol).unwrap_err();
        assert_eq!(
            err.msg(),
            "State error: Bad call to `symbol`, should have called `flush` or `table` instead."
        );
        assert!(state.check_symbols_as_columns(Op::Column).is_err());
        assert!(state.check_symbols_as_columns(Op::At).is_err());
    }

    #[test]
    fn op_state_reports_marker_errors() {
        let mut state = OpState::new();
        state.record_table();

        let err = state.ensure_marker_can_be_set().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            concat!(
                "Can't set the marker whilst constructing a line. ",
                "A marker may only be set on an empty buffer or after ",
                "`at` or `at_now` is called."
            )
        );

        let err = OpState::missing_marker_error();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(err.msg(), "Can't rewind to the marker: No marker set.");
    }
}
