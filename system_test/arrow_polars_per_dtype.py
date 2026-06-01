from __future__ import annotations

import os
import sys
import unittest
from typing import Any, Callable, Optional

import pyarrow as pa

import arrow_fuzz_common as afc
from arrow_ffi import ArrowSenderError, SenderErrorCode


_ROWS = 4
_TS_BASE_US = 1_700_000_000_000_000


def _require_polars(testcase: unittest.TestCase):
    try:
        import polars as pl  # noqa: F401
    except ImportError:
        testcase.skipTest("polars is required for the Arrow-Polars dtype coverage tests")


def _polars_to_rb(df) -> pa.RecordBatch:
    arrow_obj = df.to_arrow()
    if isinstance(arrow_obj, pa.Table):
        batches = arrow_obj.to_batches()
        if len(batches) != 1:
            raise AssertionError(
                f"polars.to_arrow() produced {len(batches)} batches, expected 1"
            )
        return batches[0]
    return arrow_obj


def _ts_series_ns(pl, n: int):
    return pl.Series(
        "ts",
        [_TS_BASE_US * 1000 + i for i in range(n)],
        dtype=pl.Datetime("ns", time_zone="UTC"),
    )


def _create_table(fixture, table: str, ddl_body: str) -> None:
    afc.exec_ddl(
        fixture,
        f"CREATE TABLE '{table}' ({ddl_body}, ts TIMESTAMP) "
        f"TIMESTAMP(ts) PARTITION BY DAY WAL",
    )


def _try_ingest(testcase, table: str, df) -> Optional[Exception]:
    try:
        rb = _polars_to_rb(df)
        afc.ingest_via_arrow(testcase._fixture, table, rb, ts_col=b"ts")
        return None
    except unittest.SkipTest:
        # Let unittest propagate the skip; never wrap it as a returned error.
        raise
    except Exception as e:
        return e


def _wait_or_zero(testcase, table: str, expected: int, timeout: float = 8.0) -> int:
    import time as _t
    deadline = _t.monotonic() + timeout
    last = 0
    while _t.monotonic() < deadline:
        try:
            resp = testcase._fixture.http_sql_query(
                f"select count() from '{table}'")
            last = int(resp["dataset"][0][0])
            if last >= expected:
                return last
        except Exception:
            pass
        _t.sleep(0.1)
    return last


class TestArrowPolarsPerDtype(afc.ArrowFuzzBase):
    """One test method per polars data type. Supported dtypes must
    round-trip cleanly; unsupported ones must surface a deterministic
    error — either a client-side ``ArrowSenderError`` with a specific
    ``line_sender_error_code`` or a server-side rejection that leaves
    the pre-created table at 0 rows."""

    SUITE_LABEL = "arrow_polars_per_dtype"

    def setUp(self) -> None:
        super().setUp()
        _require_polars(self)

    def _expect_success(self, table: str, df, ddl_body: str) -> None:
        _create_table(self._fixture, table, ddl_body)
        err = _try_ingest(self, table, df)
        if err is not None:
            self.fail(self.label(
                f"polars round-trip expected to succeed; "
                f"got {type(err).__name__}: {err}"
            ))
        rows = _wait_or_zero(self, table, df.height)
        self.assertEqual(rows, df.height, self.label(
            f"row count after polars round-trip; got {rows} want {df.height}"))

    def _expect_client_reject(self, df, expected_code: int) -> None:
        table = self.fresh_table("polars_reject")
        err = _try_ingest(self, table, df)
        if not isinstance(err, ArrowSenderError):
            self.fail(self.label(
                f"expected ArrowSenderError, got {type(err).__name__ if err else 'None'}: {err}"
            ))
        self.assertEqual(
            err.code, expected_code,
            self.label(f"expected code={expected_code} got code={err.code} msg={err}")
        )

    def _expect_server_reject(self, df, ddl_body: str) -> None:
        table = self.fresh_table("polars_server_reject")
        _create_table(self._fixture, table, ddl_body)
        _try_ingest(self, table, df)
        rows = _wait_or_zero(self, table, 1, timeout=3.0)
        self.assertEqual(
            rows, 0,
            self.label(f"expected server to reject batch (0 rows); got {rows}")
        )

    def _maybe_skip(self, fn: Callable[[], Any], reason_prefix: str) -> Any:
        try:
            return fn()
        except Exception as e:
            self.skipTest(f"{reason_prefix}: {e}")

    # ---- Supported: round-trip required ---------------------------------

    def test_dtype_boolean(self):
        import polars as pl
        table = self.fresh_table("polars_boolean")
        df = pl.DataFrame({
            "c": pl.Series([True, False, True, False], dtype=pl.Boolean),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" BOOLEAN')

    def test_dtype_int8(self):
        import polars as pl
        table = self.fresh_table("polars_int8")
        df = pl.DataFrame({
            "c": pl.Series([1, -2, 0, 3], dtype=pl.Int8),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" BYTE')

    def test_dtype_int16(self):
        import polars as pl
        table = self.fresh_table("polars_int16")
        df = pl.DataFrame({
            "c": pl.Series([100, -100, 0, 200], dtype=pl.Int16),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" SHORT')

    def test_dtype_int32(self):
        import polars as pl
        table = self.fresh_table("polars_int32")
        df = pl.DataFrame({
            "c": pl.Series([1, -1, 0, 1_000_000], dtype=pl.Int32),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" INT')

    def test_dtype_int64(self):
        import polars as pl
        table = self.fresh_table("polars_int64")
        df = pl.DataFrame({
            "c": pl.Series([1, -1, 0, 1_000_000_000_000], dtype=pl.Int64),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" LONG')

    def test_dtype_float32(self):
        import polars as pl
        table = self.fresh_table("polars_float32")
        df = pl.DataFrame({
            "c": pl.Series([1.5, -2.5, 0.0, 3.25], dtype=pl.Float32),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" FLOAT')

    def test_dtype_float64(self):
        import polars as pl
        table = self.fresh_table("polars_float64")
        df = pl.DataFrame({
            "c": pl.Series([1.5, -2.5, 0.0, 1e10], dtype=pl.Float64),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" DOUBLE')

    def test_dtype_utf8(self):
        import polars as pl
        table = self.fresh_table("polars_utf8")
        df = pl.DataFrame({
            "c": pl.Series(["a", "bb", "", "日本語"], dtype=pl.Utf8),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" VARCHAR')

    def test_dtype_binary(self):
        import polars as pl
        table = self.fresh_table("polars_binary")
        df = pl.DataFrame({
            "c": pl.Series([b"\x01", b"\x02\x03", b"", b"\xff"], dtype=pl.Binary),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" BINARY')

    def test_dtype_datetime_us(self):
        import polars as pl
        table = self.fresh_table("polars_datetime_us")
        df = pl.DataFrame({
            "c": pl.Series(
                [_TS_BASE_US + i for i in range(_ROWS)],
                dtype=pl.Datetime("us", time_zone="UTC"),
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" TIMESTAMP')

    def test_dtype_datetime_ns(self):
        import polars as pl
        table = self.fresh_table("polars_datetime_ns")
        df = pl.DataFrame({
            "c": pl.Series(
                [_TS_BASE_US * 1000 + i for i in range(_ROWS)],
                dtype=pl.Datetime("ns", time_zone="UTC"),
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" TIMESTAMP_NS')

    def test_dtype_datetime_ms(self):
        import polars as pl
        table = self.fresh_table("polars_datetime_ms")
        df = pl.DataFrame({
            "c": pl.Series(
                [_TS_BASE_US // 1000 + i for i in range(_ROWS)],
                dtype=pl.Datetime("ms", time_zone="UTC"),
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" DATE')

    def test_dtype_decimal(self):
        import polars as pl
        from decimal import Decimal
        decimal_factory = getattr(pl, "Decimal", None)
        if decimal_factory is None:
            self.skipTest("this polars version has no Decimal dtype")
        dt = self._maybe_skip(
            lambda: decimal_factory(precision=18, scale=4),
            "polars Decimal construction",
        )
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series(
                    [Decimal("1.2345"), Decimal("-1.2345"),
                     Decimal("0"), Decimal("99.9999")],
                    dtype=dt,
                ),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars Decimal DataFrame construction",
        )
        table = self.fresh_table("polars_decimal")
        self._expect_success(table, df, '"c" DECIMAL(18,4)')

    def test_dtype_categorical_becomes_symbol(self):
        import polars as pl
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series(["AAPL", "MSFT", "AAPL", "GOOG"],
                               dtype=pl.Categorical),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars Categorical DataFrame construction",
        )
        table = self.fresh_table("polars_cat")
        self._expect_success(table, df, '"c" SYMBOL')

    def test_dtype_enum_becomes_symbol(self):
        import polars as pl
        enum_factory = getattr(pl, "Enum", None)
        if enum_factory is None:
            self.skipTest("this polars version has no Enum dtype")
        dt = self._maybe_skip(
            lambda: enum_factory(["AAPL", "MSFT", "GOOG"]),
            "polars Enum construction",
        )
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series(["AAPL", "MSFT", "AAPL", "GOOG"], dtype=dt),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars Enum DataFrame construction",
        )
        table = self.fresh_table("polars_enum")
        self._expect_success(table, df, '"c" SYMBOL')

    def test_dtype_datetime_us_naive(self):
        import polars as pl
        table = self.fresh_table("polars_datetime_us_naive")
        df = pl.DataFrame({
            "c": pl.Series(
                [_TS_BASE_US + i for i in range(_ROWS)],
                dtype=pl.Datetime("us"),
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" TIMESTAMP')

    def test_dtype_decimal_high_scale(self):
        import polars as pl
        from decimal import Decimal
        decimal_factory = getattr(pl, "Decimal", None)
        if decimal_factory is None:
            self.skipTest("this polars version has no Decimal dtype")
        dt = self._maybe_skip(
            lambda: decimal_factory(precision=38, scale=10),
            "polars Decimal(38, 10) construction",
        )
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series(
                    [Decimal("1.2345678901"), Decimal("-1.2345678901"),
                     Decimal("0"), Decimal("99.9999999999")],
                    dtype=dt,
                ),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars Decimal(38, 10) DataFrame construction",
        )
        table = self.fresh_table("polars_decimal_p38s10")
        self._expect_success(table, df, '"c" DECIMAL(38,10)')

    def test_dtype_list_float64(self):
        import polars as pl
        table = self.fresh_table("polars_list_f64")
        df = pl.DataFrame({
            "c": pl.Series(
                [[1.0, 2.0], [3.0], [], [4.0, 5.0, 6.0]],
                dtype=pl.List(pl.Float64),
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" DOUBLE[]')

    def test_dtype_list_list_float64_ragged_within_row_rejected(self):
        import polars as pl
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series(
                    [[[1.0, 2.0], [3.0]],
                     [[4.0, 5.0], [6.0, 7.0]],
                     [[8.0], [9.0]],
                     [[10.0, 11.0]]],
                    dtype=pl.List(pl.List(pl.Float64)),
                ),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars 2D ragged List(List(Float64)) construction",
        )
        self._expect_client_reject(df, SenderErrorCode.ARROW_INGEST)

    def test_dtype_list_list_float64(self):
        import polars as pl
        table = self.fresh_table("polars_list2d_f64")
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series(
                    [[[1.0, 2.0], [3.0, 4.0]],
                     [[5.0, 6.0]],
                     [[7.0, 8.0, 9.0], [10.0, 11.0, 12.0]],
                     [[13.0], [14.0], [15.0]]],
                    dtype=pl.List(pl.List(pl.Float64)),
                ),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars 2D List(List(Float64)) construction",
        )
        self._expect_success(table, df, '"c" DOUBLE[][]')

    def test_dtype_array_float64(self):
        import polars as pl
        array_factory = getattr(pl, "Array", None)
        if array_factory is None:
            self.skipTest("this polars version has no Array (fixed-size list) dtype")
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series(
                    [[1.0, 2.0, 3.0]] * _ROWS,
                    dtype=array_factory(pl.Float64, 3),
                ),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars Array (fixed-size list) construction",
        )
        table = self.fresh_table("polars_array_f64")
        self._expect_success(table, df, '"c" DOUBLE[]')

    # ---- Unsupported: client-side ArrowSenderError ---------------------

    def test_dtype_uint16_widens_to_int(self):
        import polars as pl
        table = self.fresh_table("polars_uint16")
        df = pl.DataFrame({
            "c": pl.Series([1, 2, 3, 4], dtype=pl.UInt16),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" INT')

    def test_dtype_uint32_widens_to_long(self):
        import polars as pl
        table = self.fresh_table("polars_uint32")
        df = pl.DataFrame({
            "c": pl.Series([1, 2, 3, 4], dtype=pl.UInt32),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" LONG')

    def test_dtype_uint8_widens_to_short(self):
        import polars as pl
        table = self.fresh_table("polars_uint8")
        df = pl.DataFrame({
            "c": pl.Series([1, 2, 3, 4], dtype=pl.UInt8),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" SHORT')

    def test_dtype_uint64_reinterprets_as_long(self):
        import polars as pl
        table = self.fresh_table("polars_uint64")
        df = pl.DataFrame({
            "c": pl.Series([1, 2, 3, 4], dtype=pl.UInt64),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" LONG')

    def test_dtype_int128_rejected_if_present(self):
        import polars as pl
        dt = getattr(pl, "Int128", None)
        if dt is None:
            self.skipTest("this polars version has no Int128 dtype")
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series([1, -1, 0, 10**30], dtype=dt),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars Int128 DataFrame construction",
        )
        table = self.fresh_table("polars_int128")
        err = _try_ingest(self, table, df)
        if err is None:
            self.fail(self.label("expected polars Int128 ingest to be rejected"))

    def test_dtype_date(self):
        import polars as pl
        import datetime as _dt
        table = self.fresh_table("polars_date")
        df = pl.DataFrame({
            "c": pl.Series(
                [_dt.date(2023, 11, 14) for _ in range(_ROWS)],
                dtype=pl.Date,
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" DATE')

    def test_dtype_time(self):
        import polars as pl
        import datetime as _dt
        table = self.fresh_table("polars_time")
        df = pl.DataFrame({
            "c": pl.Series(
                [_dt.time(12, 30, 0) for _ in range(_ROWS)],
                dtype=pl.Time,
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" LONG')

    def test_dtype_duration(self):
        import polars as pl
        import datetime as _dt
        table = self.fresh_table("polars_duration")
        df = pl.DataFrame({
            "c": pl.Series(
                [_dt.timedelta(seconds=i) for i in range(_ROWS)],
                dtype=pl.Duration("us"),
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_success(table, df, '"c" LONG')

    def test_dtype_struct_rejected(self):
        import polars as pl
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series(
                    [{"x": i, "y": float(i) * 0.5} for i in range(_ROWS)],
                    dtype=pl.Struct({"x": pl.Int32, "y": pl.Float64}),
                ),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars Struct DataFrame construction",
        )
        self._expect_client_reject(df, SenderErrorCode.ARROW_UNSUPPORTED_COLUMN_KIND)

    def test_dtype_list_utf8_rejected(self):
        import polars as pl
        df = pl.DataFrame({
            "c": pl.Series(
                [["a"], ["b", "c"], [], ["d"]],
                dtype=pl.List(pl.Utf8),
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_client_reject(df, SenderErrorCode.ARROW_UNSUPPORTED_COLUMN_KIND)

    def test_dtype_list_int64_rejected(self):
        import polars as pl
        df = pl.DataFrame({
            "c": pl.Series(
                [[1, 2], [3], [], [4, 5, 6]],
                dtype=pl.List(pl.Int64),
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_client_reject(df, SenderErrorCode.ARROW_UNSUPPORTED_COLUMN_KIND)

    def test_dtype_list_boolean_rejected(self):
        import polars as pl
        df = pl.DataFrame({
            "c": pl.Series(
                [[True, False], [True], [], [False]],
                dtype=pl.List(pl.Boolean),
            ),
            "ts": _ts_series_ns(pl, _ROWS),
        })
        self._expect_client_reject(df, SenderErrorCode.ARROW_UNSUPPORTED_COLUMN_KIND)

    def test_dtype_object_rejected(self):
        import polars as pl
        dt = getattr(pl, "Object", None)
        if dt is None:
            self.skipTest("this polars version has no Object dtype")
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series([{"k": i} for i in range(_ROWS)], dtype=dt),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars Object DataFrame construction",
        )
        err = _try_ingest(self, self.fresh_table("polars_object"), df)
        if err is None:
            self.fail(self.label("expected polars Object to be rejected"))

    def test_dtype_null_rejected(self):
        import polars as pl
        dt = getattr(pl, "Null", None)
        if dt is None:
            self.skipTest("this polars version has no Null dtype")
        df = self._maybe_skip(
            lambda: pl.DataFrame({
                "c": pl.Series([None] * _ROWS, dtype=dt),
                "ts": _ts_series_ns(pl, _ROWS),
            }),
            "polars Null DataFrame construction",
        )
        self._expect_client_reject(df, SenderErrorCode.ARROW_UNSUPPORTED_COLUMN_KIND)


def register(loop_registry):
    loop_registry.append(TestArrowPolarsPerDtype)


if __name__ == "__main__":
    print(
        "Note: arrow_polars_per_dtype tests require a live QuestDB fixture + polars. "
        "Run via `python test.py run --existing HOST:ILP:HTTP "
        "TestArrowPolarsPerDtype`.",
        file=sys.stderr,
    )
    unittest.main()
