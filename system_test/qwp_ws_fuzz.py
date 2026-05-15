################################################################################
##     ___                  _   ____  ____
##    / _ \ _   _  ___  ___| |_|  _ \| __ )
##   | | | | | | |/ _ \/ __| __| | | |  _ \
##   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
##    \__\_\\__,_|\___||___/\__|____/|____/
##
##  Copyright (c) 2014-2019 Appsicle
##  Copyright (c) 2019-2026 QuestDB
##
##  Licensed under the Apache License, Version 2.0 (the "License");
##  you may not use this file except in compliance with the License.
##  You may obtain a copy of the License at
##
##  http://www.apache.org/licenses/LICENSE-2.0
##
##  Unless required by applicable law or agreed to in writing, software
##  distributed under the License is distributed on an "AS IS" BASIS,
##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##  See the License for the specific language governing permissions and
##  limitations under the License.
##
################################################################################

"""Helpers for the QWP/WebSocket Python fuzz tests.

Ports the schema-fuzz behaviour of
`io.questdb.test.cutlass.qwp.e2e.QwpSenderFuzzTest` so that we can run the same
shape of test against a real QuestDB fixture using the Rust client.

The helpers here are deliberately stateless and self-contained so that
`test.py` can pull them in without dragging the rest of the fuzz machinery
into module import time. Test discovery still happens in `test.py` (which
defines `TestQwpWsFuzz` on top of these helpers); putting the class there
keeps the fuzz suite consistent with `TestQwpWsSender` /
`TestQwpWsRestart` and avoids circular imports against the fixture
globals.

Reproducer model
================

Every test seeds a master RNG and prints it to stderr exactly once at
`setUp()`. Set ``QWP_WS_FUZZ_SEED`` (hex with ``0x`` prefix or decimal) to
re-run a failure. The master RNG only ever derives child seeds — for each
producer thread and for the optional ALTER thread — so freezing the master
seed reproduces every downstream stream.
"""

import sys

sys.dont_write_bytecode = True

import datetime
import os
import random
import secrets
import threading
import time
import urllib.error

import numpy as np
import questdb_line_sender as qls


# ---------------------------------------------------------------------------
# Fuzz constants — mirror QwpSenderFuzzTest exactly so we can cross-reference.
# ---------------------------------------------------------------------------

MAX_NUM_OF_SKIPPED_COLS = 2
NEW_COLUMN_RANDOMIZE_FACTOR = 2
SEND_SYMBOLS_WITH_SPACE_RANDOMIZE_FACTOR = 2
UPPERCASE_TABLE_RANDOMIZE_FACTOR = 2

BATCH_SIZE = 10

# (column-type label, integer-conversion compatible types) used by the ALTER
# thread to pick a valid target type.
INTEGER_COLUMN_TYPES = ('BYTE', 'SHORT', 'INT', 'LONG')

COL_NAME_BASES = (
    # ----- Java-parity columns (STRING/DOUBLE × 6) -----
    ('terület', 'TERÜLet', 'tERülET', 'TERÜLET'),
    ('temperature', 'TEMPERATURE', 'Temperature', 'TempeRaTuRe'),
    ('humidity', 'HUMIdity', 'HumiditY', 'HUmiDIty', 'HUMIDITY', 'Humidity'),
    ('hőmérséklet', 'HŐMÉRSÉKLET',
     'HŐmérséKLEt', 'hőMÉRséKlET'),
    ('notes', 'NOTES', 'NotEs', 'noTeS'),
    ('ветер', 'Ветер',
     'ВЕТЕР', 'вЕТЕр',
     'ВетЕР'),
    # ----- Extended wire-type coverage (not in Java) -----
    ('flag', 'FLAG', 'Flag', 'flAG'),                  # BOOLEAN
    ('count', 'COUNT', 'CounT', 'Count'),              # LONG (i64)
    ('price', 'PRICE', 'pRICE', 'Price'),              # DECIMAL256
    # Arrays are split by rank because the server locks in
    # dimensionality on first row — sending a different rank later
    # gets the batch silently dropped, which would divorce producer-
    # side expected counts from server-side reality.
    ('series_1d', 'SERIES_1D', 'sERIES_1d', 'Series_1d'),  # DOUBLE[]
    ('series_2d', 'SERIES_2D', 'sERIES_2d', 'Series_2d'),  # DOUBLE[][]
    ('event_us', 'EVENT_US', 'event_Us', 'Event_US'),  # TIMESTAMP (micros)
    ('event_ns', 'EVENT_NS', 'event_Ns', 'Event_NS'),  # TIMESTAMP (nanos)
)
COL_TYPES = (
    # Java-parity types — share `COL_VALUE_BASES` numeric strings.
    'STRING', 'DOUBLE', 'DOUBLE', 'DOUBLE', 'STRING', 'DOUBLE',
    # Extended types.
    'BOOLEAN', 'LONG', 'DECIMAL256',
    'DOUBLE_ARRAY_1D', 'DOUBLE_ARRAY_2D',
    'TIMESTAMP_MICROS', 'TIMESTAMP_NANOS',
)
COL_VALUE_BASES = (
    'europe', '8', '2', '1', 'note', '6',
    # Extended types — the per-type generator below ignores the base
    # for those that don't need it. LONG / DECIMAL still use it as a
    # numeric magnitude so values stay readable in failure logs.
    '', '4', '7',
    '', '',
    '', '',
)

NON_ASCII_CHARS = (
    'ó', 'í', 'Á', 'ч', 'Ъ', 'Ж', 'ю',
    '　', 'む', '㩕',
)

SYMBOL_NAME_BASES = (
    ('location', 'Location', 'LOCATION', 'loCATion', 'LocATioN'),
    ('city', 'ciTY', 'CITY'),
)
SYMBOL_VALUE_BASES = ('us-midwest', 'London')


def is_windows() -> bool:
    return sys.platform == 'win32'


# ---------------------------------------------------------------------------
# RNG.
# ---------------------------------------------------------------------------

class Rng:
    """``random.Random`` wrapper with java.util.Random-style helpers.

    We don't byte-match Java's `Rnd` — we just need the same shape of API
    (next_int(bound), next_boolean, shuffle, child) so a frozen master seed
    deterministically reproduces every per-thread stream.
    """

    __slots__ = ('_impl', 'seed')

    def __init__(self, seed: int):
        self.seed = seed & ((1 << 64) - 1)
        self._impl = random.Random(self.seed)

    def next_int(self, bound: int) -> int:
        if bound <= 0:
            raise ValueError('bound must be positive')
        return self._impl.randrange(bound)

    def next_boolean(self) -> bool:
        return self._impl.getrandbits(1) == 1

    def next_long(self) -> int:
        """Random 64-bit non-negative int — used to derive child seeds."""
        return self._impl.getrandbits(64)

    def next_ascii_letter(self) -> str:
        """Pick a random ASCII letter (analog of Java's nextChar in our test).

        Java's `rnd.nextChar()` returns any 16-bit value. The fuzz only uses it
        as a postfix on string/symbol values, so we restrict to ASCII letters
        — that keeps the values readable in failure logs without losing fuzz
        coverage (non-ASCII coverage comes from `non_ascii_value_factor`).
        """
        return chr(0x41 + self._impl.randrange(26))

    def shuffle(self, seq):
        self._impl.shuffle(seq)

    def child(self) -> 'Rng':
        return Rng(self.next_long())


def derive_master_seed() -> int:
    raw = os.environ.get('QWP_WS_FUZZ_SEED')
    if raw is None or not raw.strip():
        return secrets.randbits(64)
    raw = raw.strip()
    if raw.lower().startswith('0x'):
        return int(raw, 16)
    return int(raw)


def format_seed(seed: int) -> str:
    return f'0x{seed:016x}'


# ---------------------------------------------------------------------------
# Oracle data classes — ported from
# io.questdb.test.cutlass.line.tcp.load.{LineData, TableData}.
# ---------------------------------------------------------------------------

class LineData:
    """One row's worth of (col_name, formatted_value) pairs.

    Mirrors Java's `LineData` semantics for duplicates: the *first* write
    of a given column name within a line wins when we look up the expected
    value (Java uses ``putIfAbsent``).

    Java's `isValid()` also marks lines with a space in a tag value as
    invalid — that came from ILP/TCP where the wire encoding literally
    can't represent the space. QWP/WS is binary and carries the space
    faithfully, so every line we send is valid on the wire here and the
    oracle has to include it. See ``is_valid`` below.

    Values are stored already stringified the way they should appear in
    the comparison (no surrounding quotes for STRING — Java's
    `getValue` strips them; we just don't add them).
    """

    __slots__ = (
        '_timestamp_us',
        '_names',
        '_values',
        '_is_tag',
        '_name_to_first_index',
    )

    def __init__(self, timestamp_us: int):
        self._timestamp_us = timestamp_us
        self._names = []
        self._values = []
        self._is_tag = []
        self._name_to_first_index = {}

    @property
    def timestamp_us(self) -> int:
        return self._timestamp_us

    def add_tag(self, name: str, value: str):
        self._add(name, value, True)

    def add_column(self, name: str, value: str):
        self._add(name, value, False)

    def _add(self, name: str, value: str, is_tag: bool):
        self._names.append(name)
        self._values.append(value)
        self._is_tag.append(is_tag)
        key = name.lower()
        if key not in self._name_to_first_index:
            self._name_to_first_index[key] = len(self._names) - 1

    def is_valid(self) -> bool:
        # QWP/WS is a binary protocol — every well-formed call is wire-valid.
        # Kept as a method (rather than removed) so the oracle code paths
        # match Java's structure and can be tightened later if a real
        # invalidation case turns up.
        return True

    def get_value(self, name: str):
        idx = self._name_to_first_index.get(name.lower())
        if idx is None:
            return None
        return self._values[idx]


class TableData:
    """Thread-safe per-table buffer of expected rows."""

    def __init__(self, name: str):
        self._name = name
        self._lock = threading.Lock()
        self._rows = []

    @property
    def name(self) -> str:
        return self._name

    def add_line(self, line: LineData):
        with self._lock:
            self._rows.append(line)

    def all_rows(self):
        with self._lock:
            return list(self._rows)

    def valid_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._rows if r.is_valid())

    def valid_rows_sorted(self):
        rows = [r for r in self.all_rows() if r.is_valid()]
        rows.sort(key=lambda r: r.timestamp_us)
        return rows


# ---------------------------------------------------------------------------
# Value formatting — server side comes from /exec JSON, expected side comes
# from LineData. We canonicalize both to strings using the server's reported
# column type so ALTER TABLE conversions stay invisible to the comparison.
# ---------------------------------------------------------------------------

_NUMERIC_INT_TYPES = ('BYTE', 'SHORT', 'INT', 'LONG')
_NUMERIC_FLOAT_TYPES = ('FLOAT', 'DOUBLE')
_STRING_LIKE_TYPES = ('STRING', 'SYMBOL', 'VARCHAR', 'CHAR')


def _is_decimal_type(server_type: str) -> bool:
    # Server reports DECIMAL columns either as bare 'DECIMAL' or as
    # 'DECIMAL(p,s)' depending on whether scale/precision were inferred.
    return server_type.startswith('DECIMAL')


def _is_timestamp_type(server_type: str) -> bool:
    # QuestDB reports both microsecond and nanosecond timestamp columns;
    # the suffix encodes precision (`TIMESTAMP_NS`). Both round-trip
    # through `_iso_to_nanos` so we treat them identically here.
    return server_type == 'TIMESTAMP' or server_type.startswith('TIMESTAMP_')


def _is_array_type(server_type: str) -> bool:
    # 'DOUBLE[]', 'DOUBLE[][]', and any future array types include '['.
    return '[' in server_type


def _missing_default(server_type: str) -> str:
    # When a producer omits a column from a line, the server picks a
    # per-type default. JSON renders DOUBLE/FLOAT/array NULLs as null;
    # BOOLEAN has no null sentinel and defaults to false; everything
    # else comes back as null too. We canonicalise to the strings the
    # actual-side formatter would produce.
    if server_type in _NUMERIC_FLOAT_TYPES:
        return 'null'
    if _is_array_type(server_type):
        return 'null'
    if server_type == 'BOOLEAN':
        return 'false'
    return ''


def format_expected_cell(value, server_type: str) -> str:
    """Format an expected (producer-side) value to the comparison string."""
    if value is None:
        return _missing_default(server_type)
    if server_type in _NUMERIC_FLOAT_TYPES:
        try:
            return _format_float(float(value))
        except (TypeError, ValueError):
            return str(value)
    if server_type in _NUMERIC_INT_TYPES:
        try:
            return str(int(float(value)))
        except (TypeError, ValueError):
            return str(value)
    if server_type == 'BOOLEAN':
        if isinstance(value, str):
            return value.lower()
        return 'true' if value else 'false'
    if _is_timestamp_type(server_type):
        # Expected values are integers in nanoseconds-since-epoch (see
        # add_column_value for TIMESTAMP_MICROS / TIMESTAMP_NANOS).
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str):
            return str(_iso_to_nanos(value))
        return str(value)
    if _is_decimal_type(server_type):
        return _normalize_decimal(value)
    if _is_array_type(server_type):
        return _format_array(value)
    return str(value)


def format_actual_cell(value, server_type: str) -> str:
    """Format an actual cell value (from /exec JSON) to the comparison string."""
    if value is None:
        return _missing_default(server_type)
    if server_type in _NUMERIC_FLOAT_TYPES:
        try:
            return _format_float(float(value))
        except (TypeError, ValueError):
            return str(value)
    if server_type in _NUMERIC_INT_TYPES:
        try:
            return str(int(value))
        except (TypeError, ValueError):
            return str(value)
    if server_type == 'BOOLEAN':
        if isinstance(value, bool):
            return 'true' if value else 'false'
        return str(value).lower()
    if _is_timestamp_type(server_type):
        if isinstance(value, str):
            return str(_iso_to_nanos(value))
        if isinstance(value, int):
            return str(value)
        return str(value)
    if _is_decimal_type(server_type):
        return _normalize_decimal(value)
    if _is_array_type(server_type):
        return _format_array(value)
    return str(value)


def _format_float(f: float) -> str:
    # Match QuestDB /exec JSON: integer-valued doubles render as e.g. "80.0".
    if f == 0.0:
        # Avoid "-0.0" vs "0.0" mismatch.
        return '0.0'
    return repr(f)


def _format_array(value) -> str:
    """Canonical bracketed form of a (possibly nested) numeric array."""
    if isinstance(value, (list, tuple)):
        return '[' + ','.join(_format_array(v) for v in value) + ']'
    if value is None:
        return 'null'
    try:
        return _format_float(float(value))
    except (TypeError, ValueError):
        return str(value)


def _normalize_decimal(value) -> str:
    """Stringify a DECIMAL value so producer side and server side agree
    on '80.05' regardless of whether the input came in as str / int /
    float / Decimal."""
    if value is None:
        return ''
    s = str(value)
    # Strip trailing zeros after the decimal point but keep at least the
    # fractional pair we sent, so '80.05' stays '80.05' both ways. Server
    # never adds trailing zeros beyond the column scale, so just lowercase
    # any 'E' notation Python may emit for very large magnitudes.
    return s.lower()


_ISO_FORMATS_BY_FRAC_DIGITS = {
    0: '%Y-%m-%dT%H:%M:%S',
    3: '%Y-%m-%dT%H:%M:%S.%f',
    6: '%Y-%m-%dT%H:%M:%S.%f',
    9: '%Y-%m-%dT%H:%M:%S.%f',
}


def _iso_to_nanos(s: str) -> int:
    """Parse an /exec TIMESTAMP string into nanoseconds-since-epoch.

    QuestDB returns the timestamp with the fractional precision matching
    the stored column type (3/6/9 digits). We pad to 9 digits and treat
    them all as nanoseconds so the oracle compares apples-to-apples
    whether the producer sent micros or nanos.
    """
    if not isinstance(s, str):
        return int(s)
    text = s
    if text.endswith('Z'):
        text = text[:-1]
    if '.' in text:
        date_part, frac = text.split('.', 1)
        # Pad/truncate to nine digits — keep raw nanos precision.
        frac9 = (frac + '000000000')[:9]
    else:
        date_part, frac9 = text, '000000000'
    dt = datetime.datetime.strptime(date_part, '%Y-%m-%dT%H:%M:%S')
    dt = dt.replace(tzinfo=datetime.timezone.utc)
    secs = int(dt.timestamp())
    return secs * 1_000_000_000 + int(frac9)


# ---------------------------------------------------------------------------
# Name / value generators — direct ports of the Java helpers.
# ---------------------------------------------------------------------------

def should_fuzz(fuzz_factor: int, rnd: Rng) -> bool:
    return fuzz_factor > 0 and rnd.next_int(fuzz_factor) == 0


def generate_name(bases, randomize: bool, diff_cases: bool, rnd: Rng) -> str:
    case_index = rnd.next_int(len(bases)) if diff_cases else 0
    postfix = str(rnd.next_int(NEW_COLUMN_RANDOMIZE_FACTOR)) if randomize else ''
    return bases[case_index] + postfix


def generate_column_name(index: int, randomize: bool, diff_cases: bool, rnd: Rng) -> str:
    return generate_name(COL_NAME_BASES[index], randomize, diff_cases, rnd)


def generate_symbol_name(index: int, randomize: bool, diff_cases: bool, rnd: Rng) -> str:
    return generate_name(SYMBOL_NAME_BASES[index], randomize, diff_cases, rnd)


def generate_ordering(num_cols: int, reorder_factor: int, rnd: Rng):
    indexes = list(range(num_cols))
    if should_fuzz(reorder_factor, rnd):
        rnd.shuffle(indexes)
    return indexes


def skip_columns(indexes, skip_factor: int, rnd: Rng):
    if not should_fuzz(skip_factor, rnd):
        return list(indexes)
    indexes = list(indexes)
    num_to_skip = rnd.next_int(MAX_NUM_OF_SKIPPED_COLS) + 1
    num_to_skip = min(num_to_skip, max(0, len(indexes) - 1))
    for _ in range(num_to_skip):
        if not indexes:
            break
        del indexes[rnd.next_int(len(indexes))]
    return indexes


# ---------------------------------------------------------------------------
# Per-line construction — see Java `generateLine` for the original.
# ---------------------------------------------------------------------------

class FuzzParams:
    """Fuzz axis settings for one test method, mirroring Java's
    `initFuzzParameters` plus our extensions for ALTER COLUMN TYPE
    racing and server-bounce chaos."""

    __slots__ = (
        'duplicates_factor',
        'column_reordering_factor',
        'column_skip_factor',
        'new_column_factor',
        'non_ascii_value_factor',
        'diff_cases_in_col_names',
        'exercise_symbols',
        'send_symbols_with_space',
        'column_convert_prob',
        'max_bounces',
        'min_bounce_interval_s',
        'max_bounce_interval_s',
    )

    def __init__(
            self,
            duplicates_factor=-1,
            column_reordering_factor=-1,
            column_skip_factor=-1,
            new_column_factor=-1,
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=False,
            exercise_symbols=True,
            send_symbols_with_space=False,
            column_convert_prob=0.0,
            max_bounces=0,
            min_bounce_interval_s=0.5,
            max_bounce_interval_s=3.0):
        self.duplicates_factor = duplicates_factor
        self.column_reordering_factor = column_reordering_factor
        self.column_skip_factor = column_skip_factor
        self.new_column_factor = new_column_factor
        self.non_ascii_value_factor = non_ascii_value_factor
        self.diff_cases_in_col_names = diff_cases_in_col_names
        self.exercise_symbols = exercise_symbols
        self.send_symbols_with_space = send_symbols_with_space
        self.column_convert_prob = column_convert_prob
        self.max_bounces = max_bounces
        self.min_bounce_interval_s = min_bounce_interval_s
        self.max_bounce_interval_s = max(
            min_bounce_interval_s, max_bounce_interval_s)


class LoadParams:
    """Load shape for one test method, mirroring Java's
    `initLoadParameters`."""

    __slots__ = (
        'num_of_lines',
        'num_of_iterations',
        'num_of_threads',
        'num_of_tables',
        'wait_between_iterations_ms',
    )

    def __init__(
            self,
            num_of_lines: int,
            num_of_iterations: int,
            num_of_threads: int,
            num_of_tables: int,
            wait_between_iterations_ms: int):
        self.num_of_lines = num_of_lines
        self.num_of_iterations = num_of_iterations
        self.num_of_threads = num_of_threads
        self.num_of_tables = num_of_tables
        self.wait_between_iterations_ms = wait_between_iterations_ms


def add_column_value(col_type: str, value_base: str, col_name: str,
                     sender, params: FuzzParams, rnd: Rng):
    """Append a column to the sender buffer and return the expected value
    in the form the oracle stores. For string-ish columns that's a plain
    Python str (no quotes); for typed columns it's whatever
    `format_expected_cell` will recognise — see that helper for the
    canonical mapping per server type.
    """
    if col_type == 'DOUBLE':
        d = rnd.next_int(9)
        f_val = float(int(value_base) * 10 + d)
        sender.column(col_name, f_val)
        return _format_float(f_val)
    if col_type == 'SYMBOL':
        if should_fuzz(params.non_ascii_value_factor, rnd):
            postfix = NON_ASCII_CHARS[rnd.next_int(len(NON_ASCII_CHARS))]
        else:
            postfix = rnd.next_ascii_letter()
        base = value_base
        if (params.send_symbols_with_space
                and rnd.next_int(SEND_SYMBOLS_WITH_SPACE_RANDOMIZE_FACTOR) == 0):
            if len(base) > 1:
                space_index = rnd.next_int(len(base) - 1)
                base = base[:space_index] + '  ' + base[space_index:]
        sym_val = base + postfix
        sender.symbol(col_name, sym_val)
        return sym_val
    if col_type == 'STRING':
        if should_fuzz(params.non_ascii_value_factor, rnd):
            postfix = NON_ASCII_CHARS[rnd.next_int(len(NON_ASCII_CHARS))]
        else:
            postfix = rnd.next_ascii_letter()
        str_val = value_base + postfix
        sender.column(col_name, str_val)
        return str_val
    if col_type == 'BOOLEAN':
        b_val = rnd.next_boolean()
        sender.column(col_name, b_val)
        return b_val
    if col_type == 'LONG':
        d = rnd.next_int(9)
        i_val = int(value_base) * 10 + d
        sender.column(col_name, i_val)
        return i_val
    if col_type == 'DECIMAL256':
        # Keep magnitude small enough that DECIMAL(p,s) widening between
        # iterations doesn't change the comparison string. Two-digit
        # fractional part is exactly representable for any p>=4,s>=2.
        whole = int(value_base) * 10 + rnd.next_int(9)
        frac = rnd.next_int(100)
        dec_str = f'{whole}.{frac:02d}'
        sender.column_dec_str(col_name, dec_str)
        return dec_str
    if col_type == 'TIMESTAMP_MICROS':
        # Non-designated TIMESTAMP column — value can repeat across rows.
        ts_us = 1_700_000_000_000_000 + rnd.next_int(86_400_000_000)
        sender.column(col_name, qls.TimestampMicros(ts_us))
        # Oracle compares in nanoseconds-since-epoch — see format_*_cell.
        return ts_us * 1_000
    if col_type == 'TIMESTAMP_NANOS':
        ts_ns = 1_700_000_000_000_000_000 + rnd.next_int(86_400_000_000_000)
        sender.column(col_name, qls.TimestampNanos(ts_ns))
        return ts_ns
    if col_type == 'DOUBLE_ARRAY_1D':
        # Rank fixed per-column so the server's auto-created DOUBLE[]
        # column type doesn't reject rows with the wrong rank.
        length = 2 + rnd.next_int(3)
        arr = np.array(
            [float(rnd.next_int(100)) for _ in range(length)],
            dtype=np.float64)
        sender.column_f64_arr(col_name, arr)
        return arr.tolist()
    if col_type == 'DOUBLE_ARRAY_2D':
        rows = 2 + rnd.next_int(2)
        cols = 2 + rnd.next_int(2)
        arr = np.array(
            [[float(rnd.next_int(100)) for _ in range(cols)]
             for _ in range(rows)],
            dtype=np.float64)
        sender.column_f64_arr(col_name, arr)
        return arr.tolist()
    # Fallback — anything we forgot.
    sender.column(col_name, value_base)
    return value_base


def add_column(line: LineData, col_index: int, sender,
               params: FuzzParams, rnd: Rng) -> str:
    name = generate_column_name(col_index, False, params.diff_cases_in_col_names, rnd)
    value = add_column_value(
        COL_TYPES[col_index], COL_VALUE_BASES[col_index], name, sender, params, rnd)
    line.add_column(name, value)
    return name


def add_symbol(line: LineData, sym_index: int, sender,
               params: FuzzParams, rnd: Rng) -> str:
    name = generate_symbol_name(sym_index, False, params.diff_cases_in_col_names, rnd)
    value = add_column_value(
        'SYMBOL', SYMBOL_VALUE_BASES[sym_index], name, sender, params, rnd)
    line.add_tag(name, value)
    return name


def add_duplicate_column(line: LineData, col_index: int, col_name: str,
                         sender, params: FuzzParams, rnd: Rng):
    if not should_fuzz(params.duplicates_factor, rnd):
        return
    value = add_column_value(
        COL_TYPES[col_index], COL_VALUE_BASES[col_index], col_name, sender, params, rnd)
    line.add_column(col_name, value)


def add_duplicate_symbol(line: LineData, sym_index: int, sym_name: str,
                         sender, params: FuzzParams, rnd: Rng):
    if not should_fuzz(params.duplicates_factor, rnd):
        return
    value = add_column_value(
        'SYMBOL', SYMBOL_VALUE_BASES[sym_index], sym_name, sender, params, rnd)
    line.add_tag(sym_name, value)


def add_new_column(line: LineData, sender, params: FuzzParams, rnd: Rng):
    if not should_fuzz(params.new_column_factor, rnd):
        return
    extra_col_index = rnd.next_int(len(COL_NAME_BASES))
    name = generate_column_name(
        extra_col_index, True, params.diff_cases_in_col_names, rnd)
    value = add_column_value(
        COL_TYPES[extra_col_index], COL_VALUE_BASES[extra_col_index],
        name, sender, params, rnd)
    line.add_column(name, value)


def add_new_symbol(line: LineData, sender, params: FuzzParams, rnd: Rng):
    if not should_fuzz(params.new_column_factor, rnd):
        return
    extra_sym_index = rnd.next_int(len(SYMBOL_NAME_BASES))
    name = generate_symbol_name(
        extra_sym_index, True, params.diff_cases_in_col_names, rnd)
    value = add_column_value(
        'SYMBOL', SYMBOL_VALUE_BASES[extra_sym_index], name, sender, params, rnd)
    line.add_tag(name, value)


def pick_table_name(num_tables: int, rnd: Rng) -> str:
    base = 'WEATHER' if rnd.next_int(UPPERCASE_TABLE_RANDOMIZE_FACTOR) == 0 else 'weather'
    return base + str(rnd.next_int(num_tables))


def canonical_table_name(table_index: int) -> str:
    return f'weather{table_index}'


def generate_line(table_name: str, sender, params: FuzzParams,
                  timestamp_us: int, rnd: Rng) -> LineData:
    line = LineData(timestamp_us)
    sender.table(table_name)

    if params.exercise_symbols:
        sym_indexes = skip_columns(
            generate_ordering(
                len(SYMBOL_NAME_BASES), params.column_reordering_factor, rnd),
            params.column_skip_factor, rnd)
        for sym_index in sym_indexes:
            sym_name = add_symbol(line, sym_index, sender, params, rnd)
            add_duplicate_symbol(line, sym_index, sym_name, sender, params, rnd)
            add_new_symbol(line, sender, params, rnd)

    col_indexes = skip_columns(
        generate_ordering(
            len(COL_NAME_BASES), params.column_reordering_factor, rnd),
        params.column_skip_factor, rnd)
    for col_index in col_indexes:
        col_name = add_column(line, col_index, sender, params, rnd)
        add_duplicate_column(line, col_index, col_name, sender, params, rnd)
        add_new_column(line, sender, params, rnd)

    sender.at_micros(timestamp_us)
    return line


# ---------------------------------------------------------------------------
# ALTER COLUMN TYPE racing thread — mirror of Java's startAlterTableThread.
# ---------------------------------------------------------------------------

def change_column_type_to(col_type: str, rnd: Rng) -> str:
    """Pick a target column type for ALTER, matching Java's
    `changeColumnTypeTo`. Returns the original type if no compatible target
    exists.

    Note: Java's fuzz also cycles BYTE/SHORT/INT/LONG, but the QWP/WS
    wire only carries LONG and skipped columns become LONG-NULL on the
    server. Narrowing to BYTE/SHORT then causes the server to reject
    every row that omits the column ("integer value null out of range
    for SHORT"), which the DropAndContinue policy silently swallows on
    the client. We therefore leave integer columns alone.
    """
    if col_type == 'STRING':
        return 'SYMBOL' if rnd.next_boolean() else 'VARCHAR'
    if col_type == 'SYMBOL':
        return 'STRING' if rnd.next_boolean() else 'VARCHAR'
    if col_type == 'VARCHAR':
        return 'STRING' if rnd.next_boolean() else 'SYMBOL'
    if col_type == 'FLOAT':
        return 'DOUBLE'
    if col_type == 'DOUBLE':
        return 'FLOAT'
    return col_type


# Server rejection patterns we tolerate from ALTER. Anything else gets
# surfaced as a fatal failure for the alter thread, matching Java's
# behaviour where only "type is already" SQLExceptions are swallowed.
_ALTER_TOLERATED_PATTERNS = (
    'type is already',
    'designated timestamp',
    'cannot change type of column',
    'column type is fixed',
    'table does not exist',
    'no such column',
    'column does not exist',
    'invalid column',
    'unsupported conversion',
)


class AlterThread(threading.Thread):
    """Background thread that races `ALTER TABLE ... ALTER COLUMN TYPE`
    statements against the producers.

    Stops when:

    * the producers are done (``producers_done.wait``), or
    * ``stop_event`` is set, or
    * the conversion budget is exhausted.
    """

    def __init__(
            self,
            *,
            sql_query,
            list_columns,
            tables,
            convert_budget,
            rnd: Rng,
            producers_done: threading.Event,
            stop_event: threading.Event,
            failure_counter: list,
            log):
        super().__init__(name='qwp-ws-fuzz-alter', daemon=True)
        self._sql_query = sql_query
        self._list_columns = list_columns
        self._tables = list(tables)
        self._convert_budget = convert_budget
        self._rnd = rnd
        self._producers_done = producers_done
        self._stop_event = stop_event
        self._failure_counter = failure_counter
        self._log = log
        self.applied_conversions = 0

    def run(self):
        remaining = self._convert_budget
        while (
                remaining > 0
                and not self._producers_done.is_set()
                and not self._stop_event.is_set()
                and self._failure_counter[0] == 0):
            table_name = self._tables[self._rnd.next_int(len(self._tables))]
            applied = self._try_one_alter(table_name)
            if applied:
                remaining -= 1
                self.applied_conversions += 1
            time.sleep(0.010 + self._rnd.next_int(100) / 1000.0)

    def _try_one_alter(self, table_name: str) -> bool:
        try:
            cols = self._list_columns(table_name)
        except Exception as e:  # noqa: BLE001 — fixture surfaces a few error shapes
            self._log(
                f'fuzz alter: list_columns({table_name!r}) failed: {e}')
            return False
        if not cols:
            return False
        start = self._rnd.next_int(len(cols))
        for offset in range(len(cols)):
            col = cols[(start + offset) % len(cols)]
            name = col['name']
            col_type = col['type']
            if col_type == 'TIMESTAMP':
                continue
            target = change_column_type_to(col_type, self._rnd)
            if target == col_type:
                continue
            stmt = (
                f'ALTER TABLE "{table_name}" ALTER COLUMN '
                f'"{name}" TYPE {target}'
            )
            try:
                self._sql_query(stmt)
                self._log(
                    f'fuzz alter: {table_name}.{name} {col_type} -> {target}')
                return True
            except urllib.error.URLError:
                # Server is unreachable — likely mid-bounce. Drop this
                # attempt; the outer loop will pick a new target after a
                # short sleep, by which point start() should have
                # finished.
                return False
            except Exception as e:  # noqa: BLE001
                message = str(e)
                if any(p in message.lower() for p in _ALTER_TOLERATED_PATTERNS):
                    continue
                self._log(
                    f'fuzz alter: unexpected failure on '
                    f'{table_name}.{name} -> {target}: {e}')
                self._failure_counter[0] += 1
                return False
        return False


class BounceThread(threading.Thread):
    """Background thread that bounces the QuestDB fixture at random
    intervals while producers are mid-batch.

    Stops when:

    * the bounce budget is exhausted (``bounces_performed >= max_bounces``);
    * the producers signal completion via ``writers_done.set()``;
    * ``stop_event`` is set; or
    * a previous bounce raised, in which case ``failure_counter`` gets
      bumped and the thread tries one defensive ``start()`` before
      exiting so the rest of the test still has a server to talk to.

    Each bounce is atomic from the caller's perspective: once the loop
    enters a bounce cycle it completes ``stop()`` + ``start()`` before
    re-checking the exit conditions. That guarantees we never leave the
    server down at the end of the run.
    """

    def __init__(
            self,
            *,
            fixture,
            rnd: Rng,
            max_bounces: int,
            min_interval_s: float,
            max_interval_s: float,
            writers_done: threading.Event,
            stop_event: threading.Event,
            failure_counter: list,
            log,
    ):
        super().__init__(name='qwp-ws-fuzz-bounce', daemon=True)
        self._fixture = fixture
        self._rnd = rnd
        self._max_bounces = max_bounces
        self._min_interval_s = min_interval_s
        self._max_interval_s = max(max_interval_s, min_interval_s)
        self._writers_done = writers_done
        self._stop_event = stop_event
        self._failure_counter = failure_counter
        self._log = log
        self.bounces_performed = 0

    def run(self):
        while (
                self.bounces_performed < self._max_bounces
                and not self._writers_done.is_set()
                and not self._stop_event.is_set()
                and self._failure_counter[0] == 0):
            interval = self._pick_interval()
            # Bail early if writers signal completion mid-sleep.
            if self._writers_done.wait(timeout=interval):
                return
            try:
                idx = self.bounces_performed + 1
                self._log(f'fuzz bounce #{idx}: stopping QDB')
                self._fixture.stop()
                # Tiny gap so the OS settles the listening sockets
                # before start() rebinds them.
                time.sleep(0.02 + self._rnd.next_int(200) / 1000.0)
                self._log(f'fuzz bounce #{idx}: starting QDB')
                self._fixture.start()
                self.bounces_performed += 1
                self._log(f'fuzz bounce #{idx}: server back up')
            except Exception as e:  # noqa: BLE001 — fixture lifecycle is fragile
                self._log(
                    f'fuzz bounce: unexpected failure at attempt '
                    f'{self.bounces_performed + 1}: {e}')
                self._failure_counter[0] += 1
                # One defensive recovery attempt so the rest of the test
                # has a chance to surface the underlying assertion
                # failure rather than a query timeout.
                try:
                    self._fixture.start()
                except Exception:
                    pass
                return

    def _pick_interval(self) -> float:
        span_ms = max(1, int(
            (self._max_interval_s - self._min_interval_s) * 1000))
        return self._min_interval_s + self._rnd.next_int(span_ms) / 1000.0


# ---------------------------------------------------------------------------
# Verification — compare per-row expected vs server-side state.
# ---------------------------------------------------------------------------

class TableMismatch(AssertionError):
    pass


def compare_table(
        *,
        table: TableData,
        server_columns,
        server_rows,
        seed_label: str) -> None:
    """Assert that the rows the server returned match the producer-side log.

    `server_columns` is a list of {'name': ..., 'type': ...} dicts.
    `server_rows` is the dataset rows in the same column order, sorted by
    timestamp_us ascending on the caller side.

    Raises `TableMismatch` with the seed label embedded in the message — so a
    failure in CI logs the reproducer right next to the diff.
    """
    expected_rows = table.valid_rows_sorted()
    if len(expected_rows) != len(server_rows):
        raise TableMismatch(
            f'[{seed_label}] table {table.name!r}: row count mismatch — '
            f'expected {len(expected_rows)} valid lines, '
            f'server returned {len(server_rows)}')

    # The *designated* timestamp column is conventionally named
    # `timestamp` (the QWP-auto-created table default). It's used to
    # join expected/actual rows by the sort order, so we skip it during
    # the per-cell comparison. Other TIMESTAMP columns are compared
    # normally — `format_*_cell` canonicalises both sides to nanoseconds.
    has_designated_ts = any(
        col['name'].lower() == 'timestamp' and _is_timestamp_type(col['type'])
        for col in server_columns)
    if not has_designated_ts:
        raise TableMismatch(
            f'[{seed_label}] table {table.name!r}: no designated TIMESTAMP column found')

    for row_index, (expected_line, server_row) in enumerate(
            zip(expected_rows, server_rows)):
        for col_index, col in enumerate(server_columns):
            col_name = col['name']
            col_type = col['type']
            if col_name.lower() == 'timestamp' and _is_timestamp_type(col_type):
                continue
            expected_raw = expected_line.get_value(col_name)
            expected_str = format_expected_cell(expected_raw, col_type)
            actual_str = format_actual_cell(server_row[col_index], col_type)
            if expected_str != actual_str:
                raise TableMismatch(
                    f'[{seed_label}] table {table.name!r} row {row_index} '
                    f'column {col_name!r} ({col_type}): '
                    f'expected {expected_str!r}, got {actual_str!r} '
                    f'(timestamp_us={expected_line.timestamp_us})')
