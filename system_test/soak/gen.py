################################################################################
##     ___                  _   ____  ____
##    / _ \ _   _  ___  ___| |_|  _ \| __ )
##   | | | | | | |/ _ \/ __| __| | | |  _ \
##   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
##    \__\_\\__,_|\___||___/\__|____/|____/
##
##  Copyright (c) 2014-2019 Appsicle
##  Copyright (c) 2019-2025 QuestDB
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

"""
Python mirror of the soak data generator (``workload_rs/src/gen.rs``).

The soak oracle regenerates every expected read-back value here, in Python,
from ``(seed, worker_id, seq)`` — so this file MUST be a byte-for-byte faithful
port of the Rust reference. The CI conformance step asserts parity by diffing:

    soak-workload gen-vectors --seed S --rows N
    python3 gen.py gen-vectors --seed S --rows N

Any divergence there is a bug in one of the two mirrors. Keep the PRNG, fold,
edge cadence, and per-type canonicalisation identical to gen.rs.
"""

import sys

sys.dont_write_bytecode = True

import struct

M = (1 << 64) - 1  # u64 mask


# -- PRNG + fold (identical constants to gen.rs) ----------------------------

def splitmix64(x):
    z = (x + 0x9E3779B97F4A7C15) & M
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M
    return (z ^ (z >> 31)) & M


K_WORKER = 0xD1B54A32D192ED03
K_SEQ = 0xA0761D6478BD642F
K_COL = 0xE7037ED1A0B428DB
K_SUB = 0x8EBC6AF09C88C6E3


def draw(seed, worker_id, seq, col, sub):
    h = seed & M
    h ^= (worker_id * K_WORKER) & M
    h = splitmix64(h)
    h ^= (seq * K_SEQ) & M
    h = splitmix64(h)
    h ^= (col * K_COL) & M
    h = splitmix64(h)
    h ^= (sub * K_SUB) & M
    return splitmix64(h)


EDGE_SLOTS = 12
EDGE_PERIOD = 23


def edge_index(seq, col):
    phase = (seq + col * 7) & M
    if phase % EDGE_PERIOD != 0:
        return None
    slot = (phase // EDGE_PERIOD) % EDGE_SLOTS
    return None if slot == 0 else slot


# -- type table (wire order; must match gen.rs) -----------------------------

# name -> column name; order defines col_index.
QWP_TYPES = [
    'boolean', 'byte', 'short', 'int', 'long', 'float', 'double', 'symbol',
    'timestamp', 'date', 'uuid', 'long256', 'geohash', 'varchar',
    'timestamp_nanos', 'double_array', 'decimal64', 'decimal128', 'decimal256',
    'char', 'binary', 'ipv4',
]

COL_NAME = {
    'boolean': 'c_bool', 'byte': 'c_byte', 'short': 'c_short', 'int': 'c_int',
    'long': 'c_long', 'float': 'c_float', 'double': 'c_double',
    'symbol': 'c_symbol', 'timestamp': 'c_ts', 'date': 'c_date',
    'uuid': 'c_uuid', 'long256': 'c_long256', 'geohash': 'c_geohash',
    'varchar': 'c_varchar', 'timestamp_nanos': 'c_ts_nanos',
    'double_array': 'c_dbl_arr', 'decimal64': 'c_dec64',
    'decimal128': 'c_dec128', 'decimal256': 'c_dec256', 'char': 'c_char',
    'binary': 'c_binary', 'ipv4': 'c_ipv4',
}

COL_INDEX = {t: i for i, t in enumerate(QWP_TYPES)}

UNICODE_SAMPLES = ['Straße', 'café', 'Ω-Ω', '日本語', 'naïve', 'ÀÉÎ']

GEOHASH_CHARS = 8


# -- Expected value: a tagged tuple, compared / serialised like gen.rs ------
# ('null',) | ('int', i) | ('float', f) | ('bool', b) | ('text', s) | ('bytes', b'')

def NULL():
    return ('null',)


# -- integer / float bit helpers (match Rust `as` semantics) ----------------

def as_signed(x, bits):
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    return ((x & mask) ^ sign) - sign


def f32_from_bits(bits):
    return struct.unpack('<f', struct.pack('<I', bits & 0xFFFFFFFF))[0]


def f64_from_bits(bits):
    return struct.unpack('<d', struct.pack('<Q', bits & M))[0]


def f64_to_bits(v):
    return struct.unpack('<Q', struct.pack('<d', v))[0]


def f32_round(v):
    return struct.unpack('<f', struct.pack('<f', v))[0]


def f32_from(d):
    v = f32_from_bits(d >> 32)
    if v == v and v not in (float('inf'), float('-inf')):  # finite
        return v
    # Parity-safe finite fallback: (d as i32) as f32 * 0.5, widened to f64.
    return f32_round(float(as_signed(d, 32))) * 0.5


def f64_from(d):
    v = f64_from_bits(d)
    if v == v and v not in (float('inf'), float('-inf')):  # finite
        return v
    return float(as_signed(d, 64)) * 0.5


def bounded_epoch(d, lo, hi):
    return lo + d % (hi - lo)


def fmt_uuid(v):
    h = f'{v:032x}'
    return f'{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}'


def fmt_long256(words):
    s = '0x'
    started = False
    for w in reversed(words):
        if not started:
            if w == 0:
                continue
            s += f'{w:x}'
            started = True
        else:
            s += f'{w:016x}'
    if not started:
        s += '0'
    return s


BASE32 = b'0123456789bcdefghjkmnpqrstuvwxyz'


def fmt_geohash(d, chars):
    # Most-significant 5 bits first (QuestDB's canonical base32 rendering).
    return ''.join(
        chr(BASE32[(d >> (5 * (chars - 1 - i))) & 0x1F]) for i in range(chars))


def fmt_f64_array(vals):
    return '[' + ','.join(f'{f64_to_bits(v):016x}' for v in vals) + ']'


def gen_varchar(seed, worker_id, seq, col, d0):
    n = d0 % 32 + 1
    return ''.join(
        chr(0x20 + draw(seed, worker_id, seq, col, 30 + i) % 0x5F)
        for i in range(n))


def fmt_decimal(unscaled, scale):
    if scale == 0:
        return str(unscaled)
    neg = unscaled < 0
    s = str(abs(unscaled))
    if len(s) <= scale:
        s = '0' * (scale + 1 - len(s)) + s
    dot = len(s) - scale
    out = f'{s[:dot]}.{s[dot:]}'
    return f'-{out}' if neg else out


# 18-digit unscaled cap so values fit DECIMAL(18,2) (dec64's precision).
DEC_UNSCALED_MOD = 1_000_000_000_000_000_000


def gen_decimal(edge, d0, scale):
    if edge == 1:
        return NULL()
    if edge == 2:
        return ('text', fmt_decimal(0, scale))
    # Unsigned mod (matches Rust; signed % diverges between the languages)
    # plus a sign bit.
    mag = d0 % DEC_UNSCALED_MOD
    unscaled = -mag if (d0 & (1 << 63)) else mag
    return ('text', fmt_decimal(unscaled, scale))


def gen_expected(seed, worker_id, seq, ty):
    col = COL_INDEX[ty]
    edge = edge_index(seq, col)
    d0 = draw(seed, worker_id, seq, col, 0)

    if ty == 'boolean':
        return ('bool', d0 & 1 == 0)

    if ty == 'byte':
        if edge == 1:
            return ('int', -128)
        if edge == 2:
            return ('int', 127)
        if edge == 3:
            return ('int', 0)
        return ('int', as_signed(d0, 8))

    if ty == 'short':
        if edge == 1:
            return ('int', -32768)
        if edge == 2:
            return ('int', 32767)
        if edge == 3:
            return ('int', 0)
        return ('int', as_signed(d0, 16))

    if ty == 'int':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('int', 2147483647)
        if edge == 3:
            return ('int', -2147483647)  # i32::MIN+1 (MIN is the NULL sentinel)
        if edge == 4:
            return ('int', 0)
        return ('int', as_signed(d0, 32))

    if ty == 'long':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('int', 9223372036854775807)
        if edge == 3:
            return ('int', -9223372036854775807)
        if edge == 4:
            return ('int', 0)
        return ('int', as_signed(d0, 64))

    if ty == 'float':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('float', float(f32_from_bits(0x7F7FFFFF)))  # f64::from(f32::MAX)
        if edge == 3:
            return ('float', float(f32_from_bits(0xFF7FFFFF)))  # f64::from(f32::MIN)
        if edge == 4:
            return ('float', 0.0)
        return ('float', float(f32_from(d0)))

    if ty == 'double':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('float', sys.float_info.max)
        if edge == 3:
            return ('float', -sys.float_info.max)
        if edge == 4:
            return ('float', 0.0)
        return ('float', f64_from(d0))

    if ty == 'symbol':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('text', UNICODE_SAMPLES[d0 % len(UNICODE_SAMPLES)])
        if edge == 3:
            return ('text', 's')
        return ('text', f'sym_{d0 % 512}')

    if ty == 'timestamp':
        if edge == 1:
            return NULL()
        return ('int', bounded_epoch(d0, 946684800000000, 3000000000000000))

    if ty == 'date':
        if edge == 1:
            return NULL()
        return ('int', bounded_epoch(d0, 946684800000, 3000000000000))

    if ty == 'uuid':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('text', fmt_uuid(0))
        lo = draw(seed, worker_id, seq, col, 1)
        return ('text', fmt_uuid(((d0 << 64) | lo) & ((1 << 128) - 1)))

    if ty == 'long256':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('text', '0x0')
        w = [d0,
             draw(seed, worker_id, seq, col, 1),
             draw(seed, worker_id, seq, col, 2),
             draw(seed, worker_id, seq, col, 3)]
        return ('text', fmt_long256(w))

    if ty == 'geohash':
        if edge == 1:
            return NULL()
        return ('text', fmt_geohash(d0, GEOHASH_CHARS))

    if ty == 'varchar':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('text', '')
        if edge == 3:
            return ('text', UNICODE_SAMPLES[d0 % len(UNICODE_SAMPLES)])
        if edge == 4:
            return ('text', 'x' * 4096)
        return ('text', gen_varchar(seed, worker_id, seq, col, d0))

    if ty == 'timestamp_nanos':
        if edge == 1:
            return NULL()
        return ('int', bounded_epoch(d0, 946684800000000000, 3000000000000000000))

    if ty == 'double_array':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('text', '[]')
        n = d0 % 8 + 1
        vals = [f64_from(draw(seed, worker_id, seq, col, 10 + i)) for i in range(n)]
        return ('text', fmt_f64_array(vals))

    if ty == 'decimal64':
        return gen_decimal(edge, d0, 2)
    if ty == 'decimal128':
        return gen_decimal(edge, d0, 6)
    if ty == 'decimal256':
        return gen_decimal(edge, d0, 10)

    if ty == 'char':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('text', 'A')
        return ('text', chr(0x21 + d0 % 0x5E))

    if ty == 'binary':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('bytes', b'')
        n = d0 % 24 + 1
        return ('bytes', bytes(
            draw(seed, worker_id, seq, col, 20 + i) & 0xFF for i in range(n)))

    if ty == 'ipv4':
        if edge == 1:
            return NULL()
        if edge == 2:
            return ('int', 0)
        return ('int', d0 & 0xFFFFFFFF)

    raise ValueError(f'unknown type {ty}')


def gen_row(seed, worker_id, seq):
    return [(ty, gen_expected(seed, worker_id, seq, ty)) for ty in QWP_TYPES]


def double_array_values(seed, worker_id, seq):
    """Actual f64 elements of the double_array cell (mirror of gen.rs). `None`
    for the NULL edge, `[]` for the zero-length edge."""
    col = COL_INDEX['double_array']
    d0 = draw(seed, worker_id, seq, col, 0)
    edge = edge_index(seq, col)
    if edge == 1:
        return None
    if edge == 2:
        return []
    n = d0 % 8 + 1
    return [f64_from(draw(seed, worker_id, seq, col, 10 + i)) for i in range(n)]


# -- golden-vector serialisation (byte-identical to gen.rs) -----------------

def _json_string(s):
    out = ['"']
    for c in s:
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == '\\':
            out.append('\\\\')
        elif c == '\n':
            out.append('\\n')
        elif c == '\r':
            out.append('\\r')
        elif c == '\t':
            out.append('\\t')
        elif o < 0x20:
            out.append(f'\\u{o:04x}')
        else:
            out.append(c)
    out.append('"')
    return ''.join(out)


def expected_json(e):
    tag = e[0]
    if tag == 'null':
        return 'null'
    if tag == 'int':
        return f'{{"i":"{e[1]}"}}'
    if tag == 'float':
        return f'{{"f":"{f64_to_bits(e[1])}"}}'
    if tag == 'bool':
        return '{"b":true}' if e[1] else '{"b":false}'
    if tag == 'text':
        return f'{{"t":{_json_string(e[1])}}}'
    if tag == 'bytes':
        return '{"x":"' + e[1].hex() + '"}'
    raise ValueError(tag)


def write_golden_vectors(seed, worker_id, rows):
    lines = []
    for seq in range(rows):
        cells = ','.join(
            f'{{"col":"{COL_NAME[ty]}","v":{expected_json(exp)}}}'
            for ty, exp in gen_row(seed, worker_id, seq))
        lines.append(f'{{"seq":{seq},"cells":[{cells}]}}')
    return '\n'.join(lines) + ('\n' if rows else '')


# -- selftest + CLI ---------------------------------------------------------

def _selftest():
    failures = []

    def check(cond, msg):
        if cond:
            print(f'ok: {msg}')
        else:
            failures.append(msg)
            print(f'FAIL: {msg}', file=sys.stderr)

    # PRNG golden values — the cross-language contract with gen.rs.
    check(splitmix64(0) == 0xE220A8397B1DCDAF, 'splitmix64(0)')
    check(splitmix64(1) == 0x910A2DEC89025CC1, 'splitmix64(1)')
    check(splitmix64(0xDEADBEEF) == 0x4ADFB90F68C9EB9B, 'splitmix64(0xDEADBEEF)')

    check(len(QWP_TYPES) == 22, '22 types')
    check(len(set(COL_NAME.values())) == 22, '22 unique column names')

    # Determinism.
    det = all(gen_row(42, 7, s) == gen_row(42, 7, s) for s in range(500))
    check(det, 'deterministic')

    # Distinct worker / seed diverge over a window.
    w7 = [gen_row(1, 7, s) for s in range(200)]
    w8 = [gen_row(1, 8, s) for s in range(200)]
    check(w7 != w8, 'distinct worker diverges')

    # Nullable types produce NULL; finite-only floats; no NULL sentinels.
    seen_null = set()
    for seq in range(EDGE_PERIOD * EDGE_SLOTS * 4):
        for ty in QWP_TYPES:
            if gen_expected(0xABCD, 3, seq, ty) == NULL():
                seen_null.add(ty)
    for ty in ['int', 'long', 'double', 'symbol', 'uuid', 'varchar', 'binary', 'ipv4']:
        check(ty in seen_null, f'nullable {ty} yields NULL')

    ok_floats = True
    ok_sentinels = True
    for seq in range(2000):
        for ty in ('float', 'double'):
            e = gen_expected(9, 1, seq, ty)
            if e[0] == 'float' and e[1] != e[1]:  # NaN
                ok_floats = False
        ei = gen_expected(9, 1, seq, 'int')
        if ei == ('int', -2147483648):
            ok_sentinels = False
        el = gen_expected(9, 1, seq, 'long')
        if el == ('int', -9223372036854775808):
            ok_sentinels = False
    check(ok_floats, 'no NaN leaks into floats')
    check(ok_sentinels, 'no INT/LONG NULL sentinel leaks')

    # Formatting parity spot-checks.
    check(fmt_decimal(0, 2) == '0.00', 'decimal 0.00')
    check(fmt_decimal(-123, 2) == '-1.23', 'decimal -1.23')
    check(fmt_uuid(0) == '00000000-0000-0000-0000-000000000000', 'uuid zero')
    check(fmt_long256([0, 0, 0, 0]) == '0x0', 'long256 zero')
    check(fmt_long256([0, 1, 0, 0]) == '0x10000000000000000', 'long256 word1')

    gv = write_golden_vectors(7, 0, 3)
    check(len(gv.splitlines()) == 3, 'golden vectors 3 lines')

    if failures:
        print(f'\n{len(failures)} failure(s)', file=sys.stderr)
        return 1
    print('\ngen.py selftest: all checks passed')
    return 0


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='Soak generator (Python mirror)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    gv = sub.add_parser('gen-vectors')
    gv.add_argument('--seed', type=int, default=1)
    gv.add_argument('--worker', type=int, default=0)
    gv.add_argument('--rows', type=int, default=64)
    sub.add_parser('selftest')
    args = ap.parse_args(argv)
    if args.cmd == 'gen-vectors':
        sys.stdout.write(write_golden_vectors(args.seed, args.worker, args.rows))
        return 0
    if args.cmd == 'selftest':
        return _selftest()
    return 2


if __name__ == '__main__':
    sys.exit(_main(sys.argv[1:]))
