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
Soak oracle (see ``doc/QWP_SOAK_HARNESS.md``). Turns the raw signals into
pass/fail invariant verdicts and a ``summary.json``:

* **I1 Completeness** — every acked ``seq`` up to the journal watermark is
  present, no gaps.
* **I2 Bounded duplication** — duplicate rows stay within the leg's replay-window
  budget; control legs and dedup tables are exact.
* **I3 Value correctness** — sampled rows round-trip every datatype, compared
  against the regenerated expected value (:mod:`gen`).
* **I4 Resource boundedness** — RSS / FD / pool / SF curves return to a steady
  baseline (the leak detector).
* **I5 Mixed-shape coverage** — the mixed SFA leg has fsync-journaled ACKs for
  at least one complete Arrow, Buffer, and Chunk batch in its deterministic
  cycle.

The reconciliation queries (I1–I3) run over an **independent** query path (HTTP
``/exec``), never through the client under test. Pure logic here is unit-tested
by ``oracle.py selftest`` with synthetic data, no server required.
"""

import sys

sys.dont_write_bytecode = True

import json
import urllib.error
import urllib.parse
import urllib.request

import gen


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

class Verdict:
    __slots__ = ('invariant', 'name', 'passed', 'detail')

    def __init__(self, invariant, name, passed, detail):
        self.invariant = invariant   # 'I1'..'I7'
        self.name = name             # leg / subject
        self.passed = bool(passed)
        self.detail = detail

    def to_dict(self):
        return {
            'invariant': self.invariant,
            'name': self.name,
            'passed': self.passed,
            'detail': self.detail,
        }


def check_mixed_shape_coverage(name, watermark, batch_size, shapes):
    """Prove every shape in a deterministic batch cycle reached an ACK.

    The mixed leg chooses its shape from ``batch_index % len(shapes)`` and only
    advances the fsync'd journal after the whole batch is acked. Therefore the
    journal watermark independently proves how many leading shapes completed,
    including across process restart.
    """
    completed_batches = (watermark + 1) // batch_size
    completed_shapes = list(shapes[:min(completed_batches, len(shapes))])
    return Verdict('I5', f'{name}:mixed-shapes',
                   completed_batches >= len(shapes), {
                       'cycle': list(shapes),
                       'completed_batches': completed_batches,
                       'completed_shapes': completed_shapes,
                       'batch_size': batch_size,
                       'journal_watermark': watermark,
                   })


# ---------------------------------------------------------------------------
# I4 — resource boundedness (the leak detector). Pure functions over samples.
# A sample (one JSON line the orchestrator merges) looks like:
#   {"t": <epoch_s>, "leg": "rust-buffer-saf-default",
#    "rss_bytes": N, "fd_count": N,
#    "pool": {"ingress":[free,in_use,closing], ...},
#    "sf": {"mem_backlog_bytes": N, "max_bytes": N, "disk_bytes": N}}
# ---------------------------------------------------------------------------

class BoundsConfig:
    def __init__(self, warmup_seconds=600, rss_slope_max_kib_per_min=100.0,
                 rss_growth_max_frac=0.25, rss_peak_mult=4.0,
                 fd_tolerance=4, fd_slope_max_per_min=0.5,
                 require_pool_drain=True,
                 inflight_slope_max_per_min=50.0, inflight_peak_max=1_000_000):
        self.warmup_seconds = warmup_seconds
        self.rss_slope_max_kib_per_min = rss_slope_max_kib_per_min
        self.rss_growth_max_frac = rss_growth_max_frac
        self.rss_peak_mult = rss_peak_mult
        self.fd_tolerance = fd_tolerance
        self.fd_slope_max_per_min = fd_slope_max_per_min
        self.require_pool_drain = require_pool_drain
        # In-flight frames (published - acked) — a store-and-forward backlog
        # leak shows up as monotonic growth here.
        self.inflight_slope_max_per_min = inflight_slope_max_per_min
        self.inflight_peak_max = inflight_peak_max


def linreg_slope(xs, ys):
    """Least-squares slope of ys over xs (0.0 if degenerate)."""
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0.0:
        return 0.0
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    return num / den


def analyze_bounds(samples, cfg=None):
    """Return I4 verdicts, one per (leg, dimension). ``samples`` is the full
    merged sample list across all legs."""
    cfg = cfg or BoundsConfig()
    by_leg = {}
    for s in samples:
        # A dead-pid read (rss unavailable) is not a measurement; keeping it
        # would crash the numeric bounds below (None / KiB). Drop it so one
        # unlucky sample can't take down the whole reconcile.
        if s.get('rss_bytes') is None:
            continue
        by_leg.setdefault(s.get('leg', '?'), []).append(s)

    verdicts = []
    for leg, rows in sorted(by_leg.items()):
        rows = sorted(rows, key=lambda s: s['t'])
        t0 = rows[0]['t']
        warmup_end = t0 + cfg.warmup_seconds
        steady = [s for s in rows if s['t'] >= warmup_end]
        warmup = [s for s in rows if s['t'] < warmup_end]
        if len(steady) < 3:
            verdicts.append(Verdict(
                'I4', f'{leg}:rss', True,
                f'inconclusive: only {len(steady)} steady-state samples'))
            continue

        verdicts.append(_rss_verdict(leg, warmup, steady, cfg))
        verdicts.append(_fd_verdict(leg, steady, cfg))
        verdicts.extend(_pool_verdicts(leg, rows, steady, cfg))
        inflight = _inflight_verdict(leg, steady, cfg)
        if inflight:
            verdicts.append(inflight)
        sfv = _sf_verdict(leg, rows)
        if sfv:
            verdicts.append(sfv)
    return verdicts


def _inflight_verdict(leg, steady, cfg):
    """In-flight frames (published_fsn - acked_fsn) must stay bounded and not
    trend upward — an unbounded backlog is a store-and-forward / ack leak. Uses
    the sender's own watermarks (no extra instrumentation needed). Returns None
    if the leg doesn't report both watermarks."""
    pairs = [(s['t'], s['published_fsn'] - s['acked_fsn'])
             for s in steady
             if s.get('published_fsn') is not None and s.get('acked_fsn') is not None]
    if len(pairs) < 3:
        return None
    ts = [p[0] for p in pairs]
    inflight = [p[1] for p in pairs]
    t0 = ts[0]
    xs = [(t - t0) / 60.0 for t in ts]
    slope = linreg_slope(xs, inflight)
    peak = max(inflight)
    # Bounded: not trending up (slope small) and never absurdly deep. The cap
    # is generous — the point is catching monotonic growth, not a tight bound.
    ok = slope <= cfg.inflight_slope_max_per_min and peak <= cfg.inflight_peak_max
    return Verdict('I4', f'{leg}:inflight', ok, {
        'slope_per_min': round(slope, 2), 'peak': peak, 'final': inflight[-1],
        'limits': {'slope_max': cfg.inflight_slope_max_per_min,
                   'peak_max': cfg.inflight_peak_max},
    })


def _rss_verdict(leg, warmup, steady, cfg):
    t0 = steady[0]['t']
    xs = [(s['t'] - t0) / 60.0 for s in steady]           # minutes
    ys = [s['rss_bytes'] / 1024.0 for s in steady]        # KiB
    slope = linreg_slope(xs, ys)
    warmup_peak = max((s['rss_bytes'] for s in warmup), default=steady[0]['rss_bytes'])
    steady_peak = max(s['rss_bytes'] for s in steady)
    # Peak-over-warmup, not first-to-last-sample: the first steady sample can
    # land before the working set is fully paged back in after warmup, so a
    # first-relative ratio reads a large "growth" even when RSS is flat (a
    # near-zero slope with a big first-relative ratio is exactly that artefact).
    growth = (steady_peak - warmup_peak) / warmup_peak if warmup_peak else 0.0
    ok = (slope <= cfg.rss_slope_max_kib_per_min
          and growth <= cfg.rss_growth_max_frac
          and steady_peak <= warmup_peak * cfg.rss_peak_mult)
    return Verdict('I4', f'{leg}:rss', ok, {
        'slope_kib_per_min': round(slope, 3),
        'growth_frac': round(growth, 4),
        'steady_peak_bytes': steady_peak,
        'warmup_peak_bytes': warmup_peak,
        'limits': {
            'slope_max': cfg.rss_slope_max_kib_per_min,
            'growth_max': cfg.rss_growth_max_frac,
            'peak_mult': cfg.rss_peak_mult,
        },
    })


def _fd_verdict(leg, steady, cfg):
    pts = [(s['t'], s['fd_count']) for s in steady if s.get('fd_count') is not None]
    if len(pts) < 3:
        return Verdict('I4', f'{leg}:fd', True,
                       f'inconclusive: only {len(pts)} fd samples')
    t0 = pts[0][0]
    xs = [(t - t0) / 60.0 for t, _ in pts]
    fds = [f for _, f in pts]
    slope = linreg_slope(xs, fds)
    baseline = min(fds)
    peak = max(fds)
    ok = (slope <= cfg.fd_slope_max_per_min
          and peak <= baseline + cfg.fd_tolerance * 8)
    return Verdict('I4', f'{leg}:fd', ok, {
        'baseline': baseline, 'final': fds[-1], 'peak': peak,
        'slope_per_min': round(slope, 3),
        'limits': {'slope_max': cfg.fd_slope_max_per_min,
                   'peak_over_baseline': cfg.fd_tolerance * 8},
    })


def _pool_verdicts(leg, rows, steady, cfg):
    out = []
    final = rows[-1].get('pool', {})
    for pool_name, counts in sorted(final.items()):
        _free, in_use, closing = counts
        # A leg holds at most one live borrow at a time, so in_use peaking above
        # one is a leak. The orchestrator also merges the post-release stats
        # emitted during graceful shutdown, so the final sample must be fully
        # drained rather than excusing one still-held borrow.
        peak_in_use = max(
            (r.get('pool', {}).get(pool_name, (0, 0, 0))[1] for r in rows),
            default=in_use)
        ok = not (cfg.require_pool_drain
                  and (peak_in_use > 1 or in_use != 0 or closing != 0))
        detail = {'final_free': _free, 'final_in_use': in_use,
                  'final_closing': closing, 'peak_in_use': peak_in_use}
        if not ok:
            detail['reason'] = (
                'pool leak: more than one live borrow or final pool not drained')
        out.append(Verdict('I4', f'{leg}:pool:{pool_name}', ok, detail))
    return out


def _sf_verdict(leg, rows):
    sf_rows = [s for s in rows if s.get('sf')]
    if not sf_rows:
        return None
    over = []
    for s in sf_rows:
        sf = s['sf']
        mx = sf.get('max_bytes', 0)
        backlog = sf.get('mem_backlog_bytes', 0)
        if mx and backlog > mx:
            over.append({'t': s['t'], 'backlog': backlog, 'max': mx})
    final_disk = sf_rows[-1]['sf'].get('disk_bytes', 0)
    baseline_disk = min(s['sf'].get('disk_bytes', 0) for s in sf_rows)
    # Disk should reclaim back toward baseline after drain; allow generous slack
    # for one un-reaped segment.
    disk_ok = final_disk <= baseline_disk + 64 * 1024 * 1024
    ok = not over and disk_ok
    return Verdict('I4', f'{leg}:sf', ok, {
        'mem_backlog_over_max_count': len(over),
        'final_disk_bytes': final_disk,
        'baseline_disk_bytes': baseline_disk,
        'samples': over[:5],
    })


# ---------------------------------------------------------------------------
# I1 / I2 — completeness & duplication (integer seq only; representation-certain)
# ---------------------------------------------------------------------------

WORKER_COL = 'worker_id'
SEQ_COL = 'c_seq'


def check_completeness(query, table, worker, watermark):
    """I1: every seq in [0, watermark] present, no gaps.

    Uses count()/max/min — streaming O(1) aggregates. count_distinct(c_seq)
    over a 100M+-row table needs a multi-GB hash set and the server refuses it
    ("too large allocation requested"). These are DEDUP tables fed by a
    deterministic c_seq->timestamp generator, so each c_seq maps to exactly one
    row: count() == the distinct count. watermark+1 rows within [0,watermark]
    with min 0 and max watermark can only be the full sequence, no gaps."""
    sql = (f'SELECT count(), max({SEQ_COL}), min({SEQ_COL}) '
           f'FROM {table} WHERE {WORKER_COL}={worker} '
           f'AND {SEQ_COL} <= {watermark}')
    total, mx, mn = query(sql)[0]
    expected = watermark + 1
    ok = (total == expected and mx == watermark and (mn == 0))
    return Verdict('I1', f'{table}:w{worker}', ok, {
        'watermark': watermark, 'expected': expected,
        'total': total, 'max': mx, 'min': mn,
        'missing': expected - (total or 0),
    })


def check_duplication(query, table, worker, watermark, replay_budget,
                      is_control=False, dedup=False):
    """I2: duplicates within budget (0 for control legs / dedup tables).

    On these DEDUP tables each c_seq maps to one row, so the row count can never
    exceed the sequence length unless a duplicate slipped past dedup — surplus
    over ``watermark+1`` is the observable duplication. Avoids count_distinct
    (multi-GB on a huge table); c_seq<=watermark is a streaming count()."""
    sql = (f'SELECT count() '
           f'FROM {table} WHERE {WORKER_COL}={worker} '
           f'AND {SEQ_COL} <= {watermark}')
    (total,) = query(sql)[0]
    expected = watermark + 1
    dups = max(0, (total or 0) - expected)
    budget = 0 if (is_control or dedup) else replay_budget
    ok = dups <= budget
    return Verdict('I2', f'{table}:w{worker}', ok, {
        'duplicates': dups, 'budget': budget,
        'total': total, 'expected': expected,
        'is_control': is_control, 'dedup': dedup,
    })


# ---------------------------------------------------------------------------
# I3 — value correctness. Compares a normalized query value to gen's Expected.
# Scalars (bool/ints/float/double/symbol/varchar/char/ipv4) are handled with
# confidence; time / uuid / exotic types carry a projection + normalization
# that S4 calibrates against a live server (marked below).
# ---------------------------------------------------------------------------

#: Types I3 skips. Empty: all 22 QWP types are ingested by some leg and
#: verified against a live server (via _PROJECTION + compare_value). Kept as a
#: hook for any future type whose read-back rendering isn't yet calibrated.
_CALIBRATE = set()

#: SQL projection per column so /exec returns a value compare_value can check.
#: Calibrated against a live QuestDB: timestamps cast to epoch integers, IPv4 /
#: UUID / decimals read as their canonical strings, BINARY checked by length
#: (/exec does not render binary bytes).
_PROJECTION = {
    'c_ts': 'cast(c_ts as long)',
    'c_date': 'cast(c_date as long)',
    'c_ts_nanos': 'cast(c_ts_nanos as long)',
    'c_ipv4': 'c_ipv4',
    'c_uuid': 'c_uuid',
    'c_dec64': 'cast(c_dec64 as string)',
    'c_dec128': 'cast(c_dec128 as string)',
    'c_dec256': 'cast(c_dec256 as string)',
    'c_binary': 'length(c_binary)',
}


def default_projection():
    """Column-name -> SQL expression map used by reconcile_values."""
    return dict(_PROJECTION)


def compare_value(ty, expected, actual):
    """Compare gen's Expected against a value returned by /exec (already parsed
    from JSON). Returns (ok, reason)."""
    tag = expected[0]

    # Types whose calibrated /exec projection differs from the raw value.
    if ty == 'ipv4':
        v = None if tag == 'null' else expected[1]
        # QuestDB uses 0.0.0.0 as the IPv4 NULL sentinel: a sent value of 0
        # reads back as NULL, indistinguishable from an explicit null.
        if v is None or v == 0:
            return (actual is None), 'ipv4-null'
        if actual is None:
            return False, 'ipv4 unexpected null'
        dotted = '%d.%d.%d.%d' % ((v >> 24) & 0xFF, (v >> 16) & 0xFF,
                                  (v >> 8) & 0xFF, v & 0xFF)
        return (str(actual) == dotted), 'ipv4-dotted'
    if ty == 'binary':
        # /exec cannot render BINARY bytes; the projection is length(). A NULL
        # binary reads back as length -1 (QuestDB's length(NULL) == -1), not
        # SQL NULL.
        if tag == 'null':
            return (actual is None or int(actual) == -1), 'binary-null'
        return (actual is not None and int(actual) == len(expected[1])), 'binary-length'
    if ty == 'double_array':
        # /exec returns a list of doubles; gen's canonical form is the elements'
        # hex bit patterns (decimal float text differs across languages).
        if tag == 'null':
            return (actual is None), 'array-null'
        if actual is None:
            return False, 'array unexpected null'
        got = '[' + ','.join('%016x' % gen.f64_to_bits(float(x))
                             for x in actual) + ']'
        return (got == expected[1]), 'array-hex'
    if ty == 'long256':
        # /exec renders NULL as '', zero as '0x00', and values zero-padded to
        # 64 hex; gen trims leading zeros. Compare on the leading-zero-stripped
        # hex so both forms agree.
        def _norm256(s):
            if s is None or s == '':
                return None
            h = str(s)
            h = h[2:] if h.startswith('0x') else h
            h = h.lstrip('0')
            return h if h else '0'
        if tag == 'null':
            return (_norm256(actual) is None), 'long256-null'
        return (_norm256(actual) == _norm256(expected[1])), 'long256-hex'

    if tag == 'null':
        return (actual is None), 'expected null'
    if actual is None:
        return False, 'unexpected null'

    if tag == 'bool':
        return (bool(actual) == expected[1]), 'bool'
    if tag == 'int':
        return (int(actual) == expected[1]), 'int'
    if tag == 'float':
        a = float(actual)
        if ty == 'float':
            # A FLOAT column stores f32, which /exec renders at f32 precision.
            # Compare at f32 precision — idempotent, so it also holds when the
            # value sits in a widening-preserving DOUBLE column (the Buffer leg).
            return (gen.f32_round(a) == gen.f32_round(expected[1])), 'f32'
        # DOUBLE: exact via f64 bit pattern (QuestDB emits shortest
        # round-trippable text, so reparsing recovers the double).
        return (gen.f64_to_bits(a) == gen.f64_to_bits(expected[1])), 'float-bits'
    if tag == 'text':
        return (str(actual) == expected[1]), 'text'
    if tag == 'bytes':
        # /exec renders BINARY as hex text; compare hex.
        return (str(actual).lower() == expected[1].hex()), 'bytes-hex'
    return False, f'unhandled tag {tag}'


def reconcile_values(query, table, seed, worker, sample_seqs,
                     types=None, projection=None):
    """I3: for each sampled seq, compare every verifiable column of the leg's
    ``types`` against gen. ``types`` is the subset that leg actually wrote
    (each leg covers a different slice of the 22); calibration-skipped types
    (``_CALIBRATE``) are dropped. ``projection`` maps a column name to the SQL
    expression that renders it comparably (defaults to the calibrated map)."""
    types = list(types) if types is not None else list(gen.QWP_TYPES)
    projection = projection if projection is not None else default_projection()
    check_types = [t for t in types if t not in _CALIBRATE]
    cols = [gen.COL_NAME[t] for t in check_types]
    if not cols:
        return Verdict('I3', f'{table}:w{worker}', True,
                       {'checked': 0, 'note': 'no verifiable columns'})
    select_list = ', '.join(projection.get(c, c) for c in cols)

    # Fetch all sampled rows keyed by c_seq in a few IN() scans rather than one
    # query per seq. c_seq is not indexed, so a per-seq point lookup is a full
    # table scan; 1000 of them over a 100M+-row table is 1000 scans. Chunk the
    # IN list so the query URL stays small.
    seqs = list(sample_seqs)
    by_seq = {}
    chunk = 200
    for i in range(0, len(seqs), chunk):
        in_list = ','.join(str(s) for s in seqs[i:i + chunk])
        rows = query(f'SELECT {SEQ_COL}, {select_list} FROM {table} '
                     f'WHERE {WORKER_COL}={worker} AND {SEQ_COL} IN ({in_list})')
        for r in rows:
            by_seq[r[0]] = r[1:]

    mismatches = []
    checked = 0
    for seq in seqs:
        row = by_seq.get(seq)
        if row is None:
            mismatches.append({'seq': seq, 'reason': 'missing'})
            continue
        for ty, actual, col in zip(check_types, row, cols):
            exp = gen.gen_expected(seed, worker, seq, ty)
            ok, reason = compare_value(ty, exp, actual)
            checked += 1
            if not ok:
                mismatches.append({
                    'seq': seq, 'col': col, 'reason': reason,
                    'expected': exp[1] if len(exp) > 1 else None,
                    'actual': actual})
    return Verdict('I3', f'{table}:w{worker}', not mismatches, {
        'checked': checked, 'sampled_seqs': len(sample_seqs),
        'verified_types': check_types,
        'skipped_types': sorted(t for t in types if t in _CALIBRATE),
        'mismatches': mismatches[:20],
    })


# ---------------------------------------------------------------------------
# summary.json
# ---------------------------------------------------------------------------

def summarize(verdicts, seed=None, duration_min=None, profile=None, rate=None):
    failed = [v for v in verdicts if not v.passed]
    by_inv = {}
    for v in verdicts:
        b = by_inv.setdefault(v.invariant, {'pass': 0, 'fail': 0})
        b['pass' if v.passed else 'fail'] += 1
    repro = None
    if seed is not None:
        repro = (f'soak.py run --seed {seed} --duration {duration_min} '
                 f'--profile {profile}')
        if rate is not None:
            repro += f' --rate {rate}'
    return {
        'passed': not failed,
        'repro': repro,
        'totals': {'checks': len(verdicts), 'failed': len(failed)},
        'by_invariant': by_inv,
        'failures': [v.to_dict() for v in failed],
        'verdicts': [v.to_dict() for v in verdicts],
    }


# ---------------------------------------------------------------------------
# Independent query path (HTTP /exec) — never the client under test.
# ---------------------------------------------------------------------------

def wait_wal_applied(query, table, timeout=120):
    """Block until QuestDB has applied every WAL txn for `table`
    (writerTxn == sequencerTxn), so a reconciliation query sees the full
    ingested set. QuestDB WAL apply is asynchronous — querying too early
    undercounts. Returns True if synced within `timeout`."""
    import time
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            r = query("SELECT writerTxn, sequencerTxn FROM wal_tables() "
                      f"WHERE name='{table}'")
            if r and r[0][0] == r[0][1]:
                return True
        except Exception:  # noqa: BLE001 - transient; keep polling
            pass
        time.sleep(0.5)
    return False


class HttpQuery:
    def __init__(self, host, http_port, timeout=15):
        self.host = host
        self.http_port = int(http_port)
        self.timeout = timeout

    def __call__(self, sql):
        url = (f'http://{self.host}:{self.http_port}/exec?'
               + urllib.parse.urlencode({'query': sql}))
        req = urllib.request.Request(url, method='GET')
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            # QuestDB returns a 4xx with a JSON body carrying the SQL error
            # (e.g. a table in flux mid-reconcile). Surface it as a normal
            # RuntimeError instead of an opaque HTTPError so the reconcile can
            # record a failed verdict rather than abort.
            body = ''
            try:
                body = e.read().decode('utf-8', 'replace')
            except Exception:  # noqa: BLE001
                pass
            raise RuntimeError(f'query HTTP {e.code}: {body}: {sql}') from None
        if 'error' in data:
            raise RuntimeError(f'query error: {data["error"]}: {sql}')
        return data.get('dataset', [])


# ---------------------------------------------------------------------------
# selftest — synthetic data, no server.
# ---------------------------------------------------------------------------

def _selftest():
    failures = []

    def check(cond, msg):
        if cond:
            print(f'ok: {msg}')
        else:
            failures.append(msg)
            print(f'FAIL: {msg}', file=sys.stderr)

    check(abs(linreg_slope([0, 1, 2, 3], [0, 2, 4, 6]) - 2.0) < 1e-9, 'slope 2.0')
    check(abs(linreg_slope([0, 1, 2], [5, 5, 5])) < 1e-9, 'flat slope 0')

    # I4: a clean run (flat RSS/FD, drained pools) passes.
    def sample(t, rss, fd, in_use=0, backlog=0, mx=0, leg='L'):
        return {'t': t, 'leg': leg, 'rss_bytes': rss, 'fd_count': fd,
                'pool': {'ingress': [1, in_use, 0]},
                'sf': {'mem_backlog_bytes': backlog, 'max_bytes': mx,
                       'disk_bytes': 0}}

    clean = [sample(i, 100_000_000 + (i % 3) * 1000, 20) for i in range(20)]
    cfg = BoundsConfig(warmup_seconds=0, require_pool_drain=True)
    vc = analyze_bounds(clean, cfg)
    check(all(v.passed for v in vc), 'I4 clean run passes')

    # I4: a steady RSS leak (linear growth) fails the slope bound.
    leak = [sample(i, 100_000_000 + i * 5_000_000, 20) for i in range(20)]
    vl = analyze_bounds(leak, cfg)
    check(any(v.invariant == 'I4' and 'rss' in v.name and not v.passed for v in vl),
          'I4 detects RSS leak')

    # I4: an FD leak (monotonic fd growth) fails.
    fdleak = [sample(i, 100_000_000, 20 + i) for i in range(20)]
    vf = analyze_bounds(fdleak, cfg)
    check(any(v.name.endswith(':fd') and not v.passed for v in vf),
          'I4 detects FD leak')

    fdheld = [sample(i * 300, 100_000_000, 3 if i % 5 == 0 else 11) for i in range(20)]
    vh = analyze_bounds(fdheld, cfg)
    check(all(v.passed for v in vh if v.name.endswith(':fd')),
          'I4 bounded held-fd working set passes')

    # I4: SF mem backlog exceeding max_bytes fails.
    sfbad = [sample(i, 100_000_000, 20, backlog=200, mx=100) for i in range(20)]
    vs = analyze_bounds(sfbad, cfg)
    check(any(v.name.endswith(':sf') and not v.passed for v in vs),
          'I4 detects SF backlog over max')

    # I4: a pool that never drains (in_use != 0 at the end) fails.
    nodrain = [sample(i, 100_000_000, 20, in_use=2) for i in range(20)]
    vn = analyze_bounds(nodrain, cfg)
    check(any('pool' in v.name and not v.passed for v in vn),
          'I4 detects undrained pool')
    held = [sample(i, 100_000_000, 20, in_use=1) for i in range(20)]
    vh = analyze_bounds(held, cfg)
    check(any('pool' in v.name and not v.passed for v in vh),
          'I4 requires final single borrow to drain')

    # I4: a store-and-forward backlog leak (in-flight frames grow unbounded).
    def isample(t, pub, ack):
        s = sample(t, 100_000_000, 20)
        s['published_fsn'] = pub
        s['acked_fsn'] = ack
        return s
    leak_if = [isample(i, 100 + i * 5000, 100) for i in range(20)]
    check(any(v.name.endswith(':inflight') and not v.passed
              for v in analyze_bounds(leak_if, cfg)),
          'I4 detects in-flight backlog leak')
    ok_if = [isample(i, 100 + i, 90 + i) for i in range(20)]  # in-flight ~10
    check(all(v.passed for v in analyze_bounds(ok_if, cfg)
              if v.name.endswith(':inflight')),
          'I4 bounded in-flight passes')

    # I1/I2: fake query. Completeness selects count()/max/min (has `max(`);
    # duplication selects count() only. No count_distinct (multi-GB on a huge
    # table); these are DEDUP tables so count() == the distinct count.
    def fake_stats(total, mx, mn):
        def q(sql):
            if 'max(' in sql:
                return [[total, mx, mn]]
            return [[total]]
        return q

    v1_ok = check_completeness(fake_stats(1000, 999, 0), 't', 0, 999)
    check(v1_ok.passed, 'I1 complete passes')
    v1_gap = check_completeness(fake_stats(999, 999, 0), 't', 0, 999)
    check(not v1_gap.passed, 'I1 gap fails (missing seq)')

    # I2: surplus over the sequence length is the duplication; within budget vs
    # over; control / dedup must be exact (budget 0).
    v2_ok = check_duplication(fake_stats(1010, 999, 0), 't', 0, 999, replay_budget=64)
    check(v2_ok.passed, 'I2 within budget passes')
    v2_over = check_duplication(fake_stats(1100, 999, 0), 't', 0, 999, replay_budget=64)
    check(not v2_over.passed, 'I2 over budget fails')
    v2_ctl = check_duplication(fake_stats(1001, 999, 0), 't', 0, 999,
                               replay_budget=64, is_control=True)
    check(not v2_ctl.passed, 'I2 control dup fails (must be exact)')

    # I5: the fsync'd journal watermark proves which deterministic mixed-shape
    # batches reached an ACK. A partial cycle fails; one full cycle passes.
    shapes = ['arrow', 'buffer', 'chunk']
    v5_partial = check_mixed_shape_coverage('mixed', 3999, 2000, shapes)
    check(not v5_partial.passed
          and v5_partial.detail['completed_shapes'] == shapes[:2],
          'I5 partial mixed-shape cycle fails')
    v5_full = check_mixed_shape_coverage('mixed', 5999, 2000, shapes)
    check(v5_full.passed
          and v5_full.detail['completed_shapes'] == shapes,
          'I5 complete mixed-shape cycle passes')

    # I3: value comparison for scalars.
    check(compare_value('boolean', ('bool', True), True)[0], 'I3 bool match')
    check(not compare_value('boolean', ('bool', True), False)[0], 'I3 bool mismatch')
    check(compare_value('long', ('int', -5), -5)[0], 'I3 int match')
    check(compare_value('double', ('float', 1.5), 1.5)[0], 'I3 double match')
    check(compare_value('int', ('null',), None)[0], 'I3 null match')
    check(not compare_value('int', ('null',), 0)[0], 'I3 null vs 0 mismatch')
    check(compare_value('symbol', ('text', 'sym_1'), 'sym_1')[0], 'I3 text match')

    # I3 calibrated exotics: ipv4 (dotted-quad) + binary (length proxy).
    check(compare_value('ipv4', ('int', 3435573785), '204.198.178.25')[0],
          'I3 ipv4 dotted-quad match')
    check(not compare_value('ipv4', ('int', 3435573785), '1.2.3.4')[0],
          'I3 ipv4 mismatch')
    check(compare_value('ipv4', ('null',), None)[0], 'I3 ipv4 null')
    # 0.0.0.0 is QuestDB's IPv4 NULL sentinel: a sent 0 reads back as NULL.
    check(compare_value('ipv4', ('int', 0), None)[0], 'I3 ipv4 zero reads null')
    check(not compare_value('ipv4', ('int', 0), '0.0.0.0')[0],
          'I3 ipv4 zero never renders dotted')
    check(compare_value('binary', ('bytes', b'\x01\x02\x03'), 3)[0],
          'I3 binary length match')
    check(not compare_value('binary', ('bytes', b'\x01\x02\x03'), 2)[0],
          'I3 binary length mismatch')
    check(compare_value('binary', ('null',), None)[0], 'I3 binary null')
    # length(NULL binary) reads back as -1, not SQL NULL.
    check(compare_value('binary', ('null',), -1)[0], 'I3 binary null reads -1')

    # reconcile_values honours a per-leg type subset: a fake query returning
    # the expected value for the leg's single type passes and counts it.
    exp_bool = gen.gen_expected(1, 0, 0, 'boolean')
    # Query now selects c_seq first, then the value columns, and is batched by
    # IN(): the fake returns one [c_seq, value] row.
    v3 = reconcile_values(lambda sql: [[0, exp_bool[1]]], 't', 1, 0, [0],
                          types=['boolean'])
    check(v3.passed and v3.detail['checked'] == 1,
          'I3 subset reconcile passes')
    # A sampled seq missing from the table is a mismatch (not a silent pass).
    v3_missing = reconcile_values(lambda sql: [], 't', 1, 0, [0],
                                  types=['boolean'])
    check(not v3_missing.passed, 'I3 missing row fails')
    # long256 normalization: leading-zero-padded / empty-string forms.
    check(compare_value('long256', ('text', '0xb5d'), '0x0b5d')[0],
          'I3 long256 leading-zero')
    check(compare_value('long256', ('null',), '')[0], 'I3 long256 null=empty')
    check(compare_value('long256', ('text', '0x0'), '0x00')[0],
          'I3 long256 zero')
    # double_array: list of doubles vs hex-bit canonical form.
    import struct as _s
    def _hx(x):
        return '%016x' % _s.unpack('<Q', _s.pack('<d', x))[0]
    check(compare_value('double_array', ('text', '[' + _hx(1.5) + ']'), [1.5])[0],
          'I3 array hex match')

    # summary.json shape.
    s = summarize(vl, seed=7, duration_min=60, profile='full', rate=1000)
    check(s['passed'] is False and s['totals']['failed'] >= 1, 'summary marks failure')
    check(s['repro'].endswith('--rate 1000'), 'summary repro includes rate')
    check(json.dumps(s), 'summary is json-serialisable')

    if failures:
        print(f'\n{len(failures)} failure(s)', file=sys.stderr)
        return 1
    print('\noracle selftest: all checks passed')
    return 0


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='Soak oracle')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('selftest')
    args = ap.parse_args(argv)
    if args.cmd == 'selftest':
        return _selftest()
    return 2


if __name__ == '__main__':
    sys.exit(_main(sys.argv[1:]))
