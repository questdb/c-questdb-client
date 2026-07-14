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
Soak / stress orchestrator (see ``doc/QWP_SOAK_HARNESS.md``).

Conducts a run: provision QuestDB (control + faulted), start the fault proxy,
spawn the workload legs, then loop — sampling RSS/FD + workload stats every few
seconds and firing fault episodes on a seeded schedule — until the duration
elapses. Finally it drains, reconciles via :mod:`oracle`, and writes
``summary.json`` + ``stats.jsonl``.

The seeded :class:`EpisodeSchedule` and the :class:`Sampler` are pure enough to
unit-test without a server (``soak.py selftest``); the full ``run`` mode needs a
built ``soak-workload`` binary and a QuestDB to provision.
"""

import sys

sys.dont_write_bytecode = True

import json
import os
import random
import signal
import subprocess
import time


# ---------------------------------------------------------------------------
# Episodes — the seeded fault schedule (§6). Deterministic from --seed.
# ---------------------------------------------------------------------------

# Server restarts are graceful (SIGTERM) only: QuestDB flushes + fsyncs on the
# way out, so no committed data is lost — matching the fuzz suite's bounce. The
# hard-kill (SIGKILL) server path is intentionally omitted; surviving it needs
# `request_durable_ack=on` (an ack means fsynced, so the client re-drives only
# the un-acked tail), which these legs don't set. That crash-durability guarantee
# is covered by the durable-ack kill9 tests under system_test/enterprise_e2e/.
# `client_kill9` stays: the client's ack journal is fsynced, so a killed client
# resumes from its durable watermark and re-drives — no loss.
EPISODE_KINDS = [
    'server_graceful', 'client_kill9', 'client_graceful',
    'conn_reset', 'stall', 'throttle',
]


class Episode:
    __slots__ = ('at', 'kind', 'params')

    def __init__(self, at, kind, params):
        self.at = at          # seconds from run start
        self.kind = kind
        self.params = params

    def __repr__(self):
        return f'Episode(at={self.at:.1f}, {self.kind}, {self.params})'


class EpisodeSchedule:
    """A reproducible list of episodes for one run. Same seed + duration =>
    identical schedule (so a failing run replays exactly)."""

    def __init__(self, seed, duration_sec, min_gap=180, max_gap=420,
                 warmup_sec=120, kinds=None, tail_quiet=180):
        self.seed = seed
        self.duration_sec = duration_sec
        self.kinds = kinds or EPISODE_KINDS
        self._episodes = self._build(min_gap, max_gap, warmup_sec, tail_quiet)

    def _build(self, min_gap, max_gap, warmup_sec, tail_quiet):
        rng = random.Random(self.seed)
        episodes = []
        # `tail_quiet` leaves a quiet tail so the final reconciliation runs
        # undisturbed.
        t = warmup_sec + rng.uniform(min_gap, max_gap)
        while t < self.duration_sec - tail_quiet:
            kind = rng.choice(self.kinds)
            episodes.append(Episode(t, kind, self._params(kind, rng)))
            t += rng.uniform(min_gap, max_gap)
        return episodes

    def _params(self, kind, rng):
        if kind == 'stall':
            return {'seconds': round(rng.uniform(10, 60), 1)}
        if kind == 'throttle':
            return {'bps': rng.choice([50_000, 100_000, 250_000]),
                    'seconds': round(rng.uniform(60, 180), 1)}
        if kind == 'conn_reset':
            return {'after_bytes': rng.choice([0, 4096, 65536])}
        return {}

    def episodes(self):
        return list(self._episodes)

    def __len__(self):
        return len(self._episodes)


# ---------------------------------------------------------------------------
# Sampler — per-pid RSS + FD. Linux /proc first (design is Linux-first),
# psutil if available, else `ps`/`lsof` so a macOS dev box can still run the
# I4 resource checks locally (without a sampler, I4 silently collects nothing).
# ---------------------------------------------------------------------------

def _ps_rss_bytes(pid):
    """RSS via `ps` (KiB) — fallback when neither psutil nor /proc is present.
    Returns None for a dead pid (ps prints nothing)."""
    try:
        out = subprocess.run(['ps', '-o', 'rss=', '-p', str(pid)],
                             capture_output=True, text=True, timeout=5)
    except Exception:  # noqa: BLE001
        return None
    val = out.stdout.strip()
    return int(val) * 1024 if val.isdigit() else None


def _lsof_fd_count(pid):
    """Open-fd count via `lsof` — same fallback niche. Best-effort: None if
    lsof is unavailable or the pid is gone."""
    try:
        out = subprocess.run(['lsof', '-p', str(pid)],
                             capture_output=True, text=True, timeout=10)
    except Exception:  # noqa: BLE001
        return None
    lines = [ln for ln in out.stdout.splitlines() if ln]
    return max(len(lines) - 1, 0) if lines else None  # drop the header row


class Sampler:
    def __init__(self):
        self._psutil = None
        try:
            import psutil  # noqa: F401
            self._psutil = psutil
        except ImportError:
            pass

    def rss_bytes(self, pid):
        if self._psutil:
            try:
                return self._psutil.Process(pid).memory_info().rss
            except Exception:  # noqa: BLE001
                return None
        try:
            with open(f'/proc/{pid}/status') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        return int(line.split()[1]) * 1024
        except OSError:
            pass
        return _ps_rss_bytes(pid)

    def fd_count(self, pid):
        if self._psutil:
            try:
                return self._psutil.Process(pid).num_fds()
            except Exception:  # noqa: BLE001
                return None
        try:
            return len(os.listdir(f'/proc/{pid}/fd'))
        except OSError:
            pass
        return _lsof_fd_count(pid)

    def sample(self, pid):
        return {'rss_bytes': self.rss_bytes(pid), 'fd_count': self.fd_count(pid)}

    def dir_size(self, path):
        """Logical bytes in a directory tree, or zero if it vanished."""
        total = 0
        try:
            for root, _dirs, files in os.walk(path):
                for name in files:
                    try:
                        total += os.path.getsize(os.path.join(root, name))
                    except OSError:
                        pass
        except OSError:
            pass
        return total


# ---------------------------------------------------------------------------
# Workload process — spawn / graceful-stop / kill9 / restart. Emits stats to a
# per-leg stats file the orchestrator merges.
# ---------------------------------------------------------------------------

class Workload:
    def __init__(self, leg, binary, args, cwd=None):
        self.leg = leg
        self.binary = binary
        self.args = args
        self.cwd = cwd
        self.proc = None
        self.restarts = 0

    def start(self):
        self.proc = subprocess.Popen(
            [self.binary, 'run', '--leg', self.leg, *self.args],
            cwd=self.cwd)
        return self.proc.pid

    @property
    def pid(self):
        return self.proc.pid if self.proc else None

    def is_alive(self):
        return self.proc is not None and self.proc.poll() is None

    def kill9(self):
        if self.is_alive():
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait(timeout=10)

    def graceful(self, timeout=30):
        if self.is_alive():
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.kill9()

    def restart(self):
        self.start()
        self.restarts += 1
        return self.pid

    def returncode(self):
        return self.proc.returncode if self.proc else None


# ---------------------------------------------------------------------------
# Conductor
# ---------------------------------------------------------------------------

class SoakRun:
    def __init__(self, opts):
        self.opts = opts
        self.sampler = Sampler()
        self.samples = []
        self.workloads = []
        self.schedule = EpisodeSchedule(
            opts['seed'], opts['duration_sec'],
            min_gap=opts.get('min_gap', 180), max_gap=opts.get('max_gap', 420),
            warmup_sec=opts.get('warmup', 120), kinds=opts.get('kinds'),
            tail_quiet=opts.get('tail_quiet', 180))

    #: Workload binary, built by `cargo build --release` in the crate.
    WORKLOAD_BIN = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'workload_rs', 'target', 'release', 'soak-workload')

    def run(self):
        # Heavy imports only in real runs so `selftest` needs no server deps.
        import argparse
        import fault_proxy
        import oracle as oracle_mod
        # StandaloneInstance / jar resolution are proven in the failover system
        # test; reuse rather than re-implement the launch dance. It lives in the
        # parent system_test/ dir, which isn't on sys.path when soak.py runs as
        # a script (only its own dir is).
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from test_egress_failover import (
            StandaloneInstance, _resolve_jar, _find_java, _wait_for_ping)

        class _RestartableInstance(StandaloneInstance):
            """A `StandaloneInstance` that can bounce without wiping its data.

            The base `start()` resets the data dir and re-picks ports on every
            call (correct for a fresh start, but a *restart* must keep both or
            the server comes back empty — which masquerades as data loss).
            `restart()` relaunches the same jar against the existing data dir,
            conf, and ports. Keep the launch args in sync with
            `StandaloneInstance.start()`.
            """

            def restart(self):
                self._log_file = open(self.data_dir / 'log' / 'log.txt', 'ab')
                self._proc = subprocess.Popen(
                    [
                        str(_find_java()),
                        f'-DQuestDB-{self.label}',
                        '-ea',
                        '-Dnoebug',
                        '-XX:+UnlockExperimentalVMOptions',
                        '-XX:+AlwaysPreTouch',
                        '--add-exports=java.base/jdk.internal.vm=io.questdb',
                        '-p', str(self.jar),
                        '-m', 'io.questdb/io.questdb.ServerMain',
                        '-d', str(self.data_dir),
                    ],
                    cwd=str(self.data_dir),
                    stdout=self._log_file,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                )
                _wait_for_ping(self.host, self.http_port)

        outdir = self.opts['outdir']
        os.makedirs(outdir, exist_ok=True)
        self._write_episode_log(outdir)

        if not os.path.exists(self.WORKLOAD_BIN):
            raise SystemExit(
                f'workload binary missing: {self.WORKLOAD_BIN}\n'
                f'build it first: cargo build --release '
                f'--manifest-path system_test/soak/workload_rs/Cargo.toml')

        server_addr = self.opts.get('server')
        if server_addr:
            # Run against an already-running QuestDB: skip the build + provision
            # dance. No managed process, so server-restart episodes are no-ops
            # and the faulted + control legs share this single instance.
            from test_egress_failover import _http_exec

            class _ExistingServer:
                def __init__(self, host, port):
                    self.host, self.http_port, self._proc = host, port, None

                def start(self):
                    pass

                def kill(self):
                    pass

                def is_alive(self):
                    return True

                def http_exec(self, sql):
                    return _http_exec(self.host, self.http_port, sql)

            host, _, port = server_addr.partition(':')
            self.faulted = _ExistingServer(host or '127.0.0.1', int(port or 9000))
            self.control = self.faulted
            self._managed_server = False
        else:
            jar = _resolve_jar(argparse.Namespace(
                repo=self.opts.get('repo'), versions=None))
            root = os.path.join(outdir, 'servers')
            os.makedirs(root, exist_ok=True)

            self.faulted = _RestartableInstance(jar, os.path.join(root, 'faulted'), 'faulted')
            self.control = _RestartableInstance(jar, os.path.join(root, 'control'), 'control')
            self.faulted.start()
            try:
                self.control.start()
            except Exception:
                self.faulted.kill()
                raise
            self._managed_server = True

        if self.opts.get('no_proxy'):
            # Legs hit the server directly; proxy-based faults become no-ops.
            self.proxy = None
            faulted_addr = f'{self.faulted.host}:{self.faulted.http_port}'
        else:
            self.proxy = fault_proxy.FaultProxy(self.faulted.host, self.faulted.http_port)
            proxy_port = self.proxy.start()
            faulted_addr = f'{self.faulted.host}:{proxy_port}'

        # The type slice each payload leg actually writes, used for I3 value
        # reconciliation. Faulted legs use the proxy; the control leg connects
        # straight to the never-faulted server.
        buffer_types = ['boolean', 'byte', 'short', 'int', 'long', 'float',
                        'double', 'symbol', 'varchar', 'char', 'decimal64',
                        'decimal128', 'decimal256', 'double_array', 'geohash']
        chunk_types = ['boolean', 'byte', 'short', 'int', 'long', 'float',
                       'double', 'symbol', 'timestamp', 'date', 'uuid', 'varchar',
                       'timestamp_nanos', 'binary', 'ipv4', 'long256']
        mixed_types = ['boolean', 'long', 'double', 'symbol', 'varchar']
        self.legs = [
            # One borrowed SFA sender cycles Arrow -> Buffer -> Chunk. Keep the
            # disk leg first so client kill/restart episodes exercise persisted
            # mixed-shape dictionary and frame recovery.
            {'name': 'rust-mixed-saf-disk', 'faulted': True, 'worker': 6,
             'table': 'soak_mixed_saf_disk', 'types': mixed_types, 'sf': 'disk',
             'mixed_shapes': ['arrow', 'buffer', 'chunk'], 'batch': 2000,
             'addr': faulted_addr, 'server': self.faulted},
            {'name': 'rust-mixed-saf-mem', 'faulted': True, 'worker': 7,
             'table': 'soak_mixed_saf_mem', 'types': mixed_types, 'sf': 'mem',
             'mixed_shapes': ['arrow', 'buffer', 'chunk'], 'batch': 2000,
             'addr': faulted_addr, 'server': self.faulted},
            {'name': 'rust-buffer-saf-default', 'faulted': True, 'worker': 0,
             'table': 'soak_buffer_saf_default', 'types': buffer_types,
             'addr': faulted_addr, 'server': self.faulted},
            {'name': 'rust-chunk-saf-default', 'faulted': True, 'worker': 2,
             'table': 'soak_chunk_saf_default', 'types': chunk_types,
             'addr': faulted_addr, 'server': self.faulted},
            # DataFrame->Arrow->wire path (needs a `--features dataframe` binary).
            {'name': 'rust-dataframe-direct', 'faulted': True, 'worker': 3,
             'table': 'soak_dataframe_direct',
             'types': ['boolean', 'long', 'double', 'symbol'],
             'addr': faulted_addr, 'server': self.faulted},
            {'name': 'rust-buffer-saf-disk', 'faulted': True, 'worker': 4,
             'table': 'soak_buffer_saf_disk', 'types': buffer_types, 'sf': 'disk',
             'addr': faulted_addr, 'server': self.faulted},
            {'name': 'rust-buffer-saf-mem', 'faulted': True, 'worker': 5,
             'table': 'soak_buffer_saf_mem', 'types': buffer_types, 'sf': 'mem',
             'addr': faulted_addr, 'server': self.faulted},
            {'name': 'control-buffer-saf-default', 'faulted': False, 'worker': 1,
             'table': 'soak_control_buffer_saf_default', 'types': buffer_types,
             'addr': f'{self.control.host}:{self.control.http_port}',
             'server': self.control},
            # Read-only: full-scans the faulted Chunk table under query load +
            # read-side failover. No journal; its own contiguity check gates it.
            {'name': 'rust-egress-whole', 'faulted': True, 'worker': 2,
             'table': 'soak_chunk_saf_default', 'kind': 'egress',
             'addr': faulted_addr, 'server': self.faulted},
        ]

        try:
            for leg in self.legs:
                if leg.get('kind') != 'egress':  # egress reads an ingest table
                    self._create_dedup_table(leg['server'], leg['table'])
            self._spawn_legs(outdir)
            self._main_loop()
        finally:
            self._drain_and_stop()

        summary = self._reconcile(oracle_mod)
        self._write_stats(outdir)
        with open(os.path.join(outdir, 'summary.json'), 'w') as f:
            json.dump(summary, f, indent=2)

        if self.proxy is not None:
            self.proxy.stop()
        self.faulted.kill()
        self.control.kill()

        print(f'\nsummary: {summary["totals"]}  (passed={summary["passed"]})')
        return 0 if summary['passed'] else 1

    def _create_dedup_table(self, server, table):
        # worker_id + designated timestamp exist at CREATE so DEDUP can key on
        # them; ILP auto-adds c_seq and the type columns on first ingest.
        server.http_exec(
            f'CREATE TABLE IF NOT EXISTS {table} '
            f'(worker_id LONG, timestamp TIMESTAMP) '
            f'TIMESTAMP(timestamp) PARTITION BY DAY WAL '
            f'DEDUP UPSERT KEYS(timestamp, worker_id)')

    def _spawn_legs(self, outdir):
        dur = self.opts['duration_sec']
        rate = self.opts.get('rate', 20000)
        for leg in self.legs:
            journal = os.path.join(outdir, f'{leg["name"]}.journal')
            stats = os.path.join(outdir, f'{leg["name"]}.stats.jsonl')
            args = [
                '--seed', str(self.opts['seed']),
                '--worker-id', str(leg['worker']),
                '--addr', leg['addr'],
                '--table', leg['table'],
                '--journal', journal,
                '--stats', stats,
                '--rate', str(rate),
                '--duration-sec', str(dur),
                '--batch', str(leg.get('batch', 2000)),
            ]
            # Store-and-forward backends.
            sfdir = None
            if leg.get('sf') == 'disk':
                sfdir = os.path.join(outdir, f'{leg["name"]}.sfdir')
                os.makedirs(sfdir, exist_ok=True)
                args += ['--sf-dir', sfdir]
            elif leg.get('sf') == 'mem':
                args += ['--sf-mem-bytes', str(64 * 1024 * 1024)]
            w = Workload(leg['name'], self.WORKLOAD_BIN, args)
            w.stats_file = stats
            w.journal_file = journal
            w.sf_dir = sfdir
            w.meta = leg
            w.start()
            self.workloads.append(w)
            sys.stderr.write(f'[soak] spawned {leg["name"]} pid={w.pid}\n')

    def _main_loop(self):
        import time as _time
        episodes = list(self.schedule.episodes())
        next_ep = 0
        reverts = []  # (revert_at, fn)
        start = _time.monotonic()
        while True:
            now = _time.monotonic()
            elapsed = now - start
            if elapsed >= self.opts['duration_sec']:
                break
            if not any(w.is_alive() for w in self.workloads):
                sys.stderr.write('[soak] all workloads exited; ending loop\n')
                break
            # Fire due episodes.
            while next_ep < len(episodes) and episodes[next_ep].at <= elapsed:
                self._fire_episode(episodes[next_ep], reverts, start)
                next_ep += 1
            # Run due reverts (throttle clear, reset disarm).
            due = [r for r in reverts if r[0] <= now]
            for r in due:
                r[1]()
                reverts.remove(r)
            self.sample_all(_time.time())
            _time.sleep(3.0)

    def _fire_episode(self, ep, reverts, start):
        import time as _time
        sys.stderr.write(f'[soak] episode @ {ep.at:.0f}s: {ep.kind} {ep.params}\n')
        if ep.kind == 'server_graceful':
            if not self._managed_server:
                sys.stderr.write('[soak]   skipped: no managed server (existing-server mode)\n')
                return
            if self.proxy is None:
                sys.stderr.write('[soak]   skipped: no proxy to remap the restarted port (--no-proxy)\n')
                return
        if ep.kind in ('conn_reset', 'stall', 'throttle') and self.proxy is None:
            sys.stderr.write('[soak]   skipped: no proxy (--no-proxy)\n')
            return
        p = ep.params
        if ep.kind == 'server_graceful':
            # Graceful SIGTERM, then `restart()` (not `start()`): the bounce
            # preserves the data dir + port so the server recovers its committed
            # data. A fresh `start()` would wipe it and masquerade as data loss.
            if self.faulted._proc:
                self.faulted._proc.terminate()
                try:
                    self.faulted._proc.wait(timeout=30)
                except Exception:  # noqa: BLE001
                    self.faulted.kill()
            else:
                self.faulted.kill()
            _time.sleep(0.1)  # let the port free up before rebinding
            self.faulted.restart()
            self.proxy.set_upstream(self.faulted.host, self.faulted.http_port)
        elif ep.kind in ('client_kill9', 'client_graceful'):
            faulted_wls = [w for w in self.workloads if w.meta.get('faulted')]
            if faulted_wls:
                w = faulted_wls[0]
                if ep.kind == 'client_kill9':
                    w.kill9()
                else:
                    w.graceful()
                w.restart()
        elif ep.kind == 'conn_reset':
            after = p.get('after_bytes', 0)
            if after:
                self.proxy.arm_reset_after(after)
                reverts.append((_time.monotonic() + 10.0,
                                lambda: self.proxy.arm_reset_after(0)))
            else:
                self.proxy.reset_all()
        elif ep.kind == 'stall':
            self.proxy.stall(p['seconds'])  # self-expiring
        elif ep.kind == 'throttle':
            self.proxy.throttle(p['bps'])
            reverts.append((_time.monotonic() + p['seconds'],
                            lambda: self.proxy.throttle(0)))

    def _drain_and_stop(self):
        import time as _time
        # Let the legs finish their duration and drain, then merge the final
        # internal stats each leg writes after releasing its borrowed handle.
        for w in self.workloads:
            if w.is_alive():
                w.graceful(timeout=90)
        _time.sleep(2.0)
        self._append_quiesce_samples(_time.time())

    def _append_quiesce_samples(self, now):
        for w in self.workloads:
            previous = next(
                (sample for sample in reversed(self.samples)
                 if sample.get('leg') == w.leg),
                None)
            internal = self._read_latest_internal(w)
            if previous is None or internal is None:
                continue
            # The process has exited, so retain its final live RSS/FD sample for
            # trend analysis while replacing pool/watermark state with the
            # post-release record it flushed immediately before exit.
            row = {
                't': now,
                'leg': w.leg,
                'pid': w.pid,
                'rss_bytes': previous.get('rss_bytes'),
                'fd_count': previous.get('fd_count'),
            }
            row.update(internal)
            if w.sf_dir:
                row['sf'] = {'disk_bytes': self.sampler.dir_size(w.sf_dir)}
            self.samples.append(row)

    def _reconcile(self, oracle_mod):
        verdicts = []
        # I4 boundedness over all samples.
        bounds = oracle_mod.analyze_bounds(self.samples)
        if not bounds:
            # No I4 verdicts means no usable RSS samples were collected (no
            # psutil / procfs / ps on the box). Fail loudly instead of letting
            # the run report a green summary that silently skipped every
            # resource, pool and leak bound.
            verdicts.append(oracle_mod.Verdict(
                'I4', 'resource-sampling', False,
                {'reason': 'no RSS samples collected; I4 resource/pool/leak '
                           'bounds were not evaluated',
                 'samples': len(self.samples)}))
        verdicts.extend(bounds)
        wl_by_name = {w.leg: w for w in self.workloads}
        for leg in self.legs:
            # Egress legs are read-only: no journal to reconcile. Their own
            # contiguity check gates them — a non-zero (non-signal) exit means
            # a gap or query error. Surface it as an I7 verdict.
            if leg.get('kind') == 'egress':
                w = wl_by_name.get(leg['name'])
                rc = w.returncode() if w else None
                ok = rc in (0, None, -15)  # 0 clean, -15 SIGTERM stop, None still up
                verdicts.append(oracle_mod.Verdict(
                    'I7', leg['name'], ok, {'returncode': rc}))
                continue
            wm = self._journal_watermark(
                os.path.join(self.opts['outdir'], f'{leg["name"]}.journal'))
            if wm is None:
                verdicts.append(oracle_mod.Verdict(
                    'I1', leg['name'], False, 'no journal watermark'))
                continue
            if leg.get('mixed_shapes'):
                verdicts.append(oracle_mod.check_mixed_shape_coverage(
                    leg['name'], wm, leg['batch'], leg['mixed_shapes']))
            try:
                query = oracle_mod.HttpQuery(leg['server'].host, leg['server'].http_port)
                # WAL apply is async; wait until the server has applied
                # everything so completeness/value queries see the full set.
                oracle_mod.wait_wal_applied(query, leg['table'])
                is_control = not leg['faulted']
                verdicts.append(oracle_mod.check_completeness(
                    query, leg['table'], leg['worker'], wm))
                verdicts.append(oracle_mod.check_duplication(
                    query, leg['table'], leg['worker'], wm,
                    replay_budget=0, is_control=is_control, dedup=True))
                # I3: value correctness on a seeded sample of the leg's rows.
                sample = self._sample_seqs(wm)
                verdicts.append(oracle_mod.reconcile_values(
                    query, leg['table'], self.opts['seed'], leg['worker'],
                    sample, types=leg.get('types')))
            except Exception as e:  # noqa: BLE001
                # A degraded server (or a table in flux at the end of a long
                # run) can fail a reconcile query; record a failed verdict for
                # this leg and keep going so one bad query can't abort the
                # whole reconcile.
                verdicts.append(oracle_mod.Verdict(
                    'I1', leg['name'], False, f'reconcile query failed: {e}'))
        return oracle_mod.summarize(
            verdicts, seed=self.opts['seed'],
            duration_min=self.opts['duration_sec'] // 60,
            profile=self.opts.get('profile'), rate=self.opts.get('rate'))

    def _journal_watermark(self, path):
        """Last complete (newline-terminated) record — mirrors AckJournal."""
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                content = f.read()
        except OSError:
            return None
        segments = content.split('\n')
        segments = segments[:-1]  # drop trailing partial/empty
        last = None
        for seg in segments:
            seg = seg.strip()
            if seg:
                try:
                    last = int(seg)
                except ValueError:
                    return None
        return last

    def _sample_seqs(self, watermark, count=1000):
        """A seeded sample of seqs in [0, watermark] for I3 value checks."""
        n = watermark + 1
        if n <= count:
            return list(range(n))
        rng = random.Random(self.opts['seed'] ^ 0x5A17)
        return sorted(rng.sample(range(n), count))

    def _write_stats(self, outdir):
        with open(os.path.join(outdir, 'stats.jsonl'), 'w') as f:
            for s in self.samples:
                f.write(json.dumps(s) + '\n')

    def _write_episode_log(self, outdir):
        path = os.path.join(outdir, 'episodes.json')
        with open(path, 'w') as f:
            json.dump({
                'seed': self.opts['seed'],
                'duration_sec': self.opts['duration_sec'],
                'episodes': [
                    {'at': e.at, 'kind': e.kind, 'params': e.params}
                    for e in self.schedule.episodes()],
            }, f, indent=2)
        return path

    def sample_all(self, now):
        """One sampling pass across all live workloads. Merges external
        RSS/FD with any internal stats the workload has emitted."""
        rows = []
        for w in self.workloads:
            if not w.is_alive():
                continue
            metrics = self.sampler.sample(w.pid)
            if metrics.get('rss_bytes') is None:
                # The process exited between the is_alive() check and the
                # sample (a leg finishing, or one killed mid-drain), so this is
                # a dead-pid read, not a measurement. Recording it would poison
                # the I4 bounds analysis (None / KiB crashes the reconcile).
                continue
            row = {'t': now, 'leg': w.leg, 'pid': w.pid}
            row.update(metrics)
            internal = self._read_latest_internal(w)
            if internal:
                row.update(internal)
            if w.sf_dir:
                row['sf'] = {'disk_bytes': self.sampler.dir_size(w.sf_dir)}
            rows.append(row)
            self.samples.append(row)
        return rows

    def _read_latest_internal(self, workload):
        """Read the last JSON line of a workload's stats file (pool counts,
        row counters, and FSN watermarks it self-reports)."""
        path = getattr(workload, 'stats_file', None)
        if not path or not os.path.exists(path):
            return None
        try:
            with open(path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                back = min(size, 8192)
                f.seek(size - back)
                tail = f.read().decode('utf-8', 'replace')
            last = tail.strip().splitlines()
            for line in reversed(last):
                line = line.strip()
                if line:
                    return json.loads(line)
        except (OSError, ValueError):
            return None
        return None


# ---------------------------------------------------------------------------
# selftest — scheduler determinism + sampler on this process.
# ---------------------------------------------------------------------------

def _selftest():
    failures = []

    def check(cond, msg):
        if cond:
            print(f'ok: {msg}')
        else:
            failures.append(msg)
            print(f'FAIL: {msg}', file=sys.stderr)

    # Schedule determinism: same seed => identical episodes.
    a = EpisodeSchedule(seed=7, duration_sec=3600).episodes()
    b = EpisodeSchedule(seed=7, duration_sec=3600).episodes()
    check([(e.at, e.kind, e.params) for e in a] == [(e.at, e.kind, e.params) for e in b],
          'schedule is deterministic for a seed')
    c = EpisodeSchedule(seed=8, duration_sec=3600).episodes()
    check([(e.at, e.kind) for e in a] != [(e.at, e.kind) for e in c],
          'distinct seed => distinct schedule')

    # Roughly the documented cadence (~10-15/hour with 3-7min gaps).
    check(6 <= len(a) <= 20, f'~hourly episode count (got {len(a)})')
    # Episodes are ordered and inside the run window with a quiet tail.
    check(all(a[i].at < a[i + 1].at for i in range(len(a) - 1)), 'episodes ordered')
    check(all(e.at < 3600 - 120 for e in a), 'episodes leave a quiet tail')
    check(all(e.kind in EPISODE_KINDS for e in a), 'episode kinds valid')

    # Param shapes.
    stalls = [e for e in a if e.kind == 'stall']
    check(all('seconds' in e.params for e in stalls), 'stall has seconds')

    # Sampler works on the current process.
    smp = Sampler()
    pid = os.getpid()
    rss = smp.rss_bytes(pid)
    fd = smp.fd_count(pid)
    # On Linux both resolve; on macOS without psutil they may be None — accept
    # either, but if present they must be sane.
    check(rss is None or rss > 0, 'sampler rss sane')
    check(fd is None or fd > 0, 'sampler fd sane')
    check(smp.dir_size(os.path.dirname(os.path.abspath(__file__))) > 0,
          'sampler directory size sane')

    # Internal-stats tail reader.
    run = SoakRun({'seed': 1, 'duration_sec': 3600, 'outdir': '/tmp'})

    class FakeWL:
        stats_file = None
    check(run._read_latest_internal(FakeWL()) is None, 'tail reader tolerates no file')

    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.jsonl', delete=False) as tf:
        tf.write('{"pool":{"ingress":[1,0,0]}}\n')
        tf.write('{"pool":{"ingress":[1,2,0]},"acked_fsn":99}\n')
        stats_path = tf.name

    class FakeWL2:
        stats_file = stats_path
    got = run._read_latest_internal(FakeWL2())
    check(got is not None and got.get('acked_fsn') == 99, 'tail reader returns last line')
    os.unlink(stats_path)

    if failures:
        print(f'\n{len(failures)} failure(s)', file=sys.stderr)
        return 1
    print('\nsoak selftest: all checks passed')
    return 0


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='Soak orchestrator')
    sub = ap.add_subparsers(dest='cmd', required=True)

    run = sub.add_parser('run', help='run a soak (needs a built workload + QuestDB)')
    run.add_argument('--seed', type=int, default=1)
    run.add_argument('--duration', type=int, default=60, help='minutes')
    run.add_argument('--profile', default='full', choices=['full', 'sanitize', 'quick'])
    run.add_argument('--rate', type=int, default=20000,
                     help='target rows/second per ingest leg (0 is unlimited)')
    run.add_argument('--outdir', default='soak-out')
    run.add_argument('--repo', help='path to a QuestDB checkout to build+run')
    run.add_argument('--server', metavar='HOST:PORT',
                     help='run against an already-running QuestDB instead of '
                          'provisioning (skips --repo); server-restart episodes '
                          'become no-ops')
    run.add_argument('--no-proxy', action='store_true',
                     help='connect legs straight to the server (no fault proxy); '
                          'proxy faults (conn_reset/stall/throttle) become no-ops')
    # Schedule knobs — defaults match EpisodeSchedule. Compressing warmup/gap
    # (e.g. --warmup 15 --min-gap 15 --max-gap 30) fires faults early for a
    # quick reproduction instead of the multi-minute production cadence.
    run.add_argument('--warmup', type=int, default=120, help='quiet seconds before the first fault')
    run.add_argument('--min-gap', type=int, default=180, help='min seconds between faults')
    run.add_argument('--max-gap', type=int, default=420, help='max seconds between faults')
    run.add_argument('--tail-quiet', type=int, default=180, help='quiet seconds before reconcile')
    run.add_argument('--kinds', help='comma-separated episode kinds to restrict to '
                                     f'(default all: {",".join(EPISODE_KINDS)})')

    sub.add_parser('selftest', help='test the scheduler + sampler, no server')

    show = sub.add_parser('schedule', help='print the episode schedule for a seed')
    show.add_argument('--seed', type=int, default=1)
    show.add_argument('--duration', type=int, default=60)

    args = ap.parse_args(argv)
    if args.cmd == 'selftest':
        return _selftest()
    if args.cmd == 'schedule':
        sched = EpisodeSchedule(args.seed, args.duration * 60)
        for e in sched.episodes():
            print(f'{e.at:8.1f}s  {e.kind:16s}  {e.params}')
        print(f'\n{len(sched)} episodes over {args.duration} min (seed {args.seed})')
        return 0
    if args.cmd == 'run':
        if args.rate < 0:
            ap.error('--rate must be zero or greater')
        kinds = None
        if args.kinds:
            kinds = [k.strip() for k in args.kinds.split(',') if k.strip()]
            bad = [k for k in kinds if k not in EPISODE_KINDS]
            if bad:
                ap.error(f'unknown episode kind(s): {bad}; choose from {EPISODE_KINDS}')
        run = SoakRun({
            'seed': args.seed,
            'duration_sec': args.duration * 60,
            'profile': args.profile,
            'rate': args.rate,
            'outdir': args.outdir,
            'repo': args.repo,
            'server': args.server,
            'no_proxy': args.no_proxy,
            'warmup': args.warmup,
            'min_gap': args.min_gap,
            'max_gap': args.max_gap,
            'tail_quiet': args.tail_quiet,
            'kinds': kinds,
        })
        return run.run() or 0
    return 2


if __name__ == '__main__':
    sys.exit(_main(sys.argv[1:]))
