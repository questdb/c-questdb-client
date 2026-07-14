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
Fault-injecting TCP proxy for the soak / stress harness (see
``doc/QWP_SOAK_HARNESS.md``).

A faulted workload leg connects *through* this proxy instead of straight to
QuestDB. The orchestrator drives the proxy to sever, stall, or throttle those
connections on a seeded schedule, exercising the client's reconnect / failover /
store-and-forward-recovery paths without touching the server.

Primary interface is in-process: the orchestrator imports :class:`FaultProxy`
and calls its control methods. A standalone ``serve`` mode with a small
JSON-over-TCP control socket is provided so the proxy can also run as a separate
process (e.g. on another host).

Faults:

* ``reset_all()``            RST every live connection now (abrupt peer death).
* ``arm_reset_after(n)``     RST each connection once it has forwarded ``n``
                             bytes — a mid-flush failure.
* ``stall(seconds)``         Stop forwarding both directions for ``seconds``
                             (ack starvation → in-flight cap → timeouts).
* ``throttle(bps)``          Cap each connection to ``bps`` bytes/sec
                             (sustained backpressure; SF backlog growth).
* ``pass_through()``         Clear all faults; resume clean forwarding.
* ``block_new()``/``allow_new()``  Refuse / accept new connections (endpoint
                             appears down while the upstream stays alive).
"""

import sys

sys.dont_write_bytecode = True

import json
import select
import socket
import struct
import threading
import time


def _rst_close(sock):
    """Close ``sock`` with a TCP RST (SO_LINGER timeout 0) so the peer sees an
    abrupt reset rather than an orderly FIN — the point of a fault."""
    if sock is None:
        return
    try:
        sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class _State:
    """Shared, lock-guarded fault directives. Live connection handlers poll
    this each loop iteration, so a directive change takes effect on every
    connection within one poll interval."""

    def __init__(self):
        self.lock = threading.Lock()
        self.stalled_until = 0.0     # monotonic deadline; 0 = not stalled
        self.throttle_bps = 0        # per-connection cap; 0 = unlimited
        self.reset_after = 0         # RST after N forwarded bytes; 0 = off
        self.reset_generation = 0    # bump to RST all live connections
        self.accept_new = True


class FaultProxy:
    """A threaded fault-injecting TCP forwarder.

    Bind with :meth:`start`, drive with the control methods, tear down with
    :meth:`stop`. Also usable as a context manager.
    """

    #: Poll granularity: how promptly a live connection reacts to a directive
    #: change (stall/reset) and how tight the throttle loop is.
    POLL_SECONDS = 0.05
    BUF = 65536

    def __init__(self, upstream_host, upstream_port,
                 listen_host='127.0.0.1', listen_port=0):
        self.upstream_host = upstream_host
        self.upstream_port = int(upstream_port)
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self._state = _State()
        self._stop = threading.Event()
        self._listener = None
        self._accept_thread = None
        self._conn_threads = []
        self._conn_lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._accepted = 0
        self._bytes = 0
        self._resets = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self):
        """Bind the listener and start accepting. Returns the bound port
        (useful when ``listen_port=0`` picked an ephemeral one)."""
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.listen_host, self.listen_port))
        self._listener.listen(128)
        self._listener.settimeout(self.POLL_SECONDS)
        self.listen_port = self._listener.getsockname()[1]
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name='fault-proxy-accept', daemon=True)
        self._accept_thread.start()
        return self.listen_port

    def stop(self, timeout=5.0):
        """Stop accepting, RST all live connections, join threads."""
        self._stop.set()
        # Force all live connections to reset and exit.
        with self._state.lock:
            self._state.reset_generation += 1
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=timeout)
        with self._conn_lock:
            threads = list(self._conn_threads)
        for t in threads:
            t.join(timeout=timeout)
        _rst_close(self._listener)
        self._listener = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, _ty, _val, _tb):
        self.stop()

    # -- control -----------------------------------------------------------

    def pass_through(self):
        with self._state.lock:
            self._state.stalled_until = 0.0
            self._state.throttle_bps = 0
            self._state.reset_after = 0
            self._state.accept_new = True

    def reset_all(self):
        with self._state.lock:
            self._state.reset_generation += 1

    def arm_reset_after(self, n_bytes):
        with self._state.lock:
            self._state.reset_after = int(n_bytes)

    def stall(self, seconds):
        with self._state.lock:
            self._state.stalled_until = time.monotonic() + float(seconds)

    def unstall(self):
        with self._state.lock:
            self._state.stalled_until = 0.0

    def throttle(self, bytes_per_sec):
        with self._state.lock:
            self._state.throttle_bps = int(bytes_per_sec)

    def set_upstream(self, host, port):
        """Point new connections at a different upstream. Used when a server
        restart re-allocates its port; existing connections were reset by the
        restart anyway, so only new connections need the new target."""
        with self._state.lock:
            self.upstream_host = host
            self.upstream_port = int(port)

    def block_new(self):
        with self._state.lock:
            self._state.accept_new = False

    def allow_new(self):
        with self._state.lock:
            self._state.accept_new = True

    def stats(self):
        with self._metrics_lock:
            return {
                'accepted': self._accepted,
                'bytes_forwarded': self._bytes,
                'resets': self._resets,
                'listen_port': self.listen_port,
            }

    # -- internals ---------------------------------------------------------

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                client, _addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._state.lock:
                accept = self._state.accept_new
            if not accept:
                # Endpoint "down": refuse by resetting the just-accepted socket.
                _rst_close(client)
                continue
            with self._metrics_lock:
                self._accepted += 1
            t = threading.Thread(
                target=self._handle, args=(client,),
                name='fault-proxy-conn', daemon=True)
            with self._conn_lock:
                self._conn_threads.append(t)
                self._reap_conn_threads()
            t.start()

    def _reap_conn_threads(self):
        # Called under _conn_lock: drop finished handler threads so the list
        # doesn't grow unbounded across an hour of reconnects.
        self._conn_threads = [t for t in self._conn_threads if t.is_alive()]

    def _handle(self, client):
        with self._state.lock:
            up_host, up_port = self.upstream_host, self.upstream_port
        try:
            upstream = socket.create_connection((up_host, up_port), timeout=10.0)
        except OSError:
            _rst_close(client)
            return
        my_gen = self._snapshot().reset_generation
        forwarded = 0
        socks = [client, upstream]
        reset = False
        try:
            while not self._stop.is_set():
                st = self._snapshot()
                if st.reset_generation != my_gen:
                    reset = True
                    return
                now = time.monotonic()
                if st.stalled_until and now < st.stalled_until:
                    time.sleep(self.POLL_SECONDS)
                    continue
                ready, _, err = select.select(socks, [], socks,
                                              self.POLL_SECONDS)
                if err:
                    return
                for s in ready:
                    other = upstream if s is client else client
                    try:
                        data = s.recv(self.BUF)
                    except OSError:
                        return
                    if not data:
                        return  # orderly close on one side → tear down both
                    if st.throttle_bps > 0:
                        time.sleep(len(data) / st.throttle_bps)
                    try:
                        other.sendall(data)
                    except OSError:
                        return
                    forwarded += len(data)
                    with self._metrics_lock:
                        self._bytes += len(data)
                    if st.reset_after and forwarded >= st.reset_after:
                        reset = True
                        return
        finally:
            if reset:
                with self._metrics_lock:
                    self._resets += 1
            _rst_close(client)
            _rst_close(upstream)

    def _snapshot(self):
        # Cheap immutable-ish read of the shared state under the lock.
        with self._state.lock:
            snap = _State()
            snap.stalled_until = self._state.stalled_until
            snap.throttle_bps = self._state.throttle_bps
            snap.reset_after = self._state.reset_after
            snap.reset_generation = self._state.reset_generation
            snap.accept_new = self._state.accept_new
            return snap


# ---------------------------------------------------------------------------
# Standalone control: run the proxy as a subprocess, driven over a JSON-line
# TCP control socket. One command object per line; a one-line JSON reply.
# ---------------------------------------------------------------------------

def _serve(listen_port, upstream, control_port):
    host, port = upstream.rsplit(':', 1)
    proxy = FaultProxy(host, int(port), listen_port=listen_port)
    bound = proxy.start()
    print(json.dumps({'event': 'listening', 'port': bound}), flush=True)

    ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ctrl.bind(('127.0.0.1', control_port))
    ctrl.listen(4)
    print(json.dumps({'event': 'control', 'port': ctrl.getsockname()[1]}),
          flush=True)

    dispatch = {
        'pass': lambda c: proxy.pass_through(),
        'reset_all': lambda c: proxy.reset_all(),
        'arm_reset_after': lambda c: proxy.arm_reset_after(c['n']),
        'stall': lambda c: proxy.stall(c['seconds']),
        'unstall': lambda c: proxy.unstall(),
        'throttle': lambda c: proxy.throttle(c['bps']),
        'block_new': lambda c: proxy.block_new(),
        'allow_new': lambda c: proxy.allow_new(),
    }
    try:
        while True:
            conn, _ = ctrl.accept()
            with conn:
                buf = conn.makefile('rwb')
                for raw in buf:
                    try:
                        cmd = json.loads(raw)
                        name = cmd.get('cmd')
                        if name == 'stats':
                            reply = {'ok': True, 'stats': proxy.stats()}
                        elif name == 'shutdown':
                            buf.write(
                                (json.dumps({'ok': True}) + '\n').encode())
                            buf.flush()
                            return
                        elif name in dispatch:
                            dispatch[name](cmd)
                            reply = {'ok': True}
                        else:
                            reply = {'ok': False, 'error': f'unknown cmd {name!r}'}
                    except Exception as exc:  # noqa: BLE001 - report, keep serving
                        reply = {'ok': False, 'error': str(exc)}
                    buf.write((json.dumps(reply) + '\n').encode())
                    buf.flush()
    finally:
        _rst_close(ctrl)
        proxy.stop()


def _selftest():
    """Exercise every fault against a local echo upstream. Exits non-zero on
    failure so it can gate in CI (the harness ``selftest`` step)."""
    import errno

    # Echo upstream.
    up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    up.bind(('127.0.0.1', 0))
    up.listen(8)
    up_port = up.getsockname()[1]
    stop = threading.Event()

    def echo_server():
        up.settimeout(0.1)
        conns = []
        while not stop.is_set():
            try:
                c, _ = up.accept()
                c.setblocking(False)
                conns.append(c)
            except socket.timeout:
                pass
            except OSError:
                break
            for c in list(conns):
                try:
                    d = c.recv(65536)
                    if not d:
                        conns.remove(c)
                        c.close()
                    else:
                        c.sendall(d)
                except (BlockingIOError, InterruptedError):
                    pass
                except OSError:
                    conns.remove(c)
        for c in conns:
            c.close()

    th = threading.Thread(target=echo_server, daemon=True)
    th.start()

    failures = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)
            print(f'FAIL: {msg}', file=sys.stderr)
        else:
            print(f'ok: {msg}')

    with FaultProxy('127.0.0.1', up_port) as proxy:
        # 1. Clean pass-through echoes.
        s = socket.create_connection(('127.0.0.1', proxy.listen_port))
        s.sendall(b'hello')
        check(s.recv(16) == b'hello', 'pass-through echoes bytes')

        # 2. reset_all severs the live connection.
        proxy.reset_all()
        time.sleep(0.2)
        try:
            s.sendall(b'again')
            # After RST the next recv should error or return empty.
            s.setblocking(True)
            s.settimeout(1.0)
            got = s.recv(16)
            check(got == b'', 'reset_all severs connection (EOF)')
        except OSError as exc:
            check(exc.errno in (errno.ECONNRESET, errno.EPIPE, errno.ECONNABORTED),
                  f'reset_all severs connection (errno {exc.errno})')
        s.close()

        # 3. block_new refuses new connections.
        proxy.block_new()
        try:
            s2 = socket.create_connection(('127.0.0.1', proxy.listen_port),
                                          timeout=1.0)
            s2.settimeout(1.0)
            check(s2.recv(16) == b'', 'block_new refuses (immediate reset)')
            s2.close()
        except OSError:
            check(True, 'block_new refuses (connect error)')
        proxy.allow_new()

        # 4. arm_reset_after severs mid-stream past the threshold.
        proxy.pass_through()
        proxy.arm_reset_after(4)
        s3 = socket.create_connection(('127.0.0.1', proxy.listen_port))
        s3.settimeout(1.0)
        s3.sendall(b'12345678')
        time.sleep(0.2)
        severed = False
        try:
            # We may get the echo of the first bytes, then EOF/RST.
            total = b''
            while len(total) < 8:
                chunk = s3.recv(16)
                if not chunk:
                    severed = True
                    break
                total += chunk
        except OSError:
            severed = True
        check(severed, 'arm_reset_after severs past threshold')
        s3.close()
        proxy.pass_through()

        st = proxy.stats()
        check(st['resets'] >= 2, f"resets counted (got {st['resets']})")
        # Two *forwarded* connections (pass-through + arm_reset_after); the
        # block_new connection is refused before the accept counter, by design.
        check(st['accepted'] >= 2, f"accepts counted (got {st['accepted']})")

    stop.set()
    th.join(timeout=2.0)
    _rst_close(up)

    if failures:
        print(f'\n{len(failures)} selftest failure(s)', file=sys.stderr)
        return 1
    print('\nfault_proxy selftest: all checks passed')
    return 0


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='Soak harness fault proxy')
    sub = ap.add_subparsers(dest='cmd', required=True)

    serve = sub.add_parser('serve', help='run standalone with a control socket')
    serve.add_argument('--upstream', required=True, help='HOST:PORT of QuestDB')
    serve.add_argument('--listen-port', type=int, default=0)
    serve.add_argument('--control-port', type=int, default=0)

    sub.add_parser('selftest', help='self-test every fault against a local echo')

    args = ap.parse_args(argv)
    if args.cmd == 'serve':
        _serve(args.listen_port, args.upstream, args.control_port)
        return 0
    if args.cmd == 'selftest':
        return _selftest()
    return 2


if __name__ == '__main__':
    sys.exit(_main(sys.argv[1:]))
