# Unresponsive HTTP Repro

Attempting to reproduce the issue where the HTTP interface returns no results
whilst ILP seems to have succeeded.

## Build

```bash
$ cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
```

## Run tests
```bash
$ python3 system_test/test.py run -v --repeat 100 --pdb
```

The `--pdb` flag will drop you in a Python debugger when the timeout happens.
This should allow you to attach/break a java debugger to
the running process.

## Running against an existing instance

To run the tests against a specific running instance, use the `--existing` flag.

```bash
$ python3 system_test/test.py run -v --repeat 100 --existing localhost:9009:9000
```

## QuestDB Config

When the tests spawn an instance, the config is generated as so:

```python
# fixture.py

    ...

    def start(self):
        ports = discover_avail_ports(3)
        self.http_server_port, self.line_tcp_port, self.pg_port = ports
        auth_config = 'line.tcp.auth.db.path=conf/auth.txt' if self.auth else ''
        with open(self._conf_path, 'w', encoding='utf-8') as conf_file:
            conf_file.write(textwrap.dedent(rf'''
                http.bind.to=0.0.0.0:{self.http_server_port}
                line.tcp.net.bind.to=0.0.0.0:{self.line_tcp_port}
                pg.net.bind.to=0.0.0.0:{self.pg_port}
                http.min.enabled=false
                line.udp.enabled=false
                cairo.max.uncommitted.rows=1
                line.tcp.maintenance.job.interval=100
                line.tcp.min.idle.ms.before.writer.release=300
                {auth_config}
                ''').lstrip('\n'))

    ...

```