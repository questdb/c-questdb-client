"""Bounded pressure setup for the focused macOS experiment, before workload."""
import argparse
import json
import os
import subprocess
import time


def mode_for_run(plan, run):
    if run < 1:
        raise ValueError('run must be positive')
    if plan == 'paired':
        return 'warn' if run % 4 in (2, 3) else 'natural'
    if plan not in ('natural', 'warn'):
        raise ValueError(f'unknown pressure plan: {plan}')
    return plan


def wait_for_level(mode, read_level, record, timeout=20,
                   clock=time.monotonic, sleep=time.sleep):
    target = {'natural': 1, 'warn': 2}[mode]
    started = clock()
    while clock() - started < timeout:
        level = read_level()
        record(level)
        if level == target:
            return
        if level not in (1, 2):
            raise RuntimeError(f'unsafe or unknown pressure level: {level}')
        sleep(0.25)
    raise RuntimeError(f'pressure target {mode} was not reached in {timeout}s')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    plan = commands.add_parser('mode')
    plan.add_argument('plan', choices=('natural', 'warn', 'paired'))
    plan.add_argument('run', type=int)
    gate = commands.add_parser('gate')
    gate.add_argument('mode', choices=('natural', 'warn'))
    gate.add_argument('--pid', type=int)
    gate.add_argument('--timeout', type=int, choices=range(1, 61), default=20)
    args = parser.parse_args()
    if args.command == 'mode':
        print(mode_for_run(args.plan, args.run))
        return

    def read_level():
        if args.pid is not None:
            os.kill(args.pid, 0)
        return int(subprocess.check_output(
            ['sysctl', '-n', 'kern.memorystatus_vm_pressure_level'],
            text=True, timeout=2).strip())

    def record(level):
        print(json.dumps(dict(wall_ns=time.time_ns(), monotonic_ns=time.monotonic_ns(),
                              mode=args.mode, level=level)), flush=True)

    wait_for_level(args.mode, read_level, record, timeout=args.timeout)


if __name__ == '__main__':
    main()
