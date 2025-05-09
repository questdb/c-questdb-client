#!/usr/bin/env python3

import sys
sys.dont_write_bytecode = True
import pathlib
import shutil
import shlex
import subprocess
import os


PROJ_ROOT = pathlib.Path(__file__).parent


def _run(*args, env=None, cwd=None):
    """
    Log and run a command within the build dir.
    On error, exit with child's return code.
    """
    args = [str(arg) for arg in args]
    cwd = cwd or PROJ_ROOT
    sys.stderr.write('[CMD] ')
    if env is not None:
        env_str = ' '.join(f'{k}={shlex.quote(v)}' for k, v in env.items())
        sys.stderr.write(f'{env_str} ')
        env = {**os.environ, **env}
    escaped_cmd = ' '.join(shlex.quote(arg) for arg in args)
    sys.stderr.write(f'{escaped_cmd}\n')
    ret_code = subprocess.run(args, cwd=str(cwd), env=env).returncode
    if ret_code != 0:
        sys.exit(ret_code)


def _rm(path: pathlib.Path, pattern: str):
    paths = path.glob(pattern)
    for path in paths:
        sys.stderr.write(f'[RM] {path}\n')
        path.unlink()


def _rmtree(path: pathlib.Path):
    if not path.exists():
        return
    sys.stderr.write(f'[RMTREE] {path}\n')
    shutil.rmtree(path, ignore_errors=True)


def _has_command(command: str) -> bool:
    """
    Check if a command is available in the system.
    """
    return shutil.which(command) is not None


COMMANDS = []


def command(fn):
    COMMANDS.append(fn.__name__)
    return fn


@command
def clean():
    _rmtree(PROJ_ROOT / 'build')
    _rmtree(PROJ_ROOT / 'build_CXX20')
    _rmtree(PROJ_ROOT / 'questdb-rs' / 'target')
    _rmtree(PROJ_ROOT / 'questdb-rs-ffi' / 'target')


@command
def cmake_cxx17():
    _rmtree(PROJ_ROOT / 'build')
    cmd = [
        'cmake',
        '-S', '.',
        '-B', 'build',
        '-DCMAKE_BUILD_TYPE=Release',
        '-DQUESTDB_TESTS_AND_EXAMPLES=ON']
    if _has_command('ninja'):
        cmd.insert(1, '-G')
        cmd.insert(2, 'Ninja')
    _run(*cmd)


@command
def cmake_cxx20():
    _rmtree(PROJ_ROOT / 'build_CXX20')
    cmd = [
        'cmake',
        '-S', '.',
        '-B', 'build_CXX20',
        '-DCMAKE_BUILD_TYPE=Release',
        '-DQUESTDB_TESTS_AND_EXAMPLES=ON',
        '-DCMAKE_CXX_STANDARD=20']
    if _has_command('ninja'):
        cmd.insert(1, '-G')
        cmd.insert(2, 'Ninja')
    _run(*cmd)


@command
def build_cxx17():
    if not (PROJ_ROOT / 'build').exists():
        cmake_cxx17()
    _run('cmake', '--build', 'build')


@command
def build_cxx20():
    if not (PROJ_ROOT / 'build_CXX20').exists():
        cmake_cxx20()
    _run('cmake', '--build', 'build_CXX20')


@command
def build():
    build_cxx17()
    build_cxx20()


@command
def lint_rust():
    questdb_rs_path = PROJ_ROOT / 'questdb-rs'
    questdb_rs_ffi_path = PROJ_ROOT / 'questdb-rs-ffi'
    _run('cargo', 'fmt', '--all', '--', '--check', cwd=questdb_rs_path)
    _run('cargo', 'clippy', '--all-targets', '--features', 'almost-all-features', '--', '-D', 'warnings', cwd=questdb_rs_path)
    _run('cargo', 'fmt', '--all', '--', '--check', cwd=questdb_rs_ffi_path)
    _run('cargo', 'clippy', '--all-targets', '--all-features', '--', '-D', 'warnings', cwd=questdb_rs_ffi_path)


@command
def lint_cpp():
    try:
        _run(
            sys.executable,
            PROJ_ROOT / 'ci' / 'format_cpp.py',
            '--check')
    except subprocess.CalledProcessError:
        sys.stderr.write('REMINDER: To fix any C++ formatting issues, run: ./proj format_cpp\n')
        raise


@command
def lint():
    lint_rust()
    lint_cpp()


@command
def format_rust():
    questdb_rs_path = PROJ_ROOT / 'questdb-rs'
    questdb_rs_ffi_path = PROJ_ROOT / 'questdb-rs-ffi'
    _run('cargo', 'fmt', '--all', cwd=questdb_rs_path)
    _run('cargo', 'fmt', '--all', cwd=questdb_rs_ffi_path)


@command
def format_cpp():
    _run(
        sys.executable,
        PROJ_ROOT / 'ci' / 'format_cpp.py')
    

@command
def test():
    build()
    _run(
        sys.executable,
        PROJ_ROOT / 'ci' / 'run_all_tests.py')
    

@command
def build_latest_questdb(branch='master'):
    questdb_path = PROJ_ROOT / 'questdb'
    if not questdb_path.exists():
        _run('git', 'clone', 'https://github.com/questdb/questdb.git')
    _run('git', 'fetch', 'origin', branch, cwd=questdb_path)
    _run('git', 'switch', branch=questdb_path)
    _run('git', 'pull', 'origin', branch=questdb_path)
    _run('git', 'submodule', 'update', '--init', '--recursive', cwd=questdb_path)
    _run('mvn', 'clean', 'package', '-DskipTests', '-Pbuild-web-console', cwd=questdb_path)


@command
def test_vs_latest_questdb():
    questdb_path = PROJ_ROOT / 'questdb'
    if not questdb_path.exists():
        build_latest_questdb()
    _run(
        sys.executable,
        PROJ_ROOT / 'system_test' / 'test.py',
        '--repo', PROJ_ROOT / 'questdb',
        '-v')


@command
def all():
    clean()
    build()
    lint()
    test()
    test_vs_latest_questdb()


def main():
    if len(sys.argv) < 2:
        sys.stderr.write('Usage: python3 proj.py <command>\n')
        sys.stderr.write('Commands:\n')
        for command in COMMANDS:
            sys.stderr.write(f'  {command}\n')
        sys.stderr.write('\n')
        sys.exit(0)
    fn = sys.argv[1]
    args = list(sys.argv)[2:]
    globals()[fn](*args)


if __name__ == '__main__':
    main()
