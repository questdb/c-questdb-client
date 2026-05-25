#!/usr/bin/env python3

import pathlib
import sys
import os
import shutil
import platform
import numpy as np

from setuptools import setup, find_packages
from setuptools.extension import Extension
from setuptools.command.build_ext import build_ext
import subprocess
from Cython.Build import cythonize

from install_rust import cargo_path, install_rust, export_cargo_to_path


PROJ_ROOT = pathlib.Path(__file__).parent
PLATFORM = sys.platform
MODE = platform.architecture()[0]  # '32bit' or '64bit'
WIN_32BIT_CARGO_TARGET = 'i686-pc-windows-msvc'


INSTRUMENT_FUZZING = False
if os.environ.get('TEST_QUESTDB_FUZZING') == '1':
    INSTRUMENT_FUZZING = True
    ORIG_CC = os.environ.get('CC')
    os.environ['CC'] = "clang"
    ORIG_CXX = os.environ.get('CXX')
    os.environ['CXX'] = "clang++"


def ingress_extension():
    lib_prefix = ''
    lib_suffix = ''
    lib_paths = []
    libraries = []
    extra_compile_args = []
    extra_link_args = []
    extra_objects = []

    questdb_rs_ffi_dir = PROJ_ROOT / 'c-questdb-client' / 'questdb-rs-ffi'
    rpyutils_dir = PROJ_ROOT / 'rpyutils'
    questdb_client_lib_dir = None
    rpyutils_lib_dir = None
    if PLATFORM == 'win32' and MODE == '32bit':
        questdb_client_lib_dir = \
            questdb_rs_ffi_dir / 'target' / WIN_32BIT_CARGO_TARGET / 'release'
        rpyutils_lib_dir = \
            rpyutils_dir / 'target' / WIN_32BIT_CARGO_TARGET / 'release'
    else:
        questdb_client_lib_dir = questdb_rs_ffi_dir / 'target' / 'release'
        rpyutils_lib_dir = rpyutils_dir / 'target' / 'release'
        if INSTRUMENT_FUZZING:
            extra_compile_args.append('-fsanitize=fuzzer-no-link')
            extra_link_args.append('-fsanitize=fuzzer-no-link')
        else:
            extra_compile_args.append('-flto')
            extra_link_args.append('-flto')

    if PLATFORM == 'darwin':
        lib_prefix = 'lib'
        lib_suffix = '.a'
        extra_link_args.extend(['-framework', 'Security', '-framework', 'CoreFoundation'])
    elif PLATFORM == 'win32':
        lib_prefix = ''
        lib_suffix = '.lib'
        libraries.extend(['wsock32', 'ws2_32', 'ntdll', 'AdvAPI32', 'bcrypt', 'UserEnv', 'crypt32', 'Secur32', 'NCrypt'])
    elif PLATFORM == 'linux':
        lib_prefix = 'lib'
        lib_suffix = '.a'
    else:
        raise NotImplementedError(f'Unsupported platform: {PLATFORM}')

    extra_objects = [
        str(loc / f'{lib_prefix}{name}{lib_suffix}')
        for loc, name in (
            (questdb_client_lib_dir, 'questdb_client'),
            (rpyutils_lib_dir, 'rpyutils'))]
    depends = list(extra_objects)

    return Extension(
        "questdb.ingress",
        ["src/questdb/ingress.pyx"],
        include_dirs=[
            "c-questdb-client/include",
            "rpyutils/include",
            np.get_include()],
        library_dirs=lib_paths,
        libraries=libraries,
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
        extra_objects=extra_objects,
        depends=depends,
        define_macros = [
            ('NPY_NO_DEPRECATED_API', 'NPY_1_7_API_VERSION')
        ]
    )


def cargo_build():
    if not (PROJ_ROOT / 'c-questdb-client' / 'questdb-rs-ffi').exists():
        if os.environ.get('SETUP_DO_GIT_SUBMODULE_INIT') == '1':
            subprocess.check_call([
                'git', 'submodule', 'update', '--init', '--recursive'])
        else:
            sys.stderr.write('Could not find `c-questdb-client` submodule.\n')
            sys.stderr.write('You might need to run:\n')
            sys.stderr.write('    git submodule update --init --recursive\n')
            sys.stderr.write('\n')
            sys.stderr.write('Alternatively specify the '
                '`SETUP_DO_GIT_SUBMODULE_INIT=1` env variable\n')
            sys.exit(1)

    if shutil.which('cargo') is None:
        if cargo_path().exists():
            export_cargo_to_path()
        elif os.environ.get('SETUP_DO_RUSTUP_INSTALL') == '1':
            install_rust()
            export_cargo_to_path()
        else:
            sys.stderr.write('Could not find the `cargo` executable.\n')
            sys.stderr.write('You may install it via http://rustup.rs/.\n')
            sys.stderr.write('\n')
            sys.stderr.write('Alternatively specify the '
                '`SETUP_DO_RUSTUP_INSTALL=1` env variable\n')
            sys.exit(1)

    cargo_args = [
        'cargo',
        'build',
        '--release']

    if PLATFORM == 'win32' and MODE == '32bit':
        cargo_args.append(f'--target={WIN_32BIT_CARGO_TARGET}')

    env = os.environ.copy()
    if INSTRUMENT_FUZZING:
        if ORIG_CC is not None:
            env['CC'] = ORIG_CC
        else:
            del env['CC']
        if ORIG_CXX is not None:
            env['CXX'] = ORIG_CXX
        else:
            del env['CXX']
    subprocess.check_call(
        cargo_args + ['--features', 'confstr-ffi,insecure-skip-verify'],
        cwd=str(PROJ_ROOT / 'c-questdb-client' / 'questdb-rs-ffi'),
        env=env)

    subprocess.check_call(
        cargo_args,
        cwd=str(PROJ_ROOT / 'rpyutils'),
        env=env)


class questdb_build_ext(build_ext):
    """
    Build the extension, but first compile the pre-requisite
    library by invoking `cargo build --release --features ffi`.
    """
    def run(self):
        cargo_build()
        super().run()


def readme():
    with open(PROJ_ROOT / 'README.rst', 'r', encoding='utf-8') as readme:
        return readme.read()


setup(
    name='questdb',
    version='4.1.0',
    platforms=['any'],
    python_requires='>=3.8',
    install_requires=[],
    ext_modules = cythonize([ingress_extension()], annotate=True),
    cmdclass={'build_ext': questdb_build_ext},
    zip_safe = False,
    package_dir={'': 'src'},
    test_suite="tests",
    packages=find_packages('src', exclude=['test']))
