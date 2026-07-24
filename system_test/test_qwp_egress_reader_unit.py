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

"""Regression tests for borrowed, length-delimited strings in the ctypes reader.

Run with::

    python3 -m unittest discover -s system_test \
        -p 'test_qwp_egress_reader_unit.py'

The client library must already be built. No QuestDB server is required.
"""

import contextlib
import ctypes
import mmap
import os
import pathlib
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True

import qwp_egress_reader as qer


_GUARD_PAGE_CHILD = "--guard-page-child"


@contextlib.contextmanager
def _guarded_slice(payload: bytes):
    """Place ``payload`` at the end of a readable page followed by no-access.

    The payload deliberately has no NUL terminator. An accidental
    ``c_char_p.value`` or ``c_char_p`` return conversion therefore crosses into
    the guard page and terminates the subprocess instead of silently reading
    adjacent mapped memory.
    """
    if not payload or b"\0" in payload:
        raise ValueError("guarded payload must be non-empty and contain no NUL")

    page_size = mmap.PAGESIZE
    if len(payload) >= page_size:
        raise ValueError("guarded payload must fit in one page")

    region = mmap.mmap(-1, page_size * 2, access=mmap.ACCESS_WRITE)
    anchor = ctypes.c_char.from_buffer(region)
    base = ctypes.addressof(anchor)
    payload_addr = base + page_size - len(payload)
    ctypes.memmove(payload_addr, payload, len(payload))
    guard_addr = base + page_size

    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        virtual_protect = kernel32.VirtualProtect
        virtual_protect.argtypes = (
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
        )
        virtual_protect.restype = ctypes.c_int
        old_protection = ctypes.c_ulong()
        if not virtual_protect(
            guard_addr,
            page_size,
            0x01,  # PAGE_NOACCESS
            ctypes.byref(old_protection),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            del anchor
            region.close()
            raise error

        def restore_guard():
            ignored = ctypes.c_ulong()
            if not virtual_protect(
                guard_addr,
                page_size,
                old_protection.value,
                ctypes.byref(ignored),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
    else:
        libc = ctypes.CDLL(None, use_errno=True)
        mprotect = libc.mprotect
        mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
        mprotect.restype = ctypes.c_int
        if mprotect(guard_addr, page_size, 0) != 0:  # PROT_NONE
            error = OSError(ctypes.get_errno(), "mprotect(PROT_NONE) failed")
            del anchor
            region.close()
            raise error

        def restore_guard():
            protection = mmap.PROT_READ | mmap.PROT_WRITE
            if mprotect(guard_addr, page_size, protection) != 0:
                raise OSError(
                    ctypes.get_errno(), "mprotect(PROT_READ|PROT_WRITE) failed")

    try:
        yield payload_addr
    finally:
        try:
            restore_guard()
        finally:
            del anchor
            region.close()


def _run_guard_page_child() -> None:
    payload = b"column_without_nul"
    with _guarded_slice(payload) as payload_addr:
        class FakeDll:
            @staticmethod
            def qwp_reader_batch_column_name(
                    _batch, col_idx, out_buf, out_len, _err_out):
                if col_idx != 0:
                    raise AssertionError(f"unexpected column index: {col_idx}")
                ctypes.cast(
                    out_buf, ctypes.POINTER(ctypes.c_void_p)
                )[0] = payload_addr
                ctypes.cast(
                    out_len, ctypes.POINTER(ctypes.c_size_t)
                )[0] = len(payload)
                return True

        real_dll = qer._DLL
        qer._DLL = FakeDll()
        try:
            reader = qer.QwpEgressReader.__new__(qer.QwpEgressReader)
            columns = reader._collect_column_names(None, 1)
        finally:
            qer._DLL = real_dll

        expected = [{"name": payload.decode("ascii"), "type": ""}]
        if columns != expected:
            raise AssertionError(f"unexpected decoded columns: {columns!r}")


class BorrowedUtf8RegressionTest(unittest.TestCase):
    def test_column_name_does_not_scan_for_nul(self):
        env = os.environ.copy()
        env["PYTHONFAULTHANDLER"] = "1"
        child = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve()),
             _GUARD_PAGE_CHILD],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        self.assertEqual(
            child.returncode,
            0,
            "guard-page child failed; the column-name path may have scanned "
            "past its length\n"
            f"stdout:\n{child.stdout}\n"
            f"stderr:\n{child.stderr}",
        )

    def test_questdb_error_msg_restype_is_void_pointer(self):
        self.assertIs(qer._DLL.questdb_error_msg.restype, ctypes.c_void_p)

    def test_take_error_reads_real_ffi_message_by_length(self):
        # Do not call a regressed c_char_p binding here: ctypes would scan the
        # non-NUL-terminated result before Python can inspect its explicit
        # length, potentially crashing this test process.
        self.assertIs(qer._DLL.questdb_error_msg.restype, ctypes.c_void_p)

        name_ptr = ctypes.c_char_p()
        name_len = ctypes.c_size_t(0)
        err_ref = ctypes.POINTER(qer._LineReaderError)()
        null_batch = ctypes.POINTER(qer._LineReaderBatch)()
        ok = qer._DLL.qwp_reader_batch_column_name(
            null_batch,
            0,
            ctypes.byref(name_ptr),
            ctypes.byref(name_len),
            ctypes.byref(err_ref),
        )
        self.assertFalse(ok)
        self.assertTrue(err_ref)
        expected_code = int(qer._DLL.questdb_error_get_code(err_ref))

        error = qer._take_error(err_ref)

        self.assertEqual(error.code, expected_code)
        self.assertEqual(
            error.message,
            "qwp_reader_batch_column_name: batch handle is NULL",
        )


if __name__ == "__main__":
    if sys.argv[1:] == [_GUARD_PAGE_CHILD]:
        _run_guard_page_child()
    else:
        unittest.main()
