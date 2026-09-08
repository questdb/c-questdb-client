from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ci.diagnostics import kernel_wait_preflight as recorder
from ci.diagnostics.kernel_wait_preflight import command, decode_command, inspect_report, raw_command


class KernelPreflightTest(unittest.TestCase):
    def test_decode_timeout_preserves_raw_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            raw = directory / 'spindump.raw'
            raw.write_bytes(b'captured binary fixture')
            with mock.patch.object(sys, 'argv', ['recorder', temp, '--decode']), \
                    mock.patch.object(recorder.subprocess, 'run',
                                      side_effect=subprocess.TimeoutExpired('spindump', 65)) as run:
                with self.assertRaises(subprocess.TimeoutExpired):
                    recorder.main()
            self.assertEqual(raw.read_bytes(), b'captured binary fixture')
            self.assertEqual(run.call_args.kwargs['timeout'], 65)
            self.assertFalse((directory / 'decode-validation.json').exists())

    def test_empty_raw_capture_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / 'spindump.raw').touch()
            with mock.patch.object(sys, 'argv', ['recorder', temp, '--record-raw']), \
                    mock.patch.object(recorder.subprocess, 'run'):
                with self.assertRaisesRegex(RuntimeError, 'empty raw'):
                    recorder.main()
            self.assertFalse((directory / 'recorder-validation.json').exists())

    def test_raw_capture_defers_symbols_and_keeps_explicit_path(self):
        directory = Path('/artifact/kernel-stacks')
        args = raw_command(directory)
        self.assertEqual(args, ['/usr/sbin/spindump', '-notarget', '3', '20',
                                '-o', str(directory / 'spindump.raw'),
                                '-noText', '-noSymbolicate', '-timelimit', '25',
                                '-noProcessingWhileSampling'])
        decode = decode_command(directory)
        self.assertEqual(decode[decode.index('-i')+1], str(directory / 'spindump.raw'))
        self.assertIn('-symbolicate', decode)
        self.assertIn('-noBinary', decode)
        self.assertEqual(decode[-2:], ['-timelimit', '60'])

    def test_bounded_system_sample_and_explicit_output(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self.assertEqual(command(directory),
                ['/usr/sbin/spindump', '-notarget', '3', '20',
                 '-o', str(directory / 'spindump.txt'), '-timeline', '-symbolicate',
                 '-timelimit', '45', '-timestampsInCallTrees', 'all',
                 '-noProcessingWhileSampling'])

    def test_named_kernel_frames_not_user_frames_or_image_list(self):
        result = inspect_report('kernel.release.vmapple\n'
                                '  20 malloc (libsystem_malloc.dylib)\n'
                                '  15 *thread_block_reason + 123 (kernel)\n'
                                '  12 *??? [0xfffffff]\n')
        self.assertEqual(result['kernel_frame_lines'], 2)
        self.assertEqual(result['named_kernel_frame_lines'], 1)
        self.assertFalse(result['apfs_present'])

    def test_user_only_report_is_not_kernel_access(self):
        self.assertEqual(inspect_report('20 fsync (libsystem_kernel.dylib)')
                         ['named_kernel_frame_lines'], 0)

    def test_hosted_report_v60_star_precedes_sample_count(self):
        report = (' *156  IOWorkLoop::threadMain() + 0 (kernel.release.vmapple + 8226852)\n'
                  '   *1    ??? (kernel.release.vmapple + 34328)\n'
                  ' *0xfffffe0007d7c000 - 0xfffffe000866bfff kernel.release.vmapple\n')
        result = inspect_report(report)
        self.assertEqual(result['kernel_frame_lines'], 2)
        self.assertEqual(result['named_kernel_frame_lines'], 1)
