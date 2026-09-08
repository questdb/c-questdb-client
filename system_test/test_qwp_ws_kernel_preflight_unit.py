from pathlib import Path
import tempfile
import unittest

from ci.diagnostics.kernel_wait_preflight import command, inspect_report


class KernelPreflightTest(unittest.TestCase):
    def test_bounded_system_sample_and_explicit_output(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self.assertEqual(command(directory),
                ['/usr/sbin/spindump', '-notarget', '3', '20',
                 '-file', str(directory / 'spindump.txt'), '-timeline', '-symbolicate'])

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
