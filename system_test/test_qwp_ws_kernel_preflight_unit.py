from pathlib import Path
import io
import hashlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

from ci.diagnostics import kernel_wait_preflight as recorder
from ci.diagnostics import decode_kernel_capture as decoder
from ci.diagnostics.kernel_wait_preflight import command, decode_command, inspect_report, raw_command
from ci.diagnostics.decode_kernel_capture import extract_member


class KernelPreflightTest(unittest.TestCase):
    def test_symbols_only_fetch_does_not_download_raw_or_run_decoder(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            output = directory / 'output'
            sources = ((1, 'unused', 'unused', 'spindump.raw'),
                       (2, 'symbols', hashlib.sha256(b'symbol bytes').hexdigest(), 'symbols.spindump'))
            def download(command, **kwargs):
                self.assertEqual(command[0], 'curl')
                with zipfile.ZipFile(command[-1], 'w') as z:
                    z.writestr('symbols', b'symbol bytes')
            with mock.patch.object(sys, 'argv', ['decoder', str(output), '--symbols-only',
                                                 '--source-directory', str(directory / 'inputs')]), \
                    mock.patch.object(decoder, 'SOURCES', sources), \
                    mock.patch.object(decoder.subprocess, 'run', side_effect=download) as run:
                decoder.main()
            self.assertEqual(run.call_count, 1)
            self.assertEqual((output / 'symbols.spindump').read_bytes(), b'symbol bytes')
            self.assertFalse((output / 'spindump.raw').exists())

    def test_decoder_member_is_hash_pinned_and_does_not_extract_other_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            archive = directory / 'input.zip'
            output = directory / 'raw'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('wanted', b'raw bytes')
                z.writestr('../unwanted', b'never extract')
            with self.assertRaisesRegex(RuntimeError, 'hash mismatch'):
                extract_member(archive, 'wanted', 'bad hash', output)
            self.assertFalse(output.exists())
            extract_member(archive, 'wanted', hashlib.sha256(b'raw bytes').hexdigest(), output)
            self.assertEqual(output.read_bytes(), b'raw bytes')
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ['input.zip', 'raw'])

    def test_decoder_uses_retained_symbols_not_live_process_inspection(self):
        args = decode_command(Path('/capture'), Path('/retained/symbols'))
        self.assertEqual(args[-2:], ['-symbols', '/retained/symbols'])
        self.assertNotIn('-inspectLiveSystem', args)

    def test_raw_timeout_forwards_partial_binary_and_native_error(self):
        output, errors = io.BytesIO(), io.BytesIO()
        failure = subprocess.TimeoutExpired('spindump', 30, output=b'partial', stderr=b'native detail')
        with mock.patch.object(sys, 'argv', ['recorder', '/unused', '--record-raw']), \
                mock.patch.object(recorder.subprocess, 'run', side_effect=failure), \
                mock.patch.object(sys, 'stdout', mock.Mock(buffer=output)), \
                mock.patch.object(sys, 'stderr', mock.Mock(buffer=errors)):
            with self.assertRaises(subprocess.TimeoutExpired):
                recorder.main()
        self.assertEqual(output.getvalue(), b'partial')
        self.assertEqual(errors.getvalue(), b'native detail')

    def test_raw_controller_transfers_binary_over_pipes_without_files(self):
        with tempfile.TemporaryDirectory() as temp:
            output, errors = io.BytesIO(), io.BytesIO()
            child = [sys.executable, '-c',
                     'import sys; sys.stdout.buffer.write(bytes([0,255,10,13])); '
                     'sys.stderr.write("sampler status")']
            with mock.patch.object(sys, 'argv', ['recorder', temp, '--record-raw']), \
                    mock.patch.object(recorder, 'raw_command', return_value=child), \
                    mock.patch.object(sys, 'stdout', mock.Mock(buffer=output)), \
                    mock.patch.object(sys, 'stderr', mock.Mock(buffer=errors)):
                recorder.main()
            self.assertEqual(output.getvalue(), bytes([0, 255, 10, 13]))
            self.assertEqual(errors.getvalue(), b'sampler status')
            self.assertEqual(list(Path(temp).iterdir()), [])

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
                    mock.patch.object(recorder.subprocess, 'run',
                                      return_value=subprocess.CompletedProcess([], 0, stdout=b'', stderr=b'')):
                with self.assertRaisesRegex(RuntimeError, 'empty raw'):
                    recorder.main()
            self.assertFalse((directory / 'recorder-validation.json').exists())

    def test_raw_capture_defers_symbols_and_avoids_output_files(self):
        directory = Path('/artifact/kernel-stacks')
        args = raw_command()
        self.assertEqual(args, ['/usr/sbin/spindump', '-notarget', '3', '20',
                                '-noFile',
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
