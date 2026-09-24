from pathlib import Path
import tempfile
import unittest
import zipfile

from ci.diagnostics.decode_system_trace import PREFIX, content_hash, extract, selections


class TraceDecodeTest(unittest.TestCase):
    def test_selects_vm_and_scheduler_without_guessing_positions(self):
        with tempfile.TemporaryDirectory() as temp:
            toc = Path(temp) / 'toc.xml'
            toc.write_text('<trace-toc><run><data>'
                           '<table schema="syscall"/>'
                           '<table schema="virtual-memory"/>'
                           '<table schema="context-switch"/>'
                           '<table schema="kdebug" codes="0x1,0x40"/>'
                           '</data></run></trace-toc>')
            self.assertEqual([index for index, _ in selections(toc)], [2, 3, 4])

    def test_missing_required_table_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            toc = Path(temp) / 'toc.xml'
            toc.write_text('<trace-toc><run><data/></run></trace-toc>')
            with self.assertRaises(RuntimeError):
                selections(toc)

    def test_contents_not_zip_packaging_define_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            digests = []
            for number, compression in enumerate((zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                archive = root / f'{number}.zip'
                with zipfile.ZipFile(archive, 'w', compression=compression) as output:
                    output.writestr(PREFIX + 'system.trace/data', b'original recording')
                    output.writestr('unrelated-run/data', b'not selected')
                digests.append(content_hash(archive))
            self.assertEqual(digests[0], digests[1])
            destination = root / 'out'
            destination.mkdir()
            extract(archive, destination)
            self.assertEqual((destination / 'system.trace/data').read_bytes(), b'original recording')
            self.assertFalse((destination / 'unrelated-run').exists())

    def test_parent_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / 'bad.zip'
            with zipfile.ZipFile(archive, 'w') as output:
                output.writestr(PREFIX + '../escape', b'bad')
            with self.assertRaises(ValueError):
                extract(archive, root)
