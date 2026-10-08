"""Independent tests for the live symbol recycling witnesses."""
import unittest
import qwp_symbol_recycle as recycle


class RecycleCorpusTest(unittest.TestCase):
    def test_disjoint_batches_cross_rearm_floor(self):
        batches = [recycle.symbol_batch(n, 16 << n) for n in range(4)]
        sets = [set(s for _, s in batch if s is not None) for batch in batches]
        self.assertEqual([len(s) for s in sets], [12, 28, 60, 124])
        self.assertEqual(set.intersection(*sets), {''})
        self.assertEqual(len({i for b in batches for i, _ in b}), 240)
        self.assertIn(None, [s for _, s in batches[0]])
        self.assertTrue(any('東京' in s for s in sets[0]))
        self.assertEqual(recycle.expected_reset_count([12, 28, 60, 124], 4), 3)
        self.assertEqual(recycle.expected_reset_count([12, 28, 60, 124], 4, enabled=False), 0)
        self.assertLess(sum(map(len, sets)), 1_000_000)

    def test_scaled_cap_model_recycles_repeatedly(self):
        # Scale the 1M threshold ceiling/2M cap to 10/20; no million-row fixture.
        self.assertEqual(recycle.expected_reset_count([12] * 5, 10, ceiling=10), 4)

    def test_validated_dictionary_reader(self):
        chunk = b'\x02\x04\x01a\x01b'
        data = b'SYD1\x01\0\0\0' + chunk + recycle.crc32c(chunk).to_bytes(4, 'little')
        self.assertEqual(recycle.decode_dictionary(data), ['a', 'b'])
        with self.assertRaises(ValueError):
            recycle.decode_dictionary(data[:-1])
        with self.assertRaises(ValueError):
            recycle.decode_dictionary(data[:-5] + b'c' + data[-4:])
        self.assertEqual(recycle.crc32c(b'123456789'), 0xe3069283)

    def test_dictionary_rejects_bad_header_varints_and_chunk_bounds(self):
        header = b'SYD1\x01\0\0\0'
        for data in (b'', header[:7], b'SYD1\x02\0\0\0',
                     header + b'\x80' * 10,
                     header + b'\x01\xff\xff\xff\xff\x7f'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                recycle.decode_dictionary(data)
        for chunk in (b'\0\0', b'\x02\x02\x01a', b'\x01\x03\x01ab',
                      b'\x02\x04\x01a\x01a'):
            data = header + chunk + recycle.crc32c(chunk).to_bytes(4, 'little')
            with self.subTest(chunk=chunk), self.assertRaises(ValueError):
                recycle.decode_dictionary(data)
