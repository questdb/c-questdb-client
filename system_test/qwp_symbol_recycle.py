"""Test-only symbol corpus and strict persisted-dictionary witness.

Read snapshots only while the producer is idle after a publication/ACK barrier.
This is deliberately not a public monitoring API or a crash recovery decoder.
"""
from pathlib import Path


def symbol_batch(phase, size=16):
    """Globally unique row IDs; null, empty, Unicode, and repeated symbols."""
    assert size >= 8
    values = [None, '', f'東京-{phase}']
    values += [f'epoch-{phase}-{i}' for i in range(size - 6)]
    values += [None, f'東京-{phase}', f'東京-{phase}']
    return [(phase * 10000 + i, value) for i, value in enumerate(values)]


def expected_reset_count(counts, threshold, enabled=True, ceiling=1_000_000):
    """Policy model only: drained boundaries, disjoint batches except empty."""
    assert 1 <= threshold <= ceiling
    floor = 0
    count = 0
    armed = False
    resets = 0
    for unique_count in counts:
        if armed:
            floor = max(floor, min(count * 2, ceiling))
            count = 0
            armed = False
            resets += 1
        count += unique_count - int(count > 0)  # shared empty symbol
        armed = enabled and count >= max(threshold, floor)
    return resets


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def decode_dictionary(data):
    if data[:8] != b'SYD1\x01\0\0\0':
        raise ValueError('invalid SYD1 header')

    def varint(pos, limit):
        value = 0
        for shift in range(0, 70, 7):
            if pos >= limit:
                raise ValueError('truncated varint')
            byte = data[pos]
            pos += 1
            if shift == 63 and byte > 1:
                raise ValueError('overflowing varint')
            value |= (byte & 127) << shift
            if byte < 128:
                return value, pos
        raise ValueError('overflowing varint')

    symbols = []
    pos = 8
    while pos < len(data):
        start = pos
        count, pos = varint(pos, len(data))
        size, pos = varint(pos, len(data))
        end = pos + size
        if not count or count > 2_000_000 or count > size or end + 4 > len(data):
            raise ValueError('invalid chunk bounds')
        if crc32c(data[start:end]) != int.from_bytes(data[end:end + 4], 'little'):
            raise ValueError('invalid chunk checksum')
        for _ in range(count):
            size, pos = varint(pos, end)
            if pos + size > end:
                raise ValueError('invalid entry bounds')
            symbols.append(data[pos:pos + size].decode('utf-8'))
            pos += size
        if pos != end:
            raise ValueError('unconsumed chunk bytes')
        pos = end + 4
    if len(symbols) != len(set(symbols)):
        raise ValueError('duplicate symbol IDs')
    return symbols


def dictionary_snapshot(sf_dir, sender_id):
    path = Path(sf_dir) / sender_id / '.symbol-dict'
    return decode_dictionary(path.read_bytes())
