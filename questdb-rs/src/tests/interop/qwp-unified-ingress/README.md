# Unified ingress M0 wire fixtures

`m0-equivalent-buffer.hex` and `m0-equivalent-chunk.hex` are unmasked QWP
application payloads produced from the same logical input:

- table `trades`;
- ten rows;
- `sym = SYM_000..SYM_009`;
- `qty = 0..9`;
- `px = 100.0..109.0`;
- designated timestamps `1700000000000000000..1700000000000000009` ns.

The Buffer fixture is also the Java replay-encoder golden. The Chunk fixture is
the specialized zero-copy Chunk encoder's replay payload. They are not expected
to be byte-identical: the M0 contract freezes each encoder's full payload so
the unified sender cannot silently normalize, copy, or re-layout either input.

`qwp_ws_java_golden::equivalent_buffer_and_chunk_payloads_match_checked_in_goldens`
constructs the logical fixture from source and checks both files byte-for-byte.
