# 3. Decode SRUM records from raw ESE leaf-tag bytes, offsets validated against real corpora

Date: 2026-07-24
Status: Accepted

## Context

`ese-core` exposes each B-tree leaf as a raw page tag (a byte slice), but the
SRUM per-record layout is SRUM-specific and lower-level than any normalized row
API: Windows stores each record as a common-key-prefix *delta* against the
previous key, followed by fixed little-endian column offsets. A reader that
normalized these into typed rows would hide exactly the prefix/delta structure a
forensic decoder must see, and the true column offsets are not fully specified —
they were established from real `SRUDB.dat` files.

## Decision

`srum-parser` decodes each record from the raw ESE leaf-tag bytes itself
(`crates/srum-parser/src/{network,connectivity,app_usage,...}.rs`). Each decoder:

1. Reads `cbCommonKeyPrefix` (u16 LE), reconstructs the key length, and computes
   the column start (`col_start = 2 + (KEY_LEN - cb_pfx)`).
2. Reads every column with explicit little-endian `from_le_bytes` at documented
   offsets — the per-table layout is written out in each module header (e.g.
   `network.rs`: `BytesSent` at `col+40`, `BytesRecvd` at `col+48`).
3. **Length-guards before every read** (`if data.len() < need { return
   Err(SrumError::DecodeError { page, tag, detail }) }`) — a short or lying record
   returns a located error, never a panic or an out-of-bounds read.

Offsets, key lengths, and endianness were derived empirically and pinned to
observed corpora (`network.rs`: "verified across 96 records in
`chainsaw_SRUDB.dat`"), then cross-validated: 56/56 record counts match
`dissect.esedb 3.18` across seven real `SRUDB.dat` files
(`docs/validation-report.md`; commits `709aabb`/`6b02dfb` "real ESE decoders",
`64b99ed` "56/56 match").

## Consequences

The decoder sees the delta/prefix structure and can flag `AutoIncId` gaps and
checksum anomalies a normalized reader would smooth over. Robustness is
hand-rolled per decoder via explicit guards rather than routed through the
fleet `safe-read` crate — an honest residual: migrating the fixed-width reads to
`safe-read` would consolidate the bounds logic behind one audited, fuzzed
implementation. The offset maps are empirically pinned, so a new Windows build
that changes a column layout requires re-validation against a fresh corpus, not
just a spec check.
