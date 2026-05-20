# Parser Validation Report

**Tool:** `sr` (srum-forensic) · **Date:** 2026-05-20 · **Validated against:** dissect.esedb 3.18

---

## Executive Summary

**56/56 record counts match dissect.esedb exactly** across 7 real SRUDB.dat files and all 8 parse functions.
All parsers return `Ok([])` for tables absent from the catalog (correct behaviour — no crash, no error).

**0/0 page checksum anomalies** on two known-good real SRUDB.dat files using the correct Vista+ XOR-32 algorithm.

**0 AutoIncId gaps** in `chainsaw_SRUDB.dat` app_usage records (IDs 1..1660 confirmed contiguous).

| Fixture | Size | Windows | Tables present | Verdict |
|---------|------|---------|----------------|---------|
| `chainsaw_SRUDB.dat` | 1.8 MB | Win10 (APTSimulator) | 6/8 | PASS |
| `plaso_SRUDB.dat` | 7.5 MB | Win10 | 7/8 | PASS |
| `museum_rathbunvm_win10_SRUDB.dat` | 768 KB | Win10 (VM) | 6/8 | PASS |
| `museum_rathbunvm_win11_SRUDB.dat` | 2.4 MB | Win11 (VM) | 8/8 | PASS |
| `museum_belkasoftctf_win10_SRUDB.dat` | 3.1 MB | Win10 (CTF) | 6/8 | PASS |
| `museum_aptvm_server2022_clean_SRUDB.dat` | 192 KB | Server 2022 (fresh) | 1/8 | PASS |
| `museum_aptvm_server2022_1daylater_SRUDB.dat` | 640 KB | Server 2022 (+1 day) | 3/8 | PASS |

---

## Record Count Matrix

Ground truth: `dissect.esedb 3.18`. Our count: `cargo run --example count_records`.  
`—` = table absent from catalog (parser returns `Ok([])`). `0` = table present but empty.

| Table | chainsaw | plaso | win10 | win11 | belkasoft | aptvm_clean | aptvm_1day |
|-------|----------|-------|-------|-------|-----------|-------------|------------|
| Network Usage | 96 | 1840 | 23 | 143 | 465 | — | — |
| App Resource Usage | 1660 | 2851 | 163 | 791 | 4107 | — | — |
| Network Connectivity | 6 | 260 | 1 | 9 | 50 | — | 4 |
| Energy Usage | 0 | 0 | — | 13 | 0 | — | — |
| Energy Usage LT | 0 | 2 | — | 2 | 1 | — | — |
| Push Notifications | 562 | 16183 | 118 | 662 | 2087 | — | 153 |
| App Timeline | 26 | — | 4 | 33 | 101 | — | — |
| ID Map | 714 | 5895 | 288 | 1044 | 476 | 2 | 96 |
| **Total** | **3065** | **27031** | **597** | **2694** | **7287** | **2** | **253** |

All values verified identical between dissect and our parser. Zero mismatches.

---

## Page Checksum Validation

The Vista+ ESE XOR-32 checksum algorithm:

- Seed: `logical_page_number = physical_page_number - 1`
- XOR all 4-byte words across the **entire** page (including bytes[0..8])
- Compare computed XOR to `page.data[4..8]` (the stored checksum field)
- Skip pages where both `data[0..4]` and `data[4..8]` are zero (never checksummed)

| Fixture | Pages | Anomalies | Verdict |
|---------|-------|-----------|---------|
| `chainsaw_SRUDB.dat` | 326 | 0 | PASS |
| `museum_rathbunvm_win10_SRUDB.dat` | ~100 | 0 | PASS |

Validated by `ese-integrity::verify_page_checksums`. Algorithm was confirmed independently
via a Python probe across all 326 chainsaw pages before implementation.

---

## AutoIncId Continuity Validation

App Resource Usage records carry an `AutoIncId` column that Windows increments for each new
record. Gaps indicate deleted records or data loss. The diagnostic binary at
`crates/srum-parser/src/bin/gap_diag.rs` iterates raw B-tree tags and computes
`col_start = data.len() - COL_DATA_LEN` (290 bytes, invariant across all three tested fixtures)
to extract `AutoIncId` without assuming KEY_LEN.

| Fixture | Records | AutoIncId range | Gaps |
|---------|---------|-----------------|------|
| `chainsaw_SRUDB.dat` | 1660 | 1..1660 | 0 |

---

## Methodology

Record counts were compared using dissect.esedb 3.18 (independent ground truth) and
`cargo run -p srum-parser --example count_records` (our parser). Both tools were run
against each fixture file and counts compared cell-by-cell (56 comparisons total).

Field-level accuracy was verified on `museum_rathbunvm_win10_SRUDB.dat`:

| Table | Field | Dissect value | Our value | Match |
|-------|-------|--------------|-----------|-------|
| ID Map | `id` (IdIndex) | 1 | 1 | ✓ |
| ID Map | `id` (IdIndex) | 3 | 3 | ✓ |
| ID Map | `name` (IdBlob) | starts `!!` | starts `!!` | ✓ |
| App Timeline | `app_id` (AppId) | 154 | 154 | ✓ |
| App Timeline | `user_id` (UserId) | 52 | 52 | ✓ |
| Network Usage | `auto_inc_id` | non-zero | non-zero | ✓ |
| Network Usage | `timestamp` | ≥ 2013-10-17 | ≥ 2013-10-17 | ✓ |

---

## Decoder Notes

### App Resource Usage (`{5C8CF1C7-7257-4F13-B223-970EF5939312}`)

Real ESE raw-tag layout: `cbCommonKeyPrefix (2 B) | key_suffix | col_data (290 B)`.  
KEY_LEN is **not fixed**: observed 16-byte and 28-byte keys within the same file.  
`col_start = data.len() - 290` — anchoring from the tail bypasses the KEY_LEN ambiguity.  
`AutoIncId` (u32 LE) at `col_start+4`. `TimeStamp` (OLE date f64 LE) at `col_start+8`.  
`AppId` (i32 LE) at `col_start+16`. `UserId` (i32 LE) at `col_start+20`.  
`foreground_cycles` and `background_cycles` are 0 pending column location.

### ID Map (`SruDbIdMapTable`)

Real ESE raw-tag layout: `cbCommonKeyPrefix (2 B) | key_suffix (KEY_LEN−pfx B) | col_data`.  
KEY_LEN = 7. `col_start = 2 + (7 − cb_pfx)`.  
Detection: `cb_pfx ≤ 7` AND `data[col_start] == 0x02` AND `data[col_start+1] == 0x7F`.  
`IdIndex` (i32 LE) at `col_start+5`. UTF-16LE blob at `col_start+15`.

### App Timeline (`{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}`)

KEY_LEN = 28. `col_start = 2 + (28 − cb_pfx)`.  
`TimeStamp` as OLE Automation Date (f64 LE) at `col_start+8`. `AppId` (i32 LE) at `col_start+16`. `UserId` (i32 LE) at `col_start+20`.  
`focus_time_ms` and `user_input_time_ms` have no equivalent real column — returned as 0.

### Network Connectivity (`{DD6636C4-8929-4683-974E-22C046A43763}`)

KEY_LEN = 28. `col_start = 2 + (28 − cb_pfx)`.  
`L2ProfileId` (i32 LE) at `col_start+32`. `ConnectedTime` (u32 LE, stored as u64) at `col_start+36`.

### Push Notifications (`{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}`)

KEY_LEN = 16. `col_start = 2 + (16 − cb_pfx)`.  
`ForegroundCycleTime` (u64 LE) at `col_start+24`. `BackgroundCycleTime` (u64 LE) at `col_start+32`.  
`notification_type` and `count` returned as 0 (no corresponding column at these offsets).

### Energy Usage / Energy LT (`{FEE4E14F-…}`)

KEY_LEN = 28. `col_start = 2 + (28 − cb_pfx)`.  
`charge_level` and `energy_consumed` returned as 0 (all-zero in available VM fixtures, pending column location).

### Catalog Deduplication

Real SRUDB.dat files contain duplicate MSysObjects entries for the same GUID (a placeholder
page registered first, the live data B-tree registered second). `catalog_entries()` uses
last-wins deduplication so `find_table_page()` always resolves to the correct (non-empty) root.
Verified on rathbunvm_win10: placeholder page 48 is never returned.

### Server 2022 Behaviour

Fresh Server 2022 installations contain only `SruDbIdMapTable` in the SRUM catalog.
All other extension tables are absent. Our `collect_table()` returns `Ok([])` for absent
tables rather than `Err`, matching the expected forensic behaviour.

### No Synthetic Decoders

All decoders accept **real ESE raw-tag format only**. Synthetic fallback paths (FILETIME-based
32-byte test fixtures) were removed after being identified as a doer-checker violation: both
the format and the parser were written by us, so those tests proved nothing about actual
Windows SRUDB.dat files.

---

## Test Coverage

Integration tests against real SRUDB.dat fixtures:

| Suite | File | Tests | Coverage |
|-------|------|-------|---------|
| `real_srudb_tests` | `crates/srum-parser/tests/real_srudb_tests.rs` | 76 | Record counts, field values, gap detection, ID resolution, all 7 fixtures |
| `integrity_tests` | `crates/ese-integrity/tests/integrity_tests.rs` | 47 | Page checksums, B-tree structure, catalog integrity, deleted records |

Run all integration tests:

```
cargo test --workspace
```

Run only the fixture-backed tests:

```
cargo test --test real_srudb_tests -p srum-parser
cargo test -p ese-integrity
```
