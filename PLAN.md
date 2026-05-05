# PLAN.md — srum-forensic Deep Forensic Expansion

**Date:** 2026-05-04  
**Revised:** 2026-05-05 — three forensic-recovery gaps added (circular buffer/slack, timestamp skew, fragment reconstruction)
**Status:** PROPOSED
**Scope:** Expand from a partial ESE reader + SRUM type stubs into a full-featured ESE/SRUM forensic workspace covering B-tree record extraction, disk carving, structural integrity checking, and memory forensic output types.

---

## 1. Current State

`srum-forensic` is a four-crate workspace:

- **ese-core**: `EseHeader` (magic `0x89ABCDEF` at offset 4, `page_size` at `0xEC`), `EseDatabase::open` + `read_page` + `page_count`, `EsePage` with `parse_header()` (Vista+ 40-byte format) and `tags()` + `record_data()`. `CatalogEntry::from_bytes` uses a **synthetic layout** (not the real ESE catalog wire format). `walk_leaf_pages(root_page)` recursively descends parent pages. `find_table_page(name)` searches catalog entries. Tests passing with synthetic fixture builder.

- **srum-core**: `NetworkUsageRecord { app_id, user_id, timestamp, bytes_sent, bytes_recv }`, `AppUsageRecord { app_id, user_id, timestamp, foreground_cycles, background_cycles }`, `IdMapEntry { id, name }`. Types only.

- **srum-parser**: `parse_network_usage()`, `parse_app_usage()`, `parse_id_map()` — all use **synthetic 32-byte flat decoders** that do NOT match real ESE column encoding. Against a real `SRUDB.dat` the decoders will silently produce garbage.

- **sr-cli**: `sr network <path>` and `sr apps <path>` — wired to srum-parser, pretty-prints JSON.

### Key gaps

1. `CatalogEntry` uses a synthetic format — real ESE catalog records have a different layout.
2. Record decoders assume a flat 32-byte format — real ESE uses fixed-column + variable-column + tagged-column encoding.
3. No column-type-aware decoding.
4. No structural integrity checking (dirty state, checksum failures, deleted record tags).
5. No carving capability.
6. No memory forensic types.
7. Only 2 of 8 SRUM extension tables parsed.
8. **[GAP — 2026-05-05]** No circular buffer / slack space recovery — SRUM rotates old records out; raw bytes persist in page slack and ESE free pages; not scannable.
9. **[GAP — 2026-05-05]** No timestamp skew detection — file header `db_time` vs per-page `db_time` not compared; page-newer-than-header is a manipulation indicator.
10. **[GAP — 2026-05-05]** No fragmented record reconstruction — carver assumes whole pages; records split across a bad sector / truncation boundary are unrecoverable.

---

## 2. Architectural Decision: Layer Ownership

### Where structural integrity checking lives

Following the same decision as winevt-forensic:

**`ese-integrity` (in srum-forensic)** — raw binary-format anomaly detection:
- Page CRC mismatch, dirty-state bit, deleted tag flag, AutoIncId gaps
- These are PARSING-LEVEL observations made while reading binary format
- Requires format-specific knowledge; outputs raw `EseStructuralAnomaly` facts
- Available to ANY consumer, not just RapidTriage

**RapidTriage `rt-correlation`** — forensic significance:
- Converts `EseStructuralAnomaly` into `Evidence` objects
- Draws conclusions: "database was wiped", "records deleted pre-arrest"
- Correlates with other artifact sources
- DOES NOT duplicate the binary format knowledge

The crate is named `ese-integrity` (not `ese-antiforensic`) to reflect that it produces structural facts, not forensic conclusions.

### ESE memory module ownership

Identical decision to winevt-forensic: keep ESE-in-memory scanning in `memf-windows` (requires `ObjectReader<P>` infrastructure). `srum-forensic` provides the OUTPUT types that `memf-windows` populates. `srum-forensic` never depends on `memf-core`.

---

## 3. What Moves to forensicnomicon

All structural knowledge about ESE and SRUM that is pure data (no algorithms, no file I/O). New files: `src/catalog/ese_knowledge.rs` and `src/catalog/srum_knowledge.rs`.

### 3.1 Complete ESE File Header Layout

All offsets from file byte 0, little-endian:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0x00 | 4 | Checksum (XOR of header words 1..) | |
| 0x04 | 4 | Signature `0x89ABCDEF` | |
| 0x08 | 4 | Format version | |
| 0x0C | 4 | File type (0=database, 1=streaming) | |
| 0x10 | 8 | Database time | |
| 0x18 | 16 | Database signature (creation GUID) | |
| 0x28 | 4 | Database state | 1=JustCreated, 2=DirtyShutdown, 3=CleanShutdown |
| 0x2C | 8 | Consistent position (log gen+offset) | |
| 0x34 | 8 | Attach time | |
| 0x3C | 8 | Detach time | |
| 0x58 | 4 | Repair count | |
| 0xEC | 4 | Page size | 4096 or 8192 or 16384 or 32768 |

```rust
pub const ESE_HEADER_SIGNATURE_OFFSET: usize = 4;
pub const ESE_HEADER_DB_STATE_OFFSET: usize = 0x28;
pub const ESE_HEADER_PAGE_SIZE_OFFSET: usize = 0xEC;

pub const ESE_DB_STATE_JUST_CREATED:    u32 = 1;
pub const ESE_DB_STATE_DIRTY_SHUTDOWN:  u32 = 2;
pub const ESE_DB_STATE_CLEAN_SHUTDOWN:  u32 = 3;
pub const ESE_DB_STATE_BEING_CONVERTED: u32 = 4;
pub const ESE_DB_STATE_FORCE_DETACH:    u32 = 5;
```

### 3.2 ESE Database Page Header Layout (Vista+ 40-byte format)

Offsets from page start:

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 8 | Page checksum (XOR/ECC) |
| 0x08 | 4 | Database time (low 32 bits) |
| 0x0C | 4 | Previous page number |
| 0x10 | 4 | Next page number |
| 0x14 | 4 | FDP object ID |
| 0x18 | 2 | Available data size |
| 0x1A | 2 | Available uncommitted data |
| 0x1C | 2 | First free byte offset |
| 0x1E | 2 | Page tag count |
| 0x20 | 4 | Page flags |

```rust
pub const ESE_PAGE_HEADER_SIZE_VISTA: usize = 40;
pub const ESE_PAGE_HEADER_SIZE_LEGACY: usize = 24;
pub const ESE_PAGE_TAG_COUNT_OFFSET: usize = 0x1E;
pub const ESE_PAGE_FLAGS_OFFSET: usize = 0x20;
pub const ESE_PAGE_CHECKSUM_OFFSET: usize = 0x00;
```

### 3.3 Page Flag Constants

```rust
// IMPORTANT: Current ese-core has PAGE_FLAG_SPACE_TREE = 0x0400 which is WRONG.
// The correct value is 0x0020. 0x0400 is LONG_VALUE. This must be fixed.

pub const ESE_PAGE_FLAG_ROOT:        u32 = 0x0001;
pub const ESE_PAGE_FLAG_LEAF:        u32 = 0x0002;
pub const ESE_PAGE_FLAG_PARENT:      u32 = 0x0004;
pub const ESE_PAGE_FLAG_EMPTY:       u32 = 0x0008;
pub const ESE_PAGE_FLAG_SPACE_TREE:  u32 = 0x0020;  // NOT 0x0400
pub const ESE_PAGE_FLAG_LONG_VALUE:  u32 = 0x0400;  // NOT space tree
pub const ESE_PAGE_FLAG_INDEX:       u32 = 0x0800;
pub const ESE_PAGE_FLAG_NEW_FORMAT:  u32 = 0x2000;  // Vista+ ECC checksum
pub const ESE_PAGE_FLAG_SCRUBBED:    u32 = 0x4000;
```

### 3.4 B-tree Page Structure Constants

```rust
pub const ESE_TAG_ENTRY_SIZE: usize = 4;
// Tag entry layout (u32 LE, Vista+ format):
//   bits  0-12: value offset from page data start (after header)
//   bit   13:   version flag
//   bits 16-28: value size (cb_data)
//   bit   29:   deleted flag
//   bit   30:   uncommitted flag
pub const ESE_TAG_FLAG_VERSION:       u32 = 0x0000_2000;
pub const ESE_TAG_FLAG_DELETED:       u32 = 0x2000_0000;
pub const ESE_TAG_FLAG_UNCOMMITTED:   u32 = 0x4000_0000;
// Tag array grows from END of page downward.
// Tag 0 = external page header (parent key on parent pages).
// Tags 1+ = data records on leaf pages; child page pointers on parent pages.
```

### 3.5 ESE Column Type Codes

```rust
pub const JET_COLTYP_NIL:          u8 = 0;
pub const JET_COLTYP_BIT:          u8 = 1;   // 1 byte boolean
pub const JET_COLTYP_UNSIGNED_BYTE: u8 = 2;  // 1 byte unsigned
pub const JET_COLTYP_SHORT:        u8 = 3;   // 2 bytes signed
pub const JET_COLTYP_LONG:         u8 = 4;   // 4 bytes signed
pub const JET_COLTYP_CURRENCY:     u8 = 5;   // 8 bytes (100ns intervals)
pub const JET_COLTYP_IEEE_SINGLE:  u8 = 6;   // 4 bytes float
pub const JET_COLTYP_IEEE_DOUBLE:  u8 = 7;   // 8 bytes float
pub const JET_COLTYP_DATE_TIME:    u8 = 8;   // 8 bytes (OLE Automation Date)
pub const JET_COLTYP_BINARY:       u8 = 9;   // variable bytes (max 255)
pub const JET_COLTYP_TEXT:         u8 = 10;  // variable text (max 255)
pub const JET_COLTYP_LONG_BINARY:  u8 = 11;  // variable bytes (up to 2GB)
pub const JET_COLTYP_LONG_TEXT:    u8 = 12;  // variable text (up to 2GB)
// 13 unused
pub const JET_COLTYP_UNSIGNED_LONG:      u8 = 14;
pub const JET_COLTYP_LONG_LONG:          u8 = 15;
pub const JET_COLTYP_GUID:               u8 = 16;
pub const JET_COLTYP_UNSIGNED_SHORT:     u8 = 17;
pub const JET_COLTYP_UNSIGNED_LONG_LONG: u8 = 18;
```

### 3.6 ESE Leaf Record Encoding Rules (Invariants)

```
// An ESE leaf record is laid out as:
// [fixed_data][variable_count_offset_table][variable_data][tagged_data]
//
// First 4 bytes of fixed data:
//   byte 0: last_fixed_colid     (highest fixed column ID present)
//   byte 1: last_variable_colid  (highest variable column ID present)
//   bytes 2-3: variable_offset_to_data (u16 LE, offset from record start)
//
// Fixed columns (coltyp with known byte size):
//   Packed in column-ID order after the 4-byte prefix.
//   Offset of column C = 4 + sum(sizes of fixed cols with ID < C).
//
// Variable-length offset table:
//   For each variable column (ID <= last_variable_colid):
//     2-byte LE offset from variable data start. Bit 15 (0x8000) = NULL.
//
// Tagged columns (ID >= 128 in typical Windows tables):
//   2-byte column_id + 2-byte offset in tagged area. Bit 14 = multi-value.
```

### 3.7 ESE Checksum Algorithm

```
// Two modes, distinguished by ESE_PAGE_FLAG_NEW_FORMAT (0x2000):
//
// Legacy XOR (pre-Vista, flag NOT set):
//   1. XOR all 4-byte words on the page except the first word (checksum storage)
//   2. Mix in page number: result ^= page_number
//   3. Stored as u32 at offset 0
//
// ECC (Vista+, flag IS set):
//   Two u32 values at offsets 0 and 4:
//   checksum[0] = XOR of 4-byte words at positions 8, 16, 24, 32, ... (even 8-byte slots)
//   checksum[1] = XOR of 4-byte words at positions 12, 20, 28, 36, ... (odd 8-byte slots)
//   Both values XOR'd with page_number
//   Provides single-bit ECC correction
```

### 3.8 ESE Catalog Table Schema (MSysObjects, page 4)

Key fixed columns:

| Col ID | Name | Type | Description |
|--------|------|------|-------------|
| 1 | ObjidTable | Long (4) | Parent table object ID |
| 2 | Type | Short (3) | 1=table, 2=column, 3=index, 4=long-value |
| 3 | Id | Long (4) | Object ID |
| 4 | ColtypOrPgnoFDP | Long (4) | Column type (type=2) or FDP root page (type=1) |
| 5 | SpaceUsage | Long (4) | Space hints |
| 6 | Flags | Long (4) | Object flags |

Variable columns:

| Col ID | Name | Type |
|--------|------|------|
| 128 | Name | Text (10) |
| 131 | DefaultValue | Binary (9) |

### 3.9 SRUM Table Schemas

All tables share columns 1-4:

| Col | Name | Type |
|-----|------|------|
| 1 | AutoIncId | Long (4) |
| 2 | TimeStamp | DateTime (8) — OLE Automation Date |
| 3 | AppId | Long (4) — FK to SruDbIdMapTable |
| 4 | UserId | Long (4) — FK to SruDbIdMapTable |

#### Network Data Usage — `{D10CA2FE-6FCF-4F6D-848E-B2601ACE4E59}`

| Col | Name | Type |
|-----|------|------|
| 5 | InterfaceLuid | LongLong (15) |
| 6 | L2ProfileId | Long (4) |
| 7 | L2ProfileFlags | Long (4) |
| 8 | BytesSent | LongLong (15) |
| 9 | BytesRecvd | LongLong (15) |

#### Application Resource Usage — `{D10CA2FE-6FCF-4F6D-848E-B2601ACE4E61}`

| Col | Name | Type |
|-----|------|------|
| 5 | ForegroundCycleTime | UnsignedLongLong (18) |
| 6 | BackgroundCycleTime | UnsignedLongLong (18) |
| 7 | FaceTime | LongLong (15) |
| 8 | ForegroundContextSwitches | Long (4) |
| 9 | BackgroundContextSwitches | Long (4) |
| 10 | ForegroundBytesRead | LongLong (15) |
| 11 | ForegroundBytesWritten | LongLong (15) |
| 12 | ForegroundNumReadOperations | Long (4) |
| 13 | ForegroundNumWriteOperations | Long (4) |
| 14 | ForegroundNumberOfFlushes | Long (4) |
| 15 | BackgroundBytesRead | LongLong (15) |
| 16 | BackgroundBytesWritten | LongLong (15) |
| 17 | BackgroundNumReadOperations | Long (4) |
| 18 | BackgroundNumWriteOperations | Long (4) |
| 19 | BackgroundNumberOfFlushes | Long (4) |

#### Energy Usage — `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` (and `…LT` variant)

| Col | Name | Type |
|-----|------|------|
| 5 | EventTimestamp | DateTime (8) |
| 6 | StateTransition | Long (4) |
| 7 | FullChargedCapacity | Long (4) |
| 8 | DesignedCapacity | Long (4) |
| 9 | ChargeLevel | Long (4) |
| 10 | ActiveAcTime | Long (4) |
| 11 | CsAcTime | Long (4) |
| 12 | ActiveDcOnBatteryTime | Long (4) |
| 13 | CsDcOnBatteryTime | Long (4) |
| 14 | ActiveDischargeTime | Long (4) |
| 15 | CsDischargeTime | Long (4) |
| 16 | ActiveEnergy | Long (4) |
| 17 | CsEnergy | Long (4) |

#### Network Connectivity Usage — `{973F5D5C-1D90-4944-BE8E-24B22A60DB5F}`

| Col | Name | Type |
|-----|------|------|
| 5 | InterfaceLuid | LongLong (15) |
| 6 | L2ProfileId | Long (4) |
| 7 | ConnectedTime | Long (4) |
| 8 | ConnectStartTime | DateTime (8) |
| 9 | L2ProfileFlags | Long (4) |

#### Application Timeline — `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}`

| Col | Name | Type |
|-----|------|------|
| 5 | DurationMS | Long (4) |
| 6 | SpanMS | Long (4) |
| 7 | TimelineEnd | DateTime (8) |
| 8 | InFocusDurationMS | Long (4) |
| 9 | UserInputMS | Long (4) |
| 10-19 | CompRenderedDuration .. MBBBytesSent | Long / LongLong |

#### Wireless Network by SSID — `{5C8CF1C7-7257-4F13-B223-970EF5939312}`

| Col | Name | Type |
|-----|------|------|
| 5 | InterfaceLuid | LongLong (15) |
| 6 | L2ProfileId | Long (4) |
| 7 | ConnectedTime | Long (4) |

#### Push Notifications — `{97C2CE28-A37B-4920-B1E9-FEF1C070F4AD}`

| Col | Name | Type |
|-----|------|------|
| 5 | NotificationType | Long (4) |
| 6 | PayloadSize | Long (4) |
| 7 | NetworkType | Long (4) |

#### SruDbIdMapTable

| Col | Name | Type | Description |
|-----|------|------|-------------|
| 1 | IdType | UnsignedByte (2) | 0=unknown, 1=SID, 2=app path, 3=interface |
| 2 | IdIndex | Long (4) | Integer key referenced by AppId/UserId |
| 3 | IdBlob | LongBinary (11) | SID bytes or UTF-16LE path string |

---

## 4. Expanded Workspace Structure

```
srum-forensic/
  Cargo.toml
  PLAN.md
  crates/
    ese-core/          # Page-level ESE access — ALREADY EXISTS, expand
    ese-integrity/     # NEW: raw structural anomaly detection (NOT forensic conclusions)
    ese-carver/        # NEW: disk/raw-image carving for ESE pages
    ese-memory/        # NEW: output types for ESE data from memory dumps
    srum-core/         # SRUM domain types — ALREADY EXISTS, expand to all 8 tables
    srum-parser/       # SRUM B-tree record extraction — ALREADY EXISTS, rewrite internals
    srum-schema/       # NEW: SRUM table/column schema lookup
    sr-cli/            # CLI — ALREADY EXISTS, extend
```

### Dependency Graph

```
forensicnomicon         (KNOWLEDGE layer, external)
      ^
      |
ese-core                (depends on forensicnomicon for constants)
      ^
      |
ese-integrity           (depends on ese-core for page types)
      ^         ^
      |         |
ese-carver    ese-memory
      ^         ^
      |         |
srum-schema   srum-core
      ^         ^
       \       /
       srum-parser
           ^
           |
         sr-cli
```

**Note:** `ese-integrity` is named to reflect that it produces raw structural facts (CRC mismatch, deleted tag flag, dirty state), NOT forensic conclusions. Forensic significance ("this database was wiped") is drawn by RapidTriage's correlation layer from the `EseStructuralAnomaly` facts.

---

## 5. ESE B-tree Architecture (Implementation Reference)

### 5.1 Page Numbering

- Page 0: database header (not a B-tree page)
- Page 1-3: space tree pages
- Page 4: MSysObjects catalog root (start here for table discovery)
- Page 5: MSysObjectsShadow root
- Pages 6+: user-defined table B-trees

### 5.2 B-tree Walk Algorithm

```
fn walk_btree(db, root_page) -> Vec<LeafRecord>:
    page = db.read_page(root_page)
    header = page.parse_header()
    if header.flags & LEAF:
        return parse_leaf_records(page)
    if header.flags & PARENT:
        results = []
        for tag in page.tags()[1..]:  // skip tag 0 (external header)
            child_page = u32_le(page.record_data(tag)[0..4])
            results.extend(walk_btree(db, child_page))
        return results
```

### 5.3 Catalog Reading

1. Walk B-tree from page 4
2. Type=1 records: table definitions; `ColtypOrPgnoFDP` = table root page
3. Type=2 records: column definitions; `ColtypOrPgnoFDP` = column type; `Name` (col 128) = column name

### 5.4 Leaf Record Decoding

Given raw tag bytes + column definitions from catalog:
1. Byte 0: `last_fixed_colid`; byte 1: `last_variable_colid`; bytes 2-3: `variable_offset_start`
2. Fixed columns: start at byte 4, packed in column-ID order
3. Variable columns: offset table starts at `variable_offset_start`; bit 15 = NULL
4. Tagged columns: follow variable data, each entry is 2-byte column_id + 2-byte offset

### 5.5 SruDbIdMapTable Resolution

All SRUM tables use integer AppId/UserId FKs. Build a `HashMap<i32, String>` from IdMapTable leaf records:
- `IdType=1,3`: IdBlob is a SID — convert to string form
- `IdType=2`: IdBlob is UTF-16LE path string

---

## 6. ese-core Expansion

### Bug Fix (CRITICAL): PAGE_FLAG_SPACE_TREE

Current `page.rs` exports `PAGE_FLAG_SPACE_TREE = 0x0400`. This is the LONG_VALUE flag. The correct value is `0x0020`. Must be fixed in Phase 1, story 1. Breaking change to public API — acceptable since not yet on crates.io.

### New: Real Catalog Parser

Replace synthetic `CatalogEntry::from_bytes` with real ESE record decoder using MSysObjects schema. Keep `from_synthetic_bytes` for test fixture building.

```rust
pub struct CatalogEntry {
    pub object_type: u16,         // 1=table, 2=column, 3=index
    pub object_id: u32,
    pub parent_object_id: u32,
    pub coltyp_or_pgno_fdp: u32,
    pub flags: u32,
    pub object_name: String,
    pub column_id: Option<u32>,   // for type=2
    pub codepage: Option<u32>,    // for type=2
}
```

### New: ESE Record Decoder

```rust
pub struct ColumnDef {
    pub column_id: u32,
    pub name: String,
    pub coltyp: u8,
}

pub enum EseValue {
    Null,
    Bool(bool), U8(u8), I16(i16), I32(i32), I64(i64),
    U16(u16), U32(u32), U64(u64),
    F32(f32), F64(f64),
    DateTime(f64),        // OLE Automation Date
    Binary(Vec<u8>),
    Text(String),
    Guid([u8; 16]),
}

pub fn decode_record(data: &[u8], columns: &[ColumnDef]) -> Result<Vec<(String, EseValue)>, EseError>;
```

### New: Page Checksum Verification

```rust
pub enum ChecksumResult { Valid, LegacyXorMismatch { computed: u32, stored: u32 }, EccMismatch, Unknown }
pub fn verify_page_checksum(page_data: &[u8], page_number: u32) -> ChecksumResult;
```

---

## 7. ese-integrity Crate

Raw binary-format structural anomaly detection. Produces facts, not forensic conclusions.

### Indicator Types

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub enum EseStructuralAnomaly {
    DirtyDatabase { db_state: u32 },
    PageChecksumMismatch { page_number: u32, computed: u64, stored: u64 },
    DeletedRecordPresent { page_number: u32, tag_index: u16, fdp_object_id: u32 },
    UncommittedRecord { page_number: u32, tag_index: u16 },
    AutoIncIdGap { table_name: String, expected: i32, found: i32 },
    OrphanedCatalogEntry { table_name: String, referenced_page: u32, file_page_count: u64 },
    ShadowPageMismatch { page_number: u32 },
    /// Page `db_time` field is newer than the file header `db_time` (manipulation indicator).
    TimestampSkew { page_number: u32, header_db_time_low: u32, page_db_time: u32 },
    /// Bytes recovered from page slack space (between record data and tag array).
    SlackRegionData { page_number: u32, offset_in_page: u16, length: u16 },
}
```

### Public API

```rust
pub fn check_dirty_state(header: &EseHeader) -> Option<EseStructuralAnomaly>;
pub fn verify_page_checksums(db: &EseDatabase) -> Vec<EseStructuralAnomaly>;
pub fn find_deleted_records(db: &EseDatabase, root_page: u32) -> Vec<EseStructuralAnomaly>;
pub fn detect_autoinc_gaps(auto_inc_ids: &[i32], table_name: &str) -> Vec<EseStructuralAnomaly>;
pub fn detect_orphaned_catalog(db: &EseDatabase) -> Vec<EseStructuralAnomaly>;
/// Compare file header db_time (offset 0x10) against each page's db_time field (page offset 0x08).
/// A page newer than the header is anomalous — indicates post-write tampering.
pub fn detect_timestamp_skew(header: &EseHeader, db: &EseDatabase) -> Vec<EseStructuralAnomaly>;
/// Scan every page's slack region (bytes between record data end and tag array start).
/// Returns SlackRegionData for any page with non-zero slack bytes.
pub fn scan_slack_regions(db: &EseDatabase) -> Vec<EseStructuralAnomaly>;
pub fn full_scan(db: &EseDatabase) -> Vec<EseStructuralAnomaly>;
```

---

## 8. ese-carver Crate

Scan `&[u8]` or `Read + Seek` for ESE pages.

### Carving Algorithm

**Phase 1: Database Header Discovery**
- Scan for `[0xEF, 0xCD, 0xAB, 0x89]` at offset 4 of any page-aligned boundary
- Extract `page_size` from offset `0xEC`; validate as power-of-2 in {4096..32768}
- Check `db_state` at `0x28`

**Phase 2: Aligned Page Scanning**
- Scan at `page_size` intervals from `header_offset + page_size`
- Validate: tag_count > 0, plausible flags, checksum
- `Integrity::Valid` / `Integrity::PageCorrupt`

**Phase 3: Aggressive 512-byte Fallback**
- When Phase 2 finds fewer pages than expected
- Mark results `Integrity::Carved`

### Key Types

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity { Valid, PageCorrupt, ChecksumMismatch, Carved, Truncated, Reconstructed }

#[derive(Debug, Clone)]
pub struct CarvedEsePage {
    pub offset: u64,
    pub page_number: u32,
    pub flags: u32,
    pub integrity: Integrity,
    pub tag_count: u16,
    pub fdp_object_id: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct EseCarveResult {
    pub header: Option<CarvedEseHeader>,
    pub pages: Vec<CarvedEsePage>,
    pub structural_anomalies: Vec<EseStructuralAnomaly>,
    pub stats: CarveStats,
}
```

### Public API

```rust
pub fn carve_from_bytes(data: &[u8]) -> EseCarveResult;
pub fn carve_from_file(path: &Path) -> Result<EseCarveResult>;
pub fn verify_integrity(path: &Path) -> Result<Vec<EseStructuralAnomaly>>;

/// Detect records whose data is split across a sector/truncation boundary.
/// For each adjacent pair of carved pages, checks whether the last record
/// of the first page and the first record of the second are incomplete
/// and together form a valid record.
pub fn detect_fragments(pages: &[CarvedEsePage]) -> Vec<FragmentPair>;

/// Attempt to stitch two partial record byte slices into a complete record.
/// Returns `Some(Vec<u8>)` if the combined data parses as a valid ESE record.
pub fn reconstruct_fragment(prefix: &[u8], suffix: &[u8], expected_size: usize) -> Option<Vec<u8>>;

/// A pair of adjacent carved pages where a record appears split across their boundary.
pub struct FragmentPair {
    pub page_a: u32,      // page number of the page containing the prefix
    pub page_b: u32,      // page number of the page containing the suffix
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub reconstructed: Option<Vec<u8>>,
}
```

---

## 9. ese-memory Crate

Output types for ESE data recovered from process memory. Does NOT perform memory reading.

### Types

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryEsePage {
    pub vaddr: u64,
    pub page_number: u32,
    pub flags: u32,
    pub tag_count: u16,
    pub fdp_object_id: u32,
    pub is_dirty: bool,
    pub structural_anomalies: Vec<EseStructuralAnomaly>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemorySrumRecord {
    pub vaddr: u64,
    pub source_page: u32,
    pub table_guid: String,
    pub columns: Vec<(String, ese_core::EseValue)>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SrumMemoryDiscrepancy {
    pub table_guid: String,
    pub discrepancy_type: DiscrepancyType,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum DiscrepancyType {
    MemoryOnlyRecord { auto_inc_id: i32 },
    ValueMismatch { auto_inc_id: i32, field: String },
    NewerInMemory { auto_inc_id: i32 },
}
```

### Analysis Functions

```rust
pub fn detect_srum_tampering(pages: &[MemoryEsePage]) -> Vec<EseStructuralAnomaly>;
pub fn correlate_memory_with_disk(
    memory_records: &[MemorySrumRecord],
    disk_auto_inc_ids: &[i32],
    table_guid: &str,
) -> Vec<SrumMemoryDiscrepancy>;
```

---

## 10. srum-schema Crate

Thin knowledge wrapper backed by forensicnomicon constants.

```rust
pub fn srum_table_name(guid: &str) -> Option<&'static str>;
pub fn srum_column_defs(guid: &str) -> Option<&'static [SrumColumnDef]>;
pub fn all_srum_tables() -> &'static [SrumTableInfo];

pub struct SrumColumnDef {
    pub column_id: u32,
    pub name: &'static str,
    pub coltyp: u8,
}
```

---

## 11. srum-core Expansion

Add types for all 8 SRUM tables. Current NetworkUsageRecord and AppUsageRecord need all fields:

```rust
// Expand existing:
pub struct NetworkUsageRecord {
    pub auto_inc_id: i32,
    pub timestamp: DateTime<Utc>,
    pub app_id: i32,
    pub user_id: i32,
    pub interface_luid: i64,
    pub l2_profile_id: i32,
    pub l2_profile_flags: i32,
    pub bytes_sent: i64,
    pub bytes_recv: i64,
}

// Add:
pub struct EnergyUsageRecord { pub auto_inc_id: i32, pub timestamp: DateTime<Utc>, pub app_id: i32, pub user_id: i32, pub event_timestamp: DateTime<Utc>, pub state_transition: i32, pub charge_level: i32, /* ... */ }
pub struct NetworkConnectivityRecord { /* ... */ }
pub struct AppTimelineRecord { /* ... */ }
pub struct WirelessNetworkRecord { /* ... */ }
pub struct PushNotificationRecord { /* ... */ }
pub struct GenericSrumRecord { pub auto_inc_id: i32, pub timestamp: DateTime<Utc>, pub app_id: i32, pub user_id: i32, pub table_guid: String, pub fields: Vec<(String, ese_core::EseValue)> }

pub struct IdMapEntry {
    pub id: i32,
    pub id_type: u8,      // 0=unknown, 1=SID, 2=app, 3=interface
    pub name: String,
    pub raw_blob: Vec<u8>,
}
```

---

## 12. srum-parser Rewrite

Current synthetic decoders must be replaced with real ESE record decoding:

1. Open ESE database
2. Walk catalog to discover table root pages + column definitions
3. For each SRUM GUID found in catalog: walk B-tree + decode records using `decode_record()`
4. Resolve AppId/UserId via IdMapTable

New public API:

```rust
pub fn parse_srum_database(path: &Path) -> Result<SrumDatabase>;

pub struct SrumDatabase {
    pub network_usage: Vec<NetworkUsageRecord>,
    pub app_usage: Vec<AppUsageRecord>,
    pub energy_usage: Vec<EnergyUsageRecord>,
    pub energy_usage_lt: Vec<EnergyUsageRecord>,
    pub network_connectivity: Vec<NetworkConnectivityRecord>,
    pub app_timeline: Vec<AppTimelineRecord>,
    pub wireless_network: Vec<WirelessNetworkRecord>,
    pub push_notifications: Vec<PushNotificationRecord>,
    pub id_map: Vec<IdMapEntry>,
    pub unknown_tables: Vec<(String, Vec<GenericSrumRecord>)>,
    pub structural_anomalies: Vec<EseStructuralAnomaly>,
}

pub fn resolve_names(db: &SrumDatabase) -> ResolvedSrumDatabase;
```

---

## 13. sr-cli Extensions

New subcommands: `all`, `schema`, `tables`, `verify`, `carve`, `idmap`, `energy`, `connectivity`, `timeline`.

Output formats: `json`, `jsonl`, `csv`, `table`.

---

## 14. TDD Roadmap — ralph-loop User Stories

### Phase 0: forensicnomicon Additions
*Dependency: none*

| # | Story |
|---|-------|
| 1 | RED: `ese_page_flag_leaf()` returns `0x0002` |
| 2 | GREEN: Add ESE page flag constants to `ese_knowledge.rs` |
| 3 | RED: `ese_page_header_size_vista()` returns `40` |
| 4 | GREEN: Add ESE page header layout constants |
| 5 | RED: `ese_column_type_size(JET_COLTYP_LONG)` returns `4` |
| 6 | GREEN: Add JET column type codes and fixed-size table |
| 7 | RED: `srum_table_name("{D10CA2FE-6FCF-4F6D-848E-B2601ACE4E59}")` returns `Some("Network Data Usage")` |
| 8 | GREEN: Add SRUM GUID-to-name mapping in `srum_knowledge.rs` |
| 9 | RED: `srum_column_count("{D10CA2FE-6FCF-4F6D-848E-B2601ACE4E61}")` returns `19` |
| 10 | GREEN: Add SRUM column schemas for all 8 tables |
| 11 | RED: `ese_db_state_dirty_shutdown()` returns `2` |
| 12 | GREEN: Add ESE database state constants |

### Phase 1: ese-core B-tree Completion
*Dependency: Phase 0*

| # | Story |
|---|-------|
| 1 | RED: `PAGE_FLAG_SPACE_TREE` equals `0x0020`; `PAGE_FLAG_LONG_VALUE` equals `0x0400` |
| 2 | GREEN: Fix page flag constants |
| 3 | RED: `tags()` returns `EseTag { offset, size, is_deleted, is_uncommitted }` |
| 4 | GREEN: Extend tag parsing with flag bits |
| 5 | RED: `CatalogEntry::from_ese_record` parses real MSysObjects column layout |
| 6 | GREEN: Implement real catalog record parser |
| 7 | RED: `table_columns("SruDbIdMapTable")` returns 3 column defs |
| 8 | GREEN: Implement `EseDatabase::table_columns()` |
| 9 | RED: `decode_record(data, cols)` decodes 3 fixed columns correctly |
| 10 | GREEN: Implement fixed-column decoding |
| 11 | RED: `decode_record` handles variable-length Text column |
| 12 | GREEN: Implement variable-column offset table decoding |
| 13 | RED: `verify_page_checksum` returns `Valid` for correct legacy XOR |
| 14 | GREEN: Implement legacy XOR checksum |
| 15 | RED: `verify_page_checksum` returns `EccMismatch` for tampered Vista+ page |
| 16 | GREEN: Implement ECC checksum verification |
| 17 | RED: `catalog_entries()` follows multi-page B-tree via `walk_leaf_pages(4)` |
| 18 | GREEN: Replace single-page read with B-tree walk |

### Phase 2: srum-schema Crate
*Dependency: Phase 0*

| # | Story |
|---|-------|
| 1 | RED: `srum_table_name("{D10CA2FE-…E59}")` returns `Some("Network Data Usage")` |
| 2 | GREEN: Wire lookup from forensicnomicon constants |
| 3 | RED: `srum_column_defs("{D10CA2FE-…E59}")` returns BytesSent at column 8 |
| 4 | GREEN: Implement column def lookup |
| 5 | RED: `all_srum_tables()` returns 9 entries |
| 6 | GREEN: Return all 8 extension tables + IdMapTable |
| 7 | RED: `srum_column_defs` for unknown GUID returns `None` |
| 8 | GREEN: Handle missing table |
| 9 | RED: AppUsage schema has 19 columns |
| 10 | GREEN: Full schema for all tables |

### Phase 3: srum-parser Completion
*Dependency: Phase 1 + Phase 2*

| # | Story |
|---|-------|
| 1 | RED: `parse_id_map` against real-format ESE fixture returns `IdMapEntry` with correct name |
| 2 | GREEN: Rewrite id_map decoder using `decode_record` |
| 3 | RED: `parse_network_usage` returns `NetworkUsageRecord` with correct `bytes_sent` |
| 4 | GREEN: Rewrite network decoder using real ESE column encoding |
| 5 | RED: `parse_app_usage` returns all 19 fields |
| 6 | GREEN: Full app usage decoder |
| 7 | RED: `parse_srum_database` discovers all SRUM tables via catalog |
| 8 | GREEN: Catalog-driven table discovery |
| 9 | RED: OLE Automation Date `43831.0` → `2020-01-01 00:00:00 UTC` |
| 10 | GREEN: Implement OLE DateTime conversion |
| 11 | RED: `resolve_names` replaces integer AppId with path string |
| 12 | GREEN: IdMap HashMap resolution |
| 13 | RED: Unknown GUID yields `GenericSrumRecord` entries |
| 14 | GREEN: Generic record fallback |
| 15 | RED: `parse_srum_database` returns `structural_anomalies` for dirty database |
| 16 | GREEN: Wire `ese-integrity` checks into parse path |

### Phase 4: ese-integrity Crate
*Dependency: Phase 1*

| # | Story |
|---|-------|
| 1 | RED: `check_dirty_state` returns `None` for clean database (state=3) |
| 2 | GREEN: Implement dirty state check |
| 3 | RED: `check_dirty_state` returns `DirtyDatabase` for state=2 |
| 4 | GREEN: Handle dirty case |
| 5 | RED: `verify_page_checksums` returns empty vec for valid database |
| 6 | GREEN: Implement page checksum loop |
| 7 | RED: `verify_page_checksums` returns `PageChecksumMismatch` for tampered page |
| 8 | GREEN: Report mismatch with page number |
| 9 | RED: `find_deleted_records` returns empty for page with no deleted tags |
| 10 | GREEN: Implement deleted tag flag scan |
| 11 | RED: `find_deleted_records` returns `DeletedRecordPresent` for page with deleted tag |
| 12 | GREEN: Check bit 29 (0x2000_0000) of tag entry |
| 13 | RED: `detect_autoinc_gaps` returns empty for `[1, 2, 3, 4]` |
| 14 | GREEN: Implement sequential check |
| 15 | RED: `detect_autoinc_gaps` returns `AutoIncIdGap` for `[1, 2, 5, 6]` |
| 16 | GREEN: Detect gap between 2 and 5 |
| 17 | RED: `detect_orphaned_catalog` finds entry referencing page beyond file |
| 18 | GREEN: Cross-check page references against file size |
| 19 | RED: `full_scan` aggregates all indicator types |
| 20 | GREEN: Wire all checks |
| 21 | RED: `detect_timestamp_skew` returns empty for page where `db_time` ≤ header `db_time` |
| 22 | GREEN: Implement timestamp field comparison |
| 23 | RED: `detect_timestamp_skew` returns `TimestampSkew` when page `db_time` > header `db_time` |
| 24 | GREEN: Detect forward skew (page newer than header) |
| 25 | RED: `scan_slack_regions` returns empty for page with no slack |
| 26 | GREEN: Implement slack region bounds calculation |
| 27 | RED: `scan_slack_regions` returns `SlackRegionData` for page with non-zero slack |
| 28 | GREEN: Return offset + length of slack bytes |

### Phase 5: ese-carver Crate
*Dependency: Phase 1 + Phase 4*

| # | Story |
|---|-------|
| 1 | RED: `carve_from_bytes([])` returns empty `EseCarveResult` |
| 2 | GREEN: Empty-input path |
| 3 | RED: `carve_from_bytes` with valid ESE header finds header with correct page_size |
| 4 | GREEN: Phase 1 header scan |
| 5 | RED: `carve_from_bytes` finds 3 pages after header |
| 6 | GREEN: Phase 2 aligned page scan |
| 7 | RED: Corrupt checksum flagged `Integrity::ChecksumMismatch` |
| 8 | GREEN: Integrate checksum in scan |
| 9 | RED: No header → aggressive fallback scan |
| 10 | GREEN: Phase 3 512-byte scan |
| 11 | RED: Aggressive results marked `Integrity::Carved` |
| 12 | GREEN: Set integrity flag |
| 13 | RED: `verify_integrity` returns structural anomalies for dirty database |
| 14 | GREEN: Wire carve + ese-integrity into verify |
| 15 | RED: `CarveStats` counts valid vs corrupt pages |
| 16 | GREEN: Increment stats |
| 17 | RED: `detect_fragments` returns empty for slice of complete pages |
| 18 | GREEN: Implement no-fragment base case |
| 19 | RED: `detect_fragments` returns `FragmentPair` when last tag of page A + first tag of page B together reach `expected_size` |
| 20 | GREEN: Detect split at page boundary |
| 21 | RED: `reconstruct_fragment` returns `None` for two slices that don't total `expected_size` |
| 22 | GREEN: Length guard |
| 23 | RED: `reconstruct_fragment` returns stitched bytes when prefix + suffix = expected |
| 24 | GREEN: Concatenate prefix + suffix |

### Phase 6: ese-memory Types and Analysis
*Dependency: Phase 4*

| # | Story |
|---|-------|
| 1 | RED: `MemoryEsePage` constructible from page data + vaddr |
| 2 | GREEN: Implement constructor |
| 3 | RED: `MemorySrumRecord` constructible from decoded columns + vaddr |
| 4 | GREEN: Implement constructor |
| 5 | RED: `detect_srum_tampering` flags pages with checksum anomalies |
| 6 | GREEN: Delegate to ese-integrity |
| 7 | RED: `correlate_memory_with_disk` detects record present in memory but absent from disk |
| 8 | GREEN: Set-difference comparison by AutoIncId |
| 9 | RED: `correlate_memory_with_disk` detects value mismatch for same AutoIncId |
| 10 | GREEN: Compare field values |
| 11 | RED: `SrumMemoryDiscrepancy` serializes to valid JSON |
| 12 | GREEN: Confirm serde derives |

### Phase 7: sr-cli Extensions
*Dependency: Phase 3 + Phase 5*

| # | Story |
|---|-------|
| 1 | RED: `sr all <path>` exits 0 and emits valid JSON with all 8 table keys |
| 2 | GREEN: Wire `parse_srum_database` into CLI |
| 3 | RED: `sr schema` prints all known table GUIDs |
| 4 | GREEN: Wire `all_srum_tables` |
| 5 | RED: `sr schema {D10CA2FE-…E59}` prints 9-column Network Data Usage schema |
| 6 | GREEN: Wire `srum_column_defs` |
| 7 | RED: `sr tables <path>` lists tables from ESE catalog |
| 8 | GREEN: Wire `catalog_entries` |
| 9 | RED: `sr verify <path>` reports dirty database state |
| 10 | GREEN: Wire `full_scan` |
| 11 | RED: `sr carve <path>` finds and reports carved pages |
| 12 | GREEN: Wire `carve_from_file` |
| 13 | RED: `sr idmap <path>` prints resolved ID map entries |
| 14 | GREEN: Wire `parse_id_map` |
| 15 | RED: `sr all --resolve-names` replaces AppId integers with path strings |
| 16 | GREEN: Wire `resolve_names` |

---

## 15. Boundary with RapidTriage

### Current
- `rt-parser-srum` depends on `srum-parser` (wired)
- SRUM rules in `rt-correlation` (060-063 YAML files)

### Expanded
```toml
# rt-parser-srum/Cargo.toml additions
srum-parser      = { path = "../../srum-forensic/crates/srum-parser" }
srum-schema      = { path = "../../srum-forensic/crates/srum-schema" }
ese-integrity    = { path = "../../srum-forensic/crates/ese-integrity" }
```

New capabilities:
1. **Full SRUM extraction**: All 8 tables via `parse_srum_database`
2. **Structural anomaly evidence**: `EseStructuralAnomaly` → `Evidence` via forensic-pivot adapter (NOT forensic conclusions — just the raw facts that RapidTriage's correlation layer will interpret)
3. **Name resolution**: IdMap before emitting timeline events
4. **Schema-aware display**: `srum-schema` for human-readable column names

### memf-windows Integration (future)

`memf-windows` gains `srum.rs` (parallel to `evtx.rs`) that:
- Scans svchost process VADs for ESE pages
- Decodes pages using `ese-core`
- Returns `ese-memory::MemoryEsePage` and `MemorySrumRecord`

---

## 16. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| ESE checksum algorithm: two variants (XOR, ECC) with page-number mixing | Use `PAGE_FLAG_NEW_FORMAT` to select; return `Unknown` if neither matches (avoid false positives) |
| Variable-length column edge cases (multi-valued tagged cols, ID > 127) | Phase 1 supports fixed + single-value variable only; tagged columns deferred; `decode_record` returns `EseValue::Null` with warning rather than failing |
| Real catalog format vs synthetic fixture | Keep `from_synthetic_bytes` for tests; add `from_ese_record` for real databases |
| PAGE_FLAG_SPACE_TREE bug | Fix in Phase 1 story 1; semver-breaking but not yet on crates.io |
| SRUM transaction log recovery (`.jrs` files) | Flag dirty state via `EseStructuralAnomaly::DirtyDatabase`; full log replay is out of scope (future Phase 8) |
| Unknown SRUM table GUIDs from third-party providers | Dynamic catalog discovery + `GenericSrumRecord` fallback |
| Cross-workspace path deps | Same pattern as winevt-forensic: path deps for dev, crates.io order for CI |

---

## 17. File Inventory

| Crate | File | Action |
|-------|------|--------|
| forensicnomicon | `src/catalog/ese_knowledge.rs` | NEW |
| forensicnomicon | `src/catalog/srum_knowledge.rs` | NEW |
| ese-core | `src/record.rs` | NEW |
| ese-core | `src/checksum.rs` | NEW |
| ese-core | `src/catalog.rs` | REWRITE |
| ese-core | `src/page.rs` | FIX + EXTEND |
| ese-core | `src/database.rs` | EXTEND |
| ese-integrity | `src/lib.rs` | NEW |
| ese-integrity | `src/dirty.rs` | NEW |
| ese-integrity | `src/checksum.rs` | NEW |
| ese-integrity | `src/deleted.rs` | NEW |
| ese-integrity | `src/gaps.rs` | NEW |
| ese-carver | `src/lib.rs` | NEW |
| ese-carver | `src/header_scan.rs` | NEW |
| ese-carver | `src/page_scan.rs` | NEW |
| ese-carver | `src/aggressive_scan.rs` | NEW |
| ese-carver | `src/types.rs` | NEW |
| ese-memory | `src/lib.rs` | NEW |
| ese-memory | `src/analysis.rs` | NEW |
| srum-schema | `src/lib.rs` | NEW |
| srum-schema | `src/tables.rs` | NEW |
| srum-schema | `src/columns.rs` | NEW |
| srum-core | `src/energy.rs` | NEW |
| srum-core | `src/connectivity.rs` | NEW |
| srum-core | `src/timeline.rs` | NEW |
| srum-core | `src/wireless.rs` | NEW |
| srum-core | `src/push.rs` | NEW |
| srum-core | `src/generic.rs` | NEW |
| srum-parser | `src/lib.rs` | REWRITE |
| srum-parser | `src/resolve.rs` | NEW |
| srum-parser | `src/filetime.rs` | NEW |
| srum-parser | `src/(energy\|connectivity\|timeline\|wireless\|push\|generic).rs` | NEW |
| sr-cli | `src/main.rs` | EXTEND |
