# Radical Refactor Design — 2026-05-05

**Goal:** Maximum maintainability, maximum debuggability, strict DRY. Strict TDD throughout with zero regression tolerance.

---

## 1. Crate Structure

**Current (6 crates):**
```
sr-cli → srum-parser → srum-core
                     → ese-core
ese-integrity → ese-core
ese-carver    → ese-core
```

**After (7 crates, 1 new):**
```
sr-cli → srum-parser → srum-core
                     → ese-core
ese-integrity → ese-core
ese-carver    → ese-core

[dev-dependency only — never ships]
ese-test-fixtures → ese-core
  ↑ ese-core/tests, ese-integrity/tests, ese-carver/tests, srum-parser/tests
```

`ese-test-fixtures` appears only in `[dev-dependencies]`. It is never a transitive runtime dependency.

---

## 2. `ese-test-fixtures` API

Replaces three copies of `put_u32`, `put_u16`, `write_tag`, `make_header_page`, `write_ese_file` and three `PAGE_SIZE` declarations.

```rust
pub use ese_core::PAGE_SIZE;

/// Fluent builder for a single ESE page.
pub struct PageBuilder { ... }

impl PageBuilder {
    pub fn new(page_size: usize) -> Self;
    pub fn leaf(self) -> Self;          // sets PAGE_FLAG_LEAF
    pub fn parent(self) -> Self;        // sets PAGE_FLAG_PARENT | PAGE_FLAG_ROOT
    pub fn with_db_time(self, t: u32) -> Self;
    pub fn with_db_state(self, s: u32) -> Self;   // header pages only
    pub fn add_record(self, data: &[u8]) -> Self; // appends a tag + record bytes
    pub fn add_child_page(self, page_num: u32) -> Self; // for parent pages
    pub fn with_slack(self, bytes: &[u8]) -> Self; // write bytes into slack region
    pub fn build(self) -> Vec<u8>;
}

/// Assembles pages into a NamedTempFile.
pub struct EseFileBuilder { ... }

impl EseFileBuilder {
    pub fn new() -> Self;
    pub fn with_db_time(self, t: u64) -> Self;
    pub fn with_db_state(self, s: u32) -> Self;
    pub fn add_page(self, page: Vec<u8>) -> Self;
    pub fn write(self) -> NamedTempFile;  // header is always page 0
}
```

All existing fixture files reduce to imports of these two types — no local helpers.

---

## 3. `EseDatabase` Iterator API

### 3a. Single entry point

`ese_core::open_database` free function is removed. Only:
```rust
impl EseDatabase {
    pub fn open(path: &Path) -> Result<Self, EseError>;
}
```

### 3b. `TableCursor` iterator

```rust
/// Iterator over raw record bytes for one SRUM table.
/// Yields `(page_num, tag_idx, record_bytes)` for each data record.
pub struct TableCursor<'db> { ... }

impl<'db> Iterator for TableCursor<'db> {
    type Item = Result<(u32, usize, Vec<u8>), EseError>;
}

impl EseDatabase {
    /// Open a cursor over every data record in the named table.
    /// Returns `Err(EseError::TableNotFound)` immediately if the table is absent.
    pub fn table_records(&self, table_name: &str) -> Result<TableCursor<'_>, EseError>;
}
```

`walk_leaf_pages` and `read_page` remain as `pub` for `ese-integrity` and `ese-carver` which need per-page access. `table_records` is the high-level path for `srum-parser`.

### 3c. Effect on `srum-parser`

Three near-identical parse functions collapse into one private generic + three one-liners:

```rust
fn collect_table<T>(
    db: &EseDatabase,
    table: &str,
    decode: impl Fn(&[u8], u32, usize) -> Result<T, SrumError>,
) -> anyhow::Result<Vec<T>> {
    db.table_records(table)?
        .filter_map(|r| match r {
            Ok((page, tag, data)) => decode(&data, page, tag).ok(),
            Err(_) => None,
        })
        .collect::<Vec<_>>()
        .pipe(Ok)
}

pub fn parse_network_usage(path: &Path) -> anyhow::Result<Vec<NetworkUsageRecord>> {
    collect_table(&EseDatabase::open(path)?, NETWORK_TABLE, decode_network_record)
}
```

---

## 4. Error Types

### `ese-core::EseError` — always carries location

```rust
#[derive(Debug, thiserror::Error)]
pub enum EseError {
    #[error("page {page}: invalid magic {found:#010x}")]
    InvalidMagic { page: u32, found: u32 },

    #[error("page {page} tag {tag}: record too short ({got} < {need})")]
    RecordTooShort { page: u32, tag: usize, got: usize, need: usize },

    #[error("page {page}: tag array overflows page boundary")]
    TagArrayOverflow { page: u32 },

    #[error("table not found: {name}")]
    TableNotFound { name: String },

    #[error("page {page}: {detail}")]
    Corrupt { page: u32, detail: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
```

### `srum-parser::SrumError` — wraps EseError, adds SRUM context

```rust
#[derive(Debug, thiserror::Error)]
pub enum SrumError {
    #[error("ese: {0}")]
    Ese(#[from] EseError),

    #[error("page {page} tag {tag}: {detail}")]
    DecodeError { page: u32, tag: usize, detail: String },
}
```

### `sr-cli` error surface

```
error: page 42 tag 3: record too short (14 < 32)
```
via `anyhow` chain from `SrumError` / `EseError`.

---

## 5. DRY Extraction

### `srum-core` gains

```rust
pub const FILETIME_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;
pub const NETWORK_RECORD_SIZE: usize = 32;
pub const APP_RECORD_SIZE: usize = 32;
pub const ID_MAP_MIN_SIZE: usize = 6;
pub fn filetime_to_datetime(filetime: u64) -> DateTime<Utc>;
```

`network.rs` and `app_usage.rs` import from `srum-core` — no local copies of the constant or the function.

### `ese-carver` loses `parse_tags`

`parse_tags` is deleted. `detect_fragments` calls `db.read_page(n)?.tags()` — the abstraction that already exists in `ese-core`.

### `ese-core` exports `PAGE_SIZE`

```rust
pub const PAGE_SIZE: usize = 4096;
```

`ese-test-fixtures` re-exports it. No fixture file ever declares `const PAGE_SIZE`.

---

## 6. TDD & Regression Protection

### Execution order (bottom-up dependency graph)

| Step | Crate | Key change |
|------|-------|-----------|
| 1 | `ese-test-fixtures` | New crate; `PageBuilder`, `EseFileBuilder` |
| 2 | `ese-core` | `TableCursor`, structured `EseError`, export `PAGE_SIZE`; remove `open_database` |
| 3 | `ese-integrity` | Consume new `ese-core` API; swap fixtures to `ese-test-fixtures` |
| 4 | `ese-carver` | Delete `parse_tags`; consume `ese-core` API; swap fixtures |
| 5 | `srum-core` | Add `FILETIME_EPOCH_OFFSET`, `filetime_to_datetime`, record size constants |
| 6 | `srum-parser` | `collect_table` helper; import from `srum-core`; swap fixtures |
| 7 | `sr-cli` | Consume `SrumError`; structured error output |

### Two-commit protocol per step

1. `test(red): <crate> — <description>` — new tests that fail (compile error counts as RED)
2. `feat: GREEN — <crate> <description>` — minimal implementation; all prior crates still green

### Regression gate

After every GREEN commit: `cargo test --workspace` must pass. Hard stop if anything regresses — fix forward before continuing.

### Safe API migration pattern

New API added alongside old → tests import new path (RED) → implementation lands → old API removed in same GREEN commit once all call sites updated. No commit introduces a broken intermediate state.
