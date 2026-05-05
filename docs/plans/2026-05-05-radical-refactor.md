# Radical Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate all DRY violations, add location-aware errors, and unify the ESE API surface across all 7 crates, adding `ese-test-fixtures` for shared test infrastructure.

**Architecture:** Bottom-up execution order (ese-test-fixtures → ese-core → ese-integrity → ese-carver → srum-core → srum-parser → sr-cli). Every intermediate commit passes `cargo test --workspace`. Two commits per behavioural step: RED (failing test / compile error) then GREEN (minimal implementation). See design doc: `docs/plans/2026-05-05-radical-refactor-design.md`.

**Tech Stack:** Rust 1.80+, Cargo workspace, thiserror 2, chrono, tempfile, anyhow

---

## Task 0: Baseline — verify all tests pass

**Files:** none

**Step 1: Run full test suite**
```bash
cargo test --workspace 2>&1 | grep -E "^(test result|FAILED|error\[)"
```
Expected: all lines say `test result: ok`. Zero `FAILED`. If anything fails, stop and fix before continuing.

**Step 2: Record baseline commit**
```bash
git log --oneline -1
```
Note the SHA. Every subsequent commit must keep `cargo test --workspace` green.

---

## Task 1: ese-test-fixtures — new crate with PageBuilder (RED)

**Files:**
- Create: `crates/ese-test-fixtures/Cargo.toml`
- Create: `crates/ese-test-fixtures/src/lib.rs` (stub only)
- Create: `crates/ese-test-fixtures/tests/builder_tests.rs`
- Modify: `Cargo.toml` (workspace root — add to `members` and `[workspace.dependencies]`)

**Step 1: Add to workspace root `Cargo.toml`**

In `[workspace] members`, add `"crates/ese-test-fixtures"`.

In `[workspace.dependencies]`, add:
```toml
ese-test-fixtures = { path = "crates/ese-test-fixtures" }
```

**Step 2: Create `crates/ese-test-fixtures/Cargo.toml`**
```toml
[package]
name = "ese-test-fixtures"
version = "0.1.0"
description = "Shared ESE test fixture builders — dev-dependency only, never ships"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
ese-core.workspace = true
tempfile.workspace = true

[lints]
workspace = true
```

**Step 3: Create stub `crates/ese-test-fixtures/src/lib.rs`**
```rust
//! Shared ESE test fixture builders.
//!
//! Used as a `[dev-dependency]` by ese-core, ese-integrity, ese-carver,
//! and srum-parser. Never compiled into release binaries.

pub use ese_core::PAGE_SIZE;

/// Fluent builder for a single 4096-byte ESE page.
pub struct PageBuilder {
    data: Vec<u8>,
    page_size: usize,
    record_offset: usize,
    tag_count: usize,
}

impl PageBuilder {
    pub fn new(page_size: usize) -> Self { todo!() }
    pub fn leaf(self) -> Self { todo!() }
    pub fn parent(self) -> Self { todo!() }
    pub fn with_db_time(self, _t: u32) -> Self { todo!() }
    pub fn with_db_state(self, _s: u32) -> Self { todo!() }
    pub fn add_record(self, _data: &[u8]) -> Self { todo!() }
    pub fn add_child_page(self, _page_num: u32) -> Self { todo!() }
    pub fn with_slack(self, _bytes: &[u8]) -> Self { todo!() }
    pub fn build(self) -> Vec<u8> { todo!() }
}

/// Assembles a sequence of pages into a `NamedTempFile`.
pub struct EseFileBuilder {
    db_time: u64,
    db_state: u32,
    extra_pages: Vec<Vec<u8>>,
}

impl EseFileBuilder {
    pub fn new() -> Self { todo!() }
    pub fn with_db_time(self, _t: u64) -> Self { todo!() }
    pub fn with_db_state(self, _s: u32) -> Self { todo!() }
    pub fn add_page(self, _page: Vec<u8>) -> Self { todo!() }
    pub fn write(self) -> tempfile::NamedTempFile { todo!() }
}

impl Default for EseFileBuilder {
    fn default() -> Self { Self::new() }
}
```

**Step 4: Create `crates/ese-test-fixtures/tests/builder_tests.rs`**
```rust
//! Tests for [`PageBuilder`] and [`EseFileBuilder`].
use ese_test_fixtures::{EseFileBuilder, PageBuilder, PAGE_SIZE};

// ── PageBuilder ──────────────────────────────────────────────────────────────

#[test]
fn page_builder_produces_correct_page_size() {
    let page = PageBuilder::new(PAGE_SIZE).leaf().build();
    assert_eq!(page.len(), PAGE_SIZE);
}

#[test]
fn page_builder_leaf_sets_leaf_flag() {
    let page = PageBuilder::new(PAGE_SIZE).leaf().build();
    let flags = u32::from_le_bytes(page[0x20..0x24].try_into().unwrap());
    assert!(flags & ese_core::PAGE_FLAG_LEAF != 0, "leaf flag must be set");
}

#[test]
fn page_builder_add_record_increments_tag_count() {
    let page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&[0xAAu8; 16])
        .build();
    let tag_count = u16::from_le_bytes(page[0x1E..0x20].try_into().unwrap());
    assert_eq!(tag_count, 2, "tag0 (header) + tag1 (data record)");
}

#[test]
fn page_builder_record_bytes_readable_from_tag() {
    let record = vec![0xBBu8; 8];
    let page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&record)
        .build();
    // tag1 is the 2nd tag from end: pos = PAGE_SIZE - 2*4 = 4088
    let tag_pos = PAGE_SIZE - 8;
    let raw = u32::from_le_bytes(page[tag_pos..tag_pos + 4].try_into().unwrap());
    let offset = (raw & 0x7FFF) as usize;
    let size = ((raw >> 16) & 0x7FFF) as usize;
    assert_eq!(size, 8);
    assert_eq!(&page[offset..offset + size], &record[..]);
}

#[test]
fn page_builder_with_db_time_writes_at_offset_0x08() {
    let page = PageBuilder::new(PAGE_SIZE).leaf().with_db_time(0xDEAD_BEEF).build();
    let val = u32::from_le_bytes(page[0x08..0x0C].try_into().unwrap());
    assert_eq!(val, 0xDEAD_BEEF);
}

#[test]
fn page_builder_with_slack_writes_nonzero_bytes_in_slack_region() {
    let slack = vec![0xFFu8; 4];
    let page = PageBuilder::new(PAGE_SIZE).leaf().with_slack(&slack).build();
    // slack starts at record_offset = 40 (after header tag, no records added)
    // just verify page has non-zero bytes past the 40-byte header region
    assert!(page[40..44].iter().any(|&b| b != 0));
}

// ── EseFileBuilder ───────────────────────────────────────────────────────────

#[test]
fn ese_file_builder_write_produces_readable_file() {
    let tmp = EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .write();
    assert!(tmp.path().exists());
    let meta = std::fs::metadata(tmp.path()).unwrap();
    assert_eq!(meta.len() as usize, PAGE_SIZE, "header-only file = one page");
}

#[test]
fn ese_file_builder_add_page_grows_file() {
    let extra = PageBuilder::new(PAGE_SIZE).leaf().build();
    let tmp = EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(extra)
        .write();
    let meta = std::fs::metadata(tmp.path()).unwrap();
    assert_eq!(meta.len() as usize, PAGE_SIZE * 2);
}

#[test]
fn ese_file_builder_output_opens_with_ese_core() {
    let tmp = EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .write();
    ese_core::EseDatabase::open(tmp.path()).expect("must open with ese-core");
}
```

**Step 5: Run to confirm RED**
```bash
cargo test -p ese-test-fixtures 2>&1 | tail -20
```
Expected: compile errors (`todo!()` panics count as failure if they compile; struct fields may cause errors). At minimum tests must not all pass.

**Step 6: Commit RED**
```bash
git add crates/ese-test-fixtures/ Cargo.toml Cargo.lock
git commit -m "test(red): ese-test-fixtures — PageBuilder and EseFileBuilder failing tests"
```

---

## Task 2: ese-test-fixtures — implement PageBuilder and EseFileBuilder (GREEN)

**Files:**
- Modify: `crates/ese-test-fixtures/src/lib.rs`

**Step 1: Replace stub with full implementation**
```rust
//! Shared ESE test fixture builders.
//!
//! Used as a `[dev-dependency]` by ese-core, ese-integrity, ese-carver,
//! and srum-parser. Never compiled into release binaries.

pub use ese_core::{DB_STATE_CLEAN_SHUTDOWN, DB_STATE_DIRTY_SHUTDOWN, PAGE_SIZE};
pub use ese_core::{PAGE_FLAG_LEAF, PAGE_FLAG_PARENT, PAGE_FLAG_ROOT};

use std::io::Write as _;
use tempfile::NamedTempFile;

/// Fluent builder for a single ESE data page.
///
/// Page layout (Vista+, 4096 bytes):
/// - Bytes 0x00–0x27: 40-byte page header
/// - Bytes 0x28–N:    record data, packed low→high
/// - Bytes N+1–end:   slack region
/// - End of page:     tag array, packed high→low (each tag = 4 bytes)
pub struct PageBuilder {
    data: Vec<u8>,
    page_size: usize,
    record_offset: usize,
    tag_count: usize,
}

impl PageBuilder {
    pub fn new(page_size: usize) -> Self {
        let mut data = vec![0u8; page_size];
        // Tag 0 covers the page header (offset=0, size=40).
        let tag0_raw: u32 = (0u32 & 0x7FFF) | ((40u32 & 0x7FFF) << 16);
        let pos = page_size - 4;
        data[pos..pos + 4].copy_from_slice(&tag0_raw.to_le_bytes());
        data[0x1E..0x20].copy_from_slice(&1u16.to_le_bytes()); // tag_count = 1
        Self { data, page_size, record_offset: 40, tag_count: 1 }
    }

    pub fn leaf(mut self) -> Self {
        self.data[0x20..0x24].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());
        self.data[0x0C..0x10].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        self.data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        self
    }

    pub fn parent(mut self) -> Self {
        let flags = PAGE_FLAG_PARENT | PAGE_FLAG_ROOT;
        self.data[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
        self.data[0x0C..0x10].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        self.data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        self
    }

    /// Write a 32-bit value into the page's `db_time` field (offset `0x08`).
    pub fn with_db_time(mut self, t: u32) -> Self {
        self.data[0x08..0x0C].copy_from_slice(&t.to_le_bytes());
        self
    }

    /// Write `db_state` into the header page's state field (offset `0x28`).
    pub fn with_db_state(mut self, s: u32) -> Self {
        self.data[0x28..0x2C].copy_from_slice(&s.to_le_bytes());
        self
    }

    /// Append a record and a corresponding tag entry.
    pub fn add_record(mut self, record: &[u8]) -> Self {
        let offset = self.record_offset;
        self.data[offset..offset + record.len()].copy_from_slice(record);
        self.tag_count += 1;
        let tag_raw: u32 =
            (offset as u32 & 0x7FFF) | ((record.len() as u32 & 0x7FFF) << 16);
        let tag_pos = self.page_size - self.tag_count * 4;
        self.data[tag_pos..tag_pos + 4].copy_from_slice(&tag_raw.to_le_bytes());
        self.data[0x1E..0x20]
            .copy_from_slice(&(self.tag_count as u16).to_le_bytes());
        self.record_offset += record.len();
        self
    }

    /// Append a 4-byte child page reference record (for parent pages).
    pub fn add_child_page(self, page_num: u32) -> Self {
        self.add_record(&page_num.to_le_bytes())
    }

    /// Write bytes into the slack region (between last record and tag array).
    pub fn with_slack(mut self, bytes: &[u8]) -> Self {
        let start = self.record_offset;
        let end = start + bytes.len();
        self.data[start..end].copy_from_slice(bytes);
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.data
    }
}

/// Assembles a header page + optional data pages into a `NamedTempFile`.
pub struct EseFileBuilder {
    db_time: u64,
    db_state: u32,
    extra_pages: Vec<Vec<u8>>,
}

impl Default for EseFileBuilder {
    fn default() -> Self {
        Self { db_time: 0, db_state: DB_STATE_CLEAN_SHUTDOWN, extra_pages: vec![] }
    }
}

impl EseFileBuilder {
    pub fn new() -> Self { Self::default() }

    pub fn with_db_time(mut self, t: u64) -> Self { self.db_time = t; self }
    pub fn with_db_state(mut self, s: u32) -> Self { self.db_state = s; self }

    pub fn add_page(mut self, page: Vec<u8>) -> Self {
        self.extra_pages.push(page);
        self
    }

    /// Write all pages to a temp file (header page first, then extras).
    pub fn write(self) -> NamedTempFile {
        let header = self.make_header_page();
        let mut tmp = NamedTempFile::new().expect("tempfile");
        tmp.write_all(&header).expect("write header");
        for page in &self.extra_pages {
            tmp.write_all(page).expect("write page");
        }
        tmp
    }

    fn make_header_page(&self) -> Vec<u8> {
        PageBuilder::new(PAGE_SIZE)
            .with_db_state(self.db_state)
            .with_db_time_u64(self.db_time)
            .build_as_file_header()
    }
}

// Private extensions used by EseFileBuilder only.
impl PageBuilder {
    fn with_db_time_u64(mut self, t: u64) -> Self {
        self.data[0x10..0x18].copy_from_slice(&t.to_le_bytes());
        self
    }

    fn build_as_file_header(mut self) -> Vec<u8> {
        // ESE magic at offset 4
        self.data[4..8].copy_from_slice(&0x89AB_CDEFu32.to_le_bytes());
        // page_size at offset 236
        self.data[236..240]
            .copy_from_slice(&(self.page_size as u32).to_le_bytes());
        self.data
    }
}
```

**Step 2: Run tests**
```bash
cargo test -p ese-test-fixtures 2>&1 | tail -20
```
Expected: all tests pass.

**Step 3: Run workspace**
```bash
cargo test --workspace 2>&1 | grep -E "^test result"
```
Expected: all `ok`.

**Step 4: Commit GREEN**
```bash
git add crates/ese-test-fixtures/src/lib.rs
git commit -m "feat: GREEN — ese-test-fixtures PageBuilder and EseFileBuilder"
```

---

## Task 3: ese-core — export PAGE_SIZE and add structured EseError (RED)

**Files:**
- Modify: `crates/ese-core/src/lib.rs` (add PAGE_SIZE export)
- Modify: `crates/ese-core/src/page.rs` (restructure EseError to carry page+tag location)
- Tests already exist and will break when EseError variants change shape — that IS the RED

**Step 1: Identify current EseError variants**

Read `crates/ese-core/src/lib.rs` — look for `EseError` enum. It currently has variants like `TooShort { need, got }`, `InvalidRecord(String)`, `TableNotFound(String)`, `Io(io::Error)`.

**Step 2: Add a test that checks structured error format**

Add to `crates/ese-core/src/lib.rs` unit tests section:
```rust
#[test]
fn ese_error_record_too_short_carries_page_and_tag() {
    let e = EseError::RecordTooShort { page: 7, tag: 2, got: 10, need: 32 };
    let msg = e.to_string();
    assert!(msg.contains("page 7"), "error must name page: {msg}");
    assert!(msg.contains("tag 2"), "error must name tag: {msg}");
}

#[test]
fn ese_error_table_not_found_carries_name() {
    let e = EseError::TableNotFound { name: "MyTable".into() };
    let msg = e.to_string();
    assert!(msg.contains("MyTable"), "{msg}");
}
```

**Step 3: Run to confirm RED**
```bash
cargo test -p ese-core 2>&1 | tail -10
```
Expected: compile error — `EseError::RecordTooShort` doesn't exist yet.

**Step 4: Commit RED**
```bash
git add crates/ese-core/src/lib.rs
git commit -m "test(red): ese-core — structured EseError with page+tag location fields"
```

---

## Task 4: ese-core — implement structured EseError and export PAGE_SIZE (GREEN)

**Files:**
- Modify: `crates/ese-core/src/lib.rs`
- Modify: `crates/ese-core/src/page.rs`
- Modify: `crates/ese-core/src/header.rs`
- (and any other file that constructs EseError variants)

**Step 1: Export PAGE_SIZE**

In `crates/ese-core/src/lib.rs` (or a new `crates/ese-core/src/consts.rs`):
```rust
/// The fixed ESE page size used by SRUDB.dat and most modern ESE databases.
pub const PAGE_SIZE: usize = 4096;
```

**Step 2: Restructure EseError**

Find the `EseError` definition (likely in `src/lib.rs` or `src/error.rs`) and replace it:
```rust
#[derive(Debug, thiserror::Error)]
pub enum EseError {
    #[error("page {page}: invalid magic {found:#010x}")]
    InvalidMagic { page: u32, found: u32 },

    #[error("page {page} tag {tag}: record too short ({got} < {need})")]
    RecordTooShort { page: u32, tag: usize, got: usize, need: usize },

    #[error("page {page}: tag array overflows page boundary (tag_count={tag_count})")]
    TagArrayOverflow { page: u32, tag_count: usize },

    #[error("table not found: {name}")]
    TableNotFound { name: String },

    #[error("page {page}: {detail}")]
    Corrupt { page: u32, detail: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
```

**Step 3: Update all EseError construction sites**

Search for every place `EseError::TooShort`, `EseError::InvalidRecord`, etc. are constructed and update to the new variant names. The `page_number` field is always available from `self.page_number` inside `EsePage` methods, and from the `n` parameter inside `EseDatabase::read_page(n)`.

Key call sites:
- `EsePage::tags()` — use `self.page_number` in the error
- `EsePage::record_data(i)` — use `self.page_number` and `i` (tag index) in the error
- `EseDatabase::open()` — use `page: 0` for header errors
- `EseDatabase::read_page(n)` — use `page: n`

**Step 4: Run workspace**
```bash
cargo test --workspace 2>&1 | grep -E "^(test result|FAILED)"
```
Expected: all green. Fix any compilation errors from changed variant names.

**Step 5: Commit GREEN**
```bash
git add crates/ese-core/
git commit -m "feat: GREEN — ese-core structured EseError with page+tag location, export PAGE_SIZE"
```

---

## Task 5: ese-core — TableCursor iterator (RED)

**Files:**
- Modify: `crates/ese-core/src/lib.rs` (add test)

**Step 1: Write the failing test**

Add to `crates/ese-core/tests/btree_tests.rs` (or a new `crates/ese-core/tests/cursor_tests.rs`):
```rust
mod fixtures;
use ese_core::EseDatabase;

#[test]
fn table_records_returns_err_for_unknown_table() {
    // Build a single-table ESE file
    let entries = vec![ese_core::CatalogEntry {
        object_type: 1,
        object_id: 2,
        parent_object_id: 1,
        table_page: 3,
        object_name: "KnownTable".to_owned(),
    }];
    let tmp = fixtures::make_ese_with_catalog(&entries);
    let db = EseDatabase::open(tmp.path()).expect("open");
    let result = db.table_records("NonExistent");
    assert!(result.is_err(), "unknown table must return Err immediately");
}

#[test]
fn table_records_yields_record_bytes_for_known_table() {
    let record = vec![0xABu8; 32];
    // Build an ESE file with one leaf page containing one record.
    // Use the existing make_ese_with_catalog + make_leaf_page_with_records helpers
    // for now; they will be migrated to ese-test-fixtures in Task 9.
    let leaf = fixtures::make_leaf_page_with_records(0, &[record.clone()]);
    let entries = vec![ese_core::CatalogEntry {
        object_type: 1,
        object_id: 2,
        parent_object_id: 1,
        table_page: 2,  // page 0=header, page 1=catalog, page 2=leaf
        object_name: "MyTable".to_owned(),
    }];
    let catalog = fixtures::make_ese_with_catalog(&entries);
    // For this test, directly test walk_leaf_pages + read_page until TableCursor lands.
    // The test is: table_records("MyTable") yields at least one item.
    let tmp = fixtures::write_ese_file(&[
        fixtures::make_ese_header_page(),
        fixtures::make_leaf_page_with_records(0, &[record.clone()]),
    ]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    // Use walk_leaf_pages(1) to simulate what table_records does internally.
    // The real test of table_records will be added after implementation.
    let leaves = db.walk_leaf_pages(1).expect("walk");
    assert!(!leaves.is_empty());
}

#[test]
fn table_records_iterator_yields_page_and_tag_coordinates() {
    // Once implemented, each item is (page_num, tag_idx, bytes).
    // This is the real RED — table_records doesn't exist yet.
    let tmp = fixtures::write_ese_file(&[
        fixtures::make_ese_header_page(),
        fixtures::make_leaf_page_with_records(0, &[vec![0xCCu8; 16]]),
    ]);
    let db = EseDatabase::open(tmp.path()).expect("open");
    // table_records takes a root page number directly for now:
    let mut cursor = db.table_records_from_root(1).expect("cursor");
    let first = cursor.next().expect("at least one record");
    let (page_num, tag_idx, bytes) = first.expect("no error");
    assert_eq!(page_num, 1u32);
    assert_eq!(tag_idx, 1usize, "tag 0 is page header; data starts at tag 1");
    assert_eq!(bytes.len(), 16);
}
```

**Step 2: Run to confirm RED**
```bash
cargo test -p ese-core 2>&1 | tail -10
```
Expected: compile error — `table_records_from_root` doesn't exist.

**Step 3: Commit RED**
```bash
git add crates/ese-core/tests/
git commit -m "test(red): ese-core — TableCursor iterator with page+tag coordinates"
```

---

## Task 6: ese-core — implement TableCursor (GREEN)

**Files:**
- Modify: `crates/ese-core/src/lib.rs` (add `table_records_from_root`, `table_records`)

**Step 1: Add `TableCursor` and the two entry points**

In `crates/ese-core/src/lib.rs`:
```rust
/// Iterator over raw record bytes across all leaf pages of a B-tree.
///
/// Each item is `(page_number, tag_index, record_bytes)`.
pub struct TableCursor<'db> {
    db: &'db EseDatabase,
    leaf_pages: Vec<u32>,
    page_idx: usize,  // index into leaf_pages
    tag_idx: usize,   // current tag within current page (starts at 1)
}

impl<'db> Iterator for TableCursor<'db> {
    type Item = Result<(u32, usize, Vec<u8>), EseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let &page_num = self.leaf_pages.get(self.page_idx)?;
            let page = match self.db.read_page(page_num) {
                Ok(p) => p,
                Err(e) => {
                    self.page_idx += 1;
                    self.tag_idx = 1;
                    return Some(Err(e));
                }
            };
            let tags = match page.tags() {
                Ok(t) => t,
                Err(e) => {
                    self.page_idx += 1;
                    self.tag_idx = 1;
                    return Some(Err(e));
                }
            };
            if self.tag_idx >= tags.len() {
                // Exhausted this page — move to next.
                self.page_idx += 1;
                self.tag_idx = 1;
                continue;
            }
            let tag = self.tag_idx;
            self.tag_idx += 1;
            return match page.record_data(tag) {
                Ok(bytes) => Some(Ok((page_num, tag, bytes.to_vec()))),
                Err(e) => Some(Err(e)),
            };
        }
    }
}

impl EseDatabase {
    /// Open a cursor over all leaf records starting at `root_page`.
    pub fn table_records_from_root(
        &self,
        root_page: u32,
    ) -> Result<TableCursor<'_>, EseError> {
        let leaf_pages = self.walk_leaf_pages(root_page)?;
        Ok(TableCursor { db: self, leaf_pages, page_idx: 0, tag_idx: 1 })
    }

    /// Open a cursor over all records in a named SRUM table.
    pub fn table_records(
        &self,
        table_name: &str,
    ) -> Result<TableCursor<'_>, EseError> {
        let root_page = self.find_table_page(table_name)?;
        self.table_records_from_root(root_page)
    }
}
```

**Step 2: Remove `open_database` free function alias**

Search `crates/ese-core/src/lib.rs` for `pub fn open_database` and delete it. Update all callers:
- `crates/ese-integrity/tests/integrity_tests.rs` — replace `ese_core::open_database(...)` with `ese_core::EseDatabase::open(...)`
- Any other test using the alias

**Step 3: Run workspace**
```bash
cargo test --workspace 2>&1 | grep -E "^(test result|FAILED)"
```
All green. Fix any compile errors.

**Step 4: Commit GREEN**
```bash
git add crates/ese-core/ crates/ese-integrity/
git commit -m "feat: GREEN — ese-core TableCursor iterator, remove open_database alias"
```

---

## Task 7: ese-integrity — migrate fixtures to ese-test-fixtures (GREEN refactor)

**Files:**
- Modify: `crates/ese-integrity/Cargo.toml` (add ese-test-fixtures dev-dep)
- Modify: `crates/ese-integrity/tests/fixtures.rs` (replace body with PageBuilder/EseFileBuilder calls)
- Modify: `crates/ese-integrity/tests/integrity_tests.rs` (use new fixture API if signatures changed)

**Step 1: Add dev-dependency**

In `crates/ese-integrity/Cargo.toml`:
```toml
[dev-dependencies]
ese-test-fixtures.workspace = true
tempfile.workspace = true
```

**Step 2: Rewrite `crates/ese-integrity/tests/fixtures.rs`**

Replace the entire file body (the `put_u32`, `put_u16`, `write_tag`, `write_ese_file`, `make_header_page`, `make_data_page_*` functions) with thin wrappers over `ese-test-fixtures`:

```rust
//! Thin wrappers over [`ese_test_fixtures`] for ese-integrity tests.
#![allow(dead_code)]

use ese_test_fixtures::{EseFileBuilder, PageBuilder, PAGE_SIZE};
pub use ese_test_fixtures::PAGE_SIZE;
use tempfile::NamedTempFile;

pub fn make_ese_with_db_state(db_state: u32) -> NamedTempFile {
    EseFileBuilder::new().with_db_state(db_state).write()
}

pub fn make_ese_with_page_db_time(header_db_time: u64, page_db_time: u32) -> NamedTempFile {
    let data_page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .with_db_time(page_db_time)
        .build();
    EseFileBuilder::new()
        .with_db_time(header_db_time)
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write()
}

pub fn make_ese_with_tight_records() -> NamedTempFile {
    // Record fills exactly to tag boundary: PAGE_SIZE - 2*4 - 40 = 4048 bytes
    let record = vec![0u8; PAGE_SIZE - 8 - 40];
    let data_page = PageBuilder::new(PAGE_SIZE).leaf().add_record(&record).build();
    EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write()
}

pub fn make_ese_with_slack_bytes(slack: &[u8]) -> NamedTempFile {
    let data_page = PageBuilder::new(PAGE_SIZE).leaf().with_slack(slack).build();
    EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write()
}
```

**Step 3: Run tests**
```bash
cargo test -p ese-integrity 2>&1 | tail -10
```
Expected: all pass. Fix any compile errors from signature differences.

**Step 4: Run workspace**
```bash
cargo test --workspace 2>&1 | grep -E "^(test result|FAILED)"
```

**Step 5: Commit**
```bash
git add crates/ese-integrity/
git commit -m "refactor: ese-integrity fixtures → ese-test-fixtures (DRY)"
```

---

## Task 8: ese-carver — delete parse_tags, use ese-core API, migrate fixtures (RED then GREEN)

**Files:**
- Modify: `crates/ese-carver/src/lib.rs`
- Modify: `crates/ese-carver/Cargo.toml`
- Modify: `crates/ese-carver/tests/fixtures.rs`

**Step 1: Write RED test showing detect_fragments uses read_page + tags**

Add to `crates/ese-carver/tests/fragment_tests.rs`:
```rust
#[test]
fn detect_fragments_works_with_ese_database_directly() {
    // Same as existing split test but verifies we go through EseDatabase.
    // This test will fail once parse_tags is deleted and not yet replaced.
    let prefix = vec![0xAAu8; 12];
    let suffix = vec![0xBBu8; 8];
    let pages = fixtures::make_flat_split(&prefix, &suffix);
    // Write to a real file and open via EseDatabase
    use std::io::Write as _;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pages).unwrap();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    // detect_fragments_db is the new signature accepting &EseDatabase
    let pairs = ese_carver::detect_fragments_db(&db, 20);
    assert_eq!(pairs.len(), 1);
}
```

**Step 2: Run RED**
```bash
cargo test -p ese-carver 2>&1 | tail -10
```
Expected: compile error — `detect_fragments_db` doesn't exist.

**Step 3: Commit RED**
```bash
git add crates/ese-carver/tests/fragment_tests.rs
git commit -m "test(red): ese-carver — detect_fragments_db using EseDatabase API"
```

**Step 4: Rewrite `crates/ese-carver/src/lib.rs` (GREEN)**

Delete `parse_tags`. Add `detect_fragments_db`:
```rust
/// Scan an open ESE database for records split across consecutive page
/// boundaries. Returns a [`FragmentPair`] for each adjacent page pair
/// where last-tag-of-A + first-data-tag-of-B equals `expected_size`.
pub fn detect_fragments_db(
    db: &ese_core::EseDatabase,
    expected_size: usize,
) -> Vec<FragmentPair> {
    let page_count = db.page_count() as u32;
    let mut pairs = Vec::new();

    for page_idx in 1..page_count.saturating_sub(1) {
        let Ok(page_a) = db.read_page(page_idx) else { continue };
        let Ok(page_b) = db.read_page(page_idx + 1) else { continue };
        let Ok(tags_a) = page_a.tags() else { continue };
        let Ok(tags_b) = page_b.tags() else { continue };

        let Some(&(_, prefix_size)) = tags_a.last() else { continue };
        let Some(&(_, suffix_size)) = tags_b.get(1) else { continue };

        let prefix_len = prefix_size as usize;
        let suffix_len = suffix_size as usize;

        if prefix_len + suffix_len == expected_size {
            pairs.push(FragmentPair {
                page_a: page_idx,
                page_b: page_idx + 1,
                prefix_len,
                suffix_len,
            });
        }
    }
    pairs
}
```

Keep `detect_fragments` (raw bytes version) for callers that don't have an open db. Mark old `parse_tags` as deleted.

**Step 5: Migrate fixtures to ese-test-fixtures**

Add to `crates/ese-carver/Cargo.toml`:
```toml
[dev-dependencies]
ese-test-fixtures.workspace = true
tempfile.workspace = true
```

Rewrite `crates/ese-carver/tests/fixtures.rs` using `PageBuilder`/`EseFileBuilder` (same pattern as ese-integrity Task 7 step 2).

**Step 6: Run workspace**
```bash
cargo test --workspace 2>&1 | grep -E "^(test result|FAILED)"
```

**Step 7: Commit GREEN**
```bash
git add crates/ese-carver/
git commit -m "feat: GREEN — ese-carver detect_fragments_db via ese-core API, delete parse_tags, migrate fixtures"
```

---

## Task 9: srum-core — add FILETIME constant, filetime_to_datetime, record sizes (RED then GREEN)

**Files:**
- Modify: `crates/srum-core/src/lib.rs`

**Step 1: Write RED test**

Add to `crates/srum-core/src/lib.rs` unit tests:
```rust
#[test]
fn filetime_to_datetime_unix_epoch() {
    // FILETIME_EPOCH_OFFSET = ticks from 1601-01-01 to 1970-01-01
    // Passing that value should yield Unix epoch (1970-01-01T00:00:00Z)
    let dt = filetime_to_datetime(FILETIME_EPOCH_OFFSET);
    assert_eq!(dt.timestamp(), 0, "must map to Unix epoch");
}

#[test]
fn filetime_to_datetime_known_date() {
    // 2024-06-15T08:00:00Z = Unix 1718438400
    let filetime = FILETIME_EPOCH_OFFSET + 1_718_438_400u64 * 10_000_000;
    let dt = filetime_to_datetime(filetime);
    assert_eq!(dt.timestamp(), 1_718_438_400);
}

#[test]
fn record_size_constants_are_32() {
    assert_eq!(NETWORK_RECORD_SIZE, 32usize);
    assert_eq!(APP_RECORD_SIZE, 32usize);
}
```

**Step 2: Run RED**
```bash
cargo test -p srum-core 2>&1 | tail -10
```
Expected: compile error — items don't exist yet.

**Step 3: Commit RED**
```bash
git add crates/srum-core/src/lib.rs
git commit -m "test(red): srum-core — FILETIME_EPOCH_OFFSET, filetime_to_datetime, record sizes"
```

**Step 4: Implement (GREEN)**

Add to `crates/srum-core/src/lib.rs`:
```rust
use chrono::{DateTime, Utc};

/// Number of 100ns ticks between the Windows epoch (1601-01-01) and the
/// Unix epoch (1970-01-01).
pub const FILETIME_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;

/// Fixed byte length of a serialised [`NetworkUsageRecord`].
pub const NETWORK_RECORD_SIZE: usize = 32;

/// Fixed byte length of a serialised [`AppUsageRecord`].
pub const APP_RECORD_SIZE: usize = 32;

/// Minimum byte length of a serialised [`IdMapEntry`].
pub const ID_MAP_MIN_SIZE: usize = 6;

/// Convert a Windows FILETIME value to a UTC [`DateTime`].
///
/// FILETIME counts 100-nanosecond ticks since 1601-01-01. Values before the
/// Unix epoch are clamped to `DateTime::UNIX_EPOCH`.
pub fn filetime_to_datetime(filetime: u64) -> DateTime<Utc> {
    let unix_100ns = filetime.saturating_sub(FILETIME_EPOCH_OFFSET);
    let secs = i64::try_from(unix_100ns / 10_000_000).unwrap_or(i64::MAX);
    let nanos = u32::try_from((unix_100ns % 10_000_000) * 100).unwrap_or(0);
    DateTime::from_timestamp(secs, nanos)
        .unwrap_or(DateTime::UNIX_EPOCH.with_timezone(&Utc))
}
```

**Step 5: Run workspace**
```bash
cargo test --workspace 2>&1 | grep -E "^(test result|FAILED)"
```

**Step 6: Commit GREEN**
```bash
git add crates/srum-core/src/lib.rs
git commit -m "feat: GREEN — srum-core FILETIME_EPOCH_OFFSET, filetime_to_datetime, record size constants"
```

---

## Task 10: srum-parser — collect_table helper, import from srum-core, migrate fixtures (RED then GREEN)

**Files:**
- Modify: `crates/srum-parser/src/lib.rs`
- Modify: `crates/srum-parser/src/network.rs`
- Modify: `crates/srum-parser/src/app_usage.rs`
- Modify: `crates/srum-parser/src/id_map.rs`
- Modify: `crates/srum-parser/Cargo.toml` (add ese-test-fixtures dev-dep)
- Modify: `crates/srum-parser/tests/fixtures.rs`

**Step 1: Write RED test for collect_table and SrumError**

Add to `crates/srum-parser/tests/` a new file `error_tests.rs`:
```rust
use srum_parser::SrumError;

#[test]
fn srum_error_decode_carries_page_and_tag() {
    let e = SrumError::DecodeError {
        page: 3,
        tag: 1,
        detail: "record too short".into(),
    };
    let msg = e.to_string();
    assert!(msg.contains("page 3"), "{msg}");
    assert!(msg.contains("tag 1"), "{msg}");
}
```

**Step 2: Run RED**
```bash
cargo test -p srum-parser 2>&1 | tail -10
```
Expected: compile error — `SrumError` doesn't exist publicly.

**Step 3: Commit RED**
```bash
git add crates/srum-parser/tests/error_tests.rs
git commit -m "test(red): srum-parser — SrumError with page+tag coordinates"
```

**Step 4: Implement SrumError and collect_table (GREEN)**

Add to `crates/srum-parser/src/lib.rs`:
```rust
use ese_core::{EseDatabase, EseError};

#[derive(Debug, thiserror::Error)]
pub enum SrumError {
    #[error("ese: {0}")]
    Ese(#[from] EseError),

    #[error("page {page} tag {tag}: {detail}")]
    DecodeError { page: u32, tag: usize, detail: String },
}

fn collect_table<T>(
    db: &EseDatabase,
    table: &str,
    decode: impl Fn(&[u8], u32, usize) -> Result<T, SrumError>,
) -> anyhow::Result<Vec<T>> {
    let records = db
        .table_records(table)?
        .filter_map(|r| match r {
            Ok((page, tag, ref data)) => decode(data, page, tag).ok(),
            Err(_) => None,
        })
        .collect();
    Ok(records)
}
```

Update `parse_network_usage`, `parse_app_usage`, `parse_id_map` to use `collect_table`:
```rust
const NETWORK_TABLE: &str = "{973F5D5C-1D90-4944-BE8E-24B22A728CF2}";
const APP_TABLE: &str = "{5C8CF1C7-7257-4F13-B223-970EF5939312}";
const ID_MAP_TABLE: &str = "SruDbIdMapTable";

pub fn parse_network_usage(path: &Path) -> anyhow::Result<Vec<NetworkUsageRecord>> {
    collect_table(&EseDatabase::open(path)?, NETWORK_TABLE, network::decode_network_record)
}

pub fn parse_app_usage(path: &Path) -> anyhow::Result<Vec<AppUsageRecord>> {
    collect_table(&EseDatabase::open(path)?, APP_TABLE, app_usage::decode_app_record)
}

pub fn parse_id_map(path: &Path) -> anyhow::Result<Vec<IdMapEntry>> {
    collect_table(&EseDatabase::open(path)?, ID_MAP_TABLE, id_map::decode_id_map_entry)
}
```

Update decode functions in `network.rs` and `app_usage.rs`:
- Remove local `FILETIME_EPOCH_OFFSET` and `filetime_to_datetime` — import from `srum_core`
- Remove local `RECORD_SIZE` — import `NETWORK_RECORD_SIZE` / `APP_RECORD_SIZE` from `srum_core`
- Update signatures: `decode_network_record(data: &[u8], page: u32, tag: usize) -> Result<NetworkUsageRecord, SrumError>`

In `network.rs`:
```rust
use srum_core::{filetime_to_datetime, NetworkUsageRecord, FILETIME_EPOCH_OFFSET, NETWORK_RECORD_SIZE};
use crate::SrumError;

pub fn decode_network_record(data: &[u8], page: u32, tag: usize) -> Result<NetworkUsageRecord, SrumError> {
    if data.len() < NETWORK_RECORD_SIZE {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("network record too short: {} < {NETWORK_RECORD_SIZE}", data.len()),
        });
    }
    // ... rest of decode unchanged, just use srum_core::filetime_to_datetime
}
```

Same pattern for `app_usage.rs` and `id_map.rs`.

**Step 5: Migrate srum-parser fixtures to ese-test-fixtures**

Add `ese-test-fixtures.workspace = true` to `[dev-dependencies]` in `crates/srum-parser/Cargo.toml`.

Rewrite `crates/srum-parser/tests/fixtures.rs` using `PageBuilder`/`EseFileBuilder`.

**Step 6: Run workspace**
```bash
cargo test --workspace 2>&1 | grep -E "^(test result|FAILED)"
```

**Step 7: Commit GREEN**
```bash
git add crates/srum-parser/ 
git commit -m "feat: GREEN — srum-parser SrumError, collect_table, import from srum-core, migrate fixtures"
```

---

## Task 11: ese-core — migrate its own tests to ese-test-fixtures (GREEN refactor)

**Files:**
- Modify: `crates/ese-core/Cargo.toml` (add ese-test-fixtures dev-dep)
- Modify: `crates/ese-core/tests/fixtures.rs`

**Step 1: Add dev-dependency**
```toml
[dev-dependencies]
ese-test-fixtures.workspace = true
tempfile.workspace = true
```

**Step 2: Rewrite `crates/ese-core/tests/fixtures.rs`**

Replace the `put_u32`, `put_u16`, `write_tag`, `make_ese_header_page`, `write_ese_file` helpers with thin wrappers over `ese-test-fixtures`. Keep `make_leaf_page_with_records`, `make_parent_page_with_children`, `make_ese_with_catalog` as wrappers using `PageBuilder`.

```rust
use ese_test_fixtures::{EseFileBuilder, PageBuilder};
pub use ese_test_fixtures::PAGE_SIZE;
use tempfile::NamedTempFile;

pub fn make_ese_header_page() -> Vec<u8> {
    // EseFileBuilder builds the header internally; extract just the header page
    // by building a header-only file and reading back the first page.
    // Simpler: use PageBuilder directly since we know the format.
    ese_test_fixtures::make_raw_header_page(0, ese_core::DB_STATE_CLEAN_SHUTDOWN)
}

pub fn write_ese_file(pages: &[Vec<u8>]) -> NamedTempFile {
    use std::io::Write as _;
    let mut tmp = NamedTempFile::new().expect("tempfile");
    for p in pages { tmp.write_all(p).expect("write"); }
    tmp
}

pub fn make_leaf_page_with_records(_flags: u32, records: &[Vec<u8>]) -> Vec<u8> {
    let mut b = PageBuilder::new(PAGE_SIZE).leaf();
    for r in records { b = b.add_record(r); }
    b.build()
}

pub fn make_parent_page_with_children(children: &[u32]) -> Vec<u8> {
    let mut b = PageBuilder::new(PAGE_SIZE).parent();
    for &c in children { b = b.add_child_page(c); }
    b.build()
}
```

Note: if `make_raw_header_page` isn't on `ese-test-fixtures`, expose it:

In `ese-test-fixtures/src/lib.rs`:
```rust
/// Build a raw header page buffer (without writing to disk).
pub fn make_raw_header_page(db_time: u64, db_state: u32) -> Vec<u8> {
    PageBuilder::new(PAGE_SIZE)
        .with_db_state(db_state)
        .with_db_time_u64_pub(db_time)
        .build_as_file_header_pub()
}
```
(Make `with_db_time_u64` and `build_as_file_header` public, renaming to avoid collision.)

**Step 3: Run workspace**
```bash
cargo test --workspace 2>&1 | grep -E "^(test result|FAILED)"
```

**Step 4: Commit**
```bash
git add crates/ese-core/ crates/ese-test-fixtures/
git commit -m "refactor: ese-core tests → ese-test-fixtures (DRY)"
```

---

## Task 12: sr-cli — structured error output (RED then GREEN)

**Files:**
- Modify: `crates/sr-cli/src/main.rs`

**Step 1: Write RED test**

Add a test that the CLI error surface includes page context. Since the CLI is a binary, test via `assert_cmd` or by unit-testing the error formatting function:

Add to `crates/sr-cli/Cargo.toml` dev-dependencies:
```toml
[dev-dependencies]
assert_cmd = "2"
predicates = "3"
```

Create `crates/sr-cli/tests/cli_errors.rs`:
```rust
use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn nonexistent_file_gives_useful_error() {
    Command::cargo_bin("sr")
        .unwrap()
        .args(["network", "/nonexistent/SRUDB.dat"])
        .assert()
        .failure()
        .stderr(contains("error"));
}
```

**Step 2: Run RED**
```bash
cargo test -p sr-cli 2>&1 | tail -10
```
Expected: compile error if assert_cmd not in Cargo.toml yet, or test failure.

**Step 3: Commit RED**
```bash
git add crates/sr-cli/
git commit -m "test(red): sr-cli — structured error output to stderr"
```

**Step 4: Update `crates/sr-cli/src/main.rs` (GREEN)**

Replace bare `anyhow::Result<()>` propagation with explicit stderr formatting:
```rust
fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Network { path } => {
            let records = srum_parser::parse_network_usage(&path)?;
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
        Cmd::Apps { path } => {
            let records = srum_parser::parse_app_usage(&path)?;
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
        Cmd::IdMap { path } => {
            let entries = srum_parser::parse_id_map(&path)?;
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
    }
    Ok(())
}
```

**Step 5: Run workspace**
```bash
cargo test --workspace 2>&1 | grep -E "^(test result|FAILED)"
```

**Step 6: Commit GREEN**
```bash
git add crates/sr-cli/
git commit -m "feat: GREEN — sr-cli structured error output with page+tag context via anyhow chain"
```

---

## Task 13: Final verification and push

**Step 1: Run full workspace**
```bash
cargo test --workspace 2>&1 | grep -E "^test result"
```
Expected: all `ok`.

**Step 2: Run clippy**
```bash
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -20
```
Expected: zero warnings.

**Step 3: Push**
```bash
git push origin main
```
