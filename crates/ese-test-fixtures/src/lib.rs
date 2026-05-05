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
/// Layout (Vista+, 4096 bytes):
/// - `0x00–0x27`: 40-byte page header
/// - `0x28–N`:    record data packed low→high
/// - `N+1–end`:   slack region
/// - end of page: tag array packed high→low (4 bytes per tag)
pub struct PageBuilder {
    data: Vec<u8>,
    page_size: usize,
    record_offset: usize,
    tag_count: usize,
}

impl PageBuilder {
    pub fn new(page_size: usize) -> Self {
        let mut data = vec![0u8; page_size];
        // Tag 0 covers the 40-byte page header: offset=0, size=40.
        let tag0_raw: u32 = (0u32 & 0x7FFF) | ((40u32 & 0x7FFF) << 16);
        let pos = page_size - 4;
        data[pos..pos + 4].copy_from_slice(&tag0_raw.to_le_bytes());
        data[0x1E..0x20].copy_from_slice(&1u16.to_le_bytes());
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

    /// Write a 32-bit value into the page `db_time` field at offset `0x08`.
    pub fn with_db_time(mut self, t: u32) -> Self {
        self.data[0x08..0x0C].copy_from_slice(&t.to_le_bytes());
        self
    }

    /// Write `db_state` into the state field at offset `0x28`.
    pub fn with_db_state(mut self, s: u32) -> Self {
        self.data[0x28..0x2C].copy_from_slice(&s.to_le_bytes());
        self
    }

    /// Append a record and its tag entry.
    pub fn add_record(mut self, record: &[u8]) -> Self {
        let offset = self.record_offset;
        self.data[offset..offset + record.len()].copy_from_slice(record);
        self.tag_count += 1;
        let tag_raw: u32 =
            (offset as u32 & 0x7FFF) | ((record.len() as u32 & 0x7FFF) << 16);
        let tag_pos = self.page_size - self.tag_count * 4;
        self.data[tag_pos..tag_pos + 4].copy_from_slice(&tag_raw.to_le_bytes());
        self.data[0x1E..0x20].copy_from_slice(&(self.tag_count as u16).to_le_bytes());
        self.record_offset += record.len();
        self
    }

    /// Append a 4-byte child page reference (for parent pages).
    pub fn add_child_page(self, page_num: u32) -> Self {
        self.add_record(&page_num.to_le_bytes())
    }

    /// Write bytes into the slack region (between last record and tag array).
    pub fn with_slack(mut self, bytes: &[u8]) -> Self {
        let start = self.record_offset;
        self.data[start..start + bytes.len()].copy_from_slice(bytes);
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.data
    }

    /// Build a 64-bit db_time at offset `0x10` (file header only).
    pub fn with_header_db_time(mut self, t: u64) -> Self {
        self.data[0x10..0x18].copy_from_slice(&t.to_le_bytes());
        self
    }

    /// Finalize as an ESE file header page (adds magic + page_size fields).
    pub fn into_file_header(mut self) -> Vec<u8> {
        self.data[4..8].copy_from_slice(&0x89AB_CDEFu32.to_le_bytes());
        self.data[236..240].copy_from_slice(&(self.page_size as u32).to_le_bytes());
        self.data
    }
}

/// Build a raw ESE file-header page buffer (page 0).
pub fn make_raw_header_page(db_time: u64, db_state: u32) -> Vec<u8> {
    PageBuilder::new(PAGE_SIZE)
        .with_db_state(db_state)
        .with_header_db_time(db_time)
        .into_file_header()
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

    pub fn write(self) -> NamedTempFile {
        let header = make_raw_header_page(self.db_time, self.db_state);
        let mut tmp = NamedTempFile::new().expect("tempfile");
        tmp.write_all(&header).expect("write header");
        for page in &self.extra_pages {
            tmp.write_all(page).expect("write page");
        }
        tmp
    }
}
