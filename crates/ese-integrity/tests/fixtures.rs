//! Synthetic ESE fixture builder for ese-integrity integration tests.
#![allow(dead_code)] // shared helpers; each test file uses a subset

use std::io::Write as _;
use tempfile::NamedTempFile;

pub const PAGE_SIZE: usize = 4096;

fn put_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

fn put_u16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

/// Write a tag into the page tag array (grows from page end downward).
fn write_tag(page: &mut [u8], tag_idx: usize, value_offset: u16, value_size: u16) {
    let raw: u32 = (u32::from(value_offset) & 0x7FFF) | ((u32::from(value_size) & 0x7FFF) << 16);
    let pos = PAGE_SIZE - (tag_idx + 1) * 4;
    page[pos..pos + 4].copy_from_slice(&raw.to_le_bytes());
}

fn write_ese_file(pages: &[Vec<u8>]) -> NamedTempFile {
    let mut tmp = NamedTempFile::new().expect("tempfile");
    for p in pages {
        tmp.write_all(p).expect("write page");
    }
    tmp
}

/// Build a minimal ESE header page with the given `db_state` and `db_time`.
fn make_header_page(db_time: u64, db_state: u32) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    put_u32(&mut page, 4, 0x89AB_CDEF);                       // ESE magic
    put_u64(&mut page, 0x10, db_time);                         // db_time
    put_u32(&mut page, 0x28, db_state);                        // db_state
    put_u32(&mut page, 236, u32::try_from(PAGE_SIZE).unwrap()); // page_size
    page
}

/// Build a data page with a given `db_time` field at page offset `0x08`.
///
/// Contains one trivial 4-byte record with tag 1.
fn make_data_page_with_db_time(page_db_time: u32) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    // page db_time at offset 0x08 (low 32 bits)
    put_u32(&mut page, 0x08, page_db_time);
    // page flags = LEAF
    put_u32(&mut page, 0x20, ese_core::PAGE_FLAG_LEAF);
    // prev/next = sentinel
    put_u32(&mut page, 0x0C, 0xFFFF_FFFF);
    put_u32(&mut page, 0x10, 0xFFFF_FFFF);
    // 2 tags: tag0 (page header) + tag1 (one record)
    put_u16(&mut page, 0x1E, 2);
    write_tag(&mut page, 0, 0, 40);
    // one trivial 4-byte record at offset 40
    put_u32(&mut page, 40, 0xDEAD_BEEF);
    write_tag(&mut page, 1, 40, 4);
    page
}

/// Build a data page with zero records (only page header tag) and non-zero
/// bytes written into the slack region at a known location.
fn make_data_page_with_slack(slack_bytes: &[u8]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    put_u32(&mut page, 0x20, ese_core::PAGE_FLAG_LEAF);
    put_u32(&mut page, 0x0C, 0xFFFF_FFFF);
    put_u32(&mut page, 0x10, 0xFFFF_FFFF);
    // tag0 only (page header) — tag_count = 1, record data ends at offset 40
    put_u16(&mut page, 0x1E, 1);
    write_tag(&mut page, 0, 0, 40);
    // Slack region: between offset 40 (end of header record) and tag array.
    // Tag array starts at: PAGE_SIZE - 1*4 = 4092 (only tag0).
    // Write slack_bytes starting at offset 40.
    let slack_start = 40usize;
    let len = slack_bytes.len().min(PAGE_SIZE - slack_start - 4);
    page[slack_start..slack_start + len].copy_from_slice(&slack_bytes[..len]);
    page
}

/// Build a data page with a record that exactly fills the available space
/// (no slack). Uses `tag_count=2` with the record ending right before the
/// tag array.
fn make_tight_data_page() -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    put_u32(&mut page, 0x20, ese_core::PAGE_FLAG_LEAF);
    put_u32(&mut page, 0x0C, 0xFFFF_FFFF);
    put_u32(&mut page, 0x10, 0xFFFF_FFFF);
    // 2 tags: tag0 (header) + tag1 (record that fills to tag boundary)
    // Tag array: 2 tags × 4 bytes = 8 bytes at page end → starts at 4088
    // Record: starts at 40, ends at 4088 → size = 4048
    put_u16(&mut page, 0x1E, 2);
    write_tag(&mut page, 0, 0, 40);
    write_tag(&mut page, 1, 40, 4048);
    // No slack bytes — the record data runs right up to the tag array
    page
}

/// Build a complete ESE file with a given `db_state` (header page only).
pub fn make_ese_with_db_state(db_state: u32) -> NamedTempFile {
    write_ese_file(&[make_header_page(0, db_state)])
}

/// Build a complete ESE file with `header_db_time` set in the file header and
/// `page_db_time` written into page 1's `db_time` field.
pub fn make_ese_with_page_db_time(header_db_time: u64, page_db_time: u32) -> NamedTempFile {
    write_ese_file(&[
        make_header_page(header_db_time, 3), // db_state=CleanShutdown
        make_data_page_with_db_time(page_db_time),
    ])
}

/// Build an ESE file with a page that has a tight record (no slack space).
pub fn make_ese_with_tight_records() -> NamedTempFile {
    write_ese_file(&[
        make_header_page(0, 3),
        make_tight_data_page(),
    ])
}

/// Build an ESE file where page 1 contains non-zero bytes in its slack region.
pub fn make_ese_with_slack_bytes(slack: &[u8]) -> NamedTempFile {
    write_ese_file(&[
        make_header_page(0, 3),
        make_data_page_with_slack(slack),
    ])
}
