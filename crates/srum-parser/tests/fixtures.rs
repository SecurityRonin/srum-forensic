//! Synthetic SRUDB.dat fixture builder for srum-parser integration tests.
#![allow(dead_code)] // shared helpers; each test file uses a different subset
//!
//! Builds minimal valid ESE binary buffers representing a SRUDB.dat with
//! synthetic SRUM table data for parser testing.

use ese_core::{CatalogEntry, page::PAGE_FLAG_LEAF};
use std::io::Write as _;
use tempfile::NamedTempFile;

pub const PAGE_SIZE: usize = 4096;

fn put_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn put_u16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

fn write_tag(page: &mut [u8], tag_idx: usize, value_offset: u16, value_size: u16) {
    let raw: u32 = (u32::from(value_offset) & 0x7FFF) | ((u32::from(value_size) & 0x7FFF) << 16);
    let pos = PAGE_SIZE - (tag_idx + 1) * 4;
    page[pos..pos + 4].copy_from_slice(&raw.to_le_bytes());
}

fn make_header_page() -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    put_u32(&mut page, 4, 0x89AB_CDEF); // ESE magic
    put_u32(&mut page, 236, u32::try_from(PAGE_SIZE).unwrap()); // page_size
    page
}

fn make_leaf_page(records: &[Vec<u8>]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    let tag_count = u16::try_from(1 + records.len()).unwrap_or(u16::MAX);
    put_u16(&mut page, 0x1E, tag_count);
    put_u32(&mut page, 0x20, PAGE_FLAG_LEAF);
    put_u32(&mut page, 0x0C, 0xFFFF_FFFF);
    put_u32(&mut page, 0x10, 0xFFFF_FFFF);
    write_tag(&mut page, 0, 0, 40); // tag 0 = page header
    let mut cur: u16 = 40;
    for (i, rec) in records.iter().enumerate() {
        let size = u16::try_from(rec.len()).unwrap_or(u16::MAX);
        let start = usize::from(cur);
        page[start..start + rec.len()].copy_from_slice(rec);
        write_tag(&mut page, i + 1, cur, size);
        cur += size;
    }
    page
}

fn make_catalog_page(catalog_records: &[Vec<u8>]) -> Vec<u8> {
    make_leaf_page(catalog_records)
}

fn write_pages(pages: &[Vec<u8>]) -> NamedTempFile {
    let mut tmp = NamedTempFile::new().expect("tempfile");
    for p in pages {
        tmp.write_all(p).expect("write page");
    }
    tmp
}

/// Windows FILETIME → 100ns ticks since 1601-01-01 for Unix epoch.
pub const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// Encode one [`NetworkUsageRecord`](srum_core::NetworkUsageRecord) as 32 raw bytes.
///
/// Binary layout (all little-endian):
/// - `[0..8]`:   `filetime` (u64) — Windows FILETIME
/// - `[8..12]`:  `app_id` (i32)
/// - `[12..16]`: `user_id` (i32)
/// - `[16..24]`: `bytes_sent` (u64)
/// - `[24..32]`: `bytes_recv` (u64)
pub fn encode_network_record(filetime: u64, app_id: i32, user_id: i32, bytes_sent: u64, bytes_recv: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&filetime.to_le_bytes());
    out.extend_from_slice(&app_id.to_le_bytes());
    out.extend_from_slice(&user_id.to_le_bytes());
    out.extend_from_slice(&bytes_sent.to_le_bytes());
    out.extend_from_slice(&bytes_recv.to_le_bytes());
    out
}

/// Encode one [`AppUsageRecord`](srum_core::AppUsageRecord) as 32 raw bytes.
///
/// Binary layout (all little-endian):
/// - `[0..8]`:   `filetime` (u64) — Windows FILETIME
/// - `[8..12]`:  `app_id` (i32)
/// - `[12..16]`: `user_id` (i32)
/// - `[16..24]`: `foreground_cycles` (u64)
/// - `[24..32]`: `background_cycles` (u64)
pub fn encode_app_record(filetime: u64, app_id: i32, user_id: i32, fg_cycles: u64, bg_cycles: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&filetime.to_le_bytes());
    out.extend_from_slice(&app_id.to_le_bytes());
    out.extend_from_slice(&user_id.to_le_bytes());
    out.extend_from_slice(&fg_cycles.to_le_bytes());
    out.extend_from_slice(&bg_cycles.to_le_bytes());
    out
}

/// Encode one [`IdMapEntry`](srum_core::IdMapEntry).
///
/// Binary layout:
/// - `[0..4]`:  `id` (i32 LE)
/// - `[4..6]`:  `name_utf16le_byte_len` (u16 LE) — byte length of the UTF-16LE name
/// - `[6..]`:   `name` encoded as UTF-16LE bytes
pub fn encode_id_map_entry(id: i32, name: &str) -> Vec<u8> {
    let utf16: Vec<u16> = name.encode_utf16().collect();
    let name_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let byte_len = u16::try_from(name_bytes.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(6 + name_bytes.len());
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&byte_len.to_le_bytes());
    out.extend_from_slice(&name_bytes);
    out
}

/// Build a synthetic SRUDB.dat with a `NetworkUsage` leaf page at page 5.
///
/// Layout:
/// - page 0: ESE header
/// - pages 1-3: padding
/// - page 4: catalog (one entry: `{973F5D5C...}` → page 5)
/// - page 5: leaf page with the given raw network records
pub fn make_srudb_with_network_records(raw_records: &[Vec<u8>]) -> NamedTempFile {
    let catalog_entry = CatalogEntry {
        object_type: 1,
        object_id: 10,
        parent_object_id: 1,
        table_page: 5,
        object_name: "{973F5D5C-1D90-4944-BE8E-24B22A728CF2}".to_owned(),
    };
    let catalog_records = vec![catalog_entry.to_bytes()];
    let padding = vec![0u8; PAGE_SIZE];
    write_pages(&[
        make_header_page(),
        padding.clone(),
        padding.clone(),
        padding.clone(),
        make_catalog_page(&catalog_records),
        make_leaf_page(raw_records),
    ])
}

/// Build a synthetic SRUDB.dat with an `AppUsage` leaf page at page 5.
///
/// Layout mirrors [`make_srudb_with_network_records`] but uses the
/// `{5C8CF1C7...}` GUID for the `AppUsage` table.
pub fn make_srudb_with_app_records(raw_records: &[Vec<u8>]) -> NamedTempFile {
    let catalog_entry = CatalogEntry {
        object_type: 1,
        object_id: 11,
        parent_object_id: 1,
        table_page: 5,
        object_name: "{5C8CF1C7-7257-4F13-B223-970EF5939312}".to_owned(),
    };
    let catalog_records = vec![catalog_entry.to_bytes()];
    let padding = vec![0u8; PAGE_SIZE];
    write_pages(&[
        make_header_page(),
        padding.clone(),
        padding.clone(),
        padding.clone(),
        make_catalog_page(&catalog_records),
        make_leaf_page(raw_records),
    ])
}

/// Build a synthetic SRUDB.dat with an `IdMap` leaf page at page 5.
pub fn make_srudb_with_id_map_records(raw_records: &[Vec<u8>]) -> NamedTempFile {
    let catalog_entry = CatalogEntry {
        object_type: 1,
        object_id: 12,
        parent_object_id: 1,
        table_page: 5,
        object_name: "SruDbIdMapTable".to_owned(),
    };
    let catalog_records = vec![catalog_entry.to_bytes()];
    let padding = vec![0u8; PAGE_SIZE];
    write_pages(&[
        make_header_page(),
        padding.clone(),
        padding.clone(),
        padding.clone(),
        make_catalog_page(&catalog_records),
        make_leaf_page(raw_records),
    ])
}
