//! Synthetic SRUDB.dat fixture builder for srum-parser integration tests.
#![allow(dead_code)]

use ese_core::{CatalogEntry, DB_STATE_CLEAN_SHUTDOWN};
use ese_test_fixtures::{make_raw_header_page, PageBuilder, PAGE_SIZE};
use std::io::Write as _;
use tempfile::NamedTempFile;

/// Windows FILETIME for Unix epoch (100ns ticks since 1601-01-01).
pub const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// Encode one [`NetworkUsageRecord`](srum_core::NetworkUsageRecord) as 32 raw bytes.
///
/// Binary layout (all little-endian):
/// - `[0..8]`:   `filetime` (u64)
/// - `[8..12]`:  `app_id` (i32)
/// - `[12..16]`: `user_id` (i32)
/// - `[16..24]`: `bytes_sent` (u64)
/// - `[24..32]`: `bytes_recv` (u64)
pub fn encode_network_record(
    filetime: u64,
    app_id: i32,
    user_id: i32,
    bytes_sent: u64,
    bytes_recv: u64,
) -> Vec<u8> {
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
/// - `[0..8]`:   `filetime` (u64)
/// - `[8..12]`:  `app_id` (i32)
/// - `[12..16]`: `user_id` (i32)
/// - `[16..24]`: `foreground_cycles` (u64)
/// - `[24..32]`: `background_cycles` (u64)
pub fn encode_app_record(
    filetime: u64,
    app_id: i32,
    user_id: i32,
    fg_cycles: u64,
    bg_cycles: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&filetime.to_le_bytes());
    out.extend_from_slice(&app_id.to_le_bytes());
    out.extend_from_slice(&user_id.to_le_bytes());
    out.extend_from_slice(&fg_cycles.to_le_bytes());
    out.extend_from_slice(&bg_cycles.to_le_bytes());
    out
}

/// Encode one [`IdMapEntry`](srum_core::IdMapEntry) as raw bytes.
///
/// Binary layout:
/// - `[0..4]`:  `id` (i32 LE)
/// - `[4..6]`:  `name_utf16le_byte_len` (u16 LE)
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

/// Build a synthetic SRUDB.dat with a named table pointing to a leaf page.
///
/// Layout:
/// - page 0: ESE file header
/// - pages 1–4: zero-padded (ESE reserves pages 1-4 for internal metadata)
/// - page 5: catalog with one entry for `table_name` → page 6  (matches CATALOG_ROOT=5)
/// - page 6: leaf page containing `raw_records`
fn make_srudb(table_name: &str, object_id: u32, raw_records: &[Vec<u8>]) -> NamedTempFile {
    let catalog_entry = CatalogEntry {
        object_type: 1,
        object_id,
        parent_object_id: 1,
        table_page: 6,
        object_name: table_name.to_owned(),
    };
    let catalog_bytes = catalog_entry.to_bytes();
    let catalog_page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&catalog_bytes)
        .build();

    let mut data_builder = PageBuilder::new(PAGE_SIZE).leaf();
    for rec in raw_records {
        data_builder = data_builder.add_record(rec);
    }
    let data_page = data_builder.build();

    let padding = vec![0u8; PAGE_SIZE];
    let header = make_raw_header_page(0, DB_STATE_CLEAN_SHUTDOWN);

    let mut tmp = NamedTempFile::new().expect("tempfile");
    tmp.write_all(&header).expect("write header");
    tmp.write_all(&padding).expect("write pad 1");
    tmp.write_all(&padding).expect("write pad 2");
    tmp.write_all(&padding).expect("write pad 3");
    tmp.write_all(&padding).expect("write pad 4");
    tmp.write_all(&catalog_page).expect("write catalog");
    tmp.write_all(&data_page).expect("write data");
    tmp
}

/// Build a synthetic SRUDB.dat with a `NetworkUsage` leaf page at page 6.
pub fn make_srudb_with_network_records(raw_records: &[Vec<u8>]) -> NamedTempFile {
    make_srudb("{973F5D5C-1D90-4944-BE8E-24B94231A174}", 10, raw_records)
}

/// Build a synthetic SRUDB.dat with an `AppUsage` leaf page at page 5.
pub fn make_srudb_with_app_records(raw_records: &[Vec<u8>]) -> NamedTempFile {
    make_srudb("{5C8CF1C7-7257-4F13-B223-970EF5939312}", 11, raw_records)
}

/// Build a synthetic SRUDB.dat with an `IdMap` leaf page at page 5.
pub fn make_srudb_with_id_map_records(raw_records: &[Vec<u8>]) -> NamedTempFile {
    make_srudb("SruDbIdMapTable", 12, raw_records)
}
