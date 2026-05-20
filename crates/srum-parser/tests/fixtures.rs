//! SRUDB.dat fixture builder for srum-parser integration tests.
#![allow(dead_code)]

use ese_core::{CatalogEntry, DB_STATE_CLEAN_SHUTDOWN};
use ese_test_fixtures::{make_raw_header_page, PageBuilder, PAGE_SIZE};
use std::io::Write as _;
use tempfile::NamedTempFile;

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
