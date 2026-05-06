//! Thin fixture wrappers over [`ese_test_fixtures`] for ese-integrity tests.
#![allow(dead_code)]

use ese_test_fixtures::{EseFileBuilder, PageBuilder, PAGE_SIZE};
use tempfile::NamedTempFile;

pub fn make_ese_with_db_state(db_state: u32) -> NamedTempFile {
    EseFileBuilder::new().with_db_state(db_state).write()
}

pub fn make_ese_with_page_db_time(header_db_time: u64, page_db_time: u32) -> NamedTempFile {
    let data_page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .with_db_time(page_db_time)
        .add_record(&0xDEAD_BEEFu32.to_le_bytes())
        .build();
    EseFileBuilder::new()
        .with_db_time(header_db_time)
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write()
}

pub fn make_ese_with_tight_records() -> NamedTempFile {
    // Record fills exactly to tag boundary: PAGE_SIZE - 2*4 (tag array) - 40 (header) = 4048 bytes
    let record = vec![0u8; PAGE_SIZE - 8 - 40];
    let data_page = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&record)
        .build();
    EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write()
}

pub fn make_ese_with_slack_bytes(slack: &[u8]) -> NamedTempFile {
    // Leaf page with only tag0 (page header) — slack region is everything after offset 40
    let data_page = PageBuilder::new(PAGE_SIZE).leaf().with_slack(slack).build();
    EseFileBuilder::new()
        .with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN)
        .add_page(data_page)
        .write()
}
