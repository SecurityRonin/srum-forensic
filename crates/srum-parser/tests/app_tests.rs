//! Integration tests for srum-app-parsing story.
//!
//! Tests [`srum_parser::parse_app_usage`].

mod fixtures;

use fixtures::{encode_app_record, make_srudb_with_app_records, FILETIME_UNIX_EPOCH};
use srum_parser::parse_app_usage;

#[test]
fn parse_app_returns_two_records() {
    let raw = vec![
        encode_app_record(FILETIME_UNIX_EPOCH, 1, 0, 1_000_000, 500_000),
        encode_app_record(FILETIME_UNIX_EPOCH, 2, 0, 2_000_000, 0),
    ];
    let tmp = make_srudb_with_app_records(&raw);
    let records = parse_app_usage(tmp.path()).expect("parse ok");
    assert_eq!(records.len(), 2, "expected 2 app records");
}

#[test]
fn parse_app_cycles_match() {
    let raw = vec![encode_app_record(FILETIME_UNIX_EPOCH, 7, 0, 12345, 67890)];
    let tmp = make_srudb_with_app_records(&raw);
    let records = parse_app_usage(tmp.path()).expect("parse ok");
    assert_eq!(records[0].foreground_cycles, 12345);
    assert_eq!(records[0].background_cycles, 67890);
}

#[test]
fn parse_app_timestamp_known_filetime() {
    // 2024-06-15T08:00:00Z → Unix = 1718438400
    // FILETIME = unix_secs * 10_000_000 + FILETIME_EPOCH_OFFSET
    const FILETIME_2024_06_15: u64 = 1_718_438_400 * 10_000_000 + FILETIME_UNIX_EPOCH;
    let raw = vec![encode_app_record(FILETIME_2024_06_15, 1, 0, 0, 0)];
    let tmp = make_srudb_with_app_records(&raw);
    let records = parse_app_usage(tmp.path()).expect("parse ok");
    assert_eq!(records[0].timestamp.timestamp(), 1_718_438_400, "timestamp must decode to 2024-06-15T08:00:00Z");
}
