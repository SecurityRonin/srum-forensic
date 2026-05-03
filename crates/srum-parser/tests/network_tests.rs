//! Integration tests for srum-network-parsing story.
//!
//! Tests [`srum_parser::parse_network_usage`].

mod fixtures;

use fixtures::{encode_network_record, make_srudb_with_network_records, FILETIME_UNIX_EPOCH};
use srum_parser::parse_network_usage;

#[test]
fn parse_network_returns_three_records() {
    let raw = vec![
        encode_network_record(FILETIME_UNIX_EPOCH, 1, 0, 100, 200),
        encode_network_record(FILETIME_UNIX_EPOCH, 2, 0, 300, 400),
        encode_network_record(FILETIME_UNIX_EPOCH, 3, 0, 500, 600),
    ];
    let tmp = make_srudb_with_network_records(&raw);
    let records = parse_network_usage(tmp.path()).expect("parse ok");
    assert_eq!(records.len(), 3, "expected 3 network records");
}

#[test]
fn parse_network_bytes_sent_recv_match() {
    let raw = vec![encode_network_record(FILETIME_UNIX_EPOCH, 42, 7, 1111, 2222)];
    let tmp = make_srudb_with_network_records(&raw);
    let records = parse_network_usage(tmp.path()).expect("parse ok");
    assert_eq!(records[0].bytes_sent, 1111);
    assert_eq!(records[0].bytes_recv, 2222);
}

#[test]
fn parse_network_app_id_matches() {
    let raw = vec![encode_network_record(FILETIME_UNIX_EPOCH, 99, 0, 0, 0)];
    let tmp = make_srudb_with_network_records(&raw);
    let records = parse_network_usage(tmp.path()).expect("parse ok");
    assert_eq!(records[0].app_id, 99);
}

#[test]
fn parse_network_timestamp_at_unix_epoch() {
    let raw = vec![encode_network_record(FILETIME_UNIX_EPOCH, 1, 0, 0, 0)];
    let tmp = make_srudb_with_network_records(&raw);
    let records = parse_network_usage(tmp.path()).expect("parse ok");
    assert_eq!(records[0].timestamp.timestamp(), 0, "timestamp should be Unix epoch");
}

#[test]
fn parse_network_invalid_header_returns_err() {
    use std::io::Write as _;
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let mut page = vec![0u8; 4096];
    page[4..8].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes()); // wrong magic
    tmp.write_all(&page).expect("write");
    let result = parse_network_usage(tmp.path());
    assert!(result.is_err(), "invalid ESE header must return Err");
}
