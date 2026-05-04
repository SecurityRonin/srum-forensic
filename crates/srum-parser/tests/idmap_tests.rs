//! Integration tests for srum-idmap story.
//!
//! Tests [`srum_parser::parse_id_map`].

mod fixtures;

use fixtures::{encode_id_map_entry, make_srudb_with_id_map_records};
use srum_parser::parse_id_map;

#[test]
fn parse_id_map_returns_two_entries() {
    let raw = vec![
        encode_id_map_entry(1, "svchost.exe"),
        encode_id_map_entry(2, "explorer.exe"),
    ];
    let tmp = make_srudb_with_id_map_records(&raw);
    let entries = parse_id_map(tmp.path()).expect("parse ok");
    assert_eq!(entries.len(), 2, "expected 2 IdMapEntry values");
}

#[test]
fn parse_id_map_id_and_name_match() {
    let raw = vec![encode_id_map_entry(42, "explorer.exe")];
    let tmp = make_srudb_with_id_map_records(&raw);
    let entries = parse_id_map(tmp.path()).expect("parse ok");
    assert_eq!(entries[0].id, 42);
    assert_eq!(entries[0].name, "explorer.exe");
}

#[test]
fn parse_id_map_utf16le_decodes_unicode() {
    // "héllo" contains a non-ASCII character (é = U+00E9)
    let raw = vec![encode_id_map_entry(99, "héllo")];
    let tmp = make_srudb_with_id_map_records(&raw);
    let entries = parse_id_map(tmp.path()).expect("parse ok");
    assert_eq!(entries[0].name, "héllo");
}
