//! Tests that parsers return Ok(vec![]) when the target SRUM table is absent
//! from the ESE catalog — the correct behaviour for Windows Server 2022 which
//! omits the battery-energy, network-usage, app-resource, and app-timeline
//! extensions entirely.
//!
//! All other SRUM implementations (srum-dump, SrumECmd) return empty results
//! for absent tables rather than propagating an error.

mod fixtures;

use fixtures::make_srudb_with_network_records;
use srum_parser::{parse_app_usage, parse_energy_lt, parse_energy_usage, parse_network_usage};

/// A synthetic SRUDB that contains ONLY a network table is used for all tests
/// because it lets us ask for tables that definitely do not exist.
///
/// `parse_app_usage` expects `TABLE_APP_RESOURCE_USAGE`, which is not present
/// in the network-only fixture → should return `Ok(vec![])`, not `Err`.
#[test]
fn absent_app_table_returns_empty_not_err() {
    let tmp = make_srudb_with_network_records(&[]);
    let result = parse_app_usage(tmp.path());
    assert!(
        result.is_ok(),
        "absent table must return Ok(vec![]), got Err: {result:?}"
    );
    assert!(
        result.unwrap().is_empty(),
        "absent table must return empty vec"
    );
}

#[test]
fn absent_energy_table_returns_empty_not_err() {
    let tmp = make_srudb_with_network_records(&[]);
    let result = parse_energy_usage(tmp.path());
    assert!(
        result.is_ok(),
        "absent table must return Ok(vec![]), got Err: {result:?}"
    );
    assert!(result.unwrap().is_empty());
}

#[test]
fn absent_energy_lt_table_returns_empty_not_err() {
    let tmp = make_srudb_with_network_records(&[]);
    let result = parse_energy_lt(tmp.path());
    assert!(
        result.is_ok(),
        "absent table must return Ok(vec![]), got Err: {result:?}"
    );
    assert!(result.unwrap().is_empty());
}

#[test]
fn absent_network_table_returns_empty_not_err() {
    // Fixture with app records only — the network GUID is absent.
    use fixtures::make_srudb_with_app_records;
    let tmp = make_srudb_with_app_records(&[]);
    let result = parse_network_usage(tmp.path());
    assert!(
        result.is_ok(),
        "absent table must return Ok(vec![]), got Err: {result:?}"
    );
    assert!(result.unwrap().is_empty());
}
