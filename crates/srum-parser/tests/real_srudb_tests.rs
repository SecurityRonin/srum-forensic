//! Integration tests against real, third-party SRUDB.dat files.
//!
//! These tests exist specifically to catch parser bugs that our synthetic
//! fixtures cannot detect: synthetic fixtures are built by us using the same
//! assumptions as our parser (doer-checker violation). Real files produced
//! independently by Windows are the only ground truth.
//!
//! Files live in `tests/data/srudb/`. Tests skip gracefully if the files are
//! absent (CI must download them first; see `tests/data/srudb/SOURCES.md`).
//!
//! Sources:
//!   - chainsaw_SRUDB.dat — WithSecure Labs / Chainsaw test suite (Apache-2.0)
//!   - plaso_SRUDB.dat   — log2timeline / Plaso regression test   (Apache-2.0)

use std::path::Path;

use ese_core::EseDatabase;
use forensicnomicon::srum::{
    TABLE_APP_RESOURCE_USAGE, TABLE_ENERGY_USAGE, TABLE_ID_MAP, TABLE_NETWORK_CONNECTIVITY,
    TABLE_NETWORK_USAGE, TABLE_PUSH_NOTIFICATIONS,
};
use srum_parser::{parse_app_usage, parse_id_map, parse_network_usage};

// ── fixture paths ─────────────────────────────────────────────────────────────

const CHAINSAW: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/data/srudb/chainsaw_SRUDB.dat");

const PLASO: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/data/srudb/plaso_SRUDB.dat");

/// Return the path only if the file exists, otherwise print a skip message and
/// return `None`. Tests call `let Some(p) = fixture(X) else { return; }`.
fn fixture(path: &'static str) -> Option<&'static Path> {
    let p = Path::new(path);
    if p.exists() {
        Some(p)
    } else {
        eprintln!("SKIP — test fixture not present: {path}");
        eprintln!("       Run: curl -fsSL -o {path} <url>  (see tests/data/srudb/SOURCES.md)");
        None
    }
}

// ── ESE open ─────────────────────────────────────────────────────────────────

#[test]
fn chainsaw_srudb_opens_without_error() {
    let Some(p) = fixture(CHAINSAW) else { return };
    EseDatabase::open(p).expect("EseDatabase::open must succeed on chainsaw SRUDB.dat");
}

#[test]
fn plaso_srudb_opens_without_error() {
    let Some(p) = fixture(PLASO) else { return };
    EseDatabase::open(p).expect("EseDatabase::open must succeed on plaso SRUDB.dat");
}

// ── page count sanity ─────────────────────────────────────────────────────────

#[test]
fn chainsaw_srudb_has_expected_page_count() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let db = EseDatabase::open(p).expect("open");
    // 1,835,008 bytes / 4096 bytes per page = 448 pages
    assert_eq!(db.page_count(), 448, "chainsaw SRUDB.dat must have 448 pages");
}

#[test]
fn plaso_srudb_has_expected_page_count() {
    let Some(p) = fixture(PLASO) else { return };
    let db = EseDatabase::open(p).expect("open");
    // 7,864,320 bytes / 4096 bytes per page = 1920 pages
    assert_eq!(db.page_count(), 1920, "plaso SRUDB.dat must have 1920 pages");
}

// ── catalog entries ───────────────────────────────────────────────────────────

/// The catalog must contain the core SRUM extension GUIDs present on
/// every Windows 8.1+ machine.
fn assert_catalog_has_core_srum_tables(db: &EseDatabase, label: &str) {
    let entries = db
        .catalog_entries()
        .unwrap_or_else(|e| panic!("{label}: catalog_entries() failed: {e}"));
    let names: Vec<&str> = entries.iter().map(|e| e.object_name.as_str()).collect();

    for guid in [
        TABLE_NETWORK_USAGE,
        TABLE_APP_RESOURCE_USAGE,
        TABLE_NETWORK_CONNECTIVITY,
        TABLE_ENERGY_USAGE,
        TABLE_PUSH_NOTIFICATIONS,
        TABLE_ID_MAP,
    ] {
        assert!(
            names.contains(&guid),
            "{label}: catalog missing expected SRUM table: {guid}"
        );
    }
}

#[test]
fn chainsaw_srudb_catalog_has_core_srum_tables() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let db = EseDatabase::open(p).expect("open");
    assert_catalog_has_core_srum_tables(&db, "chainsaw");
}

#[test]
fn plaso_srudb_catalog_has_core_srum_tables() {
    let Some(p) = fixture(PLASO) else { return };
    let db = EseDatabase::open(p).expect("open");
    assert_catalog_has_core_srum_tables(&db, "plaso");
}

// ── network usage parsing ─────────────────────────────────────────────────────

#[test]
fn chainsaw_srudb_network_usage_parses_without_panic() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let records = parse_network_usage(p).expect("parse_network_usage must not error");
    assert!(
        !records.is_empty(),
        "chainsaw SRUDB.dat must contain at least one network usage record"
    );
}

#[test]
fn plaso_srudb_network_usage_parses_without_panic() {
    let Some(p) = fixture(PLASO) else { return };
    let records = parse_network_usage(p).expect("parse_network_usage must not error");
    assert!(
        !records.is_empty(),
        "plaso SRUDB.dat must contain at least one network usage record"
    );
}

#[test]
fn chainsaw_srudb_network_records_have_plausible_fields() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let records = parse_network_usage(p).expect("parse ok");
    // Every record must have a non-zero AutoIncId.
    assert!(
        records.iter().all(|r| r.auto_inc_id != 0),
        "all network records must have non-zero AutoIncId"
    );
    // At least one record should have non-zero byte counts.
    let has_traffic = records.iter().any(|r| r.bytes_sent > 0 || r.bytes_recv > 0);
    assert!(has_traffic, "at least one network record must have non-zero byte counts");
}

// ── app resource usage parsing ────────────────────────────────────────────────

#[test]
fn chainsaw_srudb_app_usage_parses_without_panic() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let records = parse_app_usage(p).expect("parse_app_usage must not error");
    assert!(
        !records.is_empty(),
        "chainsaw SRUDB.dat must contain at least one app resource usage record"
    );
}

#[test]
fn plaso_srudb_app_usage_parses_without_panic() {
    let Some(p) = fixture(PLASO) else { return };
    let records = parse_app_usage(p).expect("parse_app_usage must not error");
    assert!(
        !records.is_empty(),
        "plaso SRUDB.dat must contain at least one app resource usage record"
    );
}

// ── id map parsing ────────────────────────────────────────────────────────────

#[test]
fn chainsaw_srudb_id_map_parses_without_panic() {
    let Some(p) = fixture(CHAINSAW) else { return };
    // plaso noted an edge case: some SRUDB.dat files are missing IdBlob values.
    // We must not panic — either Ok(records) or Err is acceptable.
    let result = parse_id_map(p);
    assert!(result.is_ok(), "parse_id_map must not return Err on chainsaw SRUDB.dat: {result:?}");
}

#[test]
fn plaso_srudb_id_map_edge_case_no_panic() {
    let Some(p) = fixture(PLASO) else { return };
    // plaso issue #2134: IdBlob value missing from SruDbIdMapTable.
    // Our parser must handle this without panicking (Ok with partial results is fine).
    let result = parse_id_map(p);
    // We don't assert Ok here — the file is known to have malformed IdBlob entries.
    // The key requirement is no panic (no unwrap/expect in the parser itself).
    drop(result);
}

// ── integrity checks on real data ─────────────────────────────────────────────

#[test]
fn chainsaw_srudb_autoinc_ids_are_positive() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let records = parse_network_usage(p).expect("parse ok");
    assert!(
        records.iter().all(|r| r.auto_inc_id > 0),
        "all AutoIncId values must be positive (1-based)"
    );
}

#[test]
fn chainsaw_srudb_timestamps_are_after_windows8_launch() {
    let Some(p) = fixture(CHAINSAW) else { return };
    // SRUM was introduced in Windows 8.1 (Oct 2013). Any timestamp before that
    // indicates a parsing bug — we're decoding the field with the wrong offset or type.
    let windows81_launch = chrono::DateTime::parse_from_rfc3339("2013-10-17T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let records = parse_network_usage(p).expect("parse ok");
    for r in &records {
        assert!(
            r.timestamp >= windows81_launch,
            "timestamp {} predates Windows 8.1 launch — likely a parse offset bug",
            r.timestamp
        );
    }
}

// ── diagnostic: dump catalog to understand structure ─────────────────────────

#[test]
fn diag_dump_chainsaw_catalog() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let db = EseDatabase::open(p).expect("open");
    eprintln!("page_count={}", db.page_count());
    match db.catalog_entries() {
        Ok(entries) => {
            eprintln!("catalog_entries: {} total", entries.len());
            for e in entries.iter().take(30) {
                eprintln!("  type={} id={} parent={} tpage={} name={:?}",
                    e.object_type, e.object_id, e.parent_object_id, e.table_page, e.object_name);
            }
        }
        Err(e) => eprintln!("catalog_entries ERROR: {e}"),
    }
    // Always pass — this is purely diagnostic
}
