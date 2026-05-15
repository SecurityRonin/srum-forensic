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
use srum_parser::{
    parse_app_timeline, parse_app_usage, parse_energy_lt, parse_energy_usage, parse_id_map,
    parse_network_connectivity, parse_network_usage, parse_push_notifications,
};

// ── fixture paths ─────────────────────────────────────────────────────────────

const CHAINSAW: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/data/srudb/chainsaw_SRUDB.dat");

const PLASO: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/data/srudb/plaso_SRUDB.dat");

const MUSEUM_RATHBUNVM_WIN10: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_rathbunvm_win10_SRUDB.dat"
);

const MUSEUM_RATHBUNVM_WIN11: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_rathbunvm_win11_SRUDB.dat"
);

const MUSEUM_BELKASOFTCTF_WIN10: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_belkasoftctf_win10_SRUDB.dat"
);

const MUSEUM_APTVM_SERVER2022_CLEAN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_aptvm_server2022_clean_SRUDB.dat"
);

const MUSEUM_APTVM_SERVER2022_1DAYLATER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_aptvm_server2022_1daylater_SRUDB.dat"
);

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

// ── catalog last-wins deduplication (rathbunvm files) ────────────────────────

/// Real SRUDB.dat files from rathbunvm VMs contain two MSysObjects catalog
/// entries with the same GUID name `{5C8CF1C7-...}`:
///   - first  (obj_id=12/15, page 48/64): empty placeholder page (tag_count=1)
///   - second (obj_id=13/17, page 64/80): actual data B-tree root (tag_count>>1)
///
/// `catalog_entries()` must use last-wins deduplication so `find_table_page`
/// resolves to the correct (second) entry, not the empty placeholder.
#[test]
fn rathbunvm_win10_app_usage_catalog_last_wins_deduplication() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN10) else { return };
    let db = EseDatabase::open(p).expect("open");
    let table_page = db
        .find_table_page("{5C8CF1C7-7257-4F13-B223-970EF5939312}")
        .expect("must find apps table");
    assert_ne!(
        table_page, 48,
        "find_table_page must not return the empty placeholder page 48; \
         catalog_entries() must use last-wins deduplication"
    );
}

#[test]
fn rathbunvm_win10_app_usage_count_matches_dissect() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN10) else { return };
    let records = parse_app_usage(p).expect("parse_app_usage must not error");
    assert!(
        records.len() >= 160,
        "rathbunvm win10 must have >= 160 app usage records (dissect: 163), got {}",
        records.len()
    );
}

#[test]
fn rathbunvm_win11_app_usage_count_matches_dissect() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN11) else { return };
    let records = parse_app_usage(p).expect("parse_app_usage must not error");
    assert!(
        records.len() >= 780,
        "rathbunvm win11 must have >= 780 app usage records (dissect: 791), got {}",
        records.len()
    );
}

// ── idmap decoder field accuracy ──────────────────────────────────────────────

#[test]
fn rathbunvm_win10_idmap_count_matches_dissect() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN10) else { return };
    let entries = parse_id_map(p).expect("parse_id_map must not error");
    assert!(
        entries.len() >= 280,
        "rathbunvm win10 must have >= 280 idmap entries (dissect: 288), got {}",
        entries.len()
    );
}

#[test]
fn rathbunvm_win10_idmap_string_entry_has_correct_id_and_name() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN10) else { return };
    let entries = parse_id_map(p).expect("parse ok");
    let entry3 = entries.iter().find(|e| e.id == 3);
    assert!(entry3.is_some(), "must have entry with id=3");
    assert!(
        entry3.unwrap().name.starts_with("!!"),
        "IdType=0 entry name must start with '!!' (SRUM blob format), got {:?}",
        entry3.unwrap().name
    );
}

// ── app timeline decoder field accuracy ──────────────────────────────────────

#[test]
fn rathbunvm_win10_app_timeline_count_matches_dissect() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN10) else { return };
    let records = parse_app_timeline(p).expect("parse ok");
    assert!(
        records.len() >= 4,
        "rathbunvm win10 must have >= 4 app timeline records (dissect: 4), got {}",
        records.len()
    );
}

#[test]
fn rathbunvm_win10_app_timeline_records_have_correct_app_id() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN10) else { return };
    let records = parse_app_timeline(p).expect("parse ok");
    assert!(!records.is_empty(), "must have at least one record");
    assert_eq!(
        records[0].app_id, 154,
        "first app_timeline record must have AppId=154, got {}",
        records[0].app_id
    );
}

#[test]
fn rathbunvm_win10_app_timeline_records_have_correct_user_id() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN10) else { return };
    let records = parse_app_timeline(p).expect("parse ok");
    assert!(!records.is_empty(), "must have at least one record");
    assert_eq!(
        records[0].user_id, 52,
        "first app_timeline record must have UserId=52, got {}",
        records[0].user_id
    );
}

// ── full-coverage smoke tests: all parsers × all fixtures ─────────────────────
//
// Ground truth from dissect.esedb 3.18 (ABSENT = table not in catalog):
//
// fixture              net  app  conn  energy  elt  push  timeline  idmap
// chainsaw             96   1660 6     0       0    562   26        714
// plaso                1840 2851 260   0       2    16183 ABSENT    5895
// rathbunvm_win10      23   163  1     ABSENT  ABST 118   4         288
// rathbunvm_win11      143  791  9     13      2    662   33        1044
// belkasoftctf_win10   465  4107 50    0       1    2087  101       476
// aptvm_server22_clean ABST ABST ABST  ABSENT  ABST ABST  ABSENT    2
// aptvm_server22_1day  ABST ABST 4     ABSENT  ABST 153   ABSENT    96
//
// All tests assert no-panic (Ok result). Tables marked ABSENT return Ok([]).
// Tables with 0 records in dissect may return Ok([]) from our parser too.

// ── chainsaw ──────────────────────────────────────────────────────────────────

#[test]
fn chainsaw_network_connectivity_parses_without_panic() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let r = parse_network_connectivity(p);
    assert!(r.is_ok(), "chainsaw: parse_network_connectivity failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "chainsaw: network_connectivity must be non-empty (dissect: 6)");
}

#[test]
fn chainsaw_energy_usage_parses_without_panic() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let r = parse_energy_usage(p);
    assert!(r.is_ok(), "chainsaw: parse_energy_usage failed: {:?}", r);
}

#[test]
fn chainsaw_energy_lt_parses_without_panic() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let r = parse_energy_lt(p);
    assert!(r.is_ok(), "chainsaw: parse_energy_lt failed: {:?}", r);
}

#[test]
fn chainsaw_push_notifications_parses_without_panic() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let r = parse_push_notifications(p);
    assert!(r.is_ok(), "chainsaw: parse_push_notifications failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "chainsaw: push_notifications must be non-empty (dissect: 562)");
}

#[test]
fn chainsaw_app_timeline_parses_without_panic() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let r = parse_app_timeline(p);
    assert!(r.is_ok(), "chainsaw: parse_app_timeline failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "chainsaw: app_timeline must be non-empty (dissect: 26)");
}

#[test]
fn chainsaw_id_map_parses_non_empty() {
    let Some(p) = fixture(CHAINSAW) else { return };
    let entries = parse_id_map(p).expect("chainsaw: parse_id_map must not error");
    assert!(
        entries.len() >= 700,
        "chainsaw: idmap must have >= 700 entries (dissect: 714), got {}",
        entries.len()
    );
}

// ── plaso ─────────────────────────────────────────────────────────────────────

#[test]
fn plaso_network_connectivity_parses_without_panic() {
    let Some(p) = fixture(PLASO) else { return };
    let r = parse_network_connectivity(p);
    assert!(r.is_ok(), "plaso: parse_network_connectivity failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "plaso: network_connectivity must be non-empty (dissect: 260)");
}

#[test]
fn plaso_energy_lt_parses_without_panic() {
    let Some(p) = fixture(PLASO) else { return };
    let r = parse_energy_lt(p);
    assert!(r.is_ok(), "plaso: parse_energy_lt failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "plaso: energy_lt must be non-empty (dissect: 2)");
}

#[test]
fn plaso_push_notifications_parses_without_panic() {
    let Some(p) = fixture(PLASO) else { return };
    let r = parse_push_notifications(p);
    assert!(r.is_ok(), "plaso: parse_push_notifications failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "plaso: push_notifications must be non-empty (dissect: 16183)");
}

#[test]
fn plaso_id_map_parses_non_empty() {
    let Some(p) = fixture(PLASO) else { return };
    let entries = parse_id_map(p).expect("plaso: parse_id_map must not error");
    assert!(
        entries.len() >= 5800,
        "plaso: idmap must have >= 5800 entries (dissect: 5895), got {}",
        entries.len()
    );
}

// ── rathbunvm_win11 ───────────────────────────────────────────────────────────

#[test]
fn rathbunvm_win11_network_usage_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN11) else { return };
    let r = parse_network_usage(p);
    assert!(r.is_ok(), "rathbunvm_win11: parse_network_usage failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "rathbunvm_win11: network_usage must be non-empty (dissect: 143)");
}

#[test]
fn rathbunvm_win11_network_connectivity_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN11) else { return };
    let r = parse_network_connectivity(p);
    assert!(r.is_ok(), "rathbunvm_win11: parse_network_connectivity failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "rathbunvm_win11: network_connectivity must be non-empty (dissect: 9)");
}

#[test]
fn rathbunvm_win11_energy_usage_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN11) else { return };
    let r = parse_energy_usage(p);
    assert!(r.is_ok(), "rathbunvm_win11: parse_energy_usage failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "rathbunvm_win11: energy_usage must be non-empty (dissect: 13)");
}

#[test]
fn rathbunvm_win11_energy_lt_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN11) else { return };
    let r = parse_energy_lt(p);
    assert!(r.is_ok(), "rathbunvm_win11: parse_energy_lt failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "rathbunvm_win11: energy_lt must be non-empty (dissect: 2)");
}

#[test]
fn rathbunvm_win11_push_notifications_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN11) else { return };
    let r = parse_push_notifications(p);
    assert!(r.is_ok(), "rathbunvm_win11: parse_push_notifications failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "rathbunvm_win11: push_notifications must be non-empty (dissect: 662)");
}

#[test]
fn rathbunvm_win11_app_timeline_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN11) else { return };
    let r = parse_app_timeline(p);
    assert!(r.is_ok(), "rathbunvm_win11: parse_app_timeline failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "rathbunvm_win11: app_timeline must be non-empty (dissect: 33)");
}

#[test]
fn rathbunvm_win11_id_map_parses_non_empty() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN11) else { return };
    let entries = parse_id_map(p).expect("rathbunvm_win11: parse_id_map must not error");
    assert!(
        entries.len() >= 1000,
        "rathbunvm_win11: idmap must have >= 1000 entries (dissect: 1044), got {}",
        entries.len()
    );
}

// ── rathbunvm_win10 (additional parsers not yet covered) ─────────────────────

#[test]
fn rathbunvm_win10_network_usage_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN10) else { return };
    let r = parse_network_usage(p);
    assert!(r.is_ok(), "rathbunvm_win10: parse_network_usage failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "rathbunvm_win10: network_usage must be non-empty (dissect: 23)");
}

#[test]
fn rathbunvm_win10_network_connectivity_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN10) else { return };
    let r = parse_network_connectivity(p);
    assert!(r.is_ok(), "rathbunvm_win10: parse_network_connectivity failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "rathbunvm_win10: network_connectivity must be non-empty (dissect: 1)");
}

#[test]
fn rathbunvm_win10_push_notifications_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_RATHBUNVM_WIN10) else { return };
    let r = parse_push_notifications(p);
    assert!(r.is_ok(), "rathbunvm_win10: parse_push_notifications failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "rathbunvm_win10: push_notifications must be non-empty (dissect: 118)");
}

// ── belkasoftctf_win10 ────────────────────────────────────────────────────────

#[test]
fn belkasoftctf_win10_opens_without_error() {
    let Some(p) = fixture(MUSEUM_BELKASOFTCTF_WIN10) else { return };
    EseDatabase::open(p).expect("belkasoftctf_win10: EseDatabase::open must succeed");
}

#[test]
fn belkasoftctf_win10_catalog_has_core_srum_tables() {
    let Some(p) = fixture(MUSEUM_BELKASOFTCTF_WIN10) else { return };
    let db = EseDatabase::open(p).expect("open");
    assert_catalog_has_core_srum_tables(&db, "belkasoftctf_win10");
}

#[test]
fn belkasoftctf_win10_network_usage_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_BELKASOFTCTF_WIN10) else { return };
    let r = parse_network_usage(p);
    assert!(r.is_ok(), "belkasoftctf_win10: parse_network_usage failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "belkasoftctf_win10: network_usage must be non-empty (dissect: 465)");
}

#[test]
fn belkasoftctf_win10_app_usage_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_BELKASOFTCTF_WIN10) else { return };
    let r = parse_app_usage(p);
    assert!(r.is_ok(), "belkasoftctf_win10: parse_app_usage failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "belkasoftctf_win10: app_usage must be non-empty (dissect: 4107)");
}

#[test]
fn belkasoftctf_win10_network_connectivity_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_BELKASOFTCTF_WIN10) else { return };
    let r = parse_network_connectivity(p);
    assert!(r.is_ok(), "belkasoftctf_win10: parse_network_connectivity failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "belkasoftctf_win10: network_connectivity must be non-empty (dissect: 50)");
}

#[test]
fn belkasoftctf_win10_energy_usage_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_BELKASOFTCTF_WIN10) else { return };
    let r = parse_energy_usage(p);
    assert!(r.is_ok(), "belkasoftctf_win10: parse_energy_usage failed: {:?}", r);
}

#[test]
fn belkasoftctf_win10_energy_lt_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_BELKASOFTCTF_WIN10) else { return };
    let r = parse_energy_lt(p);
    assert!(r.is_ok(), "belkasoftctf_win10: parse_energy_lt failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "belkasoftctf_win10: energy_lt must be non-empty (dissect: 1)");
}

#[test]
fn belkasoftctf_win10_push_notifications_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_BELKASOFTCTF_WIN10) else { return };
    let r = parse_push_notifications(p);
    assert!(r.is_ok(), "belkasoftctf_win10: parse_push_notifications failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "belkasoftctf_win10: push_notifications must be non-empty (dissect: 2087)");
}

#[test]
fn belkasoftctf_win10_app_timeline_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_BELKASOFTCTF_WIN10) else { return };
    let r = parse_app_timeline(p);
    assert!(r.is_ok(), "belkasoftctf_win10: parse_app_timeline failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "belkasoftctf_win10: app_timeline must be non-empty (dissect: 101)");
}

#[test]
fn belkasoftctf_win10_id_map_parses_non_empty() {
    let Some(p) = fixture(MUSEUM_BELKASOFTCTF_WIN10) else { return };
    let entries = parse_id_map(p).expect("belkasoftctf_win10: parse_id_map must not error");
    assert!(
        entries.len() >= 470,
        "belkasoftctf_win10: idmap must have >= 470 entries (dissect: 476), got {}",
        entries.len()
    );
}

// ── aptvm_server2022_clean ────────────────────────────────────────────────────
// Server 2022 clean install: only SruDbIdMapTable exists (2 entries).
// All other SRUM extension tables are absent — must return Ok([]).

#[test]
fn aptvm_server2022_clean_opens_without_error() {
    let Some(p) = fixture(MUSEUM_APTVM_SERVER2022_CLEAN) else { return };
    EseDatabase::open(p).expect("aptvm_clean: EseDatabase::open must succeed");
}

#[test]
fn aptvm_server2022_clean_all_parsers_return_ok() {
    let Some(p) = fixture(MUSEUM_APTVM_SERVER2022_CLEAN) else { return };
    assert!(parse_network_usage(p).is_ok(),          "aptvm_clean: parse_network_usage failed");
    assert!(parse_app_usage(p).is_ok(),               "aptvm_clean: parse_app_usage failed");
    assert!(parse_network_connectivity(p).is_ok(),    "aptvm_clean: parse_network_connectivity failed");
    assert!(parse_energy_usage(p).is_ok(),            "aptvm_clean: parse_energy_usage failed");
    assert!(parse_energy_lt(p).is_ok(),               "aptvm_clean: parse_energy_lt failed");
    assert!(parse_push_notifications(p).is_ok(),      "aptvm_clean: parse_push_notifications failed");
    assert!(parse_app_timeline(p).is_ok(),            "aptvm_clean: parse_app_timeline failed");
    assert!(parse_id_map(p).is_ok(),                  "aptvm_clean: parse_id_map failed");
}

#[test]
fn aptvm_server2022_clean_absent_tables_return_empty() {
    let Some(p) = fixture(MUSEUM_APTVM_SERVER2022_CLEAN) else { return };
    assert!(parse_network_usage(p).unwrap().is_empty(),       "aptvm_clean: network_usage should be empty (ABSENT)");
    assert!(parse_app_usage(p).unwrap().is_empty(),            "aptvm_clean: app_usage should be empty (ABSENT)");
    assert!(parse_network_connectivity(p).unwrap().is_empty(), "aptvm_clean: network_connectivity should be empty (ABSENT)");
    assert!(parse_energy_usage(p).unwrap().is_empty(),         "aptvm_clean: energy_usage should be empty (ABSENT)");
    assert!(parse_energy_lt(p).unwrap().is_empty(),            "aptvm_clean: energy_lt should be empty (ABSENT)");
    assert!(parse_push_notifications(p).unwrap().is_empty(),   "aptvm_clean: push_notifications should be empty (ABSENT)");
    assert!(parse_app_timeline(p).unwrap().is_empty(),         "aptvm_clean: app_timeline should be empty (ABSENT)");
}

// ── aptvm_server2022_1daylater ────────────────────────────────────────────────
// After one day of use: connectivity(4), push_notifications(153), idmap(96).

#[test]
fn aptvm_server2022_1daylater_opens_without_error() {
    let Some(p) = fixture(MUSEUM_APTVM_SERVER2022_1DAYLATER) else { return };
    EseDatabase::open(p).expect("aptvm_1daylater: EseDatabase::open must succeed");
}

#[test]
fn aptvm_server2022_1daylater_all_parsers_return_ok() {
    let Some(p) = fixture(MUSEUM_APTVM_SERVER2022_1DAYLATER) else { return };
    assert!(parse_network_usage(p).is_ok(),          "aptvm_1daylater: parse_network_usage failed");
    assert!(parse_app_usage(p).is_ok(),               "aptvm_1daylater: parse_app_usage failed");
    assert!(parse_network_connectivity(p).is_ok(),    "aptvm_1daylater: parse_network_connectivity failed");
    assert!(parse_energy_usage(p).is_ok(),            "aptvm_1daylater: parse_energy_usage failed");
    assert!(parse_energy_lt(p).is_ok(),               "aptvm_1daylater: parse_energy_lt failed");
    assert!(parse_push_notifications(p).is_ok(),      "aptvm_1daylater: parse_push_notifications failed");
    assert!(parse_app_timeline(p).is_ok(),            "aptvm_1daylater: parse_app_timeline failed");
    assert!(parse_id_map(p).is_ok(),                  "aptvm_1daylater: parse_id_map failed");
}

#[test]
fn aptvm_server2022_1daylater_network_connectivity_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_APTVM_SERVER2022_1DAYLATER) else { return };
    let r = parse_network_connectivity(p);
    assert!(r.is_ok(), "aptvm_1daylater: parse_network_connectivity failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "aptvm_1daylater: network_connectivity must be non-empty (dissect: 4)");
}

#[test]
fn aptvm_server2022_1daylater_push_notifications_parses_without_panic() {
    let Some(p) = fixture(MUSEUM_APTVM_SERVER2022_1DAYLATER) else { return };
    let r = parse_push_notifications(p);
    assert!(r.is_ok(), "aptvm_1daylater: parse_push_notifications failed: {:?}", r);
    assert!(!r.unwrap().is_empty(), "aptvm_1daylater: push_notifications must be non-empty (dissect: 153)");
}

#[test]
fn aptvm_server2022_1daylater_id_map_parses_non_empty() {
    let Some(p) = fixture(MUSEUM_APTVM_SERVER2022_1DAYLATER) else { return };
    let entries = parse_id_map(p).expect("aptvm_1daylater: parse_id_map must not error");
    assert!(
        entries.len() >= 90,
        "aptvm_1daylater: idmap must have >= 90 entries (dissect: 96), got {}",
        entries.len()
    );
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
