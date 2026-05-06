//! Integration tests for ese-integrity structural anomaly detection.
//!
//! Tests [`ese_integrity::check_dirty_state`], [`ese_integrity::detect_timestamp_skew`],
//! and [`ese_integrity::scan_slack_regions`].

mod fixtures;

use ese_core::{DB_STATE_CLEAN_SHUTDOWN, DB_STATE_DIRTY_SHUTDOWN};
use ese_integrity::{
    check_dirty_state, detect_timestamp_skew, scan_slack_regions, EseStructuralAnomaly,
};

// ── check_dirty_state ────────────────────────────────────────────────────────

#[test]
fn dirty_state_returns_none_for_clean_shutdown() {
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomaly = check_dirty_state(&db.header);
    assert!(anomaly.is_none(), "clean shutdown must produce no anomaly");
}

#[test]
fn dirty_state_returns_anomaly_for_dirty_shutdown() {
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_DIRTY_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomaly = check_dirty_state(&db.header);
    assert!(
        anomaly.is_some(),
        "dirty shutdown must produce DirtyDatabase anomaly"
    );
    if let Some(EseStructuralAnomaly::DirtyDatabase { db_state }) = anomaly {
        assert_eq!(db_state, DB_STATE_DIRTY_SHUTDOWN);
    } else {
        panic!("expected DirtyDatabase variant");
    }
}

// ── detect_timestamp_skew ────────────────────────────────────────────────────

#[test]
fn timestamp_skew_empty_for_page_equal_to_header() {
    // Page db_time == header db_time low32 → no skew
    let tmp = fixtures::make_ese_with_page_db_time(
        /*header_db_time=*/ 1000_u64, /*page_db_time=*/ 1000_u32,
    );
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_timestamp_skew(&db.header, &db);
    assert!(
        anomalies.is_empty(),
        "equal timestamps must produce no anomaly"
    );
}

#[test]
fn timestamp_skew_empty_for_page_older_than_header() {
    let tmp = fixtures::make_ese_with_page_db_time(
        /*header_db_time=*/ 2000_u64, /*page_db_time=*/ 1000_u32,
    );
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_timestamp_skew(&db.header, &db);
    assert!(
        anomalies.is_empty(),
        "page older than header must produce no anomaly"
    );
}

#[test]
fn timestamp_skew_detected_when_page_newer_than_header() {
    // page db_time (5000) > header db_time low32 (1000) → skew
    let tmp = fixtures::make_ese_with_page_db_time(
        /*header_db_time=*/ 1000_u64, /*page_db_time=*/ 5000_u32,
    );
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_timestamp_skew(&db.header, &db);
    assert!(
        !anomalies.is_empty(),
        "page newer than header must produce TimestampSkew"
    );
    let found = anomalies.iter().any(|a| {
        matches!(a, EseStructuralAnomaly::TimestampSkew {
            header_db_time_low,
            page_db_time,
            ..
        } if *header_db_time_low == 1000 && *page_db_time == 5000)
    });
    assert!(found, "TimestampSkew must carry correct field values");
}

// ── scan_slack_regions ───────────────────────────────────────────────────────

#[test]
fn slack_empty_for_page_with_no_slack() {
    // A page whose records exactly fill the available space — no slack bytes
    let tmp = fixtures::make_ese_with_tight_records();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = scan_slack_regions(&db);
    assert!(
        anomalies.is_empty(),
        "page with no slack must produce no SlackRegionData"
    );
}

#[test]
fn slack_detected_for_page_with_residual_bytes() {
    // A page with records that don't fill the space — non-zero bytes in slack
    let tmp = fixtures::make_ese_with_slack_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = scan_slack_regions(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::SlackRegionData { length, .. } if *length > 0));
    assert!(
        found,
        "page with non-zero slack must produce SlackRegionData"
    );
}
