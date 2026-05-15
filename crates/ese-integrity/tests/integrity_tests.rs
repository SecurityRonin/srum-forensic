//! Integration tests for ese-integrity structural anomaly detection.

mod fixtures;

use ese_core::{DB_STATE_CLEAN_SHUTDOWN, DB_STATE_DIRTY_SHUTDOWN};
use ese_integrity::{
    check_dirty_state, detect_autoinc_gaps, detect_orphaned_catalog, detect_timestamp_skew,
    find_deleted_records, full_scan, scan_slack_regions, verify_page_checksums,
    EseStructuralAnomaly, Severity,
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

// ── severity() ───────────────────────────────────────────────────────────────

#[test]
fn dirty_database_severity_is_info() {
    let a = EseStructuralAnomaly::DirtyDatabase { db_state: 2 };
    assert_eq!(a.severity(), Severity::Info);
}

#[test]
fn timestamp_skew_severity_is_error() {
    let a = EseStructuralAnomaly::TimestampSkew {
        page_number: 1,
        header_db_time_low: 100,
        page_db_time: 500,
    };
    assert_eq!(a.severity(), Severity::Error);
}

#[test]
fn slack_region_data_severity_is_warning() {
    let a = EseStructuralAnomaly::SlackRegionData {
        page_number: 2,
        offset_in_page: 80,
        length: 16,
    };
    assert_eq!(a.severity(), Severity::Warning);
}

#[test]
fn page_checksum_mismatch_severity_is_error() {
    let a = EseStructuralAnomaly::PageChecksumMismatch {
        page_number: 3,
        expected: 0xDEAD_BEEF,
        actual: 0x1234_5678,
    };
    assert_eq!(a.severity(), Severity::Error);
}

#[test]
fn btree_link_broken_severity_is_error() {
    let a = EseStructuralAnomaly::BTreeLinkBroken {
        page_number: 4,
        broken_sibling: 99,
    };
    assert_eq!(a.severity(), Severity::Error);
}

#[test]
fn page_flag_inconsistency_severity_is_warning() {
    let a = EseStructuralAnomaly::PageFlagInconsistency {
        page_number: 5,
        flags: 0x0002,
        context: "leaf flag on internal node",
    };
    assert_eq!(a.severity(), Severity::Warning);
}

#[test]
fn orphaned_srum_table_severity_is_warning() {
    let a = EseStructuralAnomaly::OrphanedSrumTable {
        table_guid: "{deadbeef-dead-beef-dead-beefdeadbeef}".to_owned(),
    };
    assert_eq!(a.severity(), Severity::Warning);
}

#[test]
fn missing_srum_table_severity_is_warning() {
    let a = EseStructuralAnomaly::MissingSrumTable {
        table_guid: "{d10ca2fe-6fcf-4f6d-848e-b2e99266fa89}",
        table_name: "SruDbNetworkUsageTable",
    };
    assert_eq!(a.severity(), Severity::Warning);
}

#[test]
fn truncated_database_severity_is_critical() {
    let a = EseStructuralAnomaly::TruncatedDatabase {
        declared_pages: 100,
        actual_pages: 40,
    };
    assert_eq!(a.severity(), Severity::Critical);
}

// ── at_least() ───────────────────────────────────────────────────────────────

#[test]
fn at_least_exact_severity_returns_true() {
    let a = EseStructuralAnomaly::TimestampSkew {
        page_number: 1,
        header_db_time_low: 100,
        page_db_time: 500,
    };
    // severity() is Error; at_least(Error) must be true
    assert!(a.at_least(Severity::Error));
}

#[test]
fn at_least_lower_threshold_returns_true() {
    let a = EseStructuralAnomaly::TimestampSkew {
        page_number: 1,
        header_db_time_low: 100,
        page_db_time: 500,
    };
    // Error >= Warning: true
    assert!(a.at_least(Severity::Warning));
}

#[test]
fn at_least_higher_threshold_returns_false() {
    let a = EseStructuralAnomaly::TimestampSkew {
        page_number: 1,
        header_db_time_low: 100,
        page_db_time: 500,
    };
    // Error >= Critical: false
    assert!(!a.at_least(Severity::Critical));
}

// ── verify_page_checksums (Phase 4, stories 5-8) ────────────────────────────

#[test]
fn verify_page_checksums_empty_for_database_with_unchecked_pages() {
    // Pages built by PageBuilder have 0 stored checksum → "unchecked", must not be reported.
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = verify_page_checksums(&db);
    assert!(
        anomalies.is_empty(),
        "unchecked pages (zero stored checksum) must produce no anomaly"
    );
}

#[test]
fn verify_page_checksums_reports_mismatch_for_tampered_page() {
    let tmp = fixtures::make_ese_with_bad_checksum_on_page1();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = verify_page_checksums(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::PageChecksumMismatch { .. }));
    assert!(found, "tampered page must produce PageChecksumMismatch");
}

#[test]
fn verify_page_checksums_mismatch_carries_correct_page_number() {
    let tmp = fixtures::make_ese_with_bad_checksum_on_page1();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = verify_page_checksums(&db);
    let found = anomalies.iter().any(|a| {
        matches!(
            a,
            EseStructuralAnomaly::PageChecksumMismatch { page_number, .. }
                if *page_number == 1
        )
    });
    assert!(found, "mismatch on page 1 must report page_number == 1");
}

#[test]
fn verify_page_checksums_skips_page_with_zero_stored_checksum() {
    // A zero stored checksum means "unchecked" — must be silent even if computed ≠ 0.
    let tmp = fixtures::make_ese_with_page_db_time(0, 0);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = verify_page_checksums(&db);
    assert!(
        anomalies.is_empty(),
        "page with zero stored checksum must not produce PageChecksumMismatch"
    );
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

// ── find_deleted_records (Phase 4, stories 9-12) ─────────────────────────────

#[test]
fn find_deleted_records_empty_for_database_with_no_deleted_records() {
    // A freshly built page has no deleted tags — must return empty.
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = find_deleted_records(&db);
    assert!(
        anomalies.is_empty(),
        "database with no deleted records must produce no anomaly"
    );
}

#[test]
fn find_deleted_records_detects_deleted_tag() {
    // Page with a tag that has the defunct flag set in the offset word (bits 13-15).
    // Per MS-ESEDB spec: TAG_DEFUNCT = 0x2 is stored in bits 13-15 of the offset word
    // (bits 13-15 of the 32-bit tag = mask 0x4000 at bit 14 of the u32).
    let tmp = fixtures::make_ese_with_deleted_record();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = find_deleted_records(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::DeletedRecordPresent { .. }));
    assert!(found, "page with deleted tag must produce DeletedRecordPresent");
}

#[test]
fn find_deleted_records_detects_defunct_flag_in_offset_word() {
    // Per MS-ESEDB spec: the defunct (deleted) flag is TAG_DEFUNCT=0x2 in the
    // 3-bit flag field at bits 13-15 of the OFFSET word, i.e. bit 14 of the
    // 32-bit tag word (0x4000). This is the correct location; our old code
    // incorrectly checked bit 29 (0x2000_0000) in the size word.
    use std::io::Write as _;
    let page_size = ese_core::PAGE_SIZE;
    let mut page_data = vec![0u8; page_size];
    page_data[0x22..0x24].copy_from_slice(&2u16.to_le_bytes()); // tag_count=2
    page_data[0x24..0x28].copy_from_slice(&ese_core::PAGE_FLAG_LEAF.to_le_bytes());
    page_data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    page_data[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // Tag 0: relative offset=0, size=40
    let tag0: u32 = 40u32 << 16;
    page_data[page_size - 4..page_size].copy_from_slice(&tag0.to_le_bytes());

    // Tag 1: defunct flag in OFFSET word (bit 14 = TAG_DEFUNCT=0x2 at bits 13-15).
    // relative offset=0, size=4, defunct bit in offset word.
    // offset_word = 0 | (0x2 << 13) = 0x4000
    // tag_raw = 0x4000 | (4 << 16) = 0x0004_4000
    let tag1: u32 = 0x4000u32 | (4u32 << 16);
    page_data[page_size - 8..page_size - 4].copy_from_slice(&tag1.to_le_bytes());

    let header = ese_test_fixtures::make_raw_header_page(0, ese_core::DB_STATE_CLEAN_SHUTDOWN);
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&header).unwrap();
    tmp.write_all(&page_data).unwrap();

    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = find_deleted_records(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::DeletedRecordPresent { .. }));
    assert!(
        found,
        "defunct flag in offset word (bit 14 = 0x4000) must be detected as DeletedRecordPresent"
    );
}

#[test]
fn find_deleted_records_carries_correct_page_number() {
    let tmp = fixtures::make_ese_with_deleted_record();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = find_deleted_records(&db);
    let found = anomalies.iter().any(|a| {
        matches!(
            a,
            EseStructuralAnomaly::DeletedRecordPresent { page_number, .. }
                if *page_number == 1
        )
    });
    assert!(found, "deleted record on page 1 must carry page_number == 1");
}

#[test]
fn deleted_record_present_severity_is_warning() {
    let a = EseStructuralAnomaly::DeletedRecordPresent {
        page_number: 1,
        tag_index: 0,
    };
    assert_eq!(a.severity(), Severity::Warning);
}

// ── detect_autoinc_gaps (Phase 4, stories 13-16) ─────────────────────────────

#[test]
fn detect_autoinc_gaps_empty_for_contiguous_ids() {
    let ids = vec![1i32, 2, 3, 4, 5];
    let anomalies = detect_autoinc_gaps(&ids);
    assert!(
        anomalies.is_empty(),
        "contiguous AutoIncIds must produce no anomaly"
    );
}

#[test]
fn detect_autoinc_gaps_detects_single_gap() {
    // 3 → 5 is a gap (4 is missing)
    let ids = vec![1i32, 2, 3, 5, 6];
    let anomalies = detect_autoinc_gaps(&ids);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::AutoIncIdGap { prev: 3, next: 5 }));
    assert!(found, "gap between 3 and 5 must produce AutoIncIdGap {{ prev:3, next:5 }}");
}

#[test]
fn detect_autoinc_gaps_empty_for_single_element() {
    let ids = vec![42i32];
    let anomalies = detect_autoinc_gaps(&ids);
    assert!(
        anomalies.is_empty(),
        "single element produces no gaps"
    );
}

#[test]
fn autoinc_id_gap_severity_is_warning() {
    let a = EseStructuralAnomaly::AutoIncIdGap { prev: 3, next: 5 };
    assert_eq!(a.severity(), Severity::Warning);
}

// ── detect_orphaned_catalog (Phase 4, stories 17-18) ─────────────────────────

#[test]
fn detect_orphaned_catalog_empty_for_database_with_no_catalog_entries() {
    // A minimal fixture has no page 4 → catalog_entries() fails → empty result.
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_orphaned_catalog(&db);
    assert!(
        anomalies.is_empty(),
        "database with inaccessible catalog must produce no anomaly"
    );
}

#[test]
fn detect_orphaned_catalog_reports_orphan_when_table_page_is_out_of_bounds() {
    // Catalog entry references page 100; file only has 6 pages → orphaned.
    let tmp = fixtures::make_ese_with_orphaned_catalog_entry();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = detect_orphaned_catalog(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::OrphanedCatalogEntry { declared_page: 100, .. }));
    assert!(
        found,
        "catalog entry with table_page=100 beyond file size must produce OrphanedCatalogEntry"
    );
}

// ── full_scan (Phase 4, stories 19-20) ───────────────────────────────────────

#[test]
fn full_scan_empty_for_clean_database() {
    // A clean minimal database should produce no anomalies via full_scan.
    let tmp = fixtures::make_ese_with_db_state(DB_STATE_CLEAN_SHUTDOWN);
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = full_scan(&db);
    assert!(
        anomalies.is_empty(),
        "clean database must produce no anomalies from full_scan"
    );
}

#[test]
fn full_scan_detects_bad_checksum() {
    // full_scan must include the output of verify_page_checksums.
    let tmp = fixtures::make_ese_with_bad_checksum_on_page1();
    let db = ese_core::EseDatabase::open(tmp.path()).expect("open");
    let anomalies = full_scan(&db);
    let found = anomalies
        .iter()
        .any(|a| matches!(a, EseStructuralAnomaly::PageChecksumMismatch { .. }));
    assert!(
        found,
        "full_scan must surface PageChecksumMismatch from verify_page_checksums"
    );
}
