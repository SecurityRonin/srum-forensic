//! Robustness tests for [`ese_integrity::EseIntegrity`] unified analyser.
//!
//! These tests verify that EseIntegrity correctly detects structural problems
//! in crafted malformed byte buffers — cases where EseDatabase::open would
//! either panic, fail, or silently accept corrupt data.

mod fixtures;

use ese_integrity::{anomalies_at_least, EseIntegrity, EseStructuralAnomaly, Severity};

/// Minimum dual-shadow-header size required for a parseable ESE database.
/// Primary header at page 0 (4096 bytes) + shadow header at page 1 (4096 bytes).
const ESE_MIN_SIZE: usize = 8192;

// ── check_layout / TruncatedDatabase ────────────────────────────────────────

#[test]
fn empty_buffer_returns_truncated_database() {
    let anomalies = EseIntegrity::new(&[]).analyse();
    let found = anomalies.iter().any(|a| {
        matches!(a, EseStructuralAnomaly::TruncatedDatabase { .. })
    });
    assert!(found, "empty buffer must produce TruncatedDatabase");
}

#[test]
fn undersized_buffer_returns_truncated_database() {
    // A buffer with a valid header page but no shadow page (< 8192 bytes).
    let mut buf = vec![0u8; 4096];
    // Write ESE magic so header looks valid
    buf[4..8].copy_from_slice(&0x89AB_CDEF_u32.to_le_bytes());
    buf[236..240].copy_from_slice(&4096_u32.to_le_bytes()); // page_size = 4096

    let anomalies = EseIntegrity::new(&buf).analyse();
    let found = anomalies.iter().any(|a| {
        matches!(a, EseStructuralAnomaly::TruncatedDatabase { .. })
    });
    assert!(found, "buffer < 8192 bytes must produce TruncatedDatabase");
}

#[test]
fn truncated_database_has_critical_severity() {
    let anomalies = EseIntegrity::new(&[]).analyse();
    let criticals: Vec<_> = anomalies_at_least(&anomalies, Severity::Critical);
    assert!(
        !criticals.is_empty(),
        "TruncatedDatabase must produce at least one Critical anomaly"
    );
}

// ── check_pages / PageChecksumMismatch ──────────────────────────────────────

/// Build a raw two-page ESE buffer where page 1 has a non-zero, incorrect
/// XOR checksum. The XOR checksum at offset 0 should equal the XOR of all
/// subsequent 4-byte words; here it is deliberately set to 0xDEADBEEF while
/// all other bytes are zero, so the computed checksum won't match.
fn make_buf_with_bad_page_checksum() -> Vec<u8> {
    let page_size = 4096_usize;
    let mut buf = vec![0u8; page_size * 3]; // header + 2 data pages

    // Header page (page 0): valid ESE magic + page_size
    buf[4..8].copy_from_slice(&0x89AB_CDEF_u32.to_le_bytes());
    buf[236..240].copy_from_slice(&(page_size as u32).to_le_bytes());

    // Page 1 (shadow header / first data page): write a bad checksum at offset 0.
    // All other bytes in page 1 are 0, so the correct XOR checksum is
    // 0x89ABCDEF (seed only). We store 0xDEADBEEF instead → mismatch.
    let p1_start = page_size;
    buf[p1_start..p1_start + 4].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());

    buf
}

#[test]
fn page_with_bad_checksum_returns_checksum_mismatch() {
    let buf = make_buf_with_bad_page_checksum();
    let anomalies = EseIntegrity::new(&buf).analyse();
    let found = anomalies.iter().any(|a| {
        matches!(a, EseStructuralAnomaly::PageChecksumMismatch { .. })
    });
    assert!(
        found,
        "page with bad XOR checksum must produce PageChecksumMismatch"
    );
}

// ── clean minimal database → no anomalies ────────────────────────────────────

#[test]
fn minimal_valid_database_has_no_anomalies() {
    // EseFileBuilder creates pages with all-zero checksums (unchecked).
    // EseIntegrity skips checksum verification when the stored checksum is 0.
    use std::io::Read as _;
    let tmp = fixtures::make_ese_with_db_state(ese_core::DB_STATE_CLEAN_SHUTDOWN);
    let mut file = std::fs::File::open(tmp.path()).expect("open");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("read");

    let anomalies = EseIntegrity::new(&bytes).analyse();
    let errors_or_above: Vec<_> = anomalies_at_least(&anomalies, Severity::Error);
    assert!(
        errors_or_above.is_empty(),
        "clean minimal database must produce no Error/Critical anomalies; got: {errors_or_above:?}"
    );
}
