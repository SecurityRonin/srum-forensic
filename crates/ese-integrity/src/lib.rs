//! ESE database structural anomaly detection.
//!
//! Produces raw binary-format facts ([`EseStructuralAnomaly`]) from an open
//! [`EseDatabase`]. Does NOT draw forensic conclusions — that is the job of
//! the `RapidTriage` correlation layer.

use ese_core::{EseDatabase, EseHeader};

/// A raw structural anomaly detected in an ESE database binary.
///
/// These are parsing-level observations, not forensic conclusions.
#[derive(Debug, Clone, serde::Serialize)]
pub enum EseStructuralAnomaly {
    /// Database was not cleanly shut down (state = `2`).
    DirtyDatabase { db_state: u32 },
    /// A page's `db_time` field is strictly greater than the file header's
    /// `db_time` low 32 bits — the page appears newer than the header.
    TimestampSkew {
        page_number: u32,
        header_db_time_low: u32,
        page_db_time: u32,
    },
    /// Non-zero bytes exist in the page slack region (between record data
    /// end and tag array start) — possible residual record fragments.
    SlackRegionData {
        page_number: u32,
        /// Byte offset within the page where slack begins.
        offset_in_page: u16,
        /// Number of non-zero slack bytes.
        length: u16,
    },
}

/// Check whether the database header indicates an unclean shutdown.
///
/// Returns `Some(DirtyDatabase)` if `db_state == 2`, `None` otherwise.
pub fn check_dirty_state(header: &EseHeader) -> Option<EseStructuralAnomaly> {
    // TODO: implement
    let _ = header;
    None
}

/// Compare each page's `db_time` field (page offset `0x08`, 4 bytes) against
/// the file header's `db_time` low 32 bits.
///
/// A page whose `db_time` is **greater than** the header's indicates the page
/// was written after the header was last updated — a manipulation indicator.
pub fn detect_timestamp_skew(
    header: &EseHeader,
    db: &EseDatabase,
) -> Vec<EseStructuralAnomaly> {
    // TODO: implement
    let _ = (header, db);
    vec![]
}

/// Scan every page for non-zero bytes in the slack region.
///
/// The slack region is the space between the last record's data end and the
/// start of the tag array at the bottom of the page. Residual bytes here
/// may contain fragments of previously deleted records.
pub fn scan_slack_regions(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    // TODO: implement
    let _ = db;
    vec![]
}
