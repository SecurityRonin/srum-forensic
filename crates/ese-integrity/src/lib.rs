//! ESE database structural anomaly detection.
//!
//! Produces raw binary-format facts ([`EseStructuralAnomaly`]) from an open
//! [`EseDatabase`]. Does NOT draw forensic conclusions — that is the job of
//! the `RapidTriage` correlation layer.

use ese_core::{EseDatabase, EseHeader};

/// Forensic severity level for a detected structural anomaly.
///
/// Declaration order is ascending: `Info < Warning < Error < Critical`.
/// This ordering is reflected in the derived [`Ord`] implementation so
/// `anomaly.severity() >= Severity::Warning` works as a filter predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Consistent with legitimate operation; worth noting.
    Info,
    /// Suspicious; plausible legitimate explanation but warrants investigation.
    Warning,
    /// Strong indicator of tampering or structural corruption.
    Error,
    /// Database cannot be reliably decoded; forensic conclusions unsupported.
    Critical,
}

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
    /// The XOR or ECC checksum stored in the page header does not match
    /// the recomputed checksum over page bytes. Bytes changed after write.
    PageChecksumMismatch {
        page_number: u32,
        expected: u32,
        actual: u32,
    },
    /// A B-tree node's sibling-page pointer chain is broken: the declared
    /// next/previous page does not reciprocate the link.
    BTreeLinkBroken {
        page_number: u32,
        /// Page number that was supposed to link back.
        broken_sibling: u32,
    },
    /// A page is reachable via the B-tree but its `page_flags` are
    /// inconsistent with its position (e.g. leaf flag set on an internal node).
    PageFlagInconsistency {
        page_number: u32,
        flags: u16,
        context: &'static str,
    },
    /// A SRUM table identified by GUID in the catalog is referenced by
    /// a record but no corresponding B-tree root page can be found.
    OrphanedSrumTable { table_guid: String },
    /// A required SRUM table (known GUID from forensicnomicon) is absent
    /// from the catalog — the table was deleted or never populated.
    MissingSrumTable {
        table_guid: &'static str,
        table_name: &'static str,
    },
    /// The file ends before the declared page count implies. The database
    /// was truncated — either during acquisition or deliberately.
    TruncatedDatabase {
        declared_pages: u32,
        actual_pages: u32,
    },
}

impl EseStructuralAnomaly {
    /// Return the forensic severity of this anomaly.
    pub fn severity(&self) -> Severity {
        // RED STUB: returns Info for every variant so severity tests fail.
        Severity::Info
    }

    /// Return `true` if this anomaly's severity is at least `min`.
    pub fn at_least(&self, min: Severity) -> bool {
        self.severity() >= min
    }
}

/// Check whether the database header indicates an unclean shutdown.
///
/// Returns `Some(DirtyDatabase)` if `db_state == 2`, `None` otherwise.
pub fn check_dirty_state(header: &EseHeader) -> Option<EseStructuralAnomaly> {
    if header.db_state == ese_core::DB_STATE_DIRTY_SHUTDOWN {
        Some(EseStructuralAnomaly::DirtyDatabase {
            db_state: header.db_state,
        })
    } else {
        None
    }
}

/// Compare each page's `db_time` field (page offset `0x08`, 4 bytes) against
/// the file header's `db_time` low 32 bits.
///
/// A page whose `db_time` is **greater than** the header's indicates the page
/// was written after the header was last updated — a manipulation indicator.
pub fn detect_timestamp_skew(header: &EseHeader, db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    let header_low = (header.db_time & 0xFFFF_FFFF) as u32;
    let page_count = db.page_count();
    let mut anomalies = Vec::new();
    // Start at page 1 — page 0 is the header itself, not a data page.
    for page_number in 1..u32::try_from(page_count).unwrap_or(u32::MAX) {
        let Ok(page) = db.read_page(page_number) else {
            continue;
        };
        if page.data.len() < 12 {
            continue;
        }
        // Page db_time is 4 bytes at page offset 0x08.
        let page_db_time = u32::from_le_bytes([
            page.data[0x08],
            page.data[0x09],
            page.data[0x0A],
            page.data[0x0B],
        ]);
        if page_db_time > header_low {
            anomalies.push(EseStructuralAnomaly::TimestampSkew {
                page_number,
                header_db_time_low: header_low,
                page_db_time,
            });
        }
    }
    anomalies
}

/// Scan every page for non-zero bytes in the slack region.
///
/// The slack region is the space between the last record's data end and the
/// start of the tag array at the bottom of the page. Residual bytes here
/// may contain fragments of previously deleted records.
pub fn scan_slack_regions(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    let page_count = db.page_count();
    let page_size = db.header.page_size as usize;
    let mut anomalies = Vec::new();
    for page_number in 1..u32::try_from(page_count).unwrap_or(u32::MAX) {
        let Ok(page) = db.read_page(page_number) else {
            continue;
        };
        let Ok(hdr) = page.parse_header() else {
            continue;
        };
        let tag_count = hdr.available_page_tag_count as usize;
        if tag_count == 0 {
            continue;
        }
        // Tag array occupies the last tag_count * 4 bytes of the page.
        let tag_array_start = page_size.saturating_sub(tag_count * 4);
        // Find the highest data byte used by any record tag.
        let Ok(tags) = page.tags() else { continue };
        let record_data_end = tags
            .iter()
            .map(|(off, sz)| usize::from(*off) + usize::from(*sz))
            .max()
            .unwrap_or(0);
        // Slack = bytes in [record_data_end, tag_array_start)
        if record_data_end >= tag_array_start {
            continue; // no slack
        }
        let slack = &page.data[record_data_end..tag_array_start];
        let non_zero = slack.iter().any(|&b| b != 0);
        if non_zero {
            let offset_in_page = u16::try_from(record_data_end).unwrap_or(u16::MAX);
            let length = u16::try_from(slack.len()).unwrap_or(u16::MAX);
            anomalies.push(EseStructuralAnomaly::SlackRegionData {
                page_number,
                offset_in_page,
                length,
            });
        }
    }
    anomalies
}
