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
    /// A catalog entry references a B-tree root page that falls beyond the
    /// declared page count (i.e. the page does not exist in the file).
    ///
    /// This can indicate a partially written or deliberately truncated database
    /// where the catalog was updated but the corresponding data pages were not.
    OrphanedCatalogEntry {
        /// Name of the catalog entry (table or index name).
        object_name: String,
        /// The root page number that the catalog declares.
        declared_page: u32,
        /// The highest valid page index in the file.
        last_valid_page: u32,
    },
    /// One or more AutoIncId values are missing from a contiguous sequence.
    ///
    /// A gap between `prev` and `next` (non-adjacent integers) indicates that
    /// records were deleted without leaving a deleted-tag marker — either via
    /// bulk deletion or external manipulation of the ESE store.
    AutoIncIdGap {
        /// The AutoIncId immediately before the gap.
        prev: i32,
        /// The AutoIncId immediately after the gap.
        next: i32,
    },
    /// A record tag has the deleted-record flag set (bit 29 of the tag word).
    ///
    /// Deleted records are not immediately zeroed; the raw bytes often persist
    /// and can contain recoverable data or evidence of prior state.
    DeletedRecordPresent {
        page_number: u32,
        /// 0-based tag index within the page's tag array.
        tag_index: usize,
    },
}

impl EseStructuralAnomaly {
    /// Return the forensic severity of this anomaly.
    pub fn severity(&self) -> Severity {
        match self {
            Self::DirtyDatabase { .. } => Severity::Info,
            Self::TimestampSkew { .. } => Severity::Error,
            Self::SlackRegionData { .. } => Severity::Warning,
            Self::PageChecksumMismatch { .. } => Severity::Error,
            Self::BTreeLinkBroken { .. } => Severity::Error,
            Self::PageFlagInconsistency { .. } => Severity::Warning,
            Self::OrphanedSrumTable { .. } => Severity::Warning,
            Self::MissingSrumTable { .. } => Severity::Warning,
            Self::TruncatedDatabase { .. } => Severity::Critical,
            Self::DeletedRecordPresent { .. } => Severity::Warning,
            Self::AutoIncIdGap { .. } => Severity::Warning,
            Self::OrphanedCatalogEntry { .. } => Severity::Error,
        }
    }

    /// Return `true` if this anomaly's severity is at least `min`.
    pub fn at_least(&self, min: Severity) -> bool {
        self.severity() >= min
    }
}

/// Minimum number of bytes required for a parseable ESE database.
///
/// ESE stores a primary header at page 0 and a shadow copy at page 1.
/// Both must be present for reliable header reconstruction: `2 × 4096 = 8192`.
const ESE_MIN_BYTES: usize = 8192;

/// ESE header page size used when the `page_size` field cannot be parsed.
const ESE_DEFAULT_PAGE_SIZE: usize = 4096;

/// XOR checksum seed used by the Vista+ page checksum algorithm.
const XOR_CHECKSUM_SEED: u32 = 0x89AB_CDEF;

/// Compute the ESE XOR page checksum for `page_data`.
///
/// The stored checksum is at offset 0 (4 bytes). The algorithm XORs all
/// subsequent 4-byte words starting at offset 4, seeded with
/// [`XOR_CHECKSUM_SEED`]. Data beyond the last full word is ignored.
fn xor_page_checksum(page_data: &[u8]) -> u32 {
    let mut csum = XOR_CHECKSUM_SEED;
    let words = &page_data[4..];
    for chunk in words.chunks_exact(4) {
        csum ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    csum
}

/// Read-only forensic analyser for a raw ESE database byte buffer.
///
/// Operates directly on raw bytes so it can detect anomalies that would
/// prevent normal parsing (bad checksums, missing pages, truncation).
/// [`analyse`](EseIntegrity::analyse) short-circuits after any `Critical`
/// finding: a truncated file makes page-level checks meaningless.
pub struct EseIntegrity<'a> {
    data: &'a [u8],
}

impl<'a> EseIntegrity<'a> {
    /// Wrap a raw ESE database byte buffer for forensic analysis.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Run all checks and return every detected anomaly.
    ///
    /// Returns an empty `Vec` for a structurally sound database.
    /// Short-circuits after any `Critical` finding (e.g. `TruncatedDatabase`).
    pub fn analyse(&self) -> Vec<EseStructuralAnomaly> {
        let mut anomalies = self.check_layout();
        // Short-circuit: if any Critical anomaly was found, page/btree/catalog
        // checks would produce false positives on missing or unreadable pages.
        let has_critical = anomalies.iter().any(|a| a.severity() == Severity::Critical);
        if has_critical {
            return anomalies;
        }
        anomalies.extend(self.check_header());
        anomalies.extend(self.check_pages());
        anomalies.extend(self.check_btree());
        anomalies.extend(self.check_catalog());
        anomalies
    }

    /// Check for database layout problems (truncation).
    ///
    /// Returns `TruncatedDatabase` if the buffer is smaller than
    /// [`ESE_MIN_BYTES`] or shorter than the declared page count implies.
    pub fn check_layout(&self) -> Vec<EseStructuralAnomaly> {
        if self.data.len() < ESE_MIN_BYTES {
            let actual_pages = u32::try_from(self.data.len() / ESE_DEFAULT_PAGE_SIZE)
                .unwrap_or(u32::MAX);
            // Try to read declared page count from header; fall back to 0.
            let declared_pages = self.try_read_declared_pages().unwrap_or(0);
            return vec![EseStructuralAnomaly::TruncatedDatabase {
                declared_pages,
                actual_pages,
            }];
        }
        // Check that the file is at least as large as the declared page count.
        let page_size = self.try_read_page_size().unwrap_or(ESE_DEFAULT_PAGE_SIZE);
        if let Some(declared) = self.try_read_declared_pages() {
            let expected_bytes = (declared as usize).saturating_mul(page_size);
            if expected_bytes > self.data.len() {
                let actual_pages =
                    u32::try_from(self.data.len() / page_size).unwrap_or(u32::MAX);
                return vec![EseStructuralAnomaly::TruncatedDatabase {
                    declared_pages: declared,
                    actual_pages,
                }];
            }
        }
        Vec::new()
    }

    /// Check page-level integrity (XOR checksums).
    ///
    /// For each data page, verifies the stored XOR checksum at offset 0
    /// against the computed value. Pages where the stored checksum is 0 are
    /// treated as "unchecked" and skipped (common for empty/synthetic pages).
    /// Handles both legacy XOR and Vista+ ECC formats via
    /// `ese_core::verify_page_checksum()`.
    pub fn check_pages(&self) -> Vec<EseStructuralAnomaly> {
        use ese_core::{verify_page_checksum, ChecksumResult};

        let page_size = self.try_read_page_size().unwrap_or(ESE_DEFAULT_PAGE_SIZE);
        if page_size < 8 {
            return Vec::new();
        }
        let mut anomalies = Vec::new();
        // Skip page 0 (the file header page itself, which has its own checksum scheme).
        for page_number in 1u32.. {
            let start = (page_number as usize).saturating_mul(page_size);
            let end = start.saturating_add(page_size);
            if end > self.data.len() {
                break;
            }
            let page_data = &self.data[start..end];
            match verify_page_checksum(page_data, page_number) {
                ChecksumResult::Valid | ChecksumResult::Unknown => {}
                ChecksumResult::LegacyXorMismatch { stored, computed } => {
                    anomalies.push(EseStructuralAnomaly::PageChecksumMismatch {
                        page_number,
                        expected: computed,
                        actual: stored,
                    });
                }
                ChecksumResult::EccMismatch => {
                    let actual = u32::from_le_bytes([
                        page_data[0], page_data[1], page_data[2], page_data[3],
                    ]);
                    anomalies.push(EseStructuralAnomaly::PageChecksumMismatch {
                        page_number,
                        expected: 0,
                        actual,
                    });
                }
            }
        }
        anomalies
    }

    /// Check B-tree sibling link consistency.
    ///
    /// Stub — link verification requires catalog traversal and is deferred
    /// to a future phase. Returns an empty `Vec`.
    pub fn check_btree(&self) -> Vec<EseStructuralAnomaly> {
        Vec::new()
    }

    /// Check catalog consistency (orphaned/missing SRUM tables).
    ///
    /// Stub — catalog traversal requires full B-tree walk and is deferred
    /// to a future phase. Returns an empty `Vec`.
    pub fn check_catalog(&self) -> Vec<EseStructuralAnomaly> {
        Vec::new()
    }

    /// Check header fields (dirty state reported via [`check_dirty_state`]).
    ///
    /// Stub — the caller can use [`check_dirty_state`] directly on an
    /// `EseDatabase`. Returns an empty `Vec`.
    pub fn check_header(&self) -> Vec<EseStructuralAnomaly> {
        Vec::new()
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn try_read_page_size(&self) -> Option<usize> {
        if self.data.len() < 240 {
            return None;
        }
        let raw =
            u32::from_le_bytes([self.data[236], self.data[237], self.data[238], self.data[239]]);
        if raw == 0 {
            Some(ESE_DEFAULT_PAGE_SIZE)
        } else {
            Some(raw as usize)
        }
    }

    fn try_read_declared_pages(&self) -> Option<u32> {
        // ESE header `last_page_number` is at offset 0x1C8 (456) in the header page.
        // It stores the highest page number used, which equals page_count - 1.
        // We return page_count = last_page_number + 1.
        const LAST_PAGE_OFFSET: usize = 0x1C8;
        if self.data.len() < LAST_PAGE_OFFSET + 4 {
            return None;
        }
        let last = u32::from_le_bytes([
            self.data[LAST_PAGE_OFFSET],
            self.data[LAST_PAGE_OFFSET + 1],
            self.data[LAST_PAGE_OFFSET + 2],
            self.data[LAST_PAGE_OFFSET + 3],
        ]);
        Some(last.saturating_add(1))
    }
}

/// Verify the XOR page checksum for every data page in `db`.
///
/// Pages where the stored checksum at bytes `[0..4]` is zero are treated as
/// "unchecked" (common for empty or synthetic pages) and skipped silently.
/// For all other pages the stored value is compared against the XOR checksum
/// recomputed over bytes `[4..]`; a mismatch produces [`PageChecksumMismatch`].
///
/// Note: this function uses the simple XOR algorithm. ECC-format pages (Vista+
/// with non-zero bytes at `[4..8]`) are treated the same way — if the stored
/// XOR word at `[0..4]` is non-zero and wrong, the page is still flagged.
pub fn verify_page_checksums(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    let page_count = db.page_count();
    let mut anomalies = Vec::new();
    for page_number in 1..u32::try_from(page_count).unwrap_or(u32::MAX) {
        let Ok(page) = db.read_page(page_number) else {
            continue;
        };
        if page.data.len() < 8 {
            continue;
        }
        let stored = u32::from_le_bytes([
            page.data[0],
            page.data[1],
            page.data[2],
            page.data[3],
        ]);
        if stored == 0 {
            continue;
        }
        let computed = xor_page_checksum(&page.data);
        if computed != stored {
            anomalies.push(EseStructuralAnomaly::PageChecksumMismatch {
                page_number,
                expected: computed,
                actual: stored,
            });
        }
    }
    anomalies
}

/// Run all available structural integrity checks on `db` and aggregate results.
///
/// Combines the output of:
/// - [`verify_page_checksums`] — XOR checksum mismatch detection
/// - [`find_deleted_records`] — in-place deleted-tag scanning
/// - [`detect_orphaned_catalog`] — catalog entries beyond file bounds
///
/// Note: [`detect_autoinc_gaps`] is a pure function operating on caller-
/// supplied id slices and is not included here (it has no `EseDatabase` API).
pub fn full_scan(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    let mut anomalies = Vec::new();
    anomalies.extend(verify_page_checksums(db));
    anomalies.extend(find_deleted_records(db));
    anomalies.extend(detect_orphaned_catalog(db));
    anomalies
}

/// Check the catalog for table entries whose declared root page falls outside
/// the file's page range.
///
/// For each catalog entry with `object_type == 1` (table), this checks whether
/// `table_page >= page_count`. A hit means the catalog was updated but the
/// corresponding data pages were never written — either truncation or tampering.
///
/// If `db.catalog_entries()` fails (e.g. page 4 is missing), returns an
/// empty `Vec` rather than propagating the error.
pub fn detect_orphaned_catalog(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    let Ok(entries) = db.catalog_entries() else {
        return Vec::new();
    };
    let last_valid = db.page_count().saturating_sub(1) as u32;
    entries
        .iter()
        .filter(|e| e.object_type == 1 && e.table_page > last_valid)
        .map(|e| EseStructuralAnomaly::OrphanedCatalogEntry {
            object_name: e.object_name.clone(),
            declared_page: e.table_page,
            last_valid_page: last_valid,
        })
        .collect()
}

/// Detect non-adjacent AutoIncId values in a sorted (or unsorted) id slice.
///
/// Any pair of adjacent elements where `next > prev + 1` indicates that one or
/// more records were removed without leaving an in-place deleted-tag marker.
/// The input does not need to be pre-sorted; this function sorts a copy internally.
pub fn detect_autoinc_gaps(ids: &[i32]) -> Vec<EseStructuralAnomaly> {
    if ids.len() < 2 {
        return Vec::new();
    }
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted
        .windows(2)
        .filter_map(|w| {
            let (prev, next) = (w[0], w[1]);
            if next > prev + 1 {
                Some(EseStructuralAnomaly::AutoIncIdGap { prev, next })
            } else {
                None
            }
        })
        .collect()
}

/// Scan every data page for tags that have the deleted-record flag set.
///
/// ESE marks deleted records in-place: bit 29 (`0x2000_0000`) of the raw
/// 4-byte tag word is set without zeroing the record bytes. This function
/// reports each such tag as [`DeletedRecordPresent`]; the caller can then
/// attempt to recover the residual bytes from `page.data[offset..offset+size]`.
pub fn find_deleted_records(db: &EseDatabase) -> Vec<EseStructuralAnomaly> {
    const DELETED_FLAG: u32 = 0x2000_0000;
    let page_count = db.page_count();
    let mut anomalies = Vec::new();
    for page_number in 1..u32::try_from(page_count).unwrap_or(u32::MAX) {
        let Ok(page) = db.read_page(page_number) else {
            continue;
        };
        let Ok(hdr) = page.parse_header() else {
            continue;
        };
        let count = hdr.available_page_tag_count as usize;
        let page_size = page.data.len();
        for i in 0..count {
            let Some(tag_offset) = page_size.checked_sub((i + 1) * 4) else {
                break;
            };
            let raw = u32::from_le_bytes([
                page.data[tag_offset],
                page.data[tag_offset + 1],
                page.data[tag_offset + 2],
                page.data[tag_offset + 3],
            ]);
            if raw & DELETED_FLAG != 0 {
                anomalies.push(EseStructuralAnomaly::DeletedRecordPresent {
                    page_number,
                    tag_index: i,
                });
            }
        }
    }
    anomalies
}

/// Filter `anomalies` to those at or above `min` severity.
pub fn anomalies_at_least<'a>(
    anomalies: &'a [EseStructuralAnomaly],
    min: Severity,
) -> Vec<&'a EseStructuralAnomaly> {
    anomalies.iter().filter(|a| a.at_least(min)).collect()
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
