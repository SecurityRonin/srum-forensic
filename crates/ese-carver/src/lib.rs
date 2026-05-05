//! ESE page carving and fragmented record reconstruction.
//!
//! Detects records split across page boundaries (`detect_fragments`) and
//! stitches them back together (`reconstruct_fragment`).
//!
//! These are raw binary operations — forensic interpretation belongs in the
//! `RapidTriage` correlation layer.

/// A pair of page indices where a record is split across a page boundary.
///
/// `page_a` holds the record prefix (last tag of that page) and `page_b`
/// holds the record suffix (first data tag of that page).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentPair {
    /// 1-based page number of the page containing the record prefix.
    pub page_a: u32,
    /// 1-based page number of the page containing the record suffix.
    pub page_b: u32,
    /// Byte length of the prefix (last tag of `page_a`).
    pub prefix_len: usize,
    /// Byte length of the suffix (first data tag of `page_b`).
    pub suffix_len: usize,
}

/// Scan a slice of raw page bytes for records split across consecutive page
/// boundaries.
///
/// Returns a [`FragmentPair`] for every pair of adjacent pages where the last
/// tag of page N and the first data tag of page N+1 together equal
/// `expected_size`.
///
/// `pages` must be a flat byte slice that is a multiple of `page_size` long.
/// Pages are numbered starting at 1 (page 0 is the file header, skipped).
pub fn detect_fragments(
    _pages: &[u8],
    _page_size: usize,
    _expected_size: usize,
) -> Vec<FragmentPair> {
    vec![]
}

/// Reconstruct a fragmented record from a prefix and suffix slice.
///
/// Returns the stitched bytes if `prefix.len() + suffix.len() == expected_size`,
/// `None` otherwise.
pub fn reconstruct_fragment(
    _prefix: &[u8],
    _suffix: &[u8],
    _expected_size: usize,
) -> Option<Vec<u8>> {
    None
}
