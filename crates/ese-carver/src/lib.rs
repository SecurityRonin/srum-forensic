//! ESE page carving and fragmented record reconstruction.
//!
//! Detects records split across page boundaries ([`detect_fragments`]) and
//! stitches them back together ([`reconstruct_fragment`]).
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

/// Parse the tag array from a raw page slice.
///
/// Returns a `Vec<(offset, size)>` for each tag, tag 0 first.
/// Returns `None` if the page is too short to contain the tag array.
fn parse_tags(page: &[u8], page_size: usize) -> Option<Vec<(usize, usize)>> {
    if page.len() < page_size {
        return None;
    }
    // tag count at page offset 0x1E (u16 LE)
    if page_size < 0x20 {
        return None;
    }
    let tag_count = u16::from_le_bytes([page[0x1E], page[0x1F]]) as usize;
    if tag_count == 0 {
        return None;
    }
    let mut tags = Vec::with_capacity(tag_count);
    for i in 0..tag_count {
        let pos = page_size - (i + 1) * 4;
        if pos + 4 > page_size {
            return None;
        }
        let raw = u32::from_le_bytes([page[pos], page[pos + 1], page[pos + 2], page[pos + 3]]);
        let offset = (raw & 0x7FFF) as usize;
        let size = ((raw >> 16) & 0x7FFF) as usize;
        tags.push((offset, size));
    }
    Some(tags)
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
    pages: &[u8],
    page_size: usize,
    expected_size: usize,
) -> Vec<FragmentPair> {
    if page_size == 0 || pages.len() % page_size != 0 {
        return vec![];
    }
    let total_pages = pages.len() / page_size;
    // Page 0 is the header — data pages start at index 1.
    let mut pairs = Vec::new();

    for page_idx in 1..total_pages.saturating_sub(1) {
        let a_start = page_idx * page_size;
        let b_start = (page_idx + 1) * page_size;
        let page_a = &pages[a_start..a_start + page_size];
        let page_b = &pages[b_start..b_start + page_size];

        let Some(tags_a) = parse_tags(page_a, page_size) else { continue };
        let Some(tags_b) = parse_tags(page_b, page_size) else { continue };

        // Last tag of page A = potential prefix fragment
        let Some(&(_, prefix_len)) = tags_a.last() else { continue };
        // First *data* tag of page B (tag index 1, skip tag 0 = page header)
        let Some(&(_, suffix_len)) = tags_b.get(1) else { continue };

        if prefix_len + suffix_len == expected_size {
            let page_a_num = u32::try_from(page_idx).unwrap_or(u32::MAX);
            let page_b_num = u32::try_from(page_idx + 1).unwrap_or(u32::MAX);
            pairs.push(FragmentPair {
                page_a: page_a_num,
                page_b: page_b_num,
                prefix_len,
                suffix_len,
            });
        }
    }
    pairs
}

/// Reconstruct a fragmented record from a prefix and suffix slice.
///
/// Returns the stitched bytes if `prefix.len() + suffix.len() == expected_size`,
/// `None` otherwise.
pub fn reconstruct_fragment(
    prefix: &[u8],
    suffix: &[u8],
    expected_size: usize,
) -> Option<Vec<u8>> {
    if prefix.len() + suffix.len() != expected_size {
        return None;
    }
    let mut out = Vec::with_capacity(expected_size);
    out.extend_from_slice(prefix);
    out.extend_from_slice(suffix);
    Some(out)
}
