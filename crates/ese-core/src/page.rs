//! ESE database page types.

use crate::EseError;

/// Default ESE page size in bytes (Vista+).
pub const PAGE_SIZE: usize = 4096;

/// Page flag: root page.
pub const PAGE_FLAG_ROOT: u32 = 0x0001;
/// Page flag: leaf page.
pub const PAGE_FLAG_LEAF: u32 = 0x0002;
/// Page flag: parent (internal B-tree node).
pub const PAGE_FLAG_PARENT: u32 = 0x0004;
/// Page flag: empty page.
pub const PAGE_FLAG_EMPTY: u32 = 0x0008;
/// Page flag: space tree page.
pub const PAGE_FLAG_SPACE_TREE: u32 = 0x0400;

/// Parsed ESE page header fields (Vista+ "new" 40-byte format).
#[derive(Debug, Clone)]
pub struct EsePageHeader {
    /// Previous page number; `None` when `0xFFFF_FFFF`.
    pub prev_page: Option<u32>,
    /// Next page number; `None` when `0xFFFF_FFFF`.
    pub next_page: Option<u32>,
    /// Father data page object ID.
    pub fdp_object_id: u32,
    /// Available data size.
    pub available_data_size: u16,
    /// Available uncommitted data.
    pub available_uncommitted: u16,
    /// Available data offset.
    pub available_data_offset: u16,
    /// Number of page tags (includes tag 0).
    pub available_page_tag_count: u16,
    /// Page flags.
    pub page_flags: u32,
}

/// A single ESE database page.
#[derive(Debug, Clone)]
pub struct EsePage {
    /// Page number (1-based).
    pub page_number: u32,
    /// Raw page data. Parse flags via [`EsePage::parse_header`].
    pub data: Vec<u8>,
}

impl EsePage {
    /// Minimum size of the Vista+ page header.
    pub const HEADER_SIZE: usize = 40;

    /// Parse the Vista+ 40-byte page header from `self.data`.
    ///
    /// Layout (all little-endian):
    /// - 0x00 (4): checksum
    /// - 0x04 (8): database time
    /// - 0x0C (4): previous page number
    /// - 0x10 (4): next page number
    /// - 0x14 (4): FDP object ID
    /// - 0x18 (2): available data size
    /// - 0x1A (2): available uncommitted data
    /// - 0x1C (2): available data offset
    /// - 0x1E (2): available page tag count
    /// - 0x20 (4): page flags
    ///
    /// # Errors
    ///
    /// Returns [`EseError::Corrupt`] if `self.data` is shorter than 40 bytes.
    pub fn parse_header(&self) -> Result<EsePageHeader, EseError> {
        let d = &self.data;
        if d.len() < Self::HEADER_SIZE {
            return Err(EseError::Corrupt {
                page: self.page_number,
                detail: format!("page header too short: {} < {}", d.len(), Self::HEADER_SIZE),
            });
        }

        let prev_raw = u32::from_le_bytes([d[0x0C], d[0x0D], d[0x0E], d[0x0F]]);
        let next_raw = u32::from_le_bytes([d[0x10], d[0x11], d[0x12], d[0x13]]);
        let fdp_object_id = u32::from_le_bytes([d[0x14], d[0x15], d[0x16], d[0x17]]);
        let available_data_size = u16::from_le_bytes([d[0x18], d[0x19]]);
        let available_uncommitted = u16::from_le_bytes([d[0x1A], d[0x1B]]);
        let available_data_offset = u16::from_le_bytes([d[0x1C], d[0x1D]]);
        let available_page_tag_count = u16::from_le_bytes([d[0x1E], d[0x1F]]);
        let page_flags = u32::from_le_bytes([d[0x20], d[0x21], d[0x22], d[0x23]]);

        Ok(EsePageHeader {
            prev_page: if prev_raw == 0xFFFF_FFFF {
                None
            } else {
                Some(prev_raw)
            },
            next_page: if next_raw == 0xFFFF_FFFF {
                None
            } else {
                Some(next_raw)
            },
            fdp_object_id,
            available_data_size,
            available_uncommitted,
            available_data_offset,
            available_page_tag_count,
            page_flags,
        })
    }

    /// Return the tag entries from the end of the page.
    ///
    /// Tags are stored at the END of the page, growing downward.
    /// Each tag is 4 bytes: bits 0-14 = value offset, bit 15 = flag,
    /// bits 16-30 = value size, bit 31 = flag.
    ///
    /// Returns `Vec<(offset, size)>` for each tag.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::TagArrayOverflow`] if the page is too short to hold the
    /// declared tag count.
    pub fn tags(&self) -> Result<Vec<(u16, u16)>, EseError> {
        let hdr = self.parse_header()?;
        let count = hdr.available_page_tag_count as usize;
        let page_size = self.data.len();
        if page_size < count * 4 {
            return Err(EseError::TagArrayOverflow {
                page: self.page_number,
            });
        }
        let mut tags = Vec::with_capacity(count);
        for i in 0..count {
            let tag_offset = page_size - (i + 1) * 4;
            let raw = u32::from_le_bytes([
                self.data[tag_offset],
                self.data[tag_offset + 1],
                self.data[tag_offset + 2],
                self.data[tag_offset + 3],
            ]);
            let value_offset = (raw & 0x7FFF) as u16;
            let value_size = ((raw >> 16) & 0x7FFF) as u16;
            tags.push((value_offset, value_size));
        }
        Ok(tags)
    }

    /// Return the raw record data slice for tag at `index`.
    ///
    /// Tag 0 is the page header tag. Data records start at tag 1.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::Corrupt`] if `index` is beyond the tag count, or
    /// [`EseError::RecordTooShort`] if the tag's data range is out of bounds.
    pub fn record_data(&self, index: usize) -> Result<&[u8], EseError> {
        let tags = self.tags()?;
        if index >= tags.len() {
            return Err(EseError::Corrupt {
                page: self.page_number,
                detail: format!("tag index {index} out of range (tag count: {})", tags.len()),
            });
        }
        let (offset, size) = tags[index];
        let start = offset as usize;
        let end = start + size as usize;
        if end > self.data.len() {
            return Err(EseError::RecordTooShort {
                page: self.page_number,
                tag: index,
                got: self.data.len(),
                need: end,
            });
        }
        Ok(&self.data[start..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ese-page-header story ────────────────────────────────────────────────

    #[test]
    fn parse_header_page_flags_leaf() {
        let mut data = vec![0u8; 4096];
        // page_flags at offset 0x20
        data[0x20..0x24].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());
        let page = EsePage {
            page_number: 1,
            data,
        };
        let hdr = page.parse_header().expect("parse header");
        assert_eq!(hdr.page_flags, PAGE_FLAG_LEAF);
        assert!(hdr.page_flags & PAGE_FLAG_LEAF != 0);
    }

    #[test]
    fn parse_header_flag_constants_usable() {
        assert_eq!(PAGE_FLAG_ROOT, 0x0001);
        assert_eq!(PAGE_FLAG_LEAF, 0x0002);
        assert_eq!(PAGE_FLAG_PARENT, 0x0004);
        assert_eq!(PAGE_FLAG_EMPTY, 0x0008);
        assert_eq!(PAGE_FLAG_SPACE_TREE, 0x0400);
    }

    #[test]
    fn parse_header_prev_next_links() {
        let mut data = vec![0u8; 4096];
        data[0x0C..0x10].copy_from_slice(&5u32.to_le_bytes()); // prev_page = 5
        data[0x10..0x14].copy_from_slice(&7u32.to_le_bytes()); // next_page = 7
        let page = EsePage {
            page_number: 3,
            data,
        };
        let hdr = page.parse_header().expect("parse header");
        assert_eq!(hdr.prev_page, Some(5));
        assert_eq!(hdr.next_page, Some(7));
    }

    #[test]
    fn parse_header_none_when_0xffffffff() {
        let mut data = vec![0u8; 4096];
        data[0x0C..0x10].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let page = EsePage {
            page_number: 1,
            data,
        };
        let hdr = page.parse_header().expect("parse header");
        assert_eq!(hdr.prev_page, None);
        assert_eq!(hdr.next_page, None);
    }

    #[test]
    fn parse_header_short_buffer_returns_err() {
        let data = vec![0u8; 20]; // shorter than 40 bytes
        let page = EsePage {
            page_number: 1,
            data,
        };
        let result = page.parse_header();
        assert!(result.is_err(), "short buffer must return Err");
    }

    // ── ese-page-tags story ──────────────────────────────────────────────────

    /// Build a synthetic page with embedded data records.
    ///
    /// Layout:
    /// - Header (40 bytes) at offset 0
    /// - Records packed starting at offset 40
    /// - Tag array at page end: tag[0] covers header, tags[1..] cover records
    fn make_page_with_records(page_size: usize, records: &[&[u8]]) -> Vec<u8> {
        let mut d = vec![0u8; page_size];
        let tag_count = u16::try_from(1 + records.len()).unwrap_or(u16::MAX);
        // header: tag_count at 0x1E, PAGE_FLAG_LEAF at 0x20
        d[0x1E..0x20].copy_from_slice(&tag_count.to_le_bytes());
        d[0x20..0x24].copy_from_slice(&PAGE_FLAG_LEAF.to_le_bytes());

        // Tag 0: covers the page header (offset=0, size=40)
        write_tag(&mut d, page_size, 0, 0, 40);

        // Data records starting at offset 40
        let mut cur_offset: u16 = 40;
        for (i, rec) in records.iter().enumerate() {
            let tag_idx = i + 1;
            let rec_size = u16::try_from(rec.len()).unwrap_or(u16::MAX);
            let start = usize::from(cur_offset);
            d[start..start + rec.len()].copy_from_slice(rec);
            write_tag(&mut d, page_size, tag_idx, cur_offset, rec_size);
            cur_offset += rec_size;
        }
        d
    }

    fn write_tag(page: &mut [u8], page_size: usize, tag_idx: usize, offset: u16, size: u16) {
        let raw: u32 = (u32::from(offset) & 0x7FFF) | ((u32::from(size) & 0x7FFF) << 16);
        let pos = page_size - (tag_idx + 1) * 4;
        page[pos..pos + 4].copy_from_slice(&raw.to_le_bytes());
    }

    #[test]
    fn tags_count_matches_header() {
        // 2 data records => tag_count = 3 (tag0 + 2 data tags)
        let data = make_page_with_records(4096, &[b"hello", b"world"]);
        let page = EsePage {
            page_number: 1,
            data,
        };
        let tags = page.tags().expect("tags");
        assert_eq!(tags.len(), 3);
    }

    #[test]
    fn tags_first_record_offset_and_size() {
        let data = make_page_with_records(4096, &[b"AAAA", b"BBBB"]);
        let page = EsePage {
            page_number: 1,
            data,
        };
        let tags = page.tags().expect("tags");
        // tag 1 is first data record starting at offset 40, size 4
        assert_eq!(tags[1], (40, 4));
    }

    #[test]
    fn record_data_first_matches() {
        let data = make_page_with_records(4096, &[b"AAAA", b"BBBB"]);
        let page = EsePage {
            page_number: 1,
            data,
        };
        let rec = page.record_data(1).expect("record 1");
        assert_eq!(rec, b"AAAA");
    }

    #[test]
    fn record_data_second_matches() {
        let data = make_page_with_records(4096, &[b"AAAA", b"BBBB"]);
        let page = EsePage {
            page_number: 1,
            data,
        };
        let rec = page.record_data(2).expect("record 2");
        assert_eq!(rec, b"BBBB");
    }

    #[test]
    fn record_data_beyond_count_returns_err() {
        let data = make_page_with_records(4096, &[b"X", b"Y"]);
        let page = EsePage {
            page_number: 1,
            data,
        };
        let result = page.record_data(5);
        assert!(result.is_err(), "index beyond tag count must return Err");
    }
}
