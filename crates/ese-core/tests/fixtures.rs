//! Synthetic ESE database fixture builder for integration tests.
//!
//! Builds minimal valid ESE binary buffers that can be written to temp files
//! and opened with [`ese_core::EseDatabase::open`].

use ese_core::page::{PAGE_FLAG_LEAF, PAGE_FLAG_PARENT, PAGE_FLAG_ROOT};
use ese_core::CatalogEntry;
use std::io::Write as _;
use tempfile::NamedTempFile;

pub const PAGE_SIZE: usize = 4096;

/// Write a 32-bit LE value into a byte slice at the given offset.
pub fn put_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// Write a 16-bit LE value into a byte slice at the given offset.
pub fn put_u16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

/// Write a tag into the page (tag array grows from end downward).
///
/// Tag format: bits 0-14 = `value_offset`, bit 15 = flag,
///             bits 16-30 = `value_size`, bit 31 = flag.
pub fn write_tag(page: &mut [u8], tag_idx: usize, value_offset: u16, value_size: u16) {
    let raw: u32 = (u32::from(value_offset) & 0x7FFF) | ((u32::from(value_size) & 0x7FFF) << 16);
    let pos = PAGE_SIZE - (tag_idx + 1) * 4;
    page[pos..pos + 4].copy_from_slice(&raw.to_le_bytes());
}

/// Build a minimal valid ESE header page (page 0).
pub fn make_ese_header_page() -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    // ESE magic signature at offset 4
    put_u32(&mut page, 4, 0x89AB_CDEF);
    // page_size at offset 0xEC = 236
    put_u32(&mut page, 236, u32::try_from(PAGE_SIZE).unwrap());
    page
}

/// Build a leaf page containing the given raw record byte slices.
///
/// Tag 0 = page header tag (offset=0, size=40).
/// Tags 1..n = record slices, packed starting at offset 40.
pub fn make_leaf_page_with_records(flags_extra: u32, records: &[Vec<u8>]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    let tag_count = u16::try_from(1 + records.len()).unwrap_or(u16::MAX);
    let page_flags = PAGE_FLAG_LEAF | flags_extra;

    // Page header fields
    put_u16(&mut page, 0x1E, tag_count);
    put_u32(&mut page, 0x20, page_flags);
    // prev/next = none
    put_u32(&mut page, 0x0C, 0xFFFF_FFFF);
    put_u32(&mut page, 0x10, 0xFFFF_FFFF);

    // Tag 0: page header (offset=0, size=40)
    write_tag(&mut page, 0, 0, 40);

    // Pack records starting at offset 40
    let mut cur_offset: u16 = 40;
    for (i, rec) in records.iter().enumerate() {
        let tag_idx = i + 1;
        let rec_size = u16::try_from(rec.len()).unwrap_or(u16::MAX);
        let start = usize::from(cur_offset);
        page[start..start + rec.len()].copy_from_slice(rec);
        write_tag(&mut page, tag_idx, cur_offset, rec_size);
        cur_offset += rec_size;
    }

    page
}

/// Build a parent (internal B-tree node) page whose child pointers point to
/// the given page numbers.
///
/// Each child reference is encoded as an 8-byte record:
/// - 4 bytes: child page number (u32 LE)
/// - 4 bytes: padding zeros
#[allow(dead_code)] // used by upcoming btree-walk tests
pub fn make_parent_page_with_children(children: &[u32]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    let tag_count = u16::try_from(1 + children.len()).unwrap_or(u16::MAX);
    let page_flags = PAGE_FLAG_PARENT | PAGE_FLAG_ROOT;

    put_u16(&mut page, 0x1E, tag_count);
    put_u32(&mut page, 0x20, page_flags);
    put_u32(&mut page, 0x0C, 0xFFFF_FFFF);
    put_u32(&mut page, 0x10, 0xFFFF_FFFF);

    // Tag 0: page header
    write_tag(&mut page, 0, 0, 40);

    // Each child record: 8 bytes with child page number
    let mut cur_offset: u16 = 40;
    for (i, &child_page) in children.iter().enumerate() {
        let tag_idx = i + 1;
        let start = usize::from(cur_offset);
        put_u32(&mut page, start, child_page);
        // size 8 (4 page_num + 4 padding)
        write_tag(&mut page, tag_idx, cur_offset, 8);
        cur_offset += 8;
    }

    page
}

/// Write a complete multi-page ESE file to a temp file.
///
/// `pages[0]` is the header page (page 0); subsequent entries are data pages.
pub fn write_ese_file(pages: &[Vec<u8>]) -> NamedTempFile {
    let mut tmp = NamedTempFile::new().expect("tempfile");
    for page in pages {
        tmp.write_all(page).expect("write page");
    }
    tmp
}

/// Build a single-page ESE database with a catalog leaf page at page 4.
///
/// Returns a `NamedTempFile` with pages: `[header, 1, 2, 3, catalog_leaf]`.
/// The catalog page is a leaf containing the given catalog entries.
#[allow(dead_code)] // used by catalog integration tests
pub fn make_ese_with_catalog(entries: &[CatalogEntry]) -> NamedTempFile {
    let records: Vec<Vec<u8>> = entries.iter().map(CatalogEntry::to_bytes).collect();
    let catalog_page = make_leaf_page_with_records(0, &records);

    // Pages 0-3: header + 3 padding pages; page 4 = catalog
    let header = make_ese_header_page();
    let padding = vec![0u8; PAGE_SIZE];
    write_ese_file(&[
        header,
        padding.clone(), // page 1
        padding.clone(), // page 2
        padding.clone(), // page 3
        catalog_page,    // page 4
    ])
}
