//! Synthetic page fixtures for ese-carver fragment tests.
#![allow(dead_code)]

pub const PAGE_SIZE: usize = 4096;

fn put_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn put_u16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

/// Write a tag into the tag array (grows from page end downward).
/// Layout: low 15 bits = value_offset, high 15 bits = value_size.
fn write_tag(page: &mut [u8], tag_idx: usize, value_offset: u16, value_size: u16) {
    let raw: u32 =
        (u32::from(value_offset) & 0x7FFF) | ((u32::from(value_size) & 0x7FFF) << 16);
    let pos = PAGE_SIZE - (tag_idx + 1) * 4;
    page[pos..pos + 4].copy_from_slice(&raw.to_le_bytes());
}

/// Build an ESE header page (page 0). All data pages follow after this.
pub fn make_header_page() -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    put_u32(&mut page, 4, 0x89AB_CDEF); // ESE magic
    put_u32(&mut page, 236, u32::try_from(PAGE_SIZE).unwrap()); // page_size
    put_u32(&mut page, 0x28, 3); // db_state = CleanShutdown
    page
}

/// Build a data page that holds a single contiguous record of `data_bytes`
/// length (no fragmentation — the record fits entirely in this page).
pub fn make_complete_page(data: &[u8]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    put_u32(&mut page, 0x20, ese_core::PAGE_FLAG_LEAF);
    put_u32(&mut page, 0x0C, 0xFFFF_FFFF);
    put_u32(&mut page, 0x10, 0xFFFF_FFFF);
    // tag0 (page header at offset 0, size 40) + tag1 (record)
    put_u16(&mut page, 0x1E, 2);
    write_tag(&mut page, 0, 0, 40);
    let offset = 40u16;
    let size = u16::try_from(data.len()).expect("data too large");
    write_tag(&mut page, 1, offset, size);
    page[usize::from(offset)..usize::from(offset) + data.len()].copy_from_slice(data);
    page
}

/// Build two pages where a record of `expected_size` is split:
/// - `prefix` bytes in the **last tag** of page A
/// - `suffix` bytes in the **first data tag** (tag 1) of page B
///
/// Returns `(page_a_bytes, page_b_bytes)`.
pub fn make_split_pages(prefix: &[u8], suffix: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Page A: tag0 (header) + tag1 (prefix record)
    let mut page_a = vec![0u8; PAGE_SIZE];
    put_u32(&mut page_a, 0x20, ese_core::PAGE_FLAG_LEAF);
    put_u32(&mut page_a, 0x0C, 0xFFFF_FFFF);
    put_u32(&mut page_a, 0x10, 0xFFFF_FFFF);
    put_u16(&mut page_a, 0x1E, 2);
    write_tag(&mut page_a, 0, 0, 40);
    let a_offset = 40u16;
    let a_size = u16::try_from(prefix.len()).expect("prefix too large");
    write_tag(&mut page_a, 1, a_offset, a_size);
    page_a[40..40 + prefix.len()].copy_from_slice(prefix);

    // Page B: tag0 (header) + tag1 (suffix record)
    let mut page_b = vec![0u8; PAGE_SIZE];
    put_u32(&mut page_b, 0x20, ese_core::PAGE_FLAG_LEAF);
    put_u32(&mut page_b, 0x0C, 0xFFFF_FFFF);
    put_u32(&mut page_b, 0x10, 0xFFFF_FFFF);
    put_u16(&mut page_b, 0x1E, 2);
    write_tag(&mut page_b, 0, 0, 40);
    let b_offset = 40u16;
    let b_size = u16::try_from(suffix.len()).expect("suffix too large");
    write_tag(&mut page_b, 1, b_offset, b_size);
    page_b[40..40 + suffix.len()].copy_from_slice(suffix);

    (page_a, page_b)
}

/// Build a flat byte slice (header + data pages) with only complete records.
pub fn make_flat_complete(records: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = make_header_page();
    for r in records {
        buf.extend_from_slice(&make_complete_page(r));
    }
    buf
}

/// Build a flat byte slice (header + page_a + page_b) where the record of
/// `expected_size` is split across the two pages.
pub fn make_flat_split(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let (pa, pb) = make_split_pages(prefix, suffix);
    let mut buf = make_header_page();
    buf.extend_from_slice(&pa);
    buf.extend_from_slice(&pb);
    buf
}
