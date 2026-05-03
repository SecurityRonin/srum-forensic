//! ESE (Extensible Storage Engine) database reader foundation.
//!
//! Provides low-level access to ESE/JET Blue database files such as
//! `SRUDB.dat`, `WebCacheV01.dat`, and Active Directory's `ntds.dit`.

pub mod catalog;
pub mod database;
pub mod error;
pub mod header;
pub mod page;

pub use catalog::CatalogEntry;
pub use database::EseDatabase;
pub use error::EseError;
pub use header::EseHeader;
pub use page::{EsePage, EsePageHeader, PAGE_FLAG_EMPTY, PAGE_FLAG_LEAF, PAGE_FLAG_PARENT, PAGE_FLAG_ROOT, PAGE_FLAG_SPACE_TREE};

/// Open an ESE database file and return the parsed header.
///
/// # Errors
///
/// Returns [`EseError`] if the file cannot be read or is not a valid ESE database.
pub fn open(path: &std::path::Path) -> Result<EseHeader, EseError> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; EseHeader::SIZE];
    let n = f.read(&mut buf)?;
    if n < EseHeader::SIZE {
        return Err(EseError::TooShort {
            need: EseHeader::SIZE,
            got: n,
        });
    }
    EseHeader::from_bytes(&buf)
}

/// Open an ESE database file and return a [`EseDatabase`] for page-level access.
///
/// This is the primary entry point for reading records. Use [`open`] only
/// when you just need to validate the header.
///
/// # Errors
///
/// Returns [`EseError`] if the file cannot be read or is not a valid ESE database.
pub fn open_database(path: &std::path::Path) -> Result<EseDatabase, EseError> {
    EseDatabase::open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    /// Build a minimal valid ESE file in a temp file.
    ///
    /// `extra_pages` controls how many data pages (beyond the header page)
    /// are appended. Each data page's first byte is set to its 1-based page
    /// number so tests can verify the correct page was returned.
    fn make_test_ese_file(extra_pages: usize) -> NamedTempFile {
        let page_size: usize = 4096;
        let mut buf = vec![0u8; page_size * (1 + extra_pages)];
        // Header page: ESE magic at offset 4
        buf[4..8].copy_from_slice(&0x89AB_CDEF_u32.to_le_bytes());
        // page_size field at offset 0xEC = 236
        buf[236..240].copy_from_slice(&(page_size as u32).to_le_bytes());
        // Each data page: first byte = 1-based page number for easy identification
        for i in 0..extra_pages {
            buf[page_size * (i + 1)] = (i + 1) as u8;
        }
        let mut tmp = NamedTempFile::new().expect("tempfile");
        tmp.write_all(&buf).expect("write test ESE file");
        tmp
    }

    // ── EseDatabase::open ────────────────────────────────────────────────────

    #[test]
    fn database_open_valid_ese_file_succeeds() {
        let tmp = make_test_ese_file(0);
        let db = EseDatabase::open(tmp.path()).expect("should open valid ESE file");
        assert_eq!(db.header.page_size, 4096);
    }

    #[test]
    fn database_open_nonexistent_returns_err() {
        let result = EseDatabase::open(std::path::Path::new("/nonexistent/x.dat"));
        assert!(result.is_err());
    }

    #[test]
    fn database_open_empty_file_returns_err() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let result = EseDatabase::open(tmp.path());
        assert!(result.is_err());
    }

    // ── EseDatabase::read_page ───────────────────────────────────────────────

    #[test]
    fn database_read_page_1_returns_correct_data() {
        // 2 extra data pages; page 1's first byte should be 1
        let tmp = make_test_ese_file(2);
        let db = EseDatabase::open(tmp.path()).expect("open");
        let page = db.read_page(1).expect("read page 1");
        assert_eq!(page.page_number, 1);
        assert_eq!(page.data.len(), 4096);
        assert_eq!(page.data[0], 1u8, "first byte of page 1 should be 1");
    }

    #[test]
    fn database_read_page_2_returns_correct_data() {
        let tmp = make_test_ese_file(2);
        let db = EseDatabase::open(tmp.path()).expect("open");
        let page = db.read_page(2).expect("read page 2");
        assert_eq!(page.page_number, 2);
        assert_eq!(page.data[0], 2u8, "first byte of page 2 should be 2");
    }

    #[test]
    fn database_read_page_beyond_eof_returns_err() {
        // Only 1 data page exists (page 1); reading page 5 should fail
        let tmp = make_test_ese_file(1);
        let db = EseDatabase::open(tmp.path()).expect("open");
        let result = db.read_page(5);
        assert!(result.is_err(), "page beyond EOF must return Err");
    }

    // ── EseDatabase::page_count ──────────────────────────────────────────────

    #[test]
    fn database_page_count_header_only() {
        let tmp = make_test_ese_file(0); // header only = 1 page
        let db = EseDatabase::open(tmp.path()).expect("open");
        assert_eq!(db.page_count(), 1u64);
    }

    #[test]
    fn database_page_count_with_data_pages() {
        let tmp = make_test_ese_file(3); // header + 3 data pages = 4 total
        let db = EseDatabase::open(tmp.path()).expect("open");
        assert_eq!(db.page_count(), 4u64);
    }

    #[test]
    fn open_nonexistent_returns_err() {
        let result = open(std::path::Path::new("/nonexistent/SRUDB.dat"));
        assert!(result.is_err(), "opening nonexistent file must return Err");
    }

    #[test]
    fn open_empty_file_returns_err() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let result = open(tmp.path());
        assert!(result.is_err(), "empty file must return Err (too short)");
    }

    #[test]
    fn ese_header_has_page_size_field() {
        // Construct a minimal valid ESE header buffer
        let mut buf = vec![0u8; 4096];
        // Signature at offset 4
        buf[4..8].copy_from_slice(&0x89AB_CDEF_u32.to_le_bytes());
        // Page size at offset 236 (0xEC): set to 4096
        buf[236..240].copy_from_slice(&4096_u32.to_le_bytes());
        let header = EseHeader::from_bytes(&buf).expect("valid header");
        assert_eq!(header.page_size, 4096);
    }

    #[test]
    fn ese_page_has_page_number() {
        let page = EsePage {
            page_number: 42,
            flags: 0,
            data: vec![],
        };
        assert_eq!(page.page_number, 42);
    }

    #[test]
    fn ese_error_implements_display() {
        let err = EseError::TooShort { need: 4096, got: 0 };
        let msg = format!("{err}");
        assert!(msg.contains("too short"));
    }
}
