//! ESE (Extensible Storage Engine) database reader foundation.
//!
//! Provides low-level access to ESE/JET Blue database files such as
//! `SRUDB.dat`, `WebCacheV01.dat`, and Active Directory's `ntds.dit`.

pub mod error;
pub mod header;
pub mod page;

pub use error::EseError;
pub use header::EseHeader;
pub use page::EsePage;

/// Open an ESE database file and return the parsed header.
///
/// # Errors
///
/// Returns [`EseError`] if the file cannot be read or is not a valid ESE database.
pub fn open(path: &std::path::Path) -> Result<EseHeader, EseError> {
    todo!("implement ESE header parsing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

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
