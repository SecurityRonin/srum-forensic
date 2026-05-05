//! ESE error types.

/// Errors that can occur when reading an ESE database.
#[derive(Debug, thiserror::Error)]
pub enum EseError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("file too short: need at least {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },
    #[error("invalid ESE signature: expected 0x89ABCDEF, got {0:#010x}")]
    BadSignature(u32),
    #[error("unsupported page size: {0}")]
    UnsupportedPageSize(u32),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid record: {0}")]
    InvalidRecord(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ese_error_invalid_magic_display() {
        let err = EseError::InvalidMagic { page: 0, found: 0xDEAD_BEEF };
        assert!(format!("{err}").contains("invalid magic"));
    }

    #[test]
    fn ese_error_record_too_short_display() {
        let err = EseError::RecordTooShort { page: 7, tag: 2, got: 10, need: 32 };
        assert!(format!("{err}").contains("record too short"));
        assert!(format!("{err}").contains("10 < 32"));
    }

    #[test]
    fn ese_error_tag_array_overflow_display() {
        let err = EseError::TagArrayOverflow { page: 5 };
        assert!(format!("{err}").contains("tag array"));
    }

    #[test]
    fn ese_error_table_not_found_display() {
        let err = EseError::TableNotFound { name: "MyTable".into() };
        assert!(format!("{err}").contains("MyTable"));
    }

    #[test]
    fn ese_error_corrupt_display() {
        let err = EseError::Corrupt { page: 3, detail: "something bad".into() };
        assert!(format!("{err}").contains("page 3"));
        assert!(format!("{err}").contains("something bad"));
    }
}
