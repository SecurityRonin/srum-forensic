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
