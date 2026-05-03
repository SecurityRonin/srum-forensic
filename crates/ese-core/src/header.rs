//! ESE database header (first 4096 bytes of the file).

use crate::error::EseError;

/// Parsed ESE database file header.
#[derive(Debug, Clone)]
pub struct EseHeader {
    /// ESE magic: 0x89ABCDEF (little-endian at offset 4).
    pub signature: u32,
    /// Database format version.
    pub format_version: u32,
    /// Page size in bytes (typically 4096 or 8192).
    pub page_size: u32,
    /// Database time (last backup time).
    pub db_time: u64,
}

impl EseHeader {
    /// Size of the ESE header block (first full page).
    pub const SIZE: usize = 4096;

    /// Parse an ESE header from the first 4096 bytes of a database file.
    ///
    /// ESE header layout (all little-endian):
    /// - Offset 0x00 (4 bytes): checksum
    /// - Offset 0x04 (4 bytes): signature (0x89ABCDEF)
    /// - Offset 0x08 (4 bytes): format version
    /// - Offset 0x0C (4 bytes): format revision
    /// - Offset 0xEC (4 bytes): page size (0 means 4096)
    pub fn from_bytes(data: &[u8]) -> Result<Self, EseError> {
        if data.len() < Self::SIZE {
            return Err(EseError::TooShort {
                need: Self::SIZE,
                got: data.len(),
            });
        }
        let sig = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if sig != 0x89AB_CDEF {
            return Err(EseError::BadSignature(sig));
        }
        let format_version = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        // Page size is at offset 0xEC = 236
        let raw_page_size = u32::from_le_bytes([data[236], data[237], data[238], data[239]]);
        let page_size = if raw_page_size == 0 { 4096 } else { raw_page_size };
        Ok(EseHeader {
            signature: sig,
            format_version,
            page_size,
            db_time: 0,
        })
    }
}
