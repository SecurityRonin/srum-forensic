//! ESE catalog reader.
//!
//! The catalog lives at page 4 and maps table names to their root B-tree
//! pages. This implementation uses a synthetic record format suitable for
//! test fixtures.
//!
//! Synthetic catalog record layout (all little-endian):
//!
//! - bytes `0..2`: `object_type` (u16): 1 = table, 2 = column, etc.
//! - bytes `2..6`: `object_id` (u32)
//! - bytes `6..10`: `parent_object_id` (u32)
//! - bytes `10..14`: `table_page` (u32) — root page of this table's B-tree
//! - bytes `14..16`: `name_len` (u16)
//! - bytes `16..`: name bytes (UTF-8)

use crate::EseError;

/// One entry from the ESE catalog.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    /// Object type: 1 = table, 2 = column, etc.
    pub object_type: u16,
    /// Object ID.
    pub object_id: u32,
    /// Parent object ID.
    pub parent_object_id: u32,
    /// Root page number for this table's B-tree.
    pub table_page: u32,
    /// Object name (table name, column name, etc.).
    pub object_name: String,
}

impl CatalogEntry {
    /// Minimum record size.
    pub const MIN_SIZE: usize = 16;

    /// Parse one catalog record from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`EseError::InvalidRecord`] if the slice is too short or
    /// the name bytes are not valid UTF-8.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EseError> {
        if data.len() < Self::MIN_SIZE {
            return Err(EseError::Corrupt {
                page: 0,
                detail: format!("catalog record too short: {} < {}", data.len(), Self::MIN_SIZE),
            });
        }
        let object_type = u16::from_le_bytes([data[0], data[1]]);
        let object_id = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        let parent_object_id = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
        let table_page = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
        let name_len = u16::from_le_bytes([data[14], data[15]]) as usize;
        if data.len() < Self::MIN_SIZE + name_len {
            return Err(EseError::Corrupt {
                page: 0,
                detail: format!(
                    "catalog record name truncated: need {}, got {}",
                    Self::MIN_SIZE + name_len,
                    data.len()
                ),
            });
        }
        let name_bytes = &data[16..16 + name_len];
        let object_name = std::str::from_utf8(name_bytes)
            .map_err(|e| EseError::Corrupt {
                page: 0,
                detail: format!("catalog name not UTF-8: {e}"),
            })?
            .to_owned();
        Ok(Self {
            object_type,
            object_id,
            parent_object_id,
            table_page,
            object_name,
        })
    }

    /// Serialize this entry to bytes (for building test fixtures).
    pub fn to_bytes(&self) -> Vec<u8> {
        let name_bytes = self.object_name.as_bytes();
        let mut out = Vec::with_capacity(Self::MIN_SIZE + name_bytes.len());
        out.extend_from_slice(&self.object_type.to_le_bytes());
        out.extend_from_slice(&self.object_id.to_le_bytes());
        out.extend_from_slice(&self.parent_object_id.to_le_bytes());
        out.extend_from_slice(&self.table_page.to_le_bytes());
        out.extend_from_slice(&(u16::try_from(name_bytes.len()).unwrap_or(u16::MAX)).to_le_bytes());
        out.extend_from_slice(name_bytes);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_entry_roundtrip() {
        let entry = CatalogEntry {
            object_type: 1,
            object_id: 10,
            parent_object_id: 1,
            table_page: 42,
            object_name: "SruDbNetworkTable".to_owned(),
        };
        let bytes = entry.to_bytes();
        let parsed = CatalogEntry::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.object_name, "SruDbNetworkTable");
        assert_eq!(parsed.table_page, 42);
        assert_eq!(parsed.object_type, 1);
    }

    #[test]
    fn catalog_entry_too_short_returns_err() {
        let result = CatalogEntry::from_bytes(&[0u8; 5]);
        assert!(result.is_err());
    }
}
