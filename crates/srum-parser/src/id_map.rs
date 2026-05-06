//! [`IdMapEntry`] binary decoder.
//!
//! Decodes the 6+N-byte wire format used in test fixtures.
//!
//! Binary layout:
//! - `[0..4]`:  `id` (i32 LE)
//! - `[4..6]`:  `name_utf16le_byte_len` (u16 LE) — byte length of the UTF-16LE name
//! - `[6..]`:   `name` encoded as UTF-16LE bytes
//!
//! This matches the real SRUDB.dat encoding where app paths are stored as
//! UTF-16LE (the native Windows string encoding).

use srum_core::{IdMapEntry, ID_MAP_MIN_SIZE};

use crate::SrumError;

/// Decode one `IdMapEntry` record from raw bytes.
///
/// # Errors
///
/// Returns [`SrumError::DecodeError`] if the slice is too short or the
/// UTF-16LE name bytes contain an invalid surrogate pair.
pub fn decode_id_map_entry(data: &[u8], page: u32, tag: usize) -> Result<IdMapEntry, SrumError> {
    if data.len() < ID_MAP_MIN_SIZE {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "id-map record too short: {} < {ID_MAP_MIN_SIZE}",
                data.len()
            ),
        });
    }
    let id = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let name_byte_len = u16::from_le_bytes([data[4], data[5]]) as usize;
    let total = ID_MAP_MIN_SIZE + name_byte_len;
    if data.len() < total {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "id-map record name truncated: need {total}, got {}",
                data.len()
            ),
        });
    }
    let name_bytes = &data[6..6 + name_byte_len];
    let utf16_units: Vec<u16> = name_bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let name = char::decode_utf16(utf16_units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>();
    Ok(IdMapEntry { id, name })
}
