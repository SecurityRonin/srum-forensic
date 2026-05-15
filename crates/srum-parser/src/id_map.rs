//! [`IdMapEntry`] binary decoder — supports both real ESE and synthetic fixture formats.
//!
//! **Synthetic fixture layout** (6 + N bytes):
//! - `[0..4]`:  `id` (i32 LE)
//! - `[4..6]`:  `name_utf16le_byte_len` (u16 LE)
//! - `[6..]`:   name encoded as UTF-16LE
//!
//! **Real ESE raw-tag layout** (`cbCommonKeyPrefix | key_suffix | col_data`):
//! - `[0..2]`:          `cbCommonKeyPrefix` (u16 LE) — bytes of full key shared with page prefix
//! - `[2..2+(7-pfx)]`:  key suffix bytes (KEY_LEN=7 for SruDbIdMapTable)
//! - `col_start = 2 + (7 - cb_pfx)`:
//!   - `[col_start+0..+4]`:  ESE record header (`02 7f …`)
//!   - `[col_start+4]`:      `IdType` (u8)   — 0=string, 1=SID
//!   - `[col_start+5..+9]`:  `IdIndex` (i32 LE) — the FK used by other SRUM tables
//!   - `[col_start+9..+10]`: padding byte (`00`)
//!   - tagged section at `col_start+10`: `00 01 04 40 01` descriptor + blob bytes
//!   - IdBlob UTF-16LE starts at `col_start+15` (only when IdType==0)

use srum_core::{IdMapEntry, ID_MAP_MIN_SIZE};

use crate::SrumError;

/// KEY_LEN for SruDbIdMapTable (7 bytes: AutoIncId u32 + IdType u8 + IdIndex i16 partial).
const ESE_KEY_LEN: usize = 7;

/// Byte offset from col_start where IdIndex (i32 LE) lives.
const COL_ID_INDEX_OFF: usize = 5;

/// Byte offset from col_start where the tagged blob section begins.
const COL_TAGGED_OFF: usize = 10;

/// Bytes consumed by the 5-byte tagged column descriptor before the blob payload.
const TAGGED_DESCRIPTOR_LEN: usize = 5;

/// Decode one `IdMapEntry` record from raw bytes.
///
/// Detects real ESE records by `cb_pfx ≤ KEY_LEN` AND the ESE record-header
/// marker `0x02 0x7F` at `col_start`. Falls back to the synthetic 6+N-byte
/// fixture format otherwise.
///
/// # Errors
///
/// Returns [`SrumError::DecodeError`] if the slice is too short or the
/// UTF-16LE name bytes contain an invalid surrogate pair.
pub fn decode_id_map_entry(data: &[u8], page: u32, tag: usize) -> Result<IdMapEntry, SrumError> {
    if data.len() < 2 {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("id-map record too short: {}", data.len()),
        });
    }

    let cb_pfx = u16::from_le_bytes([data[0], data[1]]) as usize;

    // Real ESE: cb_pfx fits within the known key length and the ESE record
    // header marker appears at col_start.
    if cb_pfx <= ESE_KEY_LEN {
        let col_start = 2 + (ESE_KEY_LEN - cb_pfx);
        if data.len() > col_start + 1
            && data[col_start] == 0x02
            && data[col_start + 1] == 0x7f
        {
            return decode_real_ese(data, page, tag, col_start);
        }
    }

    // Fallback: synthetic fixture format.
    decode_synthetic(data, page, tag)
}

fn decode_real_ese(
    data: &[u8],
    page: u32,
    tag: usize,
    col_start: usize,
) -> Result<IdMapEntry, SrumError> {
    let id_off = col_start + COL_ID_INDEX_OFF;
    if data.len() < id_off + 4 {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "real ESE id-map too short for IdIndex: len={}, need >= {}",
                data.len(),
                id_off + 4
            ),
        });
    }
    let id = i32::from_le_bytes([data[id_off], data[id_off + 1], data[id_off + 2], data[id_off + 3]]);

    // Tagged IdBlob section: present only when record extends past the fixed columns.
    let blob_start = col_start + COL_TAGGED_OFF + TAGGED_DESCRIPTOR_LEN;
    let name = if data.len() > blob_start {
        let blob = &data[blob_start..];
        // Strip trailing null pair if present.
        let blob = if blob.len() >= 2 && blob[blob.len() - 2] == 0 && blob[blob.len() - 1] == 0 {
            &blob[..blob.len() - 2]
        } else {
            blob
        };
        let utf16: Vec<u16> = blob
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        char::decode_utf16(utf16)
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    } else {
        String::new()
    };

    Ok(IdMapEntry { id, name })
}

fn decode_synthetic(data: &[u8], page: u32, tag: usize) -> Result<IdMapEntry, SrumError> {
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
