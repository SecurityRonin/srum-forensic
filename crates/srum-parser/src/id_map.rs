//! [`IdMapEntry`] binary decoder — real ESE raw-tag format only.
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

use srum_core::IdMapEntry;

use crate::SrumError;

/// KEY_LEN for SruDbIdMapTable (7 bytes: AutoIncId u32 + IdType u8 + IdIndex i16 partial).
const ESE_KEY_LEN: usize = 7;

/// Byte offset from col_start where IdIndex (i32 LE) lives.
const COL_ID_INDEX_OFF: usize = 5;

/// Byte offset from col_start where the tagged blob section begins.
const COL_TAGGED_OFF: usize = 10;

/// Bytes consumed by the 5-byte tagged column descriptor before the blob payload.
const TAGGED_DESCRIPTOR_LEN: usize = 5;

pub fn decode_id_map_entry(data: &[u8], page: u32, tag: usize) -> Result<IdMapEntry, SrumError> {
    if data.len() < 2 {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("id-map record too short: {}", data.len()),
        });
    }

    let cb_pfx = u16::from_le_bytes([data[0], data[1]]) as usize;
    if cb_pfx > ESE_KEY_LEN {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("id-map cb_pfx={cb_pfx} exceeds KEY_LEN={ESE_KEY_LEN}"),
        });
    }

    let col_start = 2 + (ESE_KEY_LEN - cb_pfx);
    if data.len() < col_start + 2 || data[col_start] != 0x02 || data[col_start + 1] != 0x7f {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "id-map record missing ESE header marker at col_start={col_start}: len={}",
                data.len()
            ),
        });
    }

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

    let blob_start = col_start + COL_TAGGED_OFF + TAGGED_DESCRIPTOR_LEN;
    let name = if data.len() > blob_start {
        let blob = &data[blob_start..];
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
