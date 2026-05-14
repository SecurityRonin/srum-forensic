//! [`NetworkUsageRecord`] binary decoder.
//!
//! Supports two wire formats, distinguished by record length:
//!
//! **Synthetic (32 bytes)** — used by test fixtures:
//! - `[0..8]`:   `filetime` (u64) — Windows FILETIME (100ns ticks since 1601-01-01)
//! - `[8..12]`:  `app_id` (i32)
//! - `[12..16]`: `user_id` (i32)
//! - `[16..24]`: `bytes_sent` (u64)
//! - `[24..32]`: `bytes_recv` (u64)
//!
//! **Real ESE per-record delta (>32 bytes)** — produced by Windows SRUDB.dat.
//! Each record is the delta between consecutive tag end-positions on a cumulative
//! B-tree leaf page.  Layout (all little-endian):
//! - `[0..2]`:            `cbCommonKeyPrefix` (u16) — shared prefix bytes with previous key
//! - `[2..2+(16-pfx)]`:   key suffix (`16 - cbCommonKeyPrefix` bytes; total key = 16 bytes)
//! - `[col..col+4]`:      unknown (4 bytes); `col = 18 - cbCommonKeyPrefix`
//! - `[col+4..col+8]`:    `AutoIncId` (u32)
//! - `[col+8..col+16]`:   timestamp as OLE Automation Date (f64, days since 1899-12-30)
//! - `[col+16..col+20]`:  `AppId` (i32)
//! - `[col+20..col+24]`:  `UserId` (i32)
//! - `[col+24..col+40]`:  flags / unknown (16 bytes)
//! - `[col+40..col+48]`:  `BytesSent` (u64)
//! - `[col+48..col+56]`:  `BytesRecvd` (u64)

use srum_core::{filetime_to_datetime, ole_date_to_datetime, NetworkUsageRecord, NETWORK_RECORD_SIZE};

use crate::SrumError;

/// ESE network table total key length (verified across 96 records in chainsaw_SRUDB.dat).
const ESE_KEY_LEN: usize = 16;

/// Decode one raw record into a [`NetworkUsageRecord`].
///
/// Detects format by length: 32 bytes → synthetic FILETIME format;
/// >32 bytes → real ESE per-record delta with OLE date.
///
/// # Errors
///
/// Returns [`SrumError::DecodeError`] if `data` is too short or contains
/// an invalid `cbCommonKeyPrefix` value.
pub fn decode_network_record(
    data: &[u8],
    page: u32,
    tag: usize,
) -> Result<NetworkUsageRecord, SrumError> {
    if data.len() < NETWORK_RECORD_SIZE {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "network record too short: {} < {NETWORK_RECORD_SIZE}",
                data.len()
            ),
        });
    }

    if data.len() == NETWORK_RECORD_SIZE {
        // Synthetic 32-byte fixture format
        let filetime = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let app_id = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let user_id = i32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let bytes_sent = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);
        let bytes_recv = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
        return Ok(NetworkUsageRecord {
            timestamp: filetime_to_datetime(filetime),
            app_id,
            user_id,
            bytes_sent,
            bytes_recv,
            auto_inc_id: page,
        });
    }

    // Real ESE per-record delta format (data.len() > 32)
    // col_start = 2 (cbPfx field) + key_suffix_len = 2 + (ESE_KEY_LEN - cbPfx)
    let cb_pfx = u16::from_le_bytes([data[0], data[1]]) as usize;
    if cb_pfx > ESE_KEY_LEN {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("invalid cbCommonKeyPrefix {cb_pfx} > {ESE_KEY_LEN}"),
        });
    }
    let col_start = 2 + (ESE_KEY_LEN - cb_pfx);
    let need = col_start + 56;
    if data.len() < need {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "network delta too short: need {need}, got {}",
                data.len()
            ),
        });
    }

    let auto_inc_id = u32::from_le_bytes([
        data[col_start + 4], data[col_start + 5], data[col_start + 6], data[col_start + 7],
    ]);
    let ole_date = f64::from_le_bytes([
        data[col_start + 8],  data[col_start + 9],  data[col_start + 10], data[col_start + 11],
        data[col_start + 12], data[col_start + 13], data[col_start + 14], data[col_start + 15],
    ]);
    let app_id = i32::from_le_bytes([
        data[col_start + 16], data[col_start + 17], data[col_start + 18], data[col_start + 19],
    ]);
    let user_id = i32::from_le_bytes([
        data[col_start + 20], data[col_start + 21], data[col_start + 22], data[col_start + 23],
    ]);
    let bytes_sent = u64::from_le_bytes([
        data[col_start + 40], data[col_start + 41], data[col_start + 42], data[col_start + 43],
        data[col_start + 44], data[col_start + 45], data[col_start + 46], data[col_start + 47],
    ]);
    let bytes_recv = u64::from_le_bytes([
        data[col_start + 48], data[col_start + 49], data[col_start + 50], data[col_start + 51],
        data[col_start + 52], data[col_start + 53], data[col_start + 54], data[col_start + 55],
    ]);

    Ok(NetworkUsageRecord {
        timestamp: ole_date_to_datetime(ole_date),
        app_id,
        user_id,
        bytes_sent,
        bytes_recv,
        auto_inc_id,
    })
}
