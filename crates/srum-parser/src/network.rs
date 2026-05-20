//! [`NetworkUsageRecord`] binary decoder — real ESE raw-tag format only.
//!
//! **Real ESE per-record layout** — produced by Windows SRUDB.dat.
//! Layout (all little-endian):
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

use srum_core::{ole_date_to_datetime, NetworkUsageRecord};

use crate::SrumError;

/// ESE network table total key length (verified across 96 records in chainsaw_SRUDB.dat).
const ESE_KEY_LEN: usize = 16;

pub fn decode_network_record(
    data: &[u8],
    page: u32,
    tag: usize,
) -> Result<NetworkUsageRecord, SrumError> {
    if data.len() < 2 {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("network record too short: {}", data.len()),
        });
    }

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
            detail: format!("network delta too short: need {need}, got {}", data.len()),
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
