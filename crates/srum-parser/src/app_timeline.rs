//! [`AppTimelineRecord`] binary decoder — supports both real ESE and synthetic fixture formats.
//!
//! **Synthetic fixture layout** (32 bytes, all LE):
//! - `[0..8]`:   `filetime` (u64) — Windows FILETIME
//! - `[8..12]`:  `app_id` (i32)
//! - `[12..16]`: `user_id` (i32)
//! - `[16..24]`: `focus_time_ms` (u64)
//! - `[24..32]`: `user_input_time_ms` (u64)
//!
//! **Real ESE raw-tag layout** (`cbCommonKeyPrefix | key_suffix | col_data`):
//! - `[0..2]`:           `cbCommonKeyPrefix` (u16 LE)
//! - `[2..2+(28-pfx)]`:  key suffix (KEY_LEN=28 for `{7ACBBAA3-…}`)
//! - `col_start = 2 + (28 - cb_pfx)`:
//!   - `[col_start+0..+4]`:  ESE record header (`07 80 …`)
//!   - `[col_start+4..+8]`:  `AutoIncId` (i32 LE)
//!   - `[col_start+8..+16]`: `TimeStamp` as OLE Automation Date (f64 LE)
//!   - `[col_start+16..+20]`: `AppId` (i32 LE)
//!   - `[col_start+20..+24]`: `UserId` (i32 LE)
//!
//! Real ESE records always have `data.len() > 32`, so `== 32` is unambiguously
//! the synthetic fixture path.

use srum_core::{ole_date_to_datetime, AppTimelineRecord, APP_TIMELINE_RECORD_SIZE};

use crate::SrumError;

/// KEY_LEN for the `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}` AppTimeline table.
const ESE_KEY_LEN: usize = 28;

/// Byte offset from col_start to the OLE Automation Date (f64) TimeStamp field.
const COL_TIMESTAMP_OFF: usize = 8;

/// Byte offset from col_start to the AppId (i32) field.
const COL_APP_ID_OFF: usize = 16;

/// Byte offset from col_start to the UserId (i32) field.
const COL_USER_ID_OFF: usize = 20;

/// Decode one raw record into an [`AppTimelineRecord`].
///
/// Records with `data.len() == 32` are treated as synthetic fixtures.
/// Records with `data.len() > 32` are treated as real ESE raw-tag format.
///
/// # Errors
///
/// Returns [`SrumError::DecodeError`] if `data` is shorter than the minimum
/// required for the detected format, or if the key prefix exceeds KEY_LEN.
pub fn decode_app_timeline_record(
    data: &[u8],
    page: u32,
    tag: usize,
) -> Result<AppTimelineRecord, SrumError> {
    if data.len() == APP_TIMELINE_RECORD_SIZE {
        return decode_synthetic(data, page, tag);
    }
    if data.len() > APP_TIMELINE_RECORD_SIZE {
        return decode_real_ese(data, page, tag);
    }
    Err(SrumError::DecodeError {
        page,
        tag,
        detail: format!(
            "app timeline record too short: {} < {APP_TIMELINE_RECORD_SIZE}",
            data.len()
        ),
    })
}

fn decode_real_ese(data: &[u8], page: u32, tag: usize) -> Result<AppTimelineRecord, SrumError> {
    if data.len() < 2 {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: "app timeline real ESE record too short for cbCommonKeyPrefix".to_string(),
        });
    }
    let cb_pfx = u16::from_le_bytes([data[0], data[1]]) as usize;
    if cb_pfx > ESE_KEY_LEN {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "app timeline cb_pfx={cb_pfx} exceeds KEY_LEN={ESE_KEY_LEN}"
            ),
        });
    }
    let col_start = 2 + (ESE_KEY_LEN - cb_pfx);
    let need = col_start + COL_USER_ID_OFF + 4;
    if data.len() < need {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "app timeline real ESE record truncated: len={}, need >= {need}",
                data.len()
            ),
        });
    }

    let ts_off = col_start + COL_TIMESTAMP_OFF;
    let timestamp_raw = f64::from_le_bytes([
        data[ts_off],
        data[ts_off + 1],
        data[ts_off + 2],
        data[ts_off + 3],
        data[ts_off + 4],
        data[ts_off + 5],
        data[ts_off + 6],
        data[ts_off + 7],
    ]);
    let timestamp = ole_date_to_datetime(timestamp_raw);

    let app_off = col_start + COL_APP_ID_OFF;
    let app_id = i32::from_le_bytes([
        data[app_off],
        data[app_off + 1],
        data[app_off + 2],
        data[app_off + 3],
    ]);

    let usr_off = col_start + COL_USER_ID_OFF;
    let user_id = i32::from_le_bytes([
        data[usr_off],
        data[usr_off + 1],
        data[usr_off + 2],
        data[usr_off + 3],
    ]);

    Ok(AppTimelineRecord {
        timestamp,
        app_id,
        user_id,
        focus_time_ms: 0,
        user_input_time_ms: 0,
    })
}

fn decode_synthetic(data: &[u8], page: u32, tag: usize) -> Result<AppTimelineRecord, SrumError> {
    if data.len() < APP_TIMELINE_RECORD_SIZE {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "app timeline record too short: {} < {APP_TIMELINE_RECORD_SIZE}",
                data.len()
            ),
        });
    }
    let filetime = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let app_id = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let user_id = i32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let focus_time_ms = u64::from_le_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let user_input_time_ms = u64::from_le_bytes([
        data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
    ]);
    Ok(AppTimelineRecord {
        timestamp: srum_core::filetime_to_datetime(filetime),
        app_id,
        user_id,
        focus_time_ms,
        user_input_time_ms,
    })
}
