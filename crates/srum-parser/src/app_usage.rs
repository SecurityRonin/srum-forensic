//! [`AppUsageRecord`] binary decoder — supports both real ESE and synthetic fixture formats.
//!
//! **Synthetic fixture layout** (32 bytes, all LE):
//! - `[0..8]`:   `filetime` (u64) — Windows FILETIME
//! - `[8..12]`:  `app_id` (i32)
//! - `[12..16]`: `user_id` (i32)
//! - `[16..24]`: `foreground_cycles` (u64)
//! - `[24..32]`: `background_cycles` (u64)
//!
//! **Real ESE raw-tag layout** (`cbCommonKeyPrefix | key_suffix | col_data`):
//! - `[0..2]`:           `cbCommonKeyPrefix` (u16 LE)
//! - `[2..2+(16-pfx)]`:  key suffix (KEY_LEN=16 for `{5C8CF1C7-…}`)
//! - `col_start = 2 + (16 - cb_pfx)`:
//!   - `[col_start+0..+4]`:  ESE record header
//!   - `[col_start+4..+8]`:  `AutoIncId` (u32 LE) → `auto_inc_id`
//!   - `[col_start+8..+16]`: `TimeStamp` as OLE Automation Date (f64 LE) → `timestamp`
//!   - `[col_start+16..+20]`: `AppId` (i32 LE) → `app_id`
//!   - `[col_start+20..+24]`: `UserId` (i32 LE) → `user_id`
//!   - `foreground_cycles` and `background_cycles` returned as 0 (columns not yet located)

use srum_core::{ole_date_to_datetime, filetime_to_datetime, AppUsageRecord, APP_RECORD_SIZE};

use crate::SrumError;

const ESE_KEY_LEN: usize = 16;
const COL_AUTO_INC_OFF: usize = 4;
const COL_TIMESTAMP_OFF: usize = 8;
const COL_APP_ID_OFF: usize = 16;
const COL_USER_ID_OFF: usize = 20;

pub fn decode_app_record(data: &[u8], page: u32, tag: usize) -> Result<AppUsageRecord, SrumError> {
    if data.len() == APP_RECORD_SIZE {
        return decode_synthetic(data, page, tag);
    }
    if data.len() > APP_RECORD_SIZE {
        return decode_real_ese(data, page, tag);
    }
    Err(SrumError::DecodeError {
        page,
        tag,
        detail: format!("app record too short: {} < {APP_RECORD_SIZE}", data.len()),
    })
}

fn decode_real_ese(data: &[u8], page: u32, tag: usize) -> Result<AppUsageRecord, SrumError> {
    if data.len() < 2 {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: "app_usage real ESE record too short for cbCommonKeyPrefix".to_string(),
        });
    }
    let cb_pfx = u16::from_le_bytes([data[0], data[1]]) as usize;
    if cb_pfx > ESE_KEY_LEN {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("app_usage cb_pfx={cb_pfx} exceeds KEY_LEN={ESE_KEY_LEN}"),
        });
    }
    let col_start = 2 + (ESE_KEY_LEN - cb_pfx);
    let need = col_start + COL_USER_ID_OFF + 4;
    if data.len() < need {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "app_usage real ESE record truncated: len={}, need >= {need}",
                data.len()
            ),
        });
    }

    let auto_inc_id = u32::from_le_bytes([
        data[col_start + COL_AUTO_INC_OFF],
        data[col_start + COL_AUTO_INC_OFF + 1],
        data[col_start + COL_AUTO_INC_OFF + 2],
        data[col_start + COL_AUTO_INC_OFF + 3],
    ]);

    let ts_off = col_start + COL_TIMESTAMP_OFF;
    let timestamp_raw = f64::from_le_bytes([
        data[ts_off], data[ts_off + 1], data[ts_off + 2], data[ts_off + 3],
        data[ts_off + 4], data[ts_off + 5], data[ts_off + 6], data[ts_off + 7],
    ]);
    let timestamp = ole_date_to_datetime(timestamp_raw);

    let app_off = col_start + COL_APP_ID_OFF;
    let app_id = i32::from_le_bytes([
        data[app_off], data[app_off + 1], data[app_off + 2], data[app_off + 3],
    ]);

    let usr_off = col_start + COL_USER_ID_OFF;
    let user_id = i32::from_le_bytes([
        data[usr_off], data[usr_off + 1], data[usr_off + 2], data[usr_off + 3],
    ]);

    Ok(AppUsageRecord {
        timestamp,
        app_id,
        user_id,
        foreground_cycles: 0,
        background_cycles: 0,
        auto_inc_id,
    })
}

fn decode_synthetic(data: &[u8], page: u32, tag: usize) -> Result<AppUsageRecord, SrumError> {
    if data.len() < APP_RECORD_SIZE {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("app record too short: {} < {APP_RECORD_SIZE}", data.len()),
        });
    }
    let filetime = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let app_id = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let user_id = i32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let foreground_cycles = u64::from_le_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let background_cycles = u64::from_le_bytes([
        data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
    ]);
    Ok(AppUsageRecord {
        timestamp: filetime_to_datetime(filetime),
        app_id,
        user_id,
        foreground_cycles,
        background_cycles,
        auto_inc_id: page,
    })
}
