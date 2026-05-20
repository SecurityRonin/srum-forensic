//! [`PushNotificationRecord`] binary decoder — supports both real ESE and synthetic formats.
//!
//! **Synthetic fixture layout** (24 bytes, all LE):
//! - `[0..8]`:   `filetime` (u64)
//! - `[8..12]`:  `app_id` (i32)
//! - `[12..16]`: `user_id` (i32)
//! - `[16..20]`: `notification_type` (u32)
//! - `[20..24]`: `count` (u32)
//!
//! **Real ESE raw-tag layout** (`cbCommonKeyPrefix | key_suffix | col_data`):
//! - `[0..2]`:           `cbCommonKeyPrefix` (u16 LE)
//! - `[2..2+(16-pfx)]`:  key suffix (KEY_LEN=16 for `{D10CA2FE-…}`)
//! - `col_start = 2 + (16 - cb_pfx)`:
//!   - `[col_start+4..+8]`:  `AutoIncId` (u32 LE)
//!   - `[col_start+8..+16]`: `TimeStamp` as OLE Automation Date (f64 LE) → `timestamp`
//!   - `[col_start+16..+20]`: `AppId` (i32 LE) → `app_id`
//!   - `[col_start+20..+24]`: `UserId` (i32 LE) → `user_id`
//!   - `[col_start+24..+32]`: `ForegroundCycleTime` (u64 LE) → `foreground_cycle_time`
//!   - `[col_start+32..+40]`: `BackgroundCycleTime` (u64 LE) → `background_cycle_time`
//!   - `notification_type` and `count` are 0 for real ESE (no corresponding column at these offsets)

use srum_core::{
    ole_date_to_datetime, filetime_to_datetime, PushNotificationRecord,
    PUSH_NOTIFICATION_RECORD_SIZE,
};

use crate::SrumError;

const ESE_KEY_LEN: usize = 16;
const COL_TIMESTAMP_OFF: usize = 8;
const COL_APP_ID_OFF: usize = 16;
const COL_USER_ID_OFF: usize = 20;
const COL_FG_CYCLE_OFF: usize = 24;
const COL_BG_CYCLE_OFF: usize = 32;

pub fn decode_push_notification_record(
    data: &[u8],
    page: u32,
    tag: usize,
) -> Result<PushNotificationRecord, SrumError> {
    if data.len() == PUSH_NOTIFICATION_RECORD_SIZE {
        return decode_synthetic(data, page, tag);
    }
    if data.len() > PUSH_NOTIFICATION_RECORD_SIZE {
        return decode_real_ese(data, page, tag);
    }
    Err(SrumError::DecodeError {
        page,
        tag,
        detail: format!(
            "push notification record too short: {} < {PUSH_NOTIFICATION_RECORD_SIZE}",
            data.len()
        ),
    })
}

fn decode_real_ese(data: &[u8], page: u32, tag: usize) -> Result<PushNotificationRecord, SrumError> {
    if data.len() < 2 {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: "push real ESE record too short for cbCommonKeyPrefix".to_string(),
        });
    }
    let cb_pfx = u16::from_le_bytes([data[0], data[1]]) as usize;
    if cb_pfx > ESE_KEY_LEN {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("push cb_pfx={cb_pfx} exceeds KEY_LEN={ESE_KEY_LEN}"),
        });
    }
    let col_start = 2 + (ESE_KEY_LEN - cb_pfx);
    let need = col_start + COL_BG_CYCLE_OFF + 8;
    if data.len() < need {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "push real ESE record truncated: len={}, need >= {need}",
                data.len()
            ),
        });
    }

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

    let fg_off = col_start + COL_FG_CYCLE_OFF;
    let foreground_cycle_time = u64::from_le_bytes([
        data[fg_off], data[fg_off + 1], data[fg_off + 2], data[fg_off + 3],
        data[fg_off + 4], data[fg_off + 5], data[fg_off + 6], data[fg_off + 7],
    ]);

    let bg_off = col_start + COL_BG_CYCLE_OFF;
    let background_cycle_time = u64::from_le_bytes([
        data[bg_off], data[bg_off + 1], data[bg_off + 2], data[bg_off + 3],
        data[bg_off + 4], data[bg_off + 5], data[bg_off + 6], data[bg_off + 7],
    ]);

    Ok(PushNotificationRecord {
        timestamp,
        app_id,
        user_id,
        notification_type: 0,
        count: 0,
        foreground_cycle_time,
        background_cycle_time,
    })
}

fn decode_synthetic(data: &[u8], page: u32, tag: usize) -> Result<PushNotificationRecord, SrumError> {
    if data.len() < PUSH_NOTIFICATION_RECORD_SIZE {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "push notification record too short: {} < {PUSH_NOTIFICATION_RECORD_SIZE}",
                data.len()
            ),
        });
    }
    let filetime = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let app_id = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let user_id = i32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let notification_type = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let count = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    Ok(PushNotificationRecord {
        timestamp: filetime_to_datetime(filetime),
        app_id,
        user_id,
        notification_type,
        count,
        foreground_cycle_time: 0,
        background_cycle_time: 0,
    })
}
