//! [`PushNotificationRecord`] binary decoder — real ESE raw-tag format only.
//!
//! **Real ESE raw-tag layout** (`cbCommonKeyPrefix | key_suffix | col_data`):
//! - `[0..2]`:           `cbCommonKeyPrefix` (u16 LE)
//! - `[2..2+(16-pfx)]`:  key suffix (`KEY_LEN=16` for `{D10CA2FE-…}`)
//! - `col_start = 2 + (16 - cb_pfx)`:
//!   - `[col_start+4..+8]`:  `AutoIncId` (u32 LE)
//!   - `[col_start+8..+16]`: `TimeStamp` as OLE Automation Date (f64 LE) → `timestamp`
//!   - `[col_start+16..+20]`: `AppId` (i32 LE) → `app_id`
//!   - `[col_start+20..+24]`: `UserId` (i32 LE) → `user_id`
//!   - `[col_start+24..+32]`: `ForegroundCycleTime` (u64 LE) → `foreground_cycle_time`
//!   - `[col_start+32..+40]`: `BackgroundCycleTime` (u64 LE) → `background_cycle_time`
//!   - `notification_type` and `count` are 0 (no corresponding column at these offsets)

use srum_core::{ole_date_to_datetime, PushNotificationRecord};

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
    if data.len() < 2 {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("push notification record too short: {}", data.len()),
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

    let fg_off = col_start + COL_FG_CYCLE_OFF;
    let foreground_cycle_time = u64::from_le_bytes([
        data[fg_off],
        data[fg_off + 1],
        data[fg_off + 2],
        data[fg_off + 3],
        data[fg_off + 4],
        data[fg_off + 5],
        data[fg_off + 6],
        data[fg_off + 7],
    ]);

    let bg_off = col_start + COL_BG_CYCLE_OFF;
    let background_cycle_time = u64::from_le_bytes([
        data[bg_off],
        data[bg_off + 1],
        data[bg_off + 2],
        data[bg_off + 3],
        data[bg_off + 4],
        data[bg_off + 5],
        data[bg_off + 6],
        data[bg_off + 7],
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
