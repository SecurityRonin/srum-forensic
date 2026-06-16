//! [`AppUsageRecord`] binary decoder — real ESE raw-tag format only.
//!
//! **Real ESE raw-tag layout** (`cbCommonKeyPrefix | key_suffix | col_data`):
//! - `[0..2]`:           `cbCommonKeyPrefix` (u16 LE)
//! - `[2..2+(KEY_LEN-pfx)]`:  key suffix bytes (`KEY_LEN` varies: 16 or 28 observed)
//! - column data is always `COL_DATA_LEN` bytes at the tail of the record:
//!   - `[col_start+0..+4]`:  ESE record header
//!   - `[col_start+4..+8]`:  `AutoIncId` (u32 LE) → `auto_inc_id`
//!   - `[col_start+8..+16]`: `TimeStamp` as OLE Automation Date (f64 LE) → `timestamp`
//!   - `[col_start+16..+20]`: `AppId` (i32 LE) → `app_id`
//!   - `[col_start+20..+24]`: `UserId` (i32 LE) → `user_id`
//!   - `foreground_cycles` and `background_cycles` returned as 0 (columns not yet located)

use srum_core::{ole_date_to_datetime, AppUsageRecord};

use crate::SrumError;

/// Column data is always 290 bytes at the tail, regardless of `KEY_LEN` variant.
/// Verified across chainsaw (1660 records), `rathbunvm_win10` (163), `rathbunvm_win11` (791).
const COL_DATA_LEN: usize = 290;
const COL_AUTO_INC_OFF: usize = 4;
const COL_TIMESTAMP_OFF: usize = 8;
const COL_APP_ID_OFF: usize = 16;
const COL_USER_ID_OFF: usize = 20;

pub fn decode_app_record(data: &[u8], page: u32, tag: usize) -> Result<AppUsageRecord, SrumError> {
    decode_real_ese(data, page, tag)
}

fn decode_real_ese(data: &[u8], page: u32, tag: usize) -> Result<AppUsageRecord, SrumError> {
    let need = COL_DATA_LEN + 2;
    if data.len() < need {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "app_usage ESE record too short: len={}, need >= {need}",
                data.len()
            ),
        });
    }
    let col_start = data.len() - COL_DATA_LEN;

    let auto_inc_id = u32::from_le_bytes([
        data[col_start + COL_AUTO_INC_OFF],
        data[col_start + COL_AUTO_INC_OFF + 1],
        data[col_start + COL_AUTO_INC_OFF + 2],
        data[col_start + COL_AUTO_INC_OFF + 3],
    ]);

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

    Ok(AppUsageRecord {
        timestamp,
        app_id,
        user_id,
        foreground_cycles: 0,
        background_cycles: 0,
        auto_inc_id,
    })
}
