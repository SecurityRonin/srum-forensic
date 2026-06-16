//! [`EnergyUsageRecord`] binary decoder — real ESE raw-tag format only.
//!
//! **Real ESE raw-tag layout** (`cbCommonKeyPrefix | key_suffix | col_data`):
//! - `[0..2]`:           `cbCommonKeyPrefix` (u16 LE)
//! - `[2..2+(28-pfx)]`:  key suffix (`KEY_LEN=28` for `{FEE4E14F-…}`)
//! - `col_start = 2 + (28 - cb_pfx)`:
//!   - `[col_start+4..+8]`:  `AutoIncId` (u32 LE) → `auto_inc_id`
//!   - `[col_start+8..+16]`: `TimeStamp` as OLE Automation Date (f64 LE) → `timestamp`
//!   - `[col_start+16..+20]`: `AppId` (i32 LE) → `app_id`
//!   - `[col_start+20..+24]`: `UserId` (i32 LE) → `user_id`
//!   - `charge_level` and `energy_consumed` returned as 0 (all 0 in available VM fixtures)

use srum_core::{ole_date_to_datetime, EnergyUsageRecord};

use crate::SrumError;

const ESE_KEY_LEN: usize = 28;
const COL_AUTO_INC_OFF: usize = 4;
const COL_TIMESTAMP_OFF: usize = 8;
const COL_APP_ID_OFF: usize = 16;
const COL_USER_ID_OFF: usize = 20;

pub fn decode_energy_record(
    data: &[u8],
    page: u32,
    tag: usize,
) -> Result<EnergyUsageRecord, SrumError> {
    if data.len() < 2 {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("energy record too short: {}", data.len()),
        });
    }
    let cb_pfx = u16::from_le_bytes([data[0], data[1]]) as usize;
    if cb_pfx > ESE_KEY_LEN {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!("energy cb_pfx={cb_pfx} exceeds KEY_LEN={ESE_KEY_LEN}"),
        });
    }
    let col_start = 2 + (ESE_KEY_LEN - cb_pfx);
    let need = col_start + COL_USER_ID_OFF + 4;
    if data.len() < need {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "energy real ESE record truncated: len={}, need >= {need}",
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

    Ok(EnergyUsageRecord {
        timestamp,
        app_id,
        user_id,
        charge_level: 0,
        energy_consumed: 0,
        auto_inc_id,
    })
}
