//! [`AppUsageRecord`] binary decoder.
//!
//! Decodes the synthetic 32-byte wire format used in test fixtures.
//!
//! Binary layout (all little-endian):
//! - `[0..8]`:   `filetime` (u64) — Windows FILETIME (100ns ticks since 1601-01-01)
//! - `[8..12]`:  `app_id` (i32)
//! - `[12..16]`: `user_id` (i32)
//! - `[16..24]`: `foreground_cycles` (u64)
//! - `[24..32]`: `background_cycles` (u64)

use chrono::{DateTime, Utc};
use srum_core::AppUsageRecord;

use crate::EseError;

/// Number of 100ns ticks between 1601-01-01 and 1970-01-01.
const FILETIME_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;

/// Minimum size of a raw app usage record.
pub const RECORD_SIZE: usize = 32;

fn filetime_to_datetime(filetime: u64) -> DateTime<Utc> {
    let unix_100ns = filetime.saturating_sub(FILETIME_EPOCH_OFFSET);
    let secs = i64::try_from(unix_100ns / 10_000_000).unwrap_or(i64::MAX);
    let nanos = u32::try_from((unix_100ns % 10_000_000) * 100).unwrap_or(0);
    DateTime::from_timestamp(secs, nanos).unwrap_or(DateTime::UNIX_EPOCH.with_timezone(&Utc))
}

/// Decode one raw 32-byte record into an [`AppUsageRecord`].
///
/// # Errors
///
/// Returns [`EseError::Corrupt`] if `data` is shorter than 32 bytes.
pub fn decode_app_record(data: &[u8]) -> Result<AppUsageRecord, EseError> {
    if data.len() < RECORD_SIZE {
        return Err(EseError::Corrupt {
            page: 0,
            detail: format!("app record too short: {} < {RECORD_SIZE}", data.len()),
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
    })
}
