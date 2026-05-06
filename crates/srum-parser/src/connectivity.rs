//! [`NetworkConnectivityRecord`] binary decoder.
//!
//! Decodes the synthetic 28-byte wire format used in test fixtures.
//!
//! Binary layout (all little-endian):
//! - `[0..8]`:   `filetime` (u64) — Windows FILETIME
//! - `[8..12]`:  `app_id` (i32)
//! - `[12..16]`: `user_id` (i32)
//! - `[16..20]`: `profile_id` (i32)
//! - `[20..28]`: `connected_time` (u64) — seconds active

use srum_core::{
    filetime_to_datetime, NetworkConnectivityRecord, NETWORK_CONNECTIVITY_RECORD_SIZE,
};

use crate::SrumError;

pub fn decode_connectivity_record(
    data: &[u8],
    page: u32,
    tag: usize,
) -> Result<NetworkConnectivityRecord, SrumError> {
    if data.len() < NETWORK_CONNECTIVITY_RECORD_SIZE {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "connectivity record too short: {} < {NETWORK_CONNECTIVITY_RECORD_SIZE}",
                data.len()
            ),
        });
    }
    let filetime = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let app_id = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let user_id = i32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let profile_id = i32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let connected_time = u64::from_le_bytes([
        data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
    ]);
    Ok(NetworkConnectivityRecord {
        timestamp: filetime_to_datetime(filetime),
        app_id,
        user_id,
        profile_id,
        connected_time,
    })
}
