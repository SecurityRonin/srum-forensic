//! [`EnergyUsageRecord`] binary decoder.
//!
//! Decodes the synthetic 32-byte wire format used in test fixtures.
//!
//! Binary layout (all little-endian):
//! - `[0..8]`:   `filetime` (u64)
//! - `[8..12]`:  `app_id` (i32)
//! - `[12..16]`: `user_id` (i32)
//! - `[16..24]`: `charge_level` (u64) — mWh remaining
//! - `[24..32]`: `energy_consumed` (u64) — mWh consumed in interval

use srum_core::{filetime_to_datetime, EnergyUsageRecord, ENERGY_RECORD_SIZE};

use crate::SrumError;

pub fn decode_energy_record(
    data: &[u8],
    page: u32,
    tag: usize,
) -> Result<EnergyUsageRecord, SrumError> {
    if data.len() < ENERGY_RECORD_SIZE {
        return Err(SrumError::DecodeError {
            page,
            tag,
            detail: format!(
                "energy record too short: {} < {ENERGY_RECORD_SIZE}",
                data.len()
            ),
        });
    }
    let filetime = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let app_id = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let user_id = i32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let charge_level = u64::from_le_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let energy_consumed = u64::from_le_bytes([
        data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
    ]);
    Ok(EnergyUsageRecord {
        timestamp: filetime_to_datetime(filetime),
        app_id,
        user_id,
        charge_level,
        energy_consumed,
    })
}
