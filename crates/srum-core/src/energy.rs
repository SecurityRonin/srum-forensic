//! Energy usage record — battery charge and process energy consumption.
//!
//! Source table: `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` in SRUDB.dat.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One SRUM energy usage record: battery state and energy consumed per process.
///
/// Forensic value: correlates process activity with battery drain timeline;
/// timestamps power-on/off cycles; detects anomalous overnight power usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnergyUsageRecord {
    /// Integer ID of the application (look up in [`crate::IdMapEntry`]).
    pub app_id: i32,
    /// Integer ID of the user account (look up in [`crate::IdMapEntry`]).
    pub user_id: i32,
    /// UTC timestamp of the measurement interval start.
    pub timestamp: DateTime<Utc>,
    /// Remaining battery charge at interval end (mWh).
    pub charge_level: u64,
    /// Energy consumed by this process in the interval (mWh).
    pub energy_consumed: u64,
}
