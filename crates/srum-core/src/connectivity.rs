//! Network connectivity record — L2 connection sessions per process.
//!
//! Source table: `{DD6636C4-8929-4683-974E-22C046A43763}` in SRUDB.dat.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One SRUM network connectivity record: a process's L2 connection session.
///
/// Forensic value: maps processes to specific network profiles (`WiFi` SSIDs,
/// VPN adapters) and their connection durations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectivityRecord {
    /// Integer ID of the application (look up in [`crate::IdMapEntry`]).
    pub app_id: i32,
    /// Integer ID of the user account (look up in [`crate::IdMapEntry`]).
    pub user_id: i32,
    /// UTC timestamp of the measurement interval start.
    pub timestamp: DateTime<Utc>,
    /// L2 profile ID — look up in `SruDbIdMapTable` for profile name.
    pub profile_id: i32,
    /// Seconds the connection was active in this interval.
    pub connected_time: u64,
}
