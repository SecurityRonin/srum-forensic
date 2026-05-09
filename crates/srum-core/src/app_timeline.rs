//! Application Timeline record — in-focus duration and user input time per app.
//!
//! Source table: `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}` in SRUDB.dat.
//!
//! Available since Windows 10 Anniversary Update (1607).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One SRUM Application Timeline record: active engagement time per app
/// per ~1-hour interval.
///
/// Forensic value: distinguishes passive background execution (high CPU in
/// AppUsage, zero focus_time_ms here) from active user interaction. A
/// shell spawned by malware shows CPU cycles in AppUsage but no focus or
/// input time here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppTimelineRecord {
    /// Integer ID of the application (look up in [`crate::IdMapEntry`]).
    pub app_id: i32,
    /// Integer ID of the user account (look up in [`crate::IdMapEntry`]).
    pub user_id: i32,
    /// UTC timestamp of the measurement interval start.
    pub timestamp: DateTime<Utc>,
    /// Milliseconds the application window had foreground focus.
    pub focus_time_ms: u64,
    /// Milliseconds the user actively provided input to the application.
    pub user_input_time_ms: u64,
}
