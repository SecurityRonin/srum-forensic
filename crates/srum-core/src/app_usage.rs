//! Application resource usage record — CPU cycles, foreground/background time.
//!
//! Source table: `{5C8CF1C7-7257-4F13-B223-970EF5939312}` in SRUDB.dat.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One SRUM application resource usage record: CPU cycle counts for
/// foreground and background execution per ~1-hour interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppUsageRecord {
    /// Integer ID of the application (look up in [`crate::IdMapEntry`]).
    pub app_id: i32,
    /// Integer ID of the user account.
    pub user_id: i32,
    /// UTC timestamp of the measurement interval start.
    pub timestamp: DateTime<Utc>,
    /// CPU cycles consumed while the application was in the foreground.
    pub foreground_cycles: u64,
    /// CPU cycles consumed while the application was in the background.
    pub background_cycles: u64,
    /// ESE page number used as AutoIncId proxy for gap detection.
    /// Gaps in this sequence indicate deleted records (anti-forensics).
    /// Not serialised to JSON output.
    #[serde(skip)]
    pub auto_inc_id: u32,
}
