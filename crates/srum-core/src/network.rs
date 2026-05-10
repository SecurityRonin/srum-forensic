//! Network usage record — bytes sent/received per process per ~1-hour interval.
//!
//! Source table: `{973F5D5C-1D90-4944-BE8E-24B22A728CF2}` in SRUDB.dat.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One SRUM network usage record: the bytes a process sent/received in a
/// single ~1-hour measurement interval.
///
/// Forensic value: proves exfiltration volumes even after the process is deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkUsageRecord {
    /// Integer ID of the application (look up in [`crate::IdMapEntry`]).
    pub app_id: i32,
    /// Integer ID of the user account (look up in [`crate::IdMapEntry`]).
    pub user_id: i32,
    /// UTC timestamp of the measurement interval start.
    pub timestamp: DateTime<Utc>,
    /// Bytes sent by the process in this interval.
    pub bytes_sent: u64,
    /// Bytes received by the process in this interval.
    pub bytes_recv: u64,
    /// ESE page number used as AutoIncId proxy for gap detection.
    /// Gaps in this sequence indicate deleted records (anti-forensics).
    /// Not serialised to JSON output.
    #[serde(skip)]
    pub auto_inc_id: u32,
}
