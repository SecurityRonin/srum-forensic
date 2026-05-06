//! Push notification record — app notification activity per interval.
//!
//! Source table: `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` in SRUDB.dat.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One SRUM push notification record: app notification delivery per interval.
///
/// Forensic value: proves app engagement at specific timestamps even without
/// foreground CPU cycles — a communication app receiving C2 instructions shows
/// here before the user interacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushNotificationRecord {
    /// Integer ID of the application (look up in [`crate::IdMapEntry`]).
    pub app_id: i32,
    /// Integer ID of the user account (look up in [`crate::IdMapEntry`]).
    pub user_id: i32,
    /// UTC timestamp of the measurement interval start.
    pub timestamp: DateTime<Utc>,
    /// Notification category (0=toast, 1=badge, 2=tile, 3=raw).
    pub notification_type: u32,
    /// Number of notifications delivered in this interval.
    pub count: u32,
}
