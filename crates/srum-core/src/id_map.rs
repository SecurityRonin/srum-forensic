//! ID map entry — maps integer IDs to application/user string names.
//!
//! Source table: `SruDbIdMapTable` in SRUDB.dat.

use serde::{Deserialize, Serialize};

/// Maps an integer SRUM ID to a human-readable application or user name.
///
/// App IDs in [`crate::NetworkUsageRecord`] and [`crate::AppUsageRecord`]
/// are opaque integers; this table resolves them to strings like
/// `"\\Device\\HarddiskVolume3\\Windows\\explorer.exe"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdMapEntry {
    /// The integer ID used as a foreign key in SRUM tables.
    pub id: i32,
    /// The resolved application or user name string.
    pub name: String,
}
