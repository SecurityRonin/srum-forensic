//! SRUM (System Resource Usage Monitor) record type definitions.
//!
//! These are pure data types with no parsing logic.
//! Parsing is handled by the `srum-parser` crate.

pub mod app_timeline;
pub mod app_usage;
pub mod connectivity;
pub mod energy;
pub mod energy_lt;
pub mod id_map;
pub mod network;
pub mod push_notification;

pub use app_timeline::AppTimelineRecord;
pub use app_usage::AppUsageRecord;
pub use connectivity::NetworkConnectivityRecord;
pub use energy::EnergyUsageRecord;
pub use energy_lt::EnergyLtRecord;
pub use id_map::IdMapEntry;
pub use network::NetworkUsageRecord;
pub use push_notification::PushNotificationRecord;

use jiff::Timestamp;

/// Number of 100ns ticks between the Windows epoch (1601-01-01) and the
/// Unix epoch (1970-01-01).
pub const FILETIME_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;

/// Fixed byte length of a serialised [`NetworkUsageRecord`].
pub const NETWORK_RECORD_SIZE: usize = 32;

/// Fixed byte length of a serialised [`AppUsageRecord`].
pub const APP_RECORD_SIZE: usize = 32;

/// Fixed byte length of a serialised [`AppTimelineRecord`].
pub const APP_TIMELINE_RECORD_SIZE: usize = 32;

/// Fixed byte length of a serialised [`NetworkConnectivityRecord`].
pub const NETWORK_CONNECTIVITY_RECORD_SIZE: usize = 28;

/// Fixed byte length of a serialised [`EnergyUsageRecord`].
pub const ENERGY_RECORD_SIZE: usize = 32;

/// Minimum byte length of a serialised [`PushNotificationRecord`].
pub const PUSH_NOTIFICATION_RECORD_SIZE: usize = 24;

/// Minimum byte length of a serialised [`IdMapEntry`].
pub const ID_MAP_MIN_SIZE: usize = 6;

/// Convert a Windows FILETIME value to a UTC [`Timestamp`].
///
/// FILETIME counts 100-nanosecond ticks since 1601-01-01. Values before the
/// Unix epoch are clamped to `Timestamp::UNIX_EPOCH`.
pub fn filetime_to_datetime(filetime: u64) -> Timestamp {
    let unix_100ns = filetime.saturating_sub(FILETIME_EPOCH_OFFSET);
    let unix_nanos = i128::from(unix_100ns) * 100;
    Timestamp::from_nanosecond(unix_nanos).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// Convert an OLE Automation Date (f64) to a UTC [`Timestamp`].
///
/// OLE date counts days since 1899-12-30. The Unix epoch is 25569 days after
/// the OLE epoch. Infinite or NaN values are clamped to `Timestamp::UNIX_EPOCH`.
pub fn ole_date_to_datetime(v: f64) -> Timestamp {
    const OLE_TO_UNIX_DAYS: f64 = 25569.0;
    if !v.is_finite() {
        return Timestamp::UNIX_EPOCH;
    }
    let unix_secs_f64 = (v - OLE_TO_UNIX_DAYS) * 86400.0;
    let unix_secs = unix_secs_f64 as i64;
    let nanos = ((unix_secs_f64 - unix_secs as f64).abs() * 1_000_000_000.0) as u32;
    Timestamp::new(unix_secs, nanos as i32).unwrap_or(Timestamp::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_to_datetime_unix_epoch() {
        let dt = filetime_to_datetime(FILETIME_EPOCH_OFFSET);
        assert_eq!(dt.as_second(), 0, "must map to Unix epoch");
    }

    #[test]
    fn filetime_to_datetime_known_date() {
        // 2024-06-15T08:00:00Z = Unix 1718438400
        let filetime = FILETIME_EPOCH_OFFSET + 1_718_438_400u64 * 10_000_000;
        let dt = filetime_to_datetime(filetime);
        assert_eq!(dt.as_second(), 1_718_438_400);
    }

    #[test]
    fn filetime_to_datetime_sub_second() {
        // OFFSET + 12345 ticks (100ns each) = 1970-01-01T00:00:00.001234500Z.
        // Ground truth derived from the documented FILETIME math:
        // 12345 * 100 ns = 1_234_500 ns after the Unix epoch.
        let dt = filetime_to_datetime(FILETIME_EPOCH_OFFSET + 12_345);
        assert_eq!(dt.as_second(), 0);
        assert_eq!(dt.as_nanosecond(), 1_234_500_i128);
    }

    #[test]
    fn ole_date_to_datetime_unix_epoch() {
        // OLE epoch is 1899-12-30; the Unix epoch is 25569 days later.
        let dt = ole_date_to_datetime(25569.0);
        assert_eq!(dt.as_second(), 0, "OLE day 25569 == Unix epoch");
    }

    #[test]
    fn ole_date_to_datetime_known_date() {
        // OLE day 45000 (a whole-day value that converts exactly, avoiding f64
        // truncation artifacts) == 2023-03-15T00:00:00Z == Unix 1678838400.
        // Ground truth derived from the documented OLE conversion:
        // (45000 - 25569) * 86400 = 19431 * 86400 = 1678838400.
        let dt = ole_date_to_datetime(45000.0);
        assert_eq!(dt.as_second(), 1_678_838_400);
    }

    #[test]
    fn ole_date_to_datetime_non_finite_clamps_to_epoch() {
        assert_eq!(ole_date_to_datetime(f64::NAN).as_second(), 0);
        assert_eq!(ole_date_to_datetime(f64::INFINITY).as_second(), 0);
    }

    #[test]
    fn record_size_constants_are_32() {
        assert_eq!(NETWORK_RECORD_SIZE, 32usize);
        assert_eq!(APP_RECORD_SIZE, 32usize);
    }

    #[test]
    fn network_record_has_bytes_sent() {
        let r = NetworkUsageRecord {
            bytes_sent: 1024,
            bytes_recv: 0,
            timestamp: Timestamp::UNIX_EPOCH,
            app_id: 1,
            user_id: 0,
            auto_inc_id: 0,
        };
        assert_eq!(r.bytes_sent, 1024);
    }

    #[test]
    fn network_record_has_bytes_recv() {
        let r = NetworkUsageRecord {
            bytes_sent: 0,
            bytes_recv: 2048,
            timestamp: Timestamp::UNIX_EPOCH,
            app_id: 1,
            user_id: 0,
            auto_inc_id: 0,
        };
        assert_eq!(r.bytes_recv, 2048);
    }

    #[test]
    fn network_record_has_timestamp() {
        let ts = Timestamp::UNIX_EPOCH;
        let r = NetworkUsageRecord {
            bytes_sent: 0,
            bytes_recv: 0,
            timestamp: ts,
            app_id: 1,
            user_id: 0,
            auto_inc_id: 0,
        };
        let _ = r.timestamp;
    }

    #[test]
    fn network_record_has_app_id() {
        let r = NetworkUsageRecord {
            bytes_sent: 0,
            bytes_recv: 0,
            timestamp: Timestamp::UNIX_EPOCH,
            app_id: 42,
            user_id: 0,
            auto_inc_id: 0,
        };
        assert_eq!(r.app_id, 42_i32);
    }

    #[test]
    fn app_usage_record_has_foreground_cycles() {
        let r = AppUsageRecord {
            app_id: 1,
            user_id: 0,
            timestamp: Timestamp::UNIX_EPOCH,
            foreground_cycles: 999_000,
            background_cycles: 0,
            auto_inc_id: 0,
        };
        assert_eq!(r.foreground_cycles, 999_000_u64);
    }

    #[test]
    fn id_map_entry_has_id_and_name() {
        let e = IdMapEntry {
            id: 7,
            name: "explorer.exe".to_owned(),
        };
        assert_eq!(e.id, 7_i32);
        assert_eq!(e.name, "explorer.exe");
    }

    #[test]
    fn network_record_serializes_to_json() {
        let r = NetworkUsageRecord {
            bytes_sent: 512,
            bytes_recv: 1024,
            timestamp: Timestamp::UNIX_EPOCH,
            app_id: 3,
            user_id: 1,
            auto_inc_id: 0,
        };
        let json = serde_json::to_string(&r).expect("serialise to JSON");
        assert!(json.contains("bytes_sent"));
        assert!(json.contains("512"));
        // auto_inc_id must NOT appear in JSON output (#[serde(skip)])
        assert!(!json.contains("auto_inc_id"));
    }
}
