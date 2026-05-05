//! SRUM (System Resource Usage Monitor) record type definitions.
//!
//! These are pure data types with no parsing logic.
//! Parsing is handled by the `srum-parser` crate.

pub mod app_usage;
pub mod id_map;
pub mod network;

pub use app_usage::AppUsageRecord;
pub use id_map::IdMapEntry;
pub use network::NetworkUsageRecord;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_to_datetime_unix_epoch() {
        let dt = filetime_to_datetime(FILETIME_EPOCH_OFFSET);
        assert_eq!(dt.timestamp(), 0, "must map to Unix epoch");
    }

    #[test]
    fn filetime_to_datetime_known_date() {
        // 2024-06-15T08:00:00Z = Unix 1718438400
        let filetime = FILETIME_EPOCH_OFFSET + 1_718_438_400u64 * 10_000_000;
        let dt = filetime_to_datetime(filetime);
        assert_eq!(dt.timestamp(), 1_718_438_400);
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
            timestamp: chrono::DateTime::UNIX_EPOCH.with_timezone(&chrono::Utc),
            app_id: 1,
            user_id: 0,
        };
        assert_eq!(r.bytes_sent, 1024);
    }

    #[test]
    fn network_record_has_bytes_recv() {
        let r = NetworkUsageRecord {
            bytes_sent: 0,
            bytes_recv: 2048,
            timestamp: chrono::DateTime::UNIX_EPOCH.with_timezone(&chrono::Utc),
            app_id: 1,
            user_id: 0,
        };
        assert_eq!(r.bytes_recv, 2048);
    }

    #[test]
    fn network_record_has_timestamp() {
        let ts = chrono::DateTime::UNIX_EPOCH.with_timezone(&chrono::Utc);
        let r = NetworkUsageRecord {
            bytes_sent: 0,
            bytes_recv: 0,
            timestamp: ts,
            app_id: 1,
            user_id: 0,
        };
        let _ = r.timestamp;
    }

    #[test]
    fn network_record_has_app_id() {
        let r = NetworkUsageRecord {
            bytes_sent: 0,
            bytes_recv: 0,
            timestamp: chrono::DateTime::UNIX_EPOCH.with_timezone(&chrono::Utc),
            app_id: 42,
            user_id: 0,
        };
        assert_eq!(r.app_id, 42_i32);
    }

    #[test]
    fn app_usage_record_has_foreground_cycles() {
        let r = AppUsageRecord {
            app_id: 1,
            user_id: 0,
            timestamp: chrono::DateTime::UNIX_EPOCH.with_timezone(&chrono::Utc),
            foreground_cycles: 999_000,
            background_cycles: 0,
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
            timestamp: chrono::DateTime::UNIX_EPOCH.with_timezone(&chrono::Utc),
            app_id: 3,
            user_id: 1,
        };
        let json = serde_json::to_string(&r).expect("serialise to JSON");
        assert!(json.contains("bytes_sent"));
        assert!(json.contains("512"));
    }
}
