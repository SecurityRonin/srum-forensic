use crate::types::{Severity, TimelineRecord};

pub fn severity_from_flags(flags: &[String]) -> Severity {
    todo!()
}

pub fn interpret(record: &TimelineRecord) -> Option<String> {
    todo!()
}

pub fn value_to_timeline_record(
    value: serde_json::Value,
    source_table: &str,
) -> Option<TimelineRecord> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn severity_from_no_flags_is_clean() {
        assert_eq!(severity_from_flags(&[]), Severity::Clean);
    }

    #[test]
    fn severity_from_automated_execution_is_critical() {
        let flags = vec!["automated_execution".to_string()];
        assert_eq!(severity_from_flags(&flags), Severity::Critical);
    }

    #[test]
    fn severity_from_suspicious_path_is_suspicious() {
        let flags = vec!["suspicious_path".to_string()];
        assert_eq!(severity_from_flags(&flags), Severity::Suspicious);
    }

    #[test]
    fn severity_from_beaconing_is_critical() {
        let flags = vec!["beaconing".to_string()];
        assert_eq!(severity_from_flags(&flags), Severity::Critical);
    }

    #[test]
    fn severity_from_mixed_flags_takes_highest() {
        let flags = vec![
            "suspicious_path".to_string(),
            "automated_execution".to_string(),
        ];
        assert_eq!(severity_from_flags(&flags), Severity::Critical);
    }

    #[test]
    fn value_to_timeline_record_network_record() {
        let val = json!({
            "timestamp": "2024-06-15T08:00:00Z",
            "app_id": 42,
            "app_name": "chrome.exe",
            "bytes_sent": 1_000_000,
            "bytes_recv": 500_000,
        });
        let rec = value_to_timeline_record(val, "network").unwrap();
        assert_eq!(rec.source_table, "network");
        assert_eq!(rec.app_id, 42);
        assert_eq!(rec.key_metric_label, "bytes_sent");
        assert_eq!(rec.key_metric_value, 1_000_000.0);
    }

    #[test]
    fn value_to_timeline_record_missing_timestamp_returns_none() {
        let val = json!({ "app_id": 1 });
        assert!(value_to_timeline_record(val, "network").is_none());
    }

    #[test]
    fn interpret_automated_execution() {
        let rec = TimelineRecord {
            timestamp: "2024-01-01T00:00:00Z".into(),
            source_table: "apps".into(),
            app_id: 1,
            app_name: Some("powershell.exe".into()),
            key_metric_label: "foreground_cycles".into(),
            key_metric_value: 0.0,
            flags: vec!["automated_execution".into()],
            severity: Severity::Critical,
            raw: serde_json::Value::Null,
            background_cycles: Some(5_000_000),
            foreground_cycles: Some(0),
            focus_time_ms: Some(3_600_000),
            user_input_time_ms: Some(0),
            interpretation: None,
            mitre_techniques: vec![],
        };
        let text = interpret(&rec).unwrap();
        assert!(
            text.contains("focus") || text.contains("input"),
            "interpretation must mention focus or input: {text}"
        );
    }
}
