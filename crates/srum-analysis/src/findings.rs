// TODO: implement compute_findings

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AnnotatedRecord, Severity};
    use serde_json::json;

    fn make_record(flags: Vec<&str>, severity: Severity) -> AnnotatedRecord {
        AnnotatedRecord {
            timestamp: "2024-01-01T00:00:00Z".into(),
            source_table: "apps".into(),
            app_id: 1,
            app_name: Some("test.exe".into()),
            key_metric_label: "cycles".into(),
            key_metric_value: 0.0,
            flags: flags.iter().map(|s| s.to_string()).collect(),
            severity,
            raw: json!({}),
            background_cycles: None,
            foreground_cycles: None,
            focus_time_ms: None,
            user_input_time_ms: None,
            interpretation: None,
            mitre_techniques: vec![],
        }
    }

    #[test]
    fn empty_timeline_returns_no_findings() {
        assert!(compute_findings(&[]).is_empty());
    }

    #[test]
    fn clean_records_return_no_findings() {
        let records = vec![make_record(vec![], Severity::Clean)];
        assert!(compute_findings(&records).is_empty());
    }

    #[test]
    fn flagged_record_returns_finding_card() {
        let records = vec![make_record(vec!["automated_execution"], Severity::Critical)];
        let findings = compute_findings(&records);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].filter_flag, "automated_execution");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn critical_findings_sort_before_suspicious() {
        let records = vec![
            make_record(vec!["suspicious_path"], Severity::Suspicious),
            make_record(vec!["automated_execution"], Severity::Critical),
        ];
        let findings = compute_findings(&records);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
