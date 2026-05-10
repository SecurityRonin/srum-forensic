use crate::types::{FindingCard, Severity, TimelineRecord};

pub fn compute_findings(timeline: &[TimelineRecord]) -> Vec<FindingCard> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_record(app_name: &str, flags: Vec<&str>, severity: Severity) -> TimelineRecord {
        TimelineRecord {
            timestamp: "2024-01-01T00:00:00Z".into(),
            source_table: "apps".into(),
            app_id: 1,
            app_name: Some(app_name.into()),
            key_metric_label: "foreground_cycles".into(),
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
    fn empty_timeline_produces_no_findings() {
        assert!(compute_findings(&[]).is_empty());
    }

    #[test]
    fn clean_records_produce_no_findings() {
        let timeline = vec![make_record("chrome.exe", vec![], Severity::Clean)];
        assert!(compute_findings(&timeline).is_empty());
    }

    #[test]
    fn automated_execution_flag_produces_card() {
        let timeline = vec![make_record(
            "powershell.exe",
            vec!["automated_execution"],
            Severity::Critical,
        )];
        let findings = compute_findings(&timeline);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].filter_flag, "automated_execution");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn critical_cards_come_before_suspicious() {
        let timeline = vec![
            make_record("chrome.exe", vec!["suspicious_path"], Severity::Suspicious),
            make_record("cmd.exe", vec!["automated_execution"], Severity::Critical),
        ];
        let findings = compute_findings(&timeline);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Suspicious);
    }

    #[test]
    fn count_aggregates_across_records() {
        let timeline = vec![
            make_record("powershell.exe", vec!["beaconing"], Severity::Critical),
            make_record("powershell.exe", vec!["beaconing"], Severity::Critical),
            make_record("powershell.exe", vec!["beaconing"], Severity::Critical),
        ];
        let findings = compute_findings(&timeline);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].count, 3);
    }
}
