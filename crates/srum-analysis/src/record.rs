// TODO

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_critical_serializes_lowercase() {
        let s = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(s, r#""critical""#);
    }

    #[test]
    fn severity_max_critical_wins() {
        assert_eq!(Severity::Suspicious.max(Severity::Critical), Severity::Critical);
        assert_eq!(Severity::Clean.max(Severity::Informational), Severity::Informational);
    }

    #[test]
    fn annotated_record_has_source_table_field() {
        let r = AnnotatedRecord {
            timestamp: "2024-01-01T00:00:00Z".into(),
            source_table: "apps".into(),
            app_id: 1,
            app_name: None,
            key_metric_label: "foreground_cycles".into(),
            key_metric_value: 0.0,
            flags: vec![],
            severity: Severity::Clean,
            raw: serde_json::Value::Null,
            background_cycles: None,
            foreground_cycles: None,
            focus_time_ms: None,
            user_input_time_ms: None,
            interpretation: None,
            mitre_techniques: vec![],
        };
        assert_eq!(r.source_table, "apps");
    }
}
