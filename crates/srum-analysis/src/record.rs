use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Clean,           // lowest — declaration order is severity order
    Informational,
    Suspicious,
    Critical,        // highest
}

impl Severity {
    pub fn max(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedRecord {
    pub timestamp: String,
    pub source_table: String,
    pub app_id: i32,
    pub app_name: Option<String>,
    pub key_metric_label: String,
    pub key_metric_value: f64,
    pub flags: Vec<String>,
    pub severity: Severity,
    pub raw: serde_json::Value,
    pub background_cycles: Option<u64>,
    pub foreground_cycles: Option<u64>,
    pub focus_time_ms: Option<u64>,
    pub user_input_time_ms: Option<u64>,
    pub interpretation: Option<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingCard {
    pub title: String,
    pub app_name: String,
    pub description: String,
    pub mitre_techniques: Vec<String>,
    pub severity: Severity,
    pub filter_flag: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemporalSpan {
    pub first: String,
    pub last: String,
}

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
