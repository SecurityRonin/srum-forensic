use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    Suspicious,
    Informational,
    Clean,
}

impl Severity {
    pub fn max(self, other: Self) -> Self {
        use Severity::*;
        match (self, other) {
            (Critical, _) | (_, Critical) => Critical,
            (Suspicious, _) | (_, Suspicious) => Suspicious,
            (Informational, _) | (_, Informational) => Informational,
            _ => Clean,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineRecord {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCard {
    pub title: String,
    pub app_name: String,
    pub description: String,
    pub mitre_techniques: Vec<String>,
    pub severity: Severity,
    pub filter_flag: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalSpan {
    pub first: String,
    pub last: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SrumFile {
    pub path: String,
    pub timeline: Vec<TimelineRecord>,
    pub findings: Vec<FindingCard>,
    pub record_count: usize,
    pub temporal_span: Option<TemporalSpan>,
    pub table_names: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_max_critical_wins() {
        assert_eq!(Severity::Critical.max(Severity::Clean), Severity::Critical);
        assert_eq!(Severity::Clean.max(Severity::Critical), Severity::Critical);
    }

    #[test]
    fn severity_max_suspicious_over_informational() {
        assert_eq!(
            Severity::Suspicious.max(Severity::Informational),
            Severity::Suspicious
        );
    }

    #[test]
    fn severity_max_clean_clean() {
        assert_eq!(Severity::Clean.max(Severity::Clean), Severity::Clean);
    }
}
