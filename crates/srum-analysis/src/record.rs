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


impl FindingCard {
    /// Convert this triage card into a canonical [`forensicnomicon::report::Finding`],
    /// mapping the triage severity (`Clean`/`Informational`/`Suspicious`/`Critical`)
    /// onto the shared 5-level scale.
    #[must_use]
    pub fn to_finding(&self, source: forensicnomicon::report::Source) -> forensicnomicon::report::Finding {
        use forensicnomicon::report::{Category, ExternalRef, Finding, Severity as Canon};
        let severity = match self.severity {
            Severity::Clean => Canon::Info,
            Severity::Informational => Canon::Low,
            Severity::Suspicious => Canon::High,
            Severity::Critical => Canon::Critical,
        };
        let code = format!("SRUM-{}", self.filter_flag.to_uppercase().replace('_', "-"));
        let category = if self.mitre_techniques.is_empty() {
            Category::from_code(&code)
        } else {
            Category::Threat
        };
        let mut builder = Finding::observation(severity, category, code)
            .note(self.description.clone())
            .source(source)
            .evidence("app", self.app_name.clone())
            .evidence("title", self.title.clone())
            .occurrences(self.count as u64);
        for technique in &self.mitre_techniques {
            builder = builder.external_ref(ExternalRef::mitre_attack(technique.clone()));
        }
        builder.build()
    }
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
