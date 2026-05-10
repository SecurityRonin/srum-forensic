use std::collections::HashMap;
use crate::record::{AnnotatedRecord, FindingCard, Severity};

pub fn compute_findings(timeline: &[AnnotatedRecord]) -> Vec<FindingCard> {
    let mut by_flag: HashMap<String, FlagAgg> = HashMap::new();

    for rec in timeline {
        for flag in &rec.flags {
            let agg = by_flag.entry(flag.clone()).or_insert_with(|| FlagAgg {
                count: 0,
                app_name: rec.app_name.clone().unwrap_or_else(|| format!("ID {}", rec.app_id)),
                severity: rec.severity.clone(),
                mitre: rec.mitre_techniques.clone(),
            });
            agg.count += 1;
            // Promote to the highest severity seen for this flag
            if rec.severity > agg.severity {
                agg.severity = rec.severity.clone();
            }
        }
    }

    let mut cards: Vec<FindingCard> = by_flag
        .into_iter()
        .filter_map(|(flag, agg)| {
            let (title, description) = card_text(&flag, &agg);
            Some(FindingCard {
                title,
                app_name: agg.app_name,
                description,
                mitre_techniques: agg.mitre,
                severity: agg.severity,
                filter_flag: flag,
                count: agg.count,
            })
        })
        .collect();

    cards.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.count.cmp(&a.count)));
    cards
}

struct FlagAgg {
    count: usize,
    app_name: String,
    severity: Severity,
    mitre: Vec<String>,
}

fn card_text(flag: &str, agg: &FlagAgg) -> (String, String) {
    match flag {
        "automated_execution" => (
            "AUTOMATED EXECUTION".into(),
            format!("{} occurrence(s) — process held focus with zero user input", agg.count),
        ),
        "beaconing" => (
            "POSSIBLE BEACONING".into(),
            format!("{} occurrence(s) — regular network intervals detected", agg.count),
        ),
        "background_cpu_dominant" => (
            "BACKGROUND CPU DOMINANT".into(),
            format!("{} occurrence(s) — CPU in background exceeds foreground", agg.count),
        ),
        "exfil_signal" => (
            "EXFILTRATION SIGNAL".into(),
            format!("{} occurrence(s) — large outbound transfer, no user activity", agg.count),
        ),
        "suspicious_path" => (
            "SUSPICIOUS PROCESS PATH".into(),
            format!("{} occurrence(s) — executed from temp/downloads/UNC", agg.count),
        ),
        "masquerade_candidate" => (
            "PROCESS MASQUERADE".into(),
            format!("{} occurrence(s) — name similar to system binary, wrong directory", agg.count),
        ),
        "phantom_foreground" => (
            "PHANTOM FOREGROUND".into(),
            format!("{} occurrence(s) — foreground CPU with no focus time", agg.count),
        ),
        "notification_c2" => (
            "NOTIFICATION C2 CHANNEL".into(),
            format!("{} occurrence(s) — high notification volume, background CPU, no focus", agg.count),
        ),
        "selective_gap" => (
            "ANTI-FORENSICS INDICATOR".into(),
            format!("{} gap(s) — records deleted selectively, not system shutdown", agg.count),
        ),
        _ => (
            flag.to_uppercase().replace('_', " "),
            format!("{} occurrence(s)", agg.count),
        ),
    }
}

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
    fn severity_promoted_to_max_across_records() {
        let records = vec![
            make_record(vec!["beaconing"], Severity::Suspicious),
            make_record(vec!["beaconing"], Severity::Critical),
        ];
        let findings = compute_findings(&records);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical); // must be max, not first-seen
        assert_eq!(findings[0].count, 2);
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
