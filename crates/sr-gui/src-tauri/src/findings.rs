use std::collections::HashMap;
use crate::types::{FindingCard, Severity, TimelineRecord};

pub fn compute_findings(timeline: &[TimelineRecord]) -> Vec<FindingCard> {
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

    cards.sort_by(|a, b| {
        severity_order(&a.severity)
            .cmp(&severity_order(&b.severity))
            .then(b.count.cmp(&a.count))
    });
    cards
}

struct FlagAgg {
    count: usize,
    app_name: String,
    severity: Severity,
    mitre: Vec<String>,
}

fn severity_order(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::Suspicious => 1,
        Severity::Informational => 2,
        Severity::Clean => 3,
    }
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
