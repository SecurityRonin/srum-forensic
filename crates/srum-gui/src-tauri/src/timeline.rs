use srum_analysis::record::{AnnotatedRecord, Severity};
use srum_analysis::HEURISTIC_KEYS;

pub fn severity_from_flags(flags: &[String]) -> Severity {
    const CRITICAL: &[&str] = &[
        "automated_execution",
        "beaconing",
        "masquerade_candidate",
        "selective_gap",
        "notification_c2",
    ];
    const SUSPICIOUS: &[&str] = &[
        "background_cpu_dominant",
        "exfil_signal",
        "exfil_ratio",
        "no_focus_with_cpu",
        "phantom_foreground",
        "suspicious_path",
    ];
    const INFORMATIONAL: &[&str] = &["autoinc_gap"];

    let mut severity = Severity::Clean;
    for flag in flags {
        let s = if CRITICAL.contains(&flag.as_str()) {
            Severity::Critical
        } else if SUSPICIOUS.contains(&flag.as_str()) {
            Severity::Suspicious
        } else if INFORMATIONAL.contains(&flag.as_str()) {
            Severity::Informational
        } else {
            Severity::Clean
        };
        severity = severity.max(s);
    }
    severity
}

pub fn interpret(record: &AnnotatedRecord) -> Option<String> {
    if record.flags.is_empty() {
        return None;
    }

    let name = record.app_name.as_deref().unwrap_or("this process");

    if record.flags.contains(&"automated_execution".to_string()) {
        let focus_min = record.focus_time_ms.unwrap_or(0) / 60_000;
        return Some(format!(
            "{name} held focus for {focus_min} minutes with zero keyboard or mouse input. \
             Consistent with scripted or automated execution — no human was present."
        ));
    }
    if record.flags.contains(&"beaconing".to_string()) {
        return Some(format!(
            "{name} made network connections at regular intervals. \
             Regular timing is a hallmark of command-and-control beaconing."
        ));
    }
    if record.flags.contains(&"background_cpu_dominant".to_string()) {
        return Some(format!(
            "{name} consumed significant CPU in the background with little or no foreground activity. \
             Possible mining, covert computation, or malware hiding behind a cover process."
        ));
    }
    if record.flags.contains(&"phantom_foreground".to_string()) {
        return Some(format!(
            "{name} was billed foreground CPU cycles but the Application Timeline records no focus time. \
             Possible SetForegroundWindow abuse to appear interactive while running covertly."
        ));
    }
    if record.flags.contains(&"exfil_signal".to_string()) {
        let sent_mb = record
            .raw
            .get("bytes_sent")
            .and_then(|v| v.as_f64())
            .map(|b| b / 1_048_576.0)
            .unwrap_or(0.0);
        return Some(format!(
            "{name} sent {sent_mb:.1} MB with no corresponding foreground or focus activity. \
             Data transfer occurring while the user was not interacting — possible exfiltration."
        ));
    }
    if record.flags.contains(&"suspicious_path".to_string()) {
        return Some(format!(
            "{name} ran from a suspicious location (temp directory, downloads, UNC path, \
             or root of a drive). Legitimate software rarely executes from these locations."
        ));
    }
    if record.flags.contains(&"masquerade_candidate".to_string()) {
        return Some(format!(
            "The process name is very similar to a known Windows system binary but ran from \
             an unexpected directory. Possible process name masquerading."
        ));
    }
    if record.flags.contains(&"notification_c2".to_string()) {
        return Some(format!(
            "{name} generated an unusually high number of push notifications with background CPU \
             and no user focus. Notifications may be used as a covert C2 channel."
        ));
    }

    Some(format!("Heuristic flags: {}.", record.flags.join(", ")))
}

pub fn value_to_timeline_record(value: serde_json::Value) -> Option<AnnotatedRecord> {
    // Extract all fields from a borrowed reference, then drop the borrow
    let (timestamp, source_table, app_id, app_name, key_metric_label, key_metric_value,
         flags, background_cycles, foreground_cycles, focus_time_ms, user_input_time_ms,
         mitre_techniques) = {
        let obj = value.as_object()?;
        let timestamp = obj.get("timestamp")?.as_str()?.to_string();
        let source_table = obj
            .get("source_table")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let app_id = obj
            .get("app_id")
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(0);
        let app_name = obj.get("app_name").and_then(|v| v.as_str()).map(str::to_string);
        let (key_metric_label, key_metric_value) = key_metric(obj, &source_table);
        let flags: Vec<String> = HEURISTIC_KEYS
            .iter()
            .filter(|&&k| obj.get(k).and_then(|v| v.as_bool()) == Some(true))
            .map(|&k| k.to_owned())
            .collect();
        let background_cycles = obj.get("background_cycles").and_then(|v| v.as_u64());
        let foreground_cycles = obj.get("foreground_cycles").and_then(|v| v.as_u64());
        let focus_time_ms = obj.get("focus_time_ms").and_then(|v| v.as_u64());
        let user_input_time_ms = obj.get("user_input_time_ms").and_then(|v| v.as_u64());
        let mitre_techniques: Vec<String> = obj
            .get("mitre_techniques")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        (timestamp, source_table, app_id, app_name, key_metric_label, key_metric_value,
         flags, background_cycles, foreground_cycles, focus_time_ms, user_input_time_ms,
         mitre_techniques)
    }; // obj borrow dropped here — value is no longer borrowed

    let severity = severity_from_flags(&flags);
    let raw = value; // now safe to move without cloning

    let mut rec = AnnotatedRecord {
        timestamp,
        source_table,
        app_id,
        app_name,
        key_metric_label,
        key_metric_value,
        flags,
        severity,
        raw,
        background_cycles,
        foreground_cycles,
        focus_time_ms,
        user_input_time_ms,
        interpretation: None,
        mitre_techniques,
    };
    rec.interpretation = interpret(&rec);
    Some(rec)
}

fn key_metric(obj: &serde_json::Map<String, serde_json::Value>, table: &str) -> (String, f64) {
    let candidates: &[&str] = match table {
        "network" => &["bytes_sent", "bytes_recv"],
        "apps" => &["background_cycles", "foreground_cycles"],
        "energy" | "energy-lt" => &["energy_consumed", "charge_level"],
        "notifications" => &["notification_count"],
        "connectivity" => &["connected_time_ms"],
        "app-timeline" => &["focus_time_ms", "user_input_time_ms"],
        _ => &[],
    };
    for &label in candidates {
        if let Some(v) = obj.get(label).and_then(|v| v.as_f64()) {
            return (label.to_string(), v);
        }
    }
    ("value".to_string(), 0.0)
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
            "source_table": "network",
            "app_id": 42,
            "app_name": "chrome.exe",
            "bytes_sent": 1_000_000,
            "bytes_recv": 500_000,
        });
        let rec = value_to_timeline_record(val).unwrap();
        assert_eq!(rec.source_table, "network");
        assert_eq!(rec.app_id, 42);
        assert_eq!(rec.key_metric_label, "bytes_sent");
        assert_eq!(rec.key_metric_value, 1_000_000.0);
    }

    #[test]
    fn value_to_timeline_record_missing_timestamp_returns_none() {
        let val = json!({ "app_id": 1, "source_table": "network" });
        assert!(value_to_timeline_record(val).is_none());
    }

    #[test]
    fn interpret_automated_execution() {
        let rec = AnnotatedRecord {
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
