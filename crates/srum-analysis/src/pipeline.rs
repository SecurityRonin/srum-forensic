use std::collections::HashMap;
use std::path::Path;

pub const TABLE_KEY: &str = "source_table";

pub const HEURISTIC_KEYS: &[&str] = &[
    "background_cpu_dominant",
    "no_focus_with_cpu",
    "phantom_foreground",
    "automated_execution",
    "exfil_signal",
    "beaconing",
    "notification_c2",
    "suspicious_path",
    "masquerade_candidate",
    "user_present",
];

pub fn build_timeline(
    path: &Path,
    id_map: Option<&HashMap<i32, String>>,
) -> Vec<serde_json::Value> {
    let mut all: Vec<serde_json::Value> = Vec::new();

    macro_rules! load_table {
        ($name:expr, $loader:expr) => {
            if let Ok(records) = $loader(path) {
                for r in records {
                    if let Ok(mut v) = serde_json::to_value(r) {
                        if let Some(obj) = v.as_object_mut() {
                            obj.insert(TABLE_KEY.to_owned(), serde_json::Value::String($name.to_owned()));
                        }
                        all.push(v);
                    }
                }
            }
        };
    }

    load_table!("network",       srum_parser::parse_network_usage);
    load_table!("apps",          srum_parser::parse_app_usage);
    load_table!("connectivity",  srum_parser::parse_network_connectivity);
    load_table!("energy",        srum_parser::parse_energy_usage);
    load_table!("energy-lt",     srum_parser::parse_energy_lt);
    load_table!("notifications", srum_parser::parse_push_notifications);

    // Focus data: joined into apps rows, not added as standalone records
    let focus_values: Vec<serde_json::Value> = srum_parser::parse_app_timeline(path)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();

    if let Some(map) = id_map {
        all = all.into_iter().map(|v| crate::enrich::enrich_value(v, map)).collect();
    }

    merge_focus_into_apps(&mut all, focus_values);
    apply_heuristics(&mut all);
    apply_cross_table_signals(&mut all);
    apply_beaconing_signals(&mut all);
    apply_notification_c2_signal(&mut all);
    annotate_user_presence(&mut all);

    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb)
    });

    all
}

pub fn merge_focus_into_apps(all: &mut Vec<serde_json::Value>, focus: Vec<serde_json::Value>) {
    let mut focus_map: HashMap<(i64, String), (u64, u64)> = HashMap::new();
    for f in focus {
        if let (Some(app_id), Some(ts), Some(focus_ms), Some(input_ms)) = (
            f.get("app_id").and_then(serde_json::Value::as_i64),
            f.get("timestamp").and_then(serde_json::Value::as_str).map(str::to_owned),
            f.get("focus_time_ms").and_then(serde_json::Value::as_u64),
            f.get("user_input_time_ms").and_then(serde_json::Value::as_u64),
        ) {
            focus_map.insert((app_id, ts), (focus_ms, input_ms));
        }
    }
    for v in all.iter_mut() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) != Some("apps") {
            continue;
        }
        if let Some(obj) = v.as_object_mut() {
            let key = obj
                .get("app_id").and_then(serde_json::Value::as_i64)
                .zip(obj.get("timestamp").and_then(serde_json::Value::as_str).map(str::to_owned));
            if let Some((app_id, ts)) = key {
                if let Some(&(focus_ms, input_ms)) = focus_map.get(&(app_id, ts)) {
                    obj.insert("focus_time_ms".to_owned(), focus_ms.into());
                    obj.insert("user_input_time_ms".to_owned(), input_ms.into());
                }
            }
        }
    }
}

pub fn mitre_techniques_for(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<&'static str> {
    let mut techs: Vec<&'static str> = Vec::new();
    if obj.contains_key("background_cpu_dominant") { techs.push("T1496"); }
    if obj.contains_key("no_focus_with_cpu")       { techs.push("T1564"); }
    if obj.contains_key("phantom_foreground")       { techs.push("T1036"); }
    if obj.contains_key("automated_execution")      { techs.push("T1059"); }
    if obj.contains_key("exfil_signal")             { techs.push("T1048"); }
    if obj.contains_key("beaconing")                { techs.push("T1071"); }
    if obj.contains_key("notification_c2")          { techs.push("T1092"); }
    if obj.contains_key("suspicious_path")          { techs.push("T1036.005"); }
    if obj.contains_key("masquerade_candidate")     { techs.push("T1036.005"); }
    techs.sort_unstable();
    techs.dedup();
    techs
}

pub fn apply_heuristics(values: &mut Vec<serde_json::Value>) {
    use forensicnomicon::heuristics::srum::{
        is_automated_execution, is_background_cpu_dominant, is_phantom_foreground,
    };
    for v in values.iter_mut() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) != Some("apps") {
            continue;
        }
        if let Some(obj) = v.as_object_mut() {
            let bg = obj.get("background_cycles").and_then(serde_json::Value::as_u64).unwrap_or(0);
            let fg = obj.get("foreground_cycles").and_then(serde_json::Value::as_u64).unwrap_or(0);
            if is_background_cpu_dominant(bg, fg) {
                obj.insert("background_cpu_dominant".to_owned(), serde_json::Value::Bool(true));
            }
            if obj.contains_key("focus_time_ms") {
                let focus_ms = obj.get("focus_time_ms").and_then(serde_json::Value::as_u64).unwrap_or(0);
                let input_ms = obj.get("user_input_time_ms").and_then(serde_json::Value::as_u64).unwrap_or(0);
                if bg > 0 && focus_ms == 0 {
                    obj.insert("no_focus_with_cpu".to_owned(), serde_json::Value::Bool(true));
                }
                if is_phantom_foreground(fg, focus_ms) {
                    obj.insert("phantom_foreground".to_owned(), serde_json::Value::Bool(true));
                }
                if is_automated_execution(focus_ms, input_ms) {
                    obj.insert("automated_execution".to_owned(), serde_json::Value::Bool(true));
                }
                if focus_ms > 0 {
                    let ratio = input_ms as f64 / focus_ms as f64;
                    if let Some(n) = serde_json::Number::from_f64(ratio) {
                        obj.insert("interactivity_ratio".to_owned(), serde_json::Value::Number(n));
                    }
                }
            }
            let techs = mitre_techniques_for(obj);
            if !techs.is_empty() {
                let arr: Vec<serde_json::Value> = techs.iter().map(|&t| t.into()).collect();
                obj.insert("mitre_techniques".to_owned(), serde_json::Value::Array(arr));
            }
        }
    }
}

pub fn apply_cross_table_signals(all: &mut Vec<serde_json::Value>) {
    use forensicnomicon::heuristics::srum::{is_exfil_ratio, is_exfil_volume};

    let mut net_map: HashMap<(i64, String), (u64, u64)> = HashMap::new();
    for v in all.iter() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) == Some("network") {
            if let (Some(app_id), Some(ts), Some(sent), Some(recv)) = (
                v.get("app_id").and_then(serde_json::Value::as_i64),
                v.get("timestamp").and_then(serde_json::Value::as_str).map(str::to_owned),
                v.get("bytes_sent").and_then(serde_json::Value::as_u64),
                v.get("bytes_received").and_then(serde_json::Value::as_u64),
            ) {
                net_map.insert((app_id, ts), (sent, recv));
            }
        }
    }
    for v in all.iter_mut() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) != Some("apps") { continue; }
        if let Some(obj) = v.as_object_mut() {
            let key = obj.get("app_id").and_then(serde_json::Value::as_i64)
                .zip(obj.get("timestamp").and_then(serde_json::Value::as_str).map(str::to_owned));
            if let Some((app_id, ts)) = key {
                if let Some(&(sent, recv)) = net_map.get(&(app_id, ts)) {
                    let net_exfil = is_exfil_volume(sent) || is_exfil_ratio(sent, recv);
                    let bg = obj.get("background_cycles").and_then(serde_json::Value::as_u64).unwrap_or(0);
                    let focus_ms = obj.get("focus_time_ms").and_then(serde_json::Value::as_u64);
                    if net_exfil && bg > 0 && focus_ms.map_or(true, |ms| ms == 0) {
                        obj.insert("exfil_signal".to_owned(), serde_json::Value::Bool(true));
                        let techs = mitre_techniques_for(obj);
                        if !techs.is_empty() {
                            let arr: Vec<serde_json::Value> = techs.iter().map(|&t| t.into()).collect();
                            obj.insert("mitre_techniques".to_owned(), serde_json::Value::Array(arr));
                        }
                    }
                }
            }
        }
    }
}

pub fn apply_beaconing_signals(all: &mut Vec<serde_json::Value>) {
    use forensicnomicon::heuristics::srum::is_beaconing;

    let mut net_ts: HashMap<i64, Vec<String>> = HashMap::new();
    for v in all.iter() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) == Some("network") {
            if let (Some(app_id), Some(ts)) = (
                v.get("app_id").and_then(|x| x.as_i64()),
                v.get("timestamp").and_then(|x| x.as_str()),
            ) {
                net_ts.entry(app_id).or_default().push(ts.to_owned());
            }
        }
    }
    let mut beaconing_apps: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for (app_id, mut timestamps) in net_ts {
        timestamps.sort();
        let secs: Vec<i64> = timestamps.iter()
            .filter_map(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok().map(|dt| dt.timestamp()))
            .collect();
        if is_beaconing(&secs) { beaconing_apps.insert(app_id); }
    }
    for v in all.iter_mut() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) != Some("network") { continue; }
        if let Some(app_id) = v.get("app_id").and_then(|x| x.as_i64()) {
            if beaconing_apps.contains(&app_id) {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("beaconing".to_owned(), serde_json::Value::Bool(true));
                    let techs = obj.entry("mitre_techniques")
                        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                    if let serde_json::Value::Array(arr) = techs {
                        let t1071 = serde_json::Value::String("T1071".to_owned());
                        if !arr.contains(&t1071) { arr.push(t1071); }
                    }
                }
            }
        }
    }
}

const NOTIFICATION_C2_MIN_COUNT: u64 = 10;

pub fn apply_notification_c2_signal(all: &mut Vec<serde_json::Value>) {
    let mut notif_map: HashMap<(i64, String), u64> = HashMap::new();
    for v in all.iter() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) == Some("notifications") {
            if let (Some(app_id), Some(ts)) = (
                v.get("app_id").and_then(|x| x.as_i64()),
                v.get("timestamp").and_then(|x| x.as_str()).map(str::to_owned),
            ) {
                let count = v.get("notification_count").and_then(|x| x.as_u64()).unwrap_or(1);
                *notif_map.entry((app_id, ts)).or_insert(0) += count;
            }
        }
    }
    for v in all.iter_mut() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) != Some("apps") { continue; }
        if let Some(obj) = v.as_object_mut() {
            let key = obj.get("app_id").and_then(|x| x.as_i64())
                .zip(obj.get("timestamp").and_then(|x| x.as_str()).map(str::to_owned));
            if let Some((app_id, ts)) = key {
                if let Some(&count) = notif_map.get(&(app_id, ts)) {
                    if count > NOTIFICATION_C2_MIN_COUNT {
                        let bg = obj.get("background_cycles").and_then(|x| x.as_u64()).unwrap_or(0);
                        let focus_ms = obj.get("focus_time_ms").and_then(|x| x.as_u64());
                        if bg > 0 && focus_ms.map_or(true, |ms| ms == 0) {
                            obj.insert("notification_c2".to_owned(), serde_json::Value::Bool(true));
                            let techs = obj.entry("mitre_techniques")
                                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                            if let serde_json::Value::Array(arr) = techs {
                                let t1092 = serde_json::Value::String("T1092".to_owned());
                                if !arr.contains(&t1092) { arr.push(t1092); }
                            }
                        }
                    }
                }
            }
        }
    }
}

const USER_PRESENCE_THRESHOLD_MS: u64 = 10_000;

pub fn annotate_user_presence(all: &mut Vec<serde_json::Value>) {
    let mut totals: HashMap<String, u64> = HashMap::new();
    for v in all.iter() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) == Some("apps") {
            if let (Some(ts), Some(ms)) = (
                v.get("timestamp").and_then(serde_json::Value::as_str).map(str::to_owned),
                v.get("user_input_time_ms").and_then(serde_json::Value::as_u64),
            ) {
                *totals.entry(ts).or_insert(0) += ms;
            }
        }
    }
    for v in all.iter_mut() {
        if let Some(ts) = v.get("timestamp").and_then(serde_json::Value::as_str) {
            if totals.get(ts).copied().unwrap_or(0) >= USER_PRESENCE_THRESHOLD_MS {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("user_present".to_owned(), serde_json::Value::Bool(true));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_timeline_returns_empty_for_nonexistent_path() {
        let result = build_timeline(std::path::Path::new("/nonexistent/SRUDB.dat"), None);
        assert!(result.is_empty());
    }

    #[test]
    fn table_key_is_source_table() {
        assert_eq!(TABLE_KEY, "source_table");
    }

    #[test]
    fn merge_focus_injects_into_apps_rows_only() {
        let mut all = vec![
            json!({"source_table": "apps", "app_id": 1_i64, "timestamp": "2024-01-01T00:00:00Z"}),
            json!({"source_table": "network", "app_id": 1_i64, "timestamp": "2024-01-01T00:00:00Z"}),
        ];
        let focus = vec![json!({
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "focus_time_ms": 60_000_u64,
            "user_input_time_ms": 1_000_u64,
        })];
        merge_focus_into_apps(&mut all, focus);
        assert_eq!(all[0]["focus_time_ms"], json!(60_000_u64));
        assert!(all[1].get("focus_time_ms").is_none(), "network row must not get focus data");
    }

    #[test]
    fn apply_heuristics_flags_background_cpu_dominant() {
        let mut values = vec![json!({
            "source_table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "background_cycles": 10_000_000_u64,
            "foreground_cycles": 100_000_u64,
        })];
        apply_heuristics(&mut values);
        assert_eq!(values[0]["background_cpu_dominant"], json!(true));
    }

    #[test]
    fn apply_heuristics_does_not_flag_with_wrong_key() {
        // Regression: old CLI used "table" key — ensure we don't accidentally accept it
        let mut values = vec![json!({
            "table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "background_cycles": 10_000_000_u64,
            "foreground_cycles": 0_u64,
        })];
        apply_heuristics(&mut values);
        assert!(values[0].get("background_cpu_dominant").is_none());
    }

    #[test]
    fn apply_heuristics_flags_automated_execution() {
        let mut values = vec![json!({
            "source_table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "focus_time_ms": 3_600_000_u64,
            "user_input_time_ms": 0_u64,
            "background_cycles": 1_u64,
            "foreground_cycles": 1_u64,
        })];
        apply_heuristics(&mut values);
        assert_eq!(values[0]["automated_execution"], json!(true));
    }

    #[test]
    fn annotate_user_presence_marks_timestamps_above_threshold() {
        let mut all = vec![
            json!({"source_table": "apps", "timestamp": "2024-01-01T00:00:00Z",
                   "user_input_time_ms": 15_000_u64}),
            json!({"source_table": "network", "timestamp": "2024-01-01T00:00:00Z"}),
        ];
        annotate_user_presence(&mut all);
        assert_eq!(all[0]["user_present"], json!(true));
        assert_eq!(all[1]["user_present"], json!(true));
    }
}
