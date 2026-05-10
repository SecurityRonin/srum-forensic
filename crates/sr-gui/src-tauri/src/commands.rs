use crate::{
    findings::compute_findings,
    timeline::value_to_timeline_record,
    types::{SrumFile, TemporalSpan, TimelineRecord},
};
use std::path::Path;

#[tauri::command]
pub async fn open_file(path: String) -> Result<SrumFile, String> {
    let p = Path::new(&path);
    parse_srum(p).map_err(|e| format!("error: {e:#}"))
}

fn parse_srum(path: &Path) -> anyhow::Result<SrumFile> {
    let id_map = srum_parser::parse_id_map(path).unwrap_or_default();
    let name_for = |id: i32| -> Option<String> {
        id_map.iter().find(|e| e.id == id).map(|e| e.name.clone())
    };

    let mut all: Vec<serde_json::Value> = vec![];
    let mut table_names: Vec<String> = vec![];

    macro_rules! parse_table {
        ($table_name:expr, $parser:expr) => {
            match $parser(path) {
                Ok(records) if !records.is_empty() => {
                    table_names.push($table_name.to_string());
                    let mut rows: Vec<serde_json::Value> = records
                        .into_iter()
                        .filter_map(|r| serde_json::to_value(r).ok())
                        .collect();
                    for row in &mut rows {
                        if let Some(obj) = row.as_object_mut() {
                            let app_id = obj
                                .get("app_id")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0) as i32;
                            if let Some(name) = name_for(app_id) {
                                obj.insert(
                                    "app_name".to_string(),
                                    serde_json::Value::String(name),
                                );
                            }
                            obj.insert(
                                "source_table".to_string(),
                                serde_json::Value::String($table_name.to_string()),
                            );
                        }
                    }
                    all.extend(rows);
                }
                Ok(_) => {} // empty table — skip
                Err(_) => {} // table absent or unreadable — skip
            }
        };
    }

    parse_table!("network", srum_parser::parse_network_usage);
    parse_table!("apps", srum_parser::parse_app_usage);
    parse_table!("energy", srum_parser::parse_energy_usage);
    parse_table!("energy-lt", srum_parser::parse_energy_lt);
    parse_table!("connectivity", srum_parser::parse_network_connectivity);
    parse_table!("notifications", srum_parser::parse_push_notifications);
    parse_table!("app-timeline", srum_parser::parse_app_timeline);

    let mut timeline: Vec<TimelineRecord> = all
        .into_iter()
        .filter_map(|v| {
            let table = v
                .get("source_table")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            value_to_timeline_record(v, &table)
        })
        .collect();

    timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let temporal_span = match (timeline.first(), timeline.last()) {
        (Some(first), Some(last)) if first.timestamp != last.timestamp => Some(TemporalSpan {
            first: first.timestamp.clone(),
            last: last.timestamp.clone(),
        }),
        _ => None,
    };

    let record_count = timeline.len();
    let findings = compute_findings(&timeline);

    Ok(SrumFile {
        path: path.to_string_lossy().into_owned(),
        timeline,
        findings,
        record_count,
        temporal_span,
        table_names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_focus_injects_fields_into_matching_apps_row() {
        let mut all = vec![json!({
            "source_table": "apps",
            "app_id": 42_i64,
            "timestamp": "2024-06-15T08:00:00Z",
            "background_cycles": 1_000_000_u64,
        })];
        let focus = vec![json!({
            "app_id": 42_i64,
            "timestamp": "2024-06-15T08:00:00Z",
            "focus_time_ms": 3_600_000_u64,
            "user_input_time_ms": 0_u64,
        })];
        merge_focus_into_apps(&mut all, focus);
        assert_eq!(all[0]["focus_time_ms"], json!(3_600_000_u64));
        assert_eq!(all[0]["user_input_time_ms"], json!(0_u64));
    }

    #[test]
    fn merge_focus_only_targets_apps_source_table() {
        let mut all = vec![json!({
            "source_table": "network",
            "app_id": 42_i64,
            "timestamp": "2024-06-15T08:00:00Z",
        })];
        let focus = vec![json!({
            "app_id": 42_i64,
            "timestamp": "2024-06-15T08:00:00Z",
            "focus_time_ms": 3_600_000_u64,
            "user_input_time_ms": 500_u64,
        })];
        merge_focus_into_apps(&mut all, focus);
        assert!(all[0].get("focus_time_ms").is_none(), "network rows must not receive focus data");
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
    fn apply_heuristics_uses_source_table_not_table() {
        let mut values = vec![json!({
            "table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "background_cycles": 10_000_000_u64,
            "foreground_cycles": 0_u64,
        })];
        apply_heuristics(&mut values);
        assert!(
            values[0].get("background_cpu_dominant").is_none(),
            "'table' key must not trigger heuristics — GUI uses 'source_table'"
        );
    }

    #[test]
    fn apply_heuristics_flags_automated_execution() {
        let mut values = vec![json!({
            "source_table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "background_cycles": 100_000_u64,
            "foreground_cycles": 50_000_u64,
            "focus_time_ms": 3_600_000_u64,
            "user_input_time_ms": 0_u64,
        })];
        apply_heuristics(&mut values);
        assert_eq!(values[0]["automated_execution"], json!(true));
    }

    #[test]
    fn apply_heuristics_skips_non_apps_rows() {
        let mut values = vec![json!({
            "source_table": "network",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "background_cycles": 10_000_000_u64,
            "foreground_cycles": 0_u64,
        })];
        apply_heuristics(&mut values);
        assert!(values[0].get("background_cpu_dominant").is_none());
    }
}
