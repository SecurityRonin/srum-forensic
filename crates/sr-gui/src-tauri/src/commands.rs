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
                        .map(|r| serde_json::to_value(r))
                        .collect::<Result<_, _>>()?;
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
