use std::path::Path;

use crate::output::{OutputFormat, values_to_csv};

/// Map a SRUM table GUID (or well-known name) to its friendly table name.
fn guid_to_table_name(guid: &str) -> Option<&'static str> {
    match guid {
        "{973F5D5C-1D90-4944-BE8E-24B22A728CF2}" => Some("network"),
        "{5C8CF1C7-7257-4F13-B223-970EF5939312}" => Some("apps"),
        "{DD6636C4-8929-4683-974E-22C046A43763}" => Some("connectivity"),
        "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}" => Some("energy"),
        "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT" => Some("energy-lt"),
        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}" => Some("notifications"),
        "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}" => Some("app-timeline"),
        "SruDbIdMapTable" => Some("idmap"),
        "SruDbCheckpointTable" => Some("checkpoint"),
        _ => None,
    }
}

/// Derive a Windows version hint from the set of known table names present.
fn windows_version_hint(known_tables: &[String]) -> &'static str {
    if known_tables.iter().any(|t| t == "app-timeline") {
        "Windows 10 1607+ (Anniversary Update) — app-timeline table present"
    } else {
        "Windows 8.1+ — app-timeline table absent (pre-Anniversary Update or table not created)"
    }
}

/// Collect metadata about a SRUDB.dat without parsing individual records.
fn collect_metadata(path: &Path) -> anyhow::Result<serde_json::Value> {
    use sha2::{Digest, Sha256};

    // File hash and size
    let bytes = std::fs::read(path)?;
    let file_size = bytes.len() as u64;
    let hash = hex::encode(Sha256::digest(&bytes));
    drop(bytes);

    // Open ESE to enumerate tables
    let db = ese_core::EseDatabase::open(path)?;
    let catalog = db.catalog_entries().unwrap_or_default();

    // object_type == 1 means table
    let mut known_tables: Vec<String> = Vec::new();
    let mut unknown_tables: Vec<String> = Vec::new();

    for entry in catalog.iter().filter(|e| e.object_type == 1) {
        match guid_to_table_name(&entry.object_name) {
            Some(name) => known_tables.push(name.to_owned()),
            None => unknown_tables.push(entry.object_name.clone()),
        }
    }
    known_tables.sort();
    unknown_tables.sort();

    // Record counts per known table
    let mut record_counts = serde_json::Map::new();
    macro_rules! count_table {
        ($name:expr, $parser:expr) => {
            if let Ok(records) = $parser(path) {
                record_counts.insert($name.to_owned(), records.len().into());
            }
        };
    }
    count_table!("network", srum_parser::parse_network_usage);
    count_table!("apps", srum_parser::parse_app_usage);
    count_table!("connectivity", srum_parser::parse_network_connectivity);
    count_table!("energy", srum_parser::parse_energy_usage);
    count_table!("notifications", srum_parser::parse_push_notifications);
    count_table!("app-timeline", srum_parser::parse_app_timeline);
    count_table!("idmap", srum_parser::parse_id_map);

    // Temporal span — build timeline (no resolve), extract first/last timestamps
    let all = srum_analysis::build_timeline(path, None);
    let mut first_ts: Option<String> = None;
    let mut last_ts: Option<String> = None;
    for v in &all {
        if let Some(ts) = v.get("timestamp").and_then(|x| x.as_str()) {
            if first_ts.as_deref().map_or(true, |f: &str| ts < f) {
                first_ts = Some(ts.to_owned());
            }
            if last_ts.as_deref().map_or(true, |l: &str| ts > l) {
                last_ts = Some(ts.to_owned());
            }
        }
    }

    let temporal_span = match (first_ts, last_ts) {
        (Some(f), Some(l)) => serde_json::json!({"first": f, "last": l}),
        _ => serde_json::json!(null),
    };

    let hint = windows_version_hint(&known_tables);

    Ok(serde_json::json!({
        "file_path": path.to_string_lossy(),
        "sha256": hash,
        "file_size_bytes": file_size,
        "known_tables": known_tables,
        "unknown_tables": unknown_tables,
        "record_counts": serde_json::Value::Object(record_counts),
        "temporal_span": temporal_span,
        "windows_version_hint": hint,
    }))
}

pub fn run_compare(
    baseline: &Path,
    suspect: &Path,
    resolve: bool,
    format: &OutputFormat,
) -> anyhow::Result<()> {
    let id_map_baseline = resolve.then(|| srum_analysis::load_id_map(baseline));
    let id_map_suspect = resolve.then(|| srum_analysis::load_id_map(suspect));
    let baseline_timeline =
        srum_analysis::build_timeline(baseline, id_map_baseline.as_ref());
    let suspect_timeline =
        srum_analysis::build_timeline(suspect, id_map_suspect.as_ref());
    let baseline_stats = srum_analysis::analysis::build_stats(baseline_timeline);
    let suspect_stats = srum_analysis::analysis::build_stats(suspect_timeline);
    let result = srum_analysis::analysis::compare_databases(baseline_stats, suspect_stats);
    // compare outputs a single object, not an array — handle directly.
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Ndjson => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::Csv => {
            let mut flat: Vec<serde_json::Value> = Vec::new();
            if let Some(arr) = result.get("new_processes").and_then(|v| v.as_array()) {
                for r in arr {
                    let mut r = r.clone();
                    r.as_object_mut().unwrap().insert("diff_type".into(), "new".into());
                    flat.push(r);
                }
            }
            if let Some(arr) = result.get("changed").and_then(|v| v.as_array()) {
                for r in arr {
                    let mut r = r.clone();
                    r.as_object_mut()
                        .unwrap()
                        .insert("diff_type".into(), "changed".into());
                    flat.push(r);
                }
            }
            if let Some(arr) = result.get("departed_processes").and_then(|v| v.as_array()) {
                for r in arr {
                    let mut r = r.clone();
                    r.as_object_mut()
                        .unwrap()
                        .insert("diff_type".into(), "departed".into());
                    flat.push(r);
                }
            }
            print!("{}", values_to_csv(&flat)?);
        }
    }
    Ok(())
}

pub fn run_metadata(path: &Path, format: &OutputFormat) -> anyhow::Result<()> {
    let meta = collect_metadata(path)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&meta)?),
        OutputFormat::Ndjson => println!("{}", serde_json::to_string(&meta)?),
        OutputFormat::Csv => {
            print!("{}", values_to_csv(&[meta])?);
        }
    }
    Ok(())
}

