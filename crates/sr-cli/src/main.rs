//! `sr` — SRUM forensic analysis CLI.
//!
//! Subcommands:
//! - `sr network <path>` — parse and print network usage records as JSON
//! - `sr apps <path>`   — parse and print application usage records as JSON
//! - `sr idmap <path>`  — dump the `SruDbIdMapTable` as JSON

use std::collections::HashMap;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::Serialize;

/// Output format for subcommand results.
#[derive(clap::ValueEnum, Clone, Default, PartialEq)]
enum OutputFormat {
    #[default]
    Json,
    Csv,
}

/// SRUM forensic analysis tool.
///
/// Reads SRUDB.dat (Windows System Resource Usage Monitor database) and
/// extracts per-process network and application usage records.
#[derive(Parser)]
#[command(name = "sr", about = "SRUM forensic analysis tool", version)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Parse network usage records from SRUDB.dat and print as JSON.
    ///
    /// Records come from the {973F5D5C-1D90-4944-BE8E-24B22A728CF2} table.
    Network {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Resolve `app_id` and `user_id` to names from `SruDbIdMapTable`.
        ///
        /// Adds `app_name` and `user_name` fields to each record.
        #[arg(long)]
        resolve: bool,
        /// Output format (json or csv).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Parse application usage records from SRUDB.dat and print as JSON.
    ///
    /// Records come from the {5C8CF1C7-7257-4F13-B223-970EF5939312} table.
    Apps {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Resolve `app_id` and `user_id` to names from `SruDbIdMapTable`.
        ///
        /// Adds `app_name` and `user_name` fields to each record.
        #[arg(long)]
        resolve: bool,
        /// Output format (json or csv).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Dump the `SruDbIdMapTable` as JSON — resolves `app_id` / `user_id` integers
    /// to process paths and SIDs.
    Idmap {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Output format (json or csv).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Parse network connectivity records — L2 connection sessions per process.
    ///
    /// Records come from the {DD6636C4-8929-4683-974E-22C046A43763} table.
    Connectivity {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Resolve `app_id`, `user_id`, and `profile_id` to names from `SruDbIdMapTable`.
        ///
        /// Adds `app_name`, `user_name`, and `profile_name` fields to each record.
        #[arg(long)]
        resolve: bool,
        /// Output format (json or csv).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Parse energy usage records — battery drain and power consumption per process.
    ///
    /// Records come from the {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37} table.
    Energy {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Resolve `app_id` and `user_id` to names from `SruDbIdMapTable`.
        ///
        /// Adds `app_name` and `user_name` fields to each record.
        #[arg(long)]
        resolve: bool,
        /// Output format (json or csv).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Parse push notification records — app notification activity per interval.
    ///
    /// Records come from the {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} table.
    Notifications {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Resolve `app_id` and `user_id` to names from `SruDbIdMapTable`.
        ///
        /// Adds `app_name` and `user_name` fields to each record.
        #[arg(long)]
        resolve: bool,
        /// Output format (json or csv).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Parse Application Timeline records — in-focus and user-input duration per app.
    ///
    /// Records come from the {7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F} table.
    /// Available since Windows 10 Anniversary Update (1607).
    #[command(name = "app-timeline")]
    AppTimeline {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Resolve `app_id` and `user_id` to names from `SruDbIdMapTable`.
        ///
        /// Adds `app_name` and `user_name` fields to each record.
        #[arg(long)]
        resolve: bool,
        /// Output format (json or csv).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Merge all SRUM tables into a single chronological timeline.
    ///
    /// Reads network, apps, connectivity, energy, notifications, and focus
    /// records, injects a `table` field on each entry, and sorts by timestamp.
    /// Apps records are automatically flagged with `background_cpu_dominant`
    /// where background CPU dominates foreground (forensicnomicon heuristic).
    /// Tables that are absent or unreadable are silently skipped.
    Timeline {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Resolve `app_id` and `user_id` to names from `SruDbIdMapTable`.
        ///
        /// Adds `app_name` and `user_name` fields to all records that carry
        /// those integer IDs.
        #[arg(long)]
        resolve: bool,
        /// Output format (json or csv).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
}

/// Build an id→name lookup from the id-map table in `path`.
///
/// Returns an empty map if the table cannot be read (non-fatal: resolution
/// is best-effort and the caller still outputs the raw integer IDs).
fn load_id_map(path: &std::path::Path) -> HashMap<i32, String> {
    srum_parser::parse_id_map(path)
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e.id, e.name))
        .collect()
}

/// Inject `app_name` and `user_name` into a serialisable record.
///
/// Serialises `record` to a JSON object, then inserts resolved name fields
/// alongside the existing integer ID fields. Records whose IDs are absent
/// from `id_map` receive no extra field (not `null`).
fn enrich<T: Serialize>(record: T, id_map: &HashMap<i32, String>) -> serde_json::Value {
    let mut v = serde_json::to_value(record).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = v.as_object_mut() {
        if let Some(name) = obj
            .get("app_id")
            .and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .and_then(|id| id_map.get(&id))
        {
            obj.insert(
                "app_name".to_owned(),
                serde_json::Value::String(name.clone()),
            );
        }
        if let Some(name) = obj
            .get("user_id")
            .and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .and_then(|id| id_map.get(&id))
        {
            obj.insert(
                "user_name".to_owned(),
                serde_json::Value::String(name.clone()),
            );
        }
    }
    v
}

/// Inject `app_name`, `user_name`, and `profile_name` into a connectivity record.
///
/// Same pattern as [`enrich`] but also resolves `profile_id` to `profile_name`.
fn enrich_connectivity(
    mut v: serde_json::Value,
    id_map: &std::collections::HashMap<i32, String>,
) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        for &(id_key, name_key) in &[
            ("app_id", "app_name"),
            ("user_id", "user_name"),
            ("profile_id", "profile_name"),
        ] {
            if let Some(name) = obj
                .get(id_key)
                .and_then(serde_json::Value::as_i64)
                .and_then(|id| i32::try_from(id).ok())
                .and_then(|id| id_map.get(&id))
            {
                obj.insert(name_key.to_owned(), serde_json::Value::String(name.clone()));
            }
        }
    }
    v
}

/// Serialise a slice of records into a `Vec<serde_json::Value>`.
fn records_to_values<T: Serialize>(records: Vec<T>) -> anyhow::Result<Vec<serde_json::Value>> {
    records
        .into_iter()
        .map(|r| serde_json::to_value(r).map_err(Into::into))
        .collect()
}

/// Render a slice of JSON objects as CSV text.
///
/// Column order follows the key order of the first object.  Missing keys in
/// subsequent rows produce empty cells.
fn values_to_csv(values: &[serde_json::Value]) -> anyhow::Result<String> {
    if values.is_empty() {
        return Ok(String::new());
    }
    let headers: Vec<String> = match &values[0] {
        serde_json::Value::Object(m) => m.keys().cloned().collect(),
        _ => anyhow::bail!("expected JSON object for CSV serialisation"),
    };
    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(&headers)?;
    for v in values {
        if let serde_json::Value::Object(m) = v {
            let row: Vec<String> = headers
                .iter()
                .map(|k| match m.get(k) {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(val) => val.to_string(),
                    None => String::new(),
                })
                .collect();
            wtr.write_record(&row)?;
        }
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}

/// Print `values` in the requested `format`.
fn print_values(values: &[serde_json::Value], format: &OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(values)?),
        OutputFormat::Csv => print!("{}", values_to_csv(values)?),
    }
    Ok(())
}

/// Merge Application Timeline focus data into matching `apps` records.
///
/// Joins by `(app_id, timestamp)` and injects `focus_time_ms` and
/// `user_input_time_ms` into each apps record that has a counterpart in the
/// focus slice.  Unmatched focus records are silently dropped.
fn merge_focus_into_apps(apps: &mut Vec<serde_json::Value>, focus: Vec<serde_json::Value>) {
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
    for v in apps.iter_mut() {
        if let Some(obj) = v.as_object_mut() {
            let key = obj
                .get("app_id")
                .and_then(serde_json::Value::as_i64)
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

/// Apply forensic heuristics from `forensicnomicon` to a merged timeline.
///
/// Flags `apps` records with:
/// - `background_cpu_dominant`: background cycles ≥ 10× foreground
/// - `no_focus_with_cpu`: background CPU active but zero focus time (only when
///   focus data was merged in — absent focus field means unknown, not false)
fn apply_heuristics(values: &mut Vec<serde_json::Value>) {
    use forensicnomicon::heuristics::srum::is_background_cpu_dominant;
    for v in values.iter_mut() {
        if v.get("table").and_then(|t| t.as_str()) == Some("apps") {
            if let Some(obj) = v.as_object_mut() {
                let bg = obj
                    .get("background_cycles")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let fg = obj
                    .get("foreground_cycles")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                if is_background_cpu_dominant(bg, fg) {
                    obj.insert(
                        "background_cpu_dominant".to_owned(),
                        serde_json::Value::Bool(true),
                    );
                }
                if obj.contains_key("focus_time_ms") {
                    let focus_ms = obj
                        .get("focus_time_ms")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    if bg > 0 && focus_ms == 0 {
                        obj.insert("no_focus_with_cpu".to_owned(), serde_json::Value::Bool(true));
                    }
                }
            }
        }
    }
}

/// Build a merged, chronologically sorted timeline from all SRUM tables.
///
/// Each record has a `table` field injected to identify its source.
/// Heuristic flags (e.g. `background_cpu_dominant`) are applied automatically.
/// Tables that cannot be read are silently skipped (best-effort).
fn build_timeline(
    path: &std::path::Path,
    id_map: Option<&HashMap<i32, String>>,
) -> Vec<serde_json::Value> {
    let mut all: Vec<serde_json::Value> = Vec::new();

    macro_rules! load_table {
        ($name:expr, $loader:expr) => {
            if let Ok(records) = $loader(path) {
                if let Ok(mut values) = records_to_values(records) {
                    for v in &mut values {
                        if let Some(obj) = v.as_object_mut() {
                            obj.insert(
                                "table".to_owned(),
                                serde_json::Value::String($name.to_owned()),
                            );
                        }
                    }
                    all.append(&mut values);
                }
            }
        };
    }

    load_table!("network", srum_parser::parse_network_usage);
    load_table!("apps", srum_parser::parse_app_usage);
    load_table!("connectivity", srum_parser::parse_network_connectivity);
    load_table!("energy", srum_parser::parse_energy_usage);
    load_table!("notifications", srum_parser::parse_push_notifications);

    if let Ok(focus_records) = srum_parser::parse_app_timeline(path) {
        if let Ok(focus_values) = records_to_values(focus_records) {
            let mut apps_values: Vec<serde_json::Value> = all
                .iter()
                .filter(|v| v.get("table").and_then(|t| t.as_str()) == Some("apps"))
                .cloned()
                .collect();
            merge_focus_into_apps(&mut apps_values, focus_values);
            for merged in &apps_values {
                if let Some(pos) = all.iter().position(|v| {
                    v.get("app_id") == merged.get("app_id")
                        && v.get("timestamp") == merged.get("timestamp")
                        && v.get("table").and_then(|t| t.as_str()) == Some("apps")
                }) {
                    all[pos] = merged.clone();
                }
            }
        }
    }

    if let Some(map) = id_map {
        all = all.into_iter().map(|v| enrich(v, map)).collect();
    }

    apply_heuristics(&mut all);

    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb)
    });

    all
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Network {
            path,
            resolve,
            format,
        } => {
            let records = srum_parser::parse_network_usage(&path)?;
            let values: Vec<serde_json::Value> = if resolve {
                let id_map = load_id_map(&path);
                records.into_iter().map(|r| enrich(r, &id_map)).collect()
            } else {
                records_to_values(records)?
            };
            print_values(&values, &format)?;
        }
        Cmd::Apps {
            path,
            resolve,
            format,
        } => {
            let records = srum_parser::parse_app_usage(&path)?;
            let mut values: Vec<serde_json::Value> = if resolve {
                let id_map = load_id_map(&path);
                records.into_iter().map(|r| enrich(r, &id_map)).collect()
            } else {
                records_to_values(records)?
            };
            if let Ok(focus_records) = srum_parser::parse_app_timeline(&path) {
                if let Ok(focus_values) = records_to_values(focus_records) {
                    merge_focus_into_apps(&mut values, focus_values);
                }
            }
            print_values(&values, &format)?;
        }
        Cmd::Idmap { path, format } => {
            let entries = srum_parser::parse_id_map(&path)?;
            let values = records_to_values(entries)?;
            print_values(&values, &format)?;
        }
        Cmd::Connectivity {
            path,
            resolve,
            format,
        } => {
            let records = srum_parser::parse_network_connectivity(&path)?;
            let mut values = records_to_values(records)?;
            if resolve {
                let id_map = load_id_map(&path);
                values = values
                    .into_iter()
                    .map(|r| enrich_connectivity(r, &id_map))
                    .collect();
            }
            print_values(&values, &format)?;
        }
        Cmd::Energy {
            path,
            resolve,
            format,
        } => {
            let records = srum_parser::parse_energy_usage(&path)?;
            let mut values = records_to_values(records)?;
            if resolve {
                let id_map = load_id_map(&path);
                values = values.into_iter().map(|r| enrich(r, &id_map)).collect();
            }
            print_values(&values, &format)?;
        }
        Cmd::Notifications {
            path,
            resolve,
            format,
        } => {
            let records = srum_parser::parse_push_notifications(&path)?;
            let mut values = records_to_values(records)?;
            if resolve {
                let id_map = load_id_map(&path);
                values = values.into_iter().map(|r| enrich(r, &id_map)).collect();
            }
            print_values(&values, &format)?;
        }
        Cmd::AppTimeline {
            path,
            resolve,
            format,
        } => {
            let records = srum_parser::parse_app_timeline(&path)?;
            let values: Vec<serde_json::Value> = if resolve {
                let id_map = load_id_map(&path);
                records.into_iter().map(|r| enrich(r, &id_map)).collect()
            } else {
                records_to_values(records)?
            };
            print_values(&values, &format)?;
        }
        Cmd::Timeline {
            path,
            resolve,
            format,
        } => {
            let id_map = resolve.then(|| load_id_map(&path));
            let all = build_timeline(&path, id_map.as_ref());
            print_values(&all, &format)?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apps_record(bg: u64, fg: u64) -> serde_json::Value {
        serde_json::json!({
            "table": "apps",
            "app_id": 1,
            "background_cycles": bg,
            "foreground_cycles": fg,
        })
    }

    fn apps_record_with_focus(bg: u64, fg: u64, focus_ms: u64, input_ms: u64) -> serde_json::Value {
        serde_json::json!({
            "table": "apps",
            "app_id": 1,
            "timestamp": "2024-06-15T08:00:00Z",
            "background_cycles": bg,
            "foreground_cycles": fg,
            "focus_time_ms": focus_ms,
            "user_input_time_ms": input_ms,
        })
    }

    fn focus_record(app_id: i32, ts: &str, focus_ms: u64, input_ms: u64) -> serde_json::Value {
        serde_json::json!({
            "app_id": app_id,
            "timestamp": ts,
            "focus_time_ms": focus_ms,
            "user_input_time_ms": input_ms,
        })
    }

    // ── apply_heuristics: background_cpu_dominant ─────────────────────────────

    #[test]
    fn apply_heuristics_flags_dominant_background_cpu() {
        let mut values = vec![apps_record(10_000, 0)];
        apply_heuristics(&mut values);
        assert_eq!(
            values[0].get("background_cpu_dominant"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn apply_heuristics_flags_ten_to_one_ratio() {
        let mut values = vec![apps_record(1_000, 100)];
        apply_heuristics(&mut values);
        assert_eq!(
            values[0].get("background_cpu_dominant"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn apply_heuristics_does_not_flag_equal_cycles() {
        let mut values = vec![apps_record(100, 100)];
        apply_heuristics(&mut values);
        assert!(values[0].get("background_cpu_dominant").is_none());
    }

    #[test]
    fn apply_heuristics_does_not_flag_non_apps_table() {
        let mut values = vec![serde_json::json!({
            "table": "network",
            "background_cycles": 99_999,
            "foreground_cycles": 0,
        })];
        apply_heuristics(&mut values);
        assert!(values[0].get("background_cpu_dominant").is_none());
    }

    #[test]
    fn apply_heuristics_preserves_other_fields() {
        let mut values = vec![apps_record(10_000, 0)];
        apply_heuristics(&mut values);
        assert_eq!(values[0].get("app_id"), Some(&serde_json::Value::Number(1.into())));
    }

    // ── apply_heuristics: no_focus_with_cpu ──────────────────────────────────

    #[test]
    fn apply_heuristics_flags_no_focus_with_background_cpu() {
        let mut values = vec![apps_record_with_focus(5_000, 0, 0, 0)];
        apply_heuristics(&mut values);
        assert_eq!(
            values[0].get("no_focus_with_cpu"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn apply_heuristics_no_focus_with_cpu_not_set_when_focus_present() {
        // App had some foreground time and some focus — not suspicious
        let mut values = vec![apps_record_with_focus(1_000, 100, 30_000, 15_000)];
        apply_heuristics(&mut values);
        assert!(values[0].get("no_focus_with_cpu").is_none());
    }

    #[test]
    fn apply_heuristics_no_focus_with_cpu_not_set_when_no_background_cycles() {
        // Zero background cycles — not a CPU-without-focus case
        let mut values = vec![apps_record_with_focus(0, 500, 0, 0)];
        apply_heuristics(&mut values);
        assert!(values[0].get("no_focus_with_cpu").is_none());
    }

    #[test]
    fn apply_heuristics_no_focus_with_cpu_absent_when_focus_field_missing() {
        // Focus data not merged in — don't emit the signal (unknown, not false)
        let mut values = vec![apps_record(5_000, 0)];
        apply_heuristics(&mut values);
        assert!(values[0].get("no_focus_with_cpu").is_none());
    }

    #[test]
    fn apply_heuristics_both_signals_set_for_cover_ui_malware() {
        // 10:1 ratio (background_cpu_dominant) AND zero focus (no_focus_with_cpu)
        let mut values = vec![apps_record_with_focus(10_000, 1_000, 0, 0)];
        apply_heuristics(&mut values);
        assert_eq!(
            values[0].get("background_cpu_dominant"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(
            values[0].get("no_focus_with_cpu"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn apply_heuristics_only_no_focus_set_when_ratio_ok_but_zero_focus() {
        // Small background/foreground ratio (not dominant) but zero focus time
        let mut values = vec![apps_record_with_focus(200, 100, 0, 0)];
        apply_heuristics(&mut values);
        assert!(values[0].get("background_cpu_dominant").is_none());
        assert_eq!(
            values[0].get("no_focus_with_cpu"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    // ── apply_heuristics: phantom_foreground ──────────────────────────────────

    #[test]
    fn apply_heuristics_flags_phantom_foreground_fg_cycles_no_focus() {
        // fg ≥ 1000, focus = 0, focus field present → phantom_foreground: true
        let mut values = vec![apps_record_with_focus(0, 1_000, 0, 0)];
        apply_heuristics(&mut values);
        assert_eq!(
            values[0].get("phantom_foreground"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn apply_heuristics_phantom_foreground_not_set_when_focus_present() {
        // fg cycles but actual focus time → not suspicious
        let mut values = vec![apps_record_with_focus(0, 1_000, 30_000, 5_000)];
        apply_heuristics(&mut values);
        assert!(values[0].get("phantom_foreground").is_none());
    }

    #[test]
    fn apply_heuristics_phantom_foreground_absent_when_focus_field_missing() {
        // No focus_time_ms key at all → unknown, not suspicious
        let mut values = vec![serde_json::json!({
            "table": "apps",
            "app_id": 1,
            "foreground_cycles": 2_000_u64,
            "background_cycles": 0_u64,
        })];
        apply_heuristics(&mut values);
        assert!(values[0].get("phantom_foreground").is_none());
    }

    #[test]
    fn apply_heuristics_phantom_foreground_not_set_below_min_cycles() {
        // fg < PHANTOM_FOREGROUND_MIN_CYCLES (1000) → not flagged
        let mut values = vec![apps_record_with_focus(0, 999, 0, 0)];
        apply_heuristics(&mut values);
        assert!(values[0].get("phantom_foreground").is_none());
    }

    #[test]
    fn apply_heuristics_phantom_foreground_set_alongside_no_focus_with_cpu() {
        // bg > 0, fg ≥ 1000, focus = 0 → both no_focus_with_cpu AND phantom_foreground
        let mut values = vec![apps_record_with_focus(5_000, 1_000, 0, 0)];
        apply_heuristics(&mut values);
        assert_eq!(
            values[0].get("no_focus_with_cpu"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(
            values[0].get("phantom_foreground"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    // ── merge_focus_into_apps ─────────────────────────────────────────────────

    #[test]
    fn merge_focus_injects_fields_on_matching_record() {
        let mut apps = vec![serde_json::json!({
            "table": "apps",
            "app_id": 42,
            "timestamp": "2024-06-15T08:00:00Z",
            "background_cycles": 1000_u64,
        })];
        let focus = vec![focus_record(42, "2024-06-15T08:00:00Z", 30_000, 12_000)];
        merge_focus_into_apps(&mut apps, focus);
        assert_eq!(apps[0].get("focus_time_ms"), Some(&serde_json::Value::Number(30_000_u64.into())));
        assert_eq!(apps[0].get("user_input_time_ms"), Some(&serde_json::Value::Number(12_000_u64.into())));
    }

    #[test]
    fn merge_focus_does_not_inject_when_no_match() {
        let mut apps = vec![serde_json::json!({
            "table": "apps",
            "app_id": 42,
            "timestamp": "2024-06-15T08:00:00Z",
        })];
        let focus = vec![focus_record(99, "2024-06-15T08:00:00Z", 30_000, 0)];
        merge_focus_into_apps(&mut apps, focus);
        assert!(apps[0].get("focus_time_ms").is_none());
    }

    #[test]
    fn merge_focus_does_not_inject_when_timestamp_differs() {
        let mut apps = vec![serde_json::json!({
            "table": "apps",
            "app_id": 42,
            "timestamp": "2024-06-15T08:00:00Z",
        })];
        let focus = vec![focus_record(42, "2024-06-15T09:00:00Z", 30_000, 0)];
        merge_focus_into_apps(&mut apps, focus);
        assert!(apps[0].get("focus_time_ms").is_none());
    }

    #[test]
    fn merge_focus_preserves_existing_apps_fields() {
        let mut apps = vec![serde_json::json!({
            "table": "apps",
            "app_id": 7,
            "timestamp": "2024-06-15T08:00:00Z",
            "background_cycles": 500_u64,
        })];
        let focus = vec![focus_record(7, "2024-06-15T08:00:00Z", 5_000, 2_000)];
        merge_focus_into_apps(&mut apps, focus);
        assert_eq!(apps[0].get("background_cycles"), Some(&serde_json::Value::Number(500_u64.into())));
        assert_eq!(apps[0].get("table"), Some(&serde_json::Value::String("apps".into())));
    }

    #[test]
    fn merge_focus_does_not_overwrite_app_id_or_timestamp() {
        let mut apps = vec![serde_json::json!({
            "table": "apps",
            "app_id": 42,
            "timestamp": "2024-06-15T08:00:00Z",
        })];
        let focus = vec![focus_record(42, "2024-06-15T08:00:00Z", 1_000, 500)];
        merge_focus_into_apps(&mut apps, focus);
        assert_eq!(apps[0].get("app_id"), Some(&serde_json::Value::Number(42.into())));
        assert_eq!(apps[0].get("timestamp"), Some(&serde_json::Value::String("2024-06-15T08:00:00Z".into())));
    }
}
