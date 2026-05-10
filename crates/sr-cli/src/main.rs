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
    Ndjson,
}

/// Classify a SID string into a well-known account type, or return `None`.
fn classify_sid(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-5-18" => Some("system"),
        "S-1-5-19" => Some("local_service"),
        "S-1-5-20" => Some("network_service"),
        "S-1-1-0"  => Some("everyone"),
        _ if sid.starts_with("S-1-5-21-") && sid.ends_with("-500") => Some("local_admin"),
        _ if sid.starts_with("S-1-5-21-") => Some("domain_user"),
        _ => None,
    }
}

/// Return MITRE ATT&CK technique IDs applicable to the heuristic flags present in `obj`.
fn mitre_techniques_for(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Vec<&'static str> {
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

/// Named forensic hunt signature for `sr hunt`.
#[derive(clap::ValueEnum, Clone, Debug)]
enum HuntSignature {
    /// Records with exfil_signal: true (cross-table exfiltration fingerprint)
    Exfil,
    /// Records with background_cpu_dominant: true (miner/persistent background process)
    Miner,
    /// Records with masquerade_candidate: true (lookalike process name)
    Masquerade,
    /// Records with suspicious_path: true (execution from temp/downloads/UNC)
    #[value(name = "suspicious-path")]
    SuspiciousPath,
    /// Records with no_focus_with_cpu: true (CPU without keyboard focus)
    #[value(name = "no-focus")]
    NoFocus,
    /// Records with phantom_foreground: true (foreground cycles but zero focus time)
    Phantom,
    /// Records with automated_execution: true (focus without user input)
    Automated,
    /// Records with beaconing: true (regular-interval network activity)
    Beaconing,
    /// Records with notification_c2: true (notification-as-C2 pattern)
    #[value(name = "notification-c2")]
    NotificationC2,
    /// Any record with at least one heuristic flag set
    All,
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
    /// Show all SRUM activity for a single process across all tables.
    ///
    /// Accepts an integer app_id or a substring of the resolved process name
    /// (requires --resolve for name matching).
    #[command(name = "process")]
    Process {
        /// App ID (integer) or name substring to filter by.
        app: String,
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Resolve app_id and user_id to names from SruDbIdMapTable.
        #[arg(long)]
        resolve: bool,
        /// Output format (json, csv, or ndjson).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Aggregate per-process statistics across all SRUM tables.
    ///
    /// Builds a merged timeline and summarises each app's CPU cycles, bytes,
    /// active intervals, and heuristic flags. Output sorted by flag_count desc,
    /// then total_background_cycles desc. Best-effort: always exits 0.
    Stats {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Resolve `app_id` to names from `SruDbIdMapTable`.
        #[arg(long)]
        resolve: bool,
        /// Output format (json, csv, or ndjson).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Derive user keyboard sessions from the SRUM timeline.
    ///
    /// A session is a contiguous run of timestamps where `user_present: true`.
    /// A gap > 2 hours between timestamps starts a new session. Best-effort:
    /// always exits 0.
    Sessions {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Output format (json, csv, or ndjson).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Detect temporal gaps in SRUM records — identifies system-off periods and
    /// potential targeted record deletion.
    ///
    /// Analyses timestamps from the merged timeline to detect two kinds of
    /// suspicious gaps:
    ///   - `system_off`: ALL tables have a gap at the same time window.
    ///   - `selective_gap`: Only ONE specific table has a gap while others have records.
    ///
    /// Best-effort: always exits 0 even for nonexistent files.
    Gaps {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
        /// Minimum gap size in hours to report (default: 2).
        #[arg(long, default_value_t = 2u64)]
        threshold_hours: u64,
        /// Output format (json, csv, or ndjson).
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Hunt for specific forensic patterns across all SRUM tables.
    ///
    /// Filters the merged timeline to records matching a named heuristic
    /// signature. Best-effort: always exits 0 even for missing files.
    Hunt {
        /// Named forensic pattern to hunt for.
        signature: HuntSignature,
        /// Path to SRUDB.dat.
        path: PathBuf,
        #[arg(long)]
        resolve: bool,
        #[arg(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Compare two SRUDB.dat files and surface what changed between them.
    ///
    /// Detects new processes, departed processes, and processes whose behaviour
    /// changed (new heuristic flags, significant byte-count deltas).
    Compare {
        /// Baseline SRUDB.dat (before the incident).
        baseline: PathBuf,
        /// Suspect SRUDB.dat (after the incident).
        suspect: PathBuf,
        /// Resolve app_id/user_id to names for process matching.
        #[arg(long)]
        resolve: bool,
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
    /// Extract metadata from a SRUDB.dat file: SHA-256 hash, table enumeration,
    /// record counts, temporal span, and Windows version hint.
    Metadata {
        path: PathBuf,
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
            // path-based signals — only when name looks like a path
            if name.contains('\\') || name.contains('/') {
                use forensicnomicon::heuristics::srum::{is_process_masquerade, is_suspicious_path};
                if is_suspicious_path(name) {
                    obj.insert("suspicious_path".to_owned(), serde_json::Value::Bool(true));
                }
                let (dir, bin) = split_windows_path(name);
                if is_process_masquerade(bin, dir) {
                    obj.insert("masquerade_candidate".to_owned(), serde_json::Value::Bool(true));
                }
            }
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
            if name.starts_with("S-") {
                if let Some(acct_type) = classify_sid(name) {
                    obj.insert(
                        "account_type".to_owned(),
                        serde_json::Value::String(acct_type.to_owned()),
                    );
                }
            }
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
        OutputFormat::Ndjson => {
            // stub — real implementation in GREEN
            for v in values {
                println!("{}", serde_json::to_string(v)?);
            }
        }
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
    use forensicnomicon::heuristics::srum::{
        is_automated_execution, is_background_cpu_dominant, is_phantom_foreground,
    };
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
                    let input_ms = obj
                        .get("user_input_time_ms")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    if bg > 0 && focus_ms == 0 {
                        obj.insert("no_focus_with_cpu".to_owned(), serde_json::Value::Bool(true));
                    }
                    if is_phantom_foreground(fg, focus_ms) {
                        obj.insert("phantom_foreground".to_owned(), serde_json::Value::Bool(true));
                    }
                    if is_automated_execution(focus_ms, input_ms) {
                        obj.insert(
                            "automated_execution".to_owned(),
                            serde_json::Value::Bool(true),
                        );
                    }
                    if focus_ms > 0 {
                        let ratio = input_ms as f64 / focus_ms as f64;
                        if let Some(n) = serde_json::Number::from_f64(ratio) {
                            obj.insert(
                                "interactivity_ratio".to_owned(),
                                serde_json::Value::Number(n),
                            );
                        }
                    }
                }
                let techs = mitre_techniques_for(obj);
                if !techs.is_empty() {
                    let arr: Vec<serde_json::Value> = techs
                        .iter()
                        .map(|&t| serde_json::Value::String(t.to_owned()))
                        .collect();
                    obj.insert("mitre_techniques".to_owned(), serde_json::Value::Array(arr));
                }
            }
        }
    }
}

const USER_PRESENCE_THRESHOLD_MS: u64 = 10_000; // 10 seconds of actual input = user present

/// Annotate every record in `all` with `user_present: true` if the aggregate
/// `user_input_time_ms` across all `apps` records for that timestamp meets or
/// exceeds [`USER_PRESENCE_THRESHOLD_MS`].
///
/// Records at timestamps with no apps activity receive no annotation — their
/// presence status is unknown, not absent.
fn annotate_user_presence(all: &mut Vec<serde_json::Value>) {
    let mut totals: HashMap<String, u64> = HashMap::new();
    for v in all.iter() {
        if v.get("table").and_then(|t| t.as_str()) == Some("apps") {
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

/// Inject `exfil_signal: true` into `apps` records where the matching network
/// record shows exfiltration-level bytes, the app ran in the background, and
/// the user had no focus time — the three-way signature of data theft.
fn apply_cross_table_signals(all: &mut Vec<serde_json::Value>) {
    use forensicnomicon::heuristics::srum::{is_exfil_ratio, is_exfil_volume};

    let mut net_map: HashMap<(i64, String), (u64, u64)> = HashMap::new();
    for v in all.iter() {
        if v.get("table").and_then(|t| t.as_str()) == Some("network") {
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
        if v.get("table").and_then(|t| t.as_str()) == Some("apps") {
            if let Some(obj) = v.as_object_mut() {
                let key = obj
                    .get("app_id").and_then(serde_json::Value::as_i64)
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
                                let arr: Vec<serde_json::Value> = techs
                                    .iter()
                                    .map(|&t| serde_json::Value::String(t.to_owned()))
                                    .collect();
                                obj.insert(
                                    "mitre_techniques".to_owned(),
                                    serde_json::Value::Array(arr),
                                );
                            }
                        }
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
            // Build focus lookup once, then do a single O(n) pass directly over all.
            // Avoids the O(n²) clone+position-scan write-back.
            let mut focus_map: HashMap<(i64, String), (u64, u64)> = HashMap::new();
            for f in focus_values {
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
                if v.get("table").and_then(|t| t.as_str()) == Some("apps") {
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
        }
    }

    if let Some(map) = id_map {
        all = all.into_iter().map(|v| enrich(v, map)).collect();
    }

    apply_heuristics(&mut all);
    apply_cross_table_signals(&mut all);
    annotate_user_presence(&mut all);

    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb)
    });

    all
}

const HEURISTIC_KEYS: &[&str] = &[
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

/// Aggregate per-process statistics from a merged timeline.
///
/// Returns a `Vec` sorted by `flag_count` descending, then
/// `total_background_cycles` descending.
fn build_stats(all: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    use std::collections::{HashMap, HashSet};

    struct AppStats {
        app_id: i64,
        app_name: Option<String>,
        bg_cycles: u64,
        fg_cycles: u64,
        bytes_sent: u64,
        bytes_recv: u64,
        count: u64,
        first_seen: Option<String>,
        last_seen: Option<String>,
        flags: HashSet<String>,
    }

    let mut map: HashMap<i64, AppStats> = HashMap::new();

    for v in &all {
        if let Some(app_id) = v.get("app_id").and_then(|x| x.as_i64()) {
            let entry = map.entry(app_id).or_insert(AppStats {
                app_id,
                app_name: None,
                bg_cycles: 0,
                fg_cycles: 0,
                bytes_sent: 0,
                bytes_recv: 0,
                count: 0,
                first_seen: None,
                last_seen: None,
                flags: HashSet::new(),
            });
            entry.count += 1;
            // app_name (first resolved name wins)
            if entry.app_name.is_none() {
                entry.app_name = v.get("app_name").and_then(|x| x.as_str()).map(str::to_owned);
            }
            // cycles
            entry.bg_cycles += v.get("background_cycles").and_then(|x| x.as_u64()).unwrap_or(0);
            entry.fg_cycles += v.get("foreground_cycles").and_then(|x| x.as_u64()).unwrap_or(0);
            // bytes
            entry.bytes_sent += v.get("bytes_sent").and_then(|x| x.as_u64()).unwrap_or(0);
            entry.bytes_recv += v
                .get("bytes_received")
                .and_then(|x| x.as_u64())
                .or_else(|| v.get("bytes_recv").and_then(|x| x.as_u64()))
                .unwrap_or(0);
            // timestamps
            if let Some(ts) = v.get("timestamp").and_then(|x| x.as_str()) {
                let ts = ts.to_owned();
                if entry.first_seen.as_deref().map_or(true, |f: &str| ts.as_str() < f) {
                    entry.first_seen = Some(ts.clone());
                }
                if entry.last_seen.as_deref().map_or(true, |l: &str| ts.as_str() > l) {
                    entry.last_seen = Some(ts);
                }
            }
            // heuristic flags (boolean true only)
            for &key in HEURISTIC_KEYS {
                if v.get(key).and_then(|x| x.as_bool()) == Some(true) {
                    entry.flags.insert(key.to_owned());
                }
            }
        }
    }

    let mut stats: Vec<serde_json::Value> = map
        .into_values()
        .map(|s| {
            let mut flags: Vec<String> = s.flags.into_iter().collect();
            flags.sort();
            let flag_count = flags.len() as u64;
            let mut obj = serde_json::json!({
                "app_id": s.app_id,
                "total_background_cycles": s.bg_cycles,
                "total_foreground_cycles": s.fg_cycles,
                "total_bytes_sent": s.bytes_sent,
                "total_bytes_received": s.bytes_recv,
                "active_intervals": s.count,
                "heuristic_flags": flags,
                "flag_count": flag_count,
            });
            if let (Some(f), Some(l)) = (s.first_seen, s.last_seen) {
                obj.as_object_mut()
                    .unwrap()
                    .insert("first_seen".into(), f.into());
                obj.as_object_mut()
                    .unwrap()
                    .insert("last_seen".into(), l.into());
            }
            if let Some(name) = s.app_name {
                obj.as_object_mut()
                    .unwrap()
                    .insert("app_name".into(), name.into());
            }
            obj
        })
        .collect();

    // Sort: flag_count desc, then total_background_cycles desc
    stats.sort_by(|a, b| {
        let fa = a.get("flag_count").and_then(|x| x.as_u64()).unwrap_or(0);
        let fb = b.get("flag_count").and_then(|x| x.as_u64()).unwrap_or(0);
        fb.cmp(&fa).then_with(|| {
            let ba = a
                .get("total_background_cycles")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            let bb = b
                .get("total_background_cycles")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            bb.cmp(&ba)
        })
    });

    stats
}

/// Derive user-presence sessions from a merged timeline.
///
/// A session is a contiguous run of `user_present: true` timestamps where the
/// gap between successive timestamps is ≤ 2 hours.
fn build_sessions(all: &[serde_json::Value]) -> Vec<serde_json::Value> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut present_ts: BTreeSet<String> = BTreeSet::new();
    let mut input_by_ts: BTreeMap<String, u64> = BTreeMap::new();

    for v in all {
        if let Some(ts) = v.get("timestamp").and_then(|x| x.as_str()) {
            if v.get("user_present").and_then(|x| x.as_bool()) == Some(true) {
                present_ts.insert(ts.to_owned());
            }
            if v.get("table").and_then(|x| x.as_str()) == Some("apps") {
                if let Some(ms) = v.get("user_input_time_ms").and_then(|x| x.as_u64()) {
                    *input_by_ts.entry(ts.to_owned()).or_insert(0) += ms;
                }
            }
        }
    }

    if present_ts.is_empty() {
        return vec![];
    }

    const SESSION_GAP_SECS: i64 = 7_200; // 2 hours

    let mut sessions: Vec<serde_json::Value> = Vec::new();
    let mut iter = present_ts.iter();
    let first = iter.next().unwrap();
    let mut session_start = first.clone();
    let mut session_end = first.clone();
    let mut session_input: u64 = input_by_ts.get(first).copied().unwrap_or(0);

    for ts in iter {
        let gap = iso_diff_secs(&session_end, ts);
        if gap > SESSION_GAP_SECS {
            sessions.push(make_session(&session_start, &session_end, session_input));
            session_start = ts.clone();
            session_input = 0;
        }
        session_end = ts.clone();
        session_input += input_by_ts.get(ts).copied().unwrap_or(0);
    }
    sessions.push(make_session(&session_start, &session_end, session_input));
    sessions
}

/// Compute the signed difference in seconds between two RFC-3339 timestamps.
fn iso_diff_secs(a: &str, b: &str) -> i64 {
    fn to_secs(s: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.timestamp())
            .unwrap_or(0)
    }
    to_secs(b) - to_secs(a)
}

/// Serialise a single session span into a JSON object.
fn make_session(start: &str, end: &str, input_ms: u64) -> serde_json::Value {
    let duration_secs = iso_diff_secs(start, end).max(0);
    let duration_hours = (duration_secs as f64 / 3600.0).ceil() as u64;
    serde_json::json!({
        "session_start": start,
        "session_end": end,
        "duration_hours": duration_hours,
        "input_ms_total": input_ms,
    })
}

/// Detect temporal gaps in a merged SRUM timeline.
///
/// Returns gap objects sorted by `start`. Two gap types:
/// - `system_off`: all tables with records share the same gap window.
/// - `selective_gap`: only one table has a gap while others have records.
fn detect_gaps(all: &[serde_json::Value], threshold_hours: u64) -> Vec<serde_json::Value> {
    use std::collections::{BTreeSet, HashMap};

    let threshold_secs = (threshold_hours * 3600) as i64;

    // Collect timestamps per table
    let mut by_table: HashMap<String, BTreeSet<String>> = HashMap::new();
    for v in all {
        if let (Some(table), Some(ts)) = (
            v.get("table").and_then(|x| x.as_str()),
            v.get("timestamp").and_then(|x| x.as_str()),
        ) {
            by_table.entry(table.to_owned()).or_default().insert(ts.to_owned());
        }
    }

    if by_table.is_empty() {
        return vec![];
    }

    // For each table, find consecutive gaps > threshold
    struct Gap {
        table: String,
        start: String,
        end: String,
    }
    let mut all_gaps: Vec<Gap> = Vec::new();

    for (table, timestamps) in &by_table {
        let ts_vec: Vec<&String> = timestamps.iter().collect();
        for w in ts_vec.windows(2) {
            let diff = iso_diff_secs(w[0], w[1]);
            if diff >= threshold_secs {
                all_gaps.push(Gap {
                    table: table.clone(),
                    start: w[0].clone(),
                    end: w[1].clone(),
                });
            }
        }
    }

    let tables: Vec<String> = by_table.keys().cloned().collect();

    // Group gaps by (start, end) to determine system_off vs selective
    let mut gap_map: HashMap<(String, String), Vec<String>> = HashMap::new();
    for g in all_gaps {
        gap_map.entry((g.start, g.end)).or_default().push(g.table);
    }

    let mut result: Vec<serde_json::Value> = Vec::new();

    for ((start, end), affected_tables) in &gap_map {
        let gap_secs = iso_diff_secs(start, end).max(0);
        let gap_hours = gap_secs / 3600;
        if affected_tables.len() == tables.len() {
            // system_off: all tables share this gap
            let mut at = affected_tables.clone();
            at.sort();
            result.push(serde_json::json!({
                "type": "system_off",
                "start": start,
                "end": end,
                "gap_hours": gap_hours,
                "tables_affected": at,
            }));
        } else {
            // selective_gap: only some tables affected
            for t in affected_tables {
                result.push(serde_json::json!({
                    "type": "selective_gap",
                    "start": start,
                    "end": end,
                    "gap_hours": gap_hours,
                    "table": t,
                    "other_tables_active": true,
                }));
            }
        }
    }

    // Sort by start timestamp
    result.sort_by(|a, b| {
        let sa = a.get("start").and_then(|v| v.as_str()).unwrap_or("");
        let sb = b.get("start").and_then(|v| v.as_str()).unwrap_or("");
        sa.cmp(sb)
    });

    result
}

/// Filter a timeline to records matching `app` by integer app_id or name substring.
fn filter_by_app(all: Vec<serde_json::Value>, app: &str) -> Vec<serde_json::Value> {
    let app_lower = app.to_lowercase();
    let app_id_filter: Option<i64> = app.parse().ok();
    all.into_iter().filter(|v| {
        // match by integer app_id
        if let Some(id) = app_id_filter {
            if v.get("app_id").and_then(|x| x.as_i64()) == Some(id) {
                return true;
            }
        }
        // match by app_name substring (case-insensitive)
        if let Some(name) = v.get("app_name").and_then(|x| x.as_str()) {
            if name.to_lowercase().contains(&app_lower) {
                return true;
            }
        }
        false
    }).collect()
}

/// Filter timeline records matching a named forensic hunt signature.
fn hunt_filter(all: Vec<serde_json::Value>, sig: &HuntSignature) -> Vec<serde_json::Value> {
    let flag_key: Option<&str> = match sig {
        HuntSignature::Exfil          => Some("exfil_signal"),
        HuntSignature::Miner          => Some("background_cpu_dominant"),
        HuntSignature::Masquerade     => Some("masquerade_candidate"),
        HuntSignature::SuspiciousPath => Some("suspicious_path"),
        HuntSignature::NoFocus        => Some("no_focus_with_cpu"),
        HuntSignature::Phantom        => Some("phantom_foreground"),
        HuntSignature::Automated      => Some("automated_execution"),
        HuntSignature::Beaconing      => Some("beaconing"),
        HuntSignature::NotificationC2 => Some("notification_c2"),
        HuntSignature::All            => None,
    };

    all.into_iter().filter(|v| {
        match flag_key {
            Some(key) => v.get(key).and_then(|x| x.as_bool()) == Some(true),
            None => {
                HEURISTIC_KEYS.iter().any(|&k| {
                    v.get(k).and_then(|x| x.as_bool()) == Some(true)
                })
            }
        }
    }).collect()
}

/// Compare per-process aggregates from two SRUM databases and return a diff.
///
/// Returns a JSON object with three arrays:
/// - `new_processes`: processes present in `suspect` but not in `baseline`
/// - `departed_processes`: processes present in `baseline` but not in `suspect`
/// - `changed`: processes present in both with new heuristic flags or byte deltas
fn compare_databases(
    baseline_stats: Vec<serde_json::Value>,
    suspect_stats: Vec<serde_json::Value>,
) -> serde_json::Value {
    use std::collections::HashMap;

    // Key each stat by app_name if present, else app_id string.
    fn process_key(v: &serde_json::Value) -> String {
        v.get("app_name")
            .and_then(|x| x.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| {
                v.get("app_id")
                    .and_then(|x| x.as_i64())
                    .map(|id| id.to_string())
                    .unwrap_or_default()
            })
    }

    let baseline_map: HashMap<String, &serde_json::Value> =
        baseline_stats.iter().map(|v| (process_key(v), v)).collect();
    let suspect_map: HashMap<String, &serde_json::Value> =
        suspect_stats.iter().map(|v| (process_key(v), v)).collect();

    let mut new_processes: Vec<serde_json::Value> = Vec::new();
    let mut departed_processes: Vec<serde_json::Value> = Vec::new();
    let mut changed: Vec<serde_json::Value> = Vec::new();

    // New: in suspect but not in baseline.
    for (key, sv) in &suspect_map {
        if !baseline_map.contains_key(key) {
            new_processes.push((*sv).clone());
        }
    }

    // Departed: in baseline but not in suspect.
    for (key, bv) in &baseline_map {
        if !suspect_map.contains_key(key) {
            let mut entry = serde_json::json!({});
            if let Some(id) = bv.get("app_id") {
                entry.as_object_mut().unwrap().insert("app_id".into(), id.clone());
            }
            if let Some(name) = bv.get("app_name") {
                entry.as_object_mut().unwrap().insert("app_name".into(), name.clone());
            }
            departed_processes.push(entry);
        }
    }

    // Changed: in both, with new flags or significant deltas.
    for (key, sv) in &suspect_map {
        if let Some(bv) = baseline_map.get(key) {
            let b_flags: Vec<String> = bv
                .get("heuristic_flags")
                .and_then(|f| f.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
                .unwrap_or_default();
            let s_flags: Vec<String> = sv
                .get("heuristic_flags")
                .and_then(|f| f.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
                .unwrap_or_default();

            let new_flags: Vec<&str> = s_flags
                .iter()
                .filter(|f| !b_flags.contains(f))
                .map(String::as_str)
                .collect();

            let b_bytes = bv.get("total_bytes_sent").and_then(|x| x.as_i64()).unwrap_or(0);
            let s_bytes = sv.get("total_bytes_sent").and_then(|x| x.as_i64()).unwrap_or(0);
            let delta_bytes = s_bytes - b_bytes;

            let b_bg = bv.get("total_background_cycles").and_then(|x| x.as_i64()).unwrap_or(0);
            let s_bg = sv.get("total_background_cycles").and_then(|x| x.as_i64()).unwrap_or(0);
            let delta_bg = s_bg - b_bg;

            if !new_flags.is_empty() || delta_bytes != 0 || delta_bg != 0 {
                let mut entry = serde_json::json!({
                    "new_flags": new_flags,
                    "delta_bytes_sent": delta_bytes,
                    "delta_background_cycles": delta_bg,
                });
                if let Some(id) = sv.get("app_id") {
                    entry.as_object_mut().unwrap().insert("app_id".into(), id.clone());
                }
                if let Some(name) = sv.get("app_name") {
                    entry.as_object_mut().unwrap().insert("app_name".into(), name.clone());
                }
                changed.push(entry);
            }
        }
    }

    // Sort each section by app_id for deterministic output.
    let sort_by_id = |a: &serde_json::Value, b: &serde_json::Value| {
        let ia = a.get("app_id").and_then(|x| x.as_i64()).unwrap_or(0);
        let ib = b.get("app_id").and_then(|x| x.as_i64()).unwrap_or(0);
        ia.cmp(&ib)
    };
    new_processes.sort_by(sort_by_id);
    departed_processes.sort_by(sort_by_id);
    changed.sort_by(sort_by_id);

    serde_json::json!({
        "new_processes": new_processes,
        "departed_processes": departed_processes,
        "changed": changed,
    })
}

/// Map a SRUM table GUID (or well-known name) to its friendly table name.
fn guid_to_table_name(guid: &str) -> Option<&'static str> {
    match guid {
        "{973F5D5C-1D90-4944-BE8E-24B22A728CF2}" => Some("network"),
        "{5C8CF1C7-7257-4F13-B223-970EF5939312}" => Some("apps"),
        "{DD6636C4-8929-4683-974E-22C046A43763}" => Some("connectivity"),
        "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}" => Some("energy"),
        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}" => Some("notifications"),
        "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}" => Some("app-timeline"),
        "SruDbIdMapTable"                         => Some("idmap"),
        "SruDbCheckpointTable"                    => Some("checkpoint"),
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
fn collect_metadata(path: &std::path::Path) -> anyhow::Result<serde_json::Value> {
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
    count_table!("network",       srum_parser::parse_network_usage);
    count_table!("apps",          srum_parser::parse_app_usage);
    count_table!("connectivity",  srum_parser::parse_network_connectivity);
    count_table!("energy",        srum_parser::parse_energy_usage);
    count_table!("notifications", srum_parser::parse_push_notifications);
    count_table!("app-timeline",  srum_parser::parse_app_timeline);
    count_table!("idmap",         srum_parser::parse_id_map);

    // Temporal span — build timeline (no resolve), extract first/last timestamps
    let all = build_timeline(path, None);
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
        Cmd::Stats { path, resolve, format } => {
            let id_map = resolve.then(|| load_id_map(&path));
            let all = build_timeline(&path, id_map.as_ref());
            let stats = build_stats(all);
            print_values(&stats, &format)?;
        }
        Cmd::Sessions { path, format } => {
            let all = build_timeline(&path, None);
            let sessions = build_sessions(&all);
            print_values(&sessions, &format)?;
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
        Cmd::Process { app, path, resolve, format } => {
            let id_map = resolve.then(|| load_id_map(&path));
            let all = build_timeline(&path, id_map.as_ref());
            let filtered = filter_by_app(all, &app);
            print_values(&filtered, &format)?;
        }
        Cmd::Gaps { path, threshold_hours, format } => {
            let all = build_timeline(&path, None);
            let gaps = detect_gaps(&all, threshold_hours);
            print_values(&gaps, &format)?;
        }
        Cmd::Hunt { signature, path, resolve, format } => {
            let id_map = resolve.then(|| load_id_map(&path));
            let all = build_timeline(&path, id_map.as_ref());
            let filtered = hunt_filter(all, &signature);
            print_values(&filtered, &format)?;
        }
        Cmd::Compare { baseline, suspect, resolve, format } => {
            let id_map_baseline = resolve.then(|| load_id_map(&baseline));
            let id_map_suspect  = resolve.then(|| load_id_map(&suspect));
            let baseline_timeline = build_timeline(&baseline, id_map_baseline.as_ref());
            let suspect_timeline  = build_timeline(&suspect,  id_map_suspect.as_ref());
            let baseline_stats = build_stats(baseline_timeline);
            let suspect_stats  = build_stats(suspect_timeline);
            let result = compare_databases(baseline_stats, suspect_stats);
            // compare outputs a single object, not an array — handle directly.
            match &format {
                OutputFormat::Json  => println!("{}", serde_json::to_string_pretty(&result)?),
                OutputFormat::Ndjson => println!("{}", serde_json::to_string(&result)?),
                OutputFormat::Csv   => {
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
                            r.as_object_mut().unwrap().insert("diff_type".into(), "changed".into());
                            flat.push(r);
                        }
                    }
                    if let Some(arr) = result.get("departed_processes").and_then(|v| v.as_array()) {
                        for r in arr {
                            let mut r = r.clone();
                            r.as_object_mut().unwrap().insert("diff_type".into(), "departed".into());
                            flat.push(r);
                        }
                    }
                    print!("{}", values_to_csv(&flat)?);
                }
            }
        }
        Cmd::Metadata { path, format } => {
            let meta = collect_metadata(&path)?;
            match &format {
                OutputFormat::Json   => println!("{}", serde_json::to_string_pretty(&meta)?),
                OutputFormat::Ndjson => println!("{}", serde_json::to_string(&meta)?),
                OutputFormat::Csv    => {
                    print!("{}", values_to_csv(&[meta])?);
                }
            }
        }
    }
    Ok(())
}

/// Split a Windows (or Unix) path into (directory, binary_name) at the last
/// path separator.  Returns `("", path)` when no separator is present.
fn split_windows_path(path: &str) -> (&str, &str) {
    match path.rfind(|c| c == '\\' || c == '/') {
        Some(idx) => (&path[..idx], &path[idx + 1..]),
        None => ("", path),
    }
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

    // ── filter_by_app ─────────────────────────────────────────────────────────

    fn timeline_record(table: &str, app_id: i64) -> serde_json::Value {
        serde_json::json!({"table": table, "app_id": app_id, "timestamp": "2024-01-01T00:00:00Z"})
    }

    fn timeline_record_with_name(table: &str, app_id: i64, app_name: &str) -> serde_json::Value {
        serde_json::json!({"table": table, "app_id": app_id, "app_name": app_name, "timestamp": "2024-01-01T00:00:00Z"})
    }

    #[test]
    fn filter_by_app_matches_integer_id() {
        let records = vec![
            timeline_record("apps", 42),
            timeline_record("apps", 99),
        ];
        let result = filter_by_app(records, "42");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].get("app_id").and_then(|v| v.as_i64()), Some(42));
    }

    #[test]
    fn filter_by_app_matches_name_substring_case_insensitive() {
        let records = vec![
            timeline_record_with_name("apps", 1, r"C:\Windows\System32\svchost.exe"),
            timeline_record_with_name("apps", 2, r"C:\Program Files\MyApp\myapp.exe"),
        ];
        let result = filter_by_app(records, "svchost");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].get("app_id").and_then(|v| v.as_i64()), Some(1));
    }

    #[test]
    fn filter_by_app_case_insensitive() {
        let records = vec![
            timeline_record_with_name("apps", 1, r"C:\Windows\svchost.exe"),
        ];
        let result = filter_by_app(records, "SVCHOST");
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filter_by_app_returns_empty_when_no_match() {
        let records = vec![timeline_record("apps", 1)];
        let result = filter_by_app(records, "nonexistent");
        assert!(result.is_empty());
    }

    #[test]
    fn filter_by_app_matches_across_tables() {
        // same app_id appears in multiple tables — all should match
        let records = vec![
            timeline_record("apps", 42),
            timeline_record("network", 42),
            timeline_record("apps", 99),
        ];
        let result = filter_by_app(records, "42");
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|r| r.get("app_id").and_then(|v| v.as_i64()) == Some(42)));
    }

    #[test]
    fn filter_by_app_empty_timeline_returns_empty() {
        let result = filter_by_app(vec![], "svchost");
        assert!(result.is_empty());
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

    // ── apply_heuristics: automated_execution + interactivity_ratio ──────────

    #[test]
    fn apply_heuristics_flags_automated_execution_sustained_focus_no_input() {
        // focus ≥ 60_000 ms with zero user input
        let mut values = vec![apps_record_with_focus(0, 0, 60_000, 0)];
        apply_heuristics(&mut values);
        assert_eq!(
            values[0].get("automated_execution"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn apply_heuristics_automated_execution_not_set_when_input_present() {
        let mut values = vec![apps_record_with_focus(0, 0, 60_000, 1)];
        apply_heuristics(&mut values);
        assert!(values[0].get("automated_execution").is_none());
    }

    #[test]
    fn apply_heuristics_automated_execution_not_set_below_threshold() {
        let mut values = vec![apps_record_with_focus(0, 0, 59_999, 0)];
        apply_heuristics(&mut values);
        assert!(values[0].get("automated_execution").is_none());
    }

    #[test]
    fn apply_heuristics_automated_execution_absent_when_focus_field_missing() {
        let mut values = vec![apps_record(0, 0)];
        apply_heuristics(&mut values);
        assert!(values[0].get("automated_execution").is_none());
    }

    #[test]
    fn apply_heuristics_interactivity_ratio_emitted_when_focus_nonzero() {
        // 30_000 input / 60_000 focus = 0.5
        let mut values = vec![apps_record_with_focus(0, 0, 60_000, 30_000)];
        apply_heuristics(&mut values);
        let ratio = values[0]
            .get("interactivity_ratio")
            .and_then(serde_json::Value::as_f64);
        assert!((ratio.unwrap() - 0.5).abs() < f64::EPSILON, "expected 0.5, got {ratio:?}");
    }

    #[test]
    fn apply_heuristics_interactivity_ratio_zero_when_no_user_input() {
        let mut values = vec![apps_record_with_focus(0, 0, 60_000, 0)];
        apply_heuristics(&mut values);
        let ratio = values[0]
            .get("interactivity_ratio")
            .and_then(serde_json::Value::as_f64);
        assert_eq!(ratio, Some(0.0));
    }

    #[test]
    fn apply_heuristics_interactivity_ratio_absent_when_focus_zero() {
        // focus_time_ms = 0: don't divide, don't emit
        let mut values = vec![apps_record_with_focus(0, 0, 0, 0)];
        apply_heuristics(&mut values);
        assert!(values[0].get("interactivity_ratio").is_none());
    }

    #[test]
    fn apply_heuristics_interactivity_ratio_absent_when_focus_field_missing() {
        let mut values = vec![apps_record(0, 0)];
        apply_heuristics(&mut values);
        assert!(values[0].get("interactivity_ratio").is_none());
    }

    // ── apply_cross_table_signals ─────────────────────────────────────────────

    fn network_record(app_id: i32, ts: &str, bytes_sent: u64, bytes_recv: u64) -> serde_json::Value {
        serde_json::json!({
            "table": "network",
            "app_id": app_id,
            "timestamp": ts,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_recv,
        })
    }

    #[test]
    fn cross_table_signals_flags_exfil_on_matching_background_app() {
        // Network: 200 MiB sent (above volume threshold) for app 42 at T1
        // Apps: app 42 at T1, background_cycles > 0, focus_time_ms = 0
        let mut all = vec![
            network_record(42, "2024-06-15T08:00:00Z", 200 * 1024 * 1024, 1024),
            serde_json::json!({
                "table": "apps", "app_id": 42, "timestamp": "2024-06-15T08:00:00Z",
                "background_cycles": 5000_u64, "foreground_cycles": 0_u64,
                "focus_time_ms": 0_u64, "user_input_time_ms": 0_u64,
            }),
        ];
        apply_cross_table_signals(&mut all);
        let apps_rec = all.iter().find(|v| v.get("table").and_then(|t| t.as_str()) == Some("apps")).unwrap();
        assert_eq!(apps_rec.get("exfil_signal"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn cross_table_signals_no_flag_when_focus_present() {
        // Same setup but app had focus — not a background exfil
        let mut all = vec![
            network_record(42, "2024-06-15T08:00:00Z", 200 * 1024 * 1024, 1024),
            serde_json::json!({
                "table": "apps", "app_id": 42, "timestamp": "2024-06-15T08:00:00Z",
                "background_cycles": 5000_u64, "foreground_cycles": 0_u64,
                "focus_time_ms": 30_000_u64, "user_input_time_ms": 10_000_u64,
            }),
        ];
        apply_cross_table_signals(&mut all);
        let apps_rec = all.iter().find(|v| v.get("table").and_then(|t| t.as_str()) == Some("apps")).unwrap();
        assert!(apps_rec.get("exfil_signal").is_none());
    }

    #[test]
    fn cross_table_signals_no_flag_when_network_below_threshold() {
        // Network bytes below both volume and ratio thresholds
        let mut all = vec![
            network_record(42, "2024-06-15T08:00:00Z", 1024, 1024),
            serde_json::json!({
                "table": "apps", "app_id": 42, "timestamp": "2024-06-15T08:00:00Z",
                "background_cycles": 5000_u64, "foreground_cycles": 0_u64,
                "focus_time_ms": 0_u64, "user_input_time_ms": 0_u64,
            }),
        ];
        apply_cross_table_signals(&mut all);
        let apps_rec = all.iter().find(|v| v.get("table").and_then(|t| t.as_str()) == Some("apps")).unwrap();
        assert!(apps_rec.get("exfil_signal").is_none());
    }

    #[test]
    fn cross_table_signals_no_flag_when_no_matching_network_record() {
        // Apps record with background CPU + no focus, but no network record for this app/time
        let mut all = vec![
            network_record(99, "2024-06-15T08:00:00Z", 200 * 1024 * 1024, 0),
            serde_json::json!({
                "table": "apps", "app_id": 42, "timestamp": "2024-06-15T08:00:00Z",
                "background_cycles": 5000_u64, "foreground_cycles": 0_u64,
                "focus_time_ms": 0_u64, "user_input_time_ms": 0_u64,
            }),
        ];
        apply_cross_table_signals(&mut all);
        let apps_rec = all.iter().find(|v| v.get("table").and_then(|t| t.as_str()) == Some("apps")).unwrap();
        assert!(apps_rec.get("exfil_signal").is_none());
    }

    #[test]
    fn cross_table_signals_no_flag_when_background_cycles_zero() {
        // Network exfil volume but app used no background CPU
        let mut all = vec![
            network_record(42, "2024-06-15T08:00:00Z", 200 * 1024 * 1024, 0),
            serde_json::json!({
                "table": "apps", "app_id": 42, "timestamp": "2024-06-15T08:00:00Z",
                "background_cycles": 0_u64, "foreground_cycles": 500_u64,
                "focus_time_ms": 0_u64, "user_input_time_ms": 0_u64,
            }),
        ];
        apply_cross_table_signals(&mut all);
        let apps_rec = all.iter().find(|v| v.get("table").and_then(|t| t.as_str()) == Some("apps")).unwrap();
        assert!(apps_rec.get("exfil_signal").is_none());
    }

    #[test]
    fn cross_table_signals_flags_exfil_by_ratio_not_just_volume() {
        // 10 MiB sent, 0 received: triggers is_exfil_ratio (10:0), not is_exfil_volume
        let mut all = vec![
            network_record(42, "2024-06-15T08:00:00Z", 10 * 1024 * 1024, 0),
            serde_json::json!({
                "table": "apps", "app_id": 42, "timestamp": "2024-06-15T08:00:00Z",
                "background_cycles": 5000_u64, "foreground_cycles": 0_u64,
                "focus_time_ms": 0_u64, "user_input_time_ms": 0_u64,
            }),
        ];
        apply_cross_table_signals(&mut all);
        let apps_rec = all.iter().find(|v| v.get("table").and_then(|t| t.as_str()) == Some("apps")).unwrap();
        assert_eq!(apps_rec.get("exfil_signal"), Some(&serde_json::Value::Bool(true)));
    }

    // ── annotate_user_presence ────────────────────────────────────────────────

    #[test]
    fn user_presence_annotates_all_records_in_interval_when_input_above_threshold() {
        // Two records at same timestamp: apps with 15_000 ms input, and a network record.
        // Both should get user_present: true because aggregate (15_000) > 10_000.
        let ts = "2024-06-15T08:00:00Z";
        let mut all = vec![
            serde_json::json!({
                "table": "apps", "app_id": 1, "timestamp": ts,
                "user_input_time_ms": 15_000_u64,
            }),
            serde_json::json!({
                "table": "network", "app_id": 1, "timestamp": ts,
                "bytes_sent": 1024_u64,
            }),
        ];
        annotate_user_presence(&mut all);
        for rec in &all {
            assert_eq!(
                rec.get("user_present"),
                Some(&serde_json::Value::Bool(true)),
                "all records in a user-present interval must be annotated: {rec}"
            );
        }
    }

    #[test]
    fn user_presence_does_not_annotate_when_input_below_threshold() {
        let ts = "2024-06-15T08:00:00Z";
        let mut all = vec![serde_json::json!({
            "table": "apps", "app_id": 1, "timestamp": ts,
            "user_input_time_ms": 9_999_u64,
        })];
        annotate_user_presence(&mut all);
        assert!(all[0].get("user_present").is_none());
    }

    #[test]
    fn user_presence_aggregates_across_multiple_apps_in_same_interval() {
        // Two apps each contribute 6_000 ms → total 12_000 > 10_000 → user_present
        let ts = "2024-06-15T08:00:00Z";
        let mut all = vec![
            serde_json::json!({"table": "apps", "app_id": 1, "timestamp": ts, "user_input_time_ms": 6_000_u64}),
            serde_json::json!({"table": "apps", "app_id": 2, "timestamp": ts, "user_input_time_ms": 6_000_u64}),
        ];
        annotate_user_presence(&mut all);
        assert_eq!(all[0].get("user_present"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(all[1].get("user_present"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn user_presence_annotates_exactly_at_threshold() {
        let ts = "2024-06-15T08:00:00Z";
        let mut all = vec![serde_json::json!({
            "table": "apps", "app_id": 1, "timestamp": ts,
            "user_input_time_ms": USER_PRESENCE_THRESHOLD_MS,
        })];
        annotate_user_presence(&mut all);
        assert_eq!(all[0].get("user_present"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn user_presence_different_intervals_annotated_independently() {
        // T1 has input > threshold, T2 does not
        let mut all = vec![
            serde_json::json!({"table": "apps", "app_id": 1, "timestamp": "2024-06-15T08:00:00Z", "user_input_time_ms": 20_000_u64}),
            serde_json::json!({"table": "apps", "app_id": 1, "timestamp": "2024-06-15T09:00:00Z", "user_input_time_ms": 500_u64}),
        ];
        annotate_user_presence(&mut all);
        assert_eq!(all[0].get("user_present"), Some(&serde_json::Value::Bool(true)));
        assert!(all[1].get("user_present").is_none());
    }

    #[test]
    fn user_presence_non_apps_record_without_matching_apps_gets_no_annotation() {
        // A network record at a timestamp that has no apps activity
        let mut all = vec![serde_json::json!({
            "table": "network", "app_id": 5, "timestamp": "2024-06-15T08:00:00Z",
            "bytes_sent": 1024_u64,
        })];
        annotate_user_presence(&mut all);
        assert!(all[0].get("user_present").is_none());
    }

    #[test]
    fn cross_table_signals_flags_exfil_when_focus_field_absent() {
        // When the Application Timeline table is unavailable, focus_time_ms is
        // never merged in. The signal must still fire on network + background CPU
        // — absence of exculpatory focus data should not suppress the signal.
        let mut all = vec![
            network_record(42, "2024-06-15T08:00:00Z", 200 * 1024 * 1024, 0),
            serde_json::json!({
                "table": "apps", "app_id": 42, "timestamp": "2024-06-15T08:00:00Z",
                "background_cycles": 5000_u64, "foreground_cycles": 0_u64,
                // no focus_time_ms field — Timeline table unavailable
            }),
        ];
        apply_cross_table_signals(&mut all);
        let apps_rec = all.iter().find(|v| v.get("table").and_then(|t| t.as_str()) == Some("apps")).unwrap();
        assert_eq!(
            apps_rec.get("exfil_signal"),
            Some(&serde_json::Value::Bool(true)),
            "exfil_signal must fire even when focus_time_ms is absent"
        );
    }

    // ── classify_sid ─────────────────────────────────────────────────────────────

    #[test]
    fn classify_sid_system() {
        assert_eq!(classify_sid("S-1-5-18"), Some("system"));
    }

    #[test]
    fn classify_sid_local_service() {
        assert_eq!(classify_sid("S-1-5-19"), Some("local_service"));
    }

    #[test]
    fn classify_sid_network_service() {
        assert_eq!(classify_sid("S-1-5-20"), Some("network_service"));
    }

    #[test]
    fn classify_sid_everyone() {
        assert_eq!(classify_sid("S-1-1-0"), Some("everyone"));
    }

    #[test]
    fn classify_sid_local_admin() {
        assert_eq!(classify_sid("S-1-5-21-111-222-333-500"), Some("local_admin"));
    }

    #[test]
    fn classify_sid_domain_user() {
        assert_eq!(classify_sid("S-1-5-21-111-222-333-1000"), Some("domain_user"));
    }

    #[test]
    fn classify_sid_non_sid_returns_none() {
        assert_eq!(classify_sid("C:\\Windows\\explorer.exe"), None);
    }

    #[test]
    fn classify_sid_empty_returns_none() {
        assert_eq!(classify_sid(""), None);
    }

    // ── mitre_techniques_for ─────────────────────────────────────────────────

    #[test]
    fn mitre_for_background_cpu_dominant() {
        let mut map = serde_json::Map::new();
        map.insert("background_cpu_dominant".to_owned(), serde_json::Value::Bool(true));
        let techs = mitre_techniques_for(&map);
        assert!(techs.contains(&"T1496"));
    }

    #[test]
    fn mitre_for_exfil_signal() {
        let mut map = serde_json::Map::new();
        map.insert("exfil_signal".to_owned(), serde_json::Value::Bool(true));
        let techs = mitre_techniques_for(&map);
        assert!(techs.contains(&"T1048"));
    }

    #[test]
    fn mitre_for_empty_returns_empty() {
        let map = serde_json::Map::new();
        let techs = mitre_techniques_for(&map);
        assert!(techs.is_empty());
    }

    #[test]
    fn mitre_deduplicates_t1036_005() {
        let mut map = serde_json::Map::new();
        map.insert("suspicious_path".to_owned(), serde_json::Value::Bool(true));
        map.insert("masquerade_candidate".to_owned(), serde_json::Value::Bool(true));
        let techs = mitre_techniques_for(&map);
        assert_eq!(techs.iter().filter(|&&t| t == "T1036.005").count(), 1);
    }

    // ── enrich: path-based forensic signals ──────────────────────────────────

    fn make_id_map(entries: &[(i32, &str)]) -> HashMap<i32, String> {
        entries.iter().map(|&(id, name)| (id, name.to_owned())).collect()
    }

    // ── suspicious_path signal ────────────────────────────────────────────────

    #[test]
    fn enrich_suspicious_path_for_temp_exe() {
        let id_map = make_id_map(&[(42, r"C:\Users\User\AppData\Local\Temp\payload.exe")]);
        let record = serde_json::json!({"app_id": 42});
        let result = enrich(record, &id_map);
        assert_eq!(result.get("suspicious_path"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn enrich_no_suspicious_path_for_system32() {
        let id_map = make_id_map(&[(1, r"C:\Windows\System32\svchost.exe")]);
        let record = serde_json::json!({"app_id": 1});
        let result = enrich(record, &id_map);
        assert_eq!(result.get("suspicious_path"), None);
    }

    #[test]
    fn enrich_no_suspicious_path_when_name_not_a_path() {
        // plain name with no slashes — not treated as path
        let id_map = make_id_map(&[(5, "S-1-5-18")]);
        let record = serde_json::json!({"app_id": 5});
        let result = enrich(record, &id_map);
        assert_eq!(result.get("suspicious_path"), None);
    }

    // ── masquerade_candidate signal ───────────────────────────────────────────

    #[test]
    fn enrich_masquerade_candidate_for_svch0st() {
        let id_map = make_id_map(&[(43, r"C:\Users\User\svch0st.exe")]);
        let record = serde_json::json!({"app_id": 43});
        let result = enrich(record, &id_map);
        assert_eq!(result.get("masquerade_candidate"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn enrich_no_masquerade_for_legitimate_svchost() {
        let id_map = make_id_map(&[(2, r"C:\Windows\System32\svchost.exe")]);
        let record = serde_json::json!({"app_id": 2});
        let result = enrich(record, &id_map);
        assert_eq!(result.get("masquerade_candidate"), None);
    }

    #[test]
    fn enrich_no_masquerade_for_unrelated_app() {
        let id_map = make_id_map(&[(10, r"C:\Program Files\MyApp\myapp.exe")]);
        let record = serde_json::json!({"app_id": 10});
        let result = enrich(record, &id_map);
        assert_eq!(result.get("masquerade_candidate"), None);
    }

    // ── both signals can fire together ────────────────────────────────────────

    #[test]
    fn enrich_both_signals_for_masquerade_in_temp() {
        // svch0st.exe in Windows\Temp — both suspicious path AND masquerade
        let id_map = make_id_map(&[(99, r"C:\Windows\Temp\svch0st.exe")]);
        let record = serde_json::json!({"app_id": 99});
        let result = enrich(record, &id_map);
        assert_eq!(result.get("suspicious_path"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(result.get("masquerade_candidate"), Some(&serde_json::Value::Bool(true)));
    }

    fn apps_record_at(ts: &str, app_id: i64, input_ms: u64) -> serde_json::Value {
        serde_json::json!({
            "table": "apps",
            "app_id": app_id,
            "timestamp": ts,
            "user_input_time_ms": input_ms,
            "user_present": true,
            "background_cycles": 0u64,
            "foreground_cycles": 0u64,
        })
    }

    // ── detect_gaps ───────────────────────────────────────────────────────────────

    fn record_at(table: &str, ts: &str) -> serde_json::Value {
        serde_json::json!({"table": table, "timestamp": ts, "app_id": 1})
    }

    #[test]
    fn gaps_empty_timeline_produces_no_gaps() {
        let gaps = detect_gaps(&[], 2);
        assert!(gaps.is_empty());
    }

    #[test]
    fn gaps_contiguous_hourly_records_no_gaps() {
        let records = vec![
            record_at("apps", "2024-01-15T08:00:00Z"),
            record_at("apps", "2024-01-15T09:00:00Z"),
            record_at("apps", "2024-01-15T10:00:00Z"),
        ];
        let gaps = detect_gaps(&records, 2);
        assert!(gaps.is_empty());
    }

    #[test]
    fn gaps_detects_system_off_all_tables() {
        // Both tables have a gap at the same time
        let records = vec![
            record_at("apps",    "2024-01-15T08:00:00Z"),
            record_at("network", "2024-01-15T08:00:00Z"),
            record_at("apps",    "2024-01-15T14:00:00Z"), // 6h gap
            record_at("network", "2024-01-15T14:00:00Z"), // 6h gap
        ];
        let gaps = detect_gaps(&records, 2);
        assert!(!gaps.is_empty());
        assert!(gaps.iter().any(|g| g.get("type").and_then(|t| t.as_str()) == Some("system_off")));
    }

    #[test]
    fn gaps_detects_selective_gap_one_table() {
        // Only network has a gap; apps is continuous
        let records = vec![
            record_at("apps",    "2024-01-15T08:00:00Z"),
            record_at("network", "2024-01-15T08:00:00Z"),
            record_at("apps",    "2024-01-15T09:00:00Z"),
            // network has no 09:00 record
            record_at("apps",    "2024-01-15T10:00:00Z"),
            record_at("network", "2024-01-15T13:00:00Z"), // 5h gap in network only
        ];
        let gaps = detect_gaps(&records, 2);
        // The gap in network (08:00 to 13:00, 5h) should be selective because apps had records
        assert!(gaps.iter().any(|g| {
            g.get("type").and_then(|t| t.as_str()) == Some("selective_gap")
            && g.get("table").and_then(|t| t.as_str()) == Some("network")
        }));
    }

    #[test]
    fn gaps_below_threshold_not_reported() {
        // 1h gap with threshold=2 should not appear
        let records = vec![
            record_at("apps", "2024-01-15T08:00:00Z"),
            record_at("apps", "2024-01-15T09:00:00Z"), // only 1h
        ];
        let gaps = detect_gaps(&records, 2);
        assert!(gaps.is_empty());
    }

    #[test]
    fn gaps_result_sorted_by_start() {
        let records = vec![
            record_at("apps", "2024-01-15T00:00:00Z"),
            record_at("apps", "2024-01-15T10:00:00Z"), // 10h gap
            record_at("network", "2024-01-15T05:00:00Z"),
            record_at("network", "2024-01-15T20:00:00Z"), // 15h gap
        ];
        let gaps = detect_gaps(&records, 2);
        // All gaps sorted by start
        let starts: Vec<&str> = gaps.iter()
            .map(|g| g.get("start").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        let mut sorted = starts.clone();
        sorted.sort();
        assert_eq!(starts, sorted);
    }

    // ── build_stats ───────────────────────────────────────────────────────────────

    #[test]
    fn stats_aggregates_background_cycles() {
        let records = vec![
            serde_json::json!({"table":"apps","app_id":1,"background_cycles":5000u64,"foreground_cycles":500u64,"timestamp":"2024-01-01T00:00:00Z"}),
            serde_json::json!({"table":"apps","app_id":1,"background_cycles":3000u64,"foreground_cycles":300u64,"timestamp":"2024-01-01T01:00:00Z"}),
        ];
        let stats = build_stats(records);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].get("total_background_cycles").and_then(|v| v.as_u64()), Some(8000));
        assert_eq!(stats[0].get("active_intervals").and_then(|v| v.as_u64()), Some(2));
    }

    #[test]
    fn stats_collects_heuristic_flags() {
        let records = vec![
            serde_json::json!({"table":"apps","app_id":1,"background_cpu_dominant":true,"timestamp":"2024-01-01T00:00:00Z","background_cycles":0u64,"foreground_cycles":0u64}),
            serde_json::json!({"table":"network","app_id":1,"exfil_signal":true,"timestamp":"2024-01-01T01:00:00Z"}),
        ];
        let stats = build_stats(records);
        let flags = stats[0].get("heuristic_flags").and_then(|v| v.as_array()).unwrap();
        let flag_strs: Vec<&str> = flags.iter().map(|f| f.as_str().unwrap()).collect();
        assert!(flag_strs.contains(&"background_cpu_dominant"));
        assert!(flag_strs.contains(&"exfil_signal"));
        assert_eq!(stats[0].get("flag_count").and_then(|v| v.as_u64()), Some(2));
    }

    #[test]
    fn stats_sorted_by_flag_count_desc() {
        let records = vec![
            serde_json::json!({"table":"apps","app_id":1,"background_cycles":100u64,"foreground_cycles":0u64,"timestamp":"2024-01-01T00:00:00Z"}),
            serde_json::json!({"table":"apps","app_id":2,"background_cycles":50u64,"foreground_cycles":0u64,"background_cpu_dominant":true,"exfil_signal":true,"timestamp":"2024-01-01T00:00:00Z"}),
        ];
        let stats = build_stats(records);
        // app_id 2 has 2 flags, so it should come first
        assert_eq!(stats[0].get("app_id").and_then(|v| v.as_i64()), Some(2));
    }

    #[test]
    fn stats_empty_timeline_returns_empty() {
        let stats = build_stats(vec![]);
        assert!(stats.is_empty());
    }

    // ── build_sessions ────────────────────────────────────────────────────────────

    #[test]
    fn sessions_contiguous_hours_form_one_session() {
        let records = vec![
            apps_record_at("2024-01-15T08:00:00Z", 1, 30000),
            apps_record_at("2024-01-15T09:00:00Z", 1, 20000),
            apps_record_at("2024-01-15T10:00:00Z", 1, 15000),
        ];
        let sessions = build_sessions(&records);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].get("session_start").and_then(|v| v.as_str()), Some("2024-01-15T08:00:00Z"));
        assert_eq!(sessions[0].get("session_end").and_then(|v| v.as_str()), Some("2024-01-15T10:00:00Z"));
    }

    #[test]
    fn sessions_gap_over_two_hours_splits_session() {
        let records = vec![
            apps_record_at("2024-01-15T08:00:00Z", 1, 30000),
            apps_record_at("2024-01-15T09:00:00Z", 1, 20000),
            // 8-hour gap
            apps_record_at("2024-01-15T17:00:00Z", 1, 25000),
            apps_record_at("2024-01-15T18:00:00Z", 1, 10000),
        ];
        let sessions = build_sessions(&records);
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn sessions_empty_input_returns_empty() {
        let sessions = build_sessions(&[]);
        assert!(sessions.is_empty());
    }

    #[test]
    fn sessions_sums_input_ms() {
        let records = vec![
            apps_record_at("2024-01-15T08:00:00Z", 1, 30000),
            apps_record_at("2024-01-15T09:00:00Z", 2, 20000),
        ];
        let sessions = build_sessions(&records);
        assert_eq!(sessions.len(), 1);
        // Total input: 30000 + 20000 = 50000
        assert_eq!(sessions[0].get("input_ms_total").and_then(|v| v.as_u64()), Some(50000));
    }

    // ── apply_heuristics injects mitre_techniques ────────────────────────────────

    #[test]
    fn apply_heuristics_injects_mitre_for_background_cpu() {
        let mut values = vec![apps_record(10_000, 0)];
        apply_heuristics(&mut values);
        let techs = values[0]
            .get("mitre_techniques")
            .expect("mitre_techniques must be present")
            .as_array()
            .expect("must be array");
        assert!(techs.iter().any(|t| t.as_str() == Some("T1496")));
    }

    #[test]
    fn apply_heuristics_no_mitre_when_no_flags() {
        // Equal CPU: not dominant, no flags
        let mut values = vec![apps_record(100, 100)];
        apply_heuristics(&mut values);
        assert!(values[0].get("mitre_techniques").is_none());
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

    // ── hunt_filter ───────────────────────────────────────────────────────────

    fn flagged_record(flag: &str) -> serde_json::Value {
        serde_json::json!({
            "table": "apps",
            "app_id": 1,
            "timestamp": "2024-01-01T00:00:00Z",
            flag: true,
        })
    }

    fn unflagged_record() -> serde_json::Value {
        serde_json::json!({"table": "apps", "app_id": 2, "timestamp": "2024-01-01T00:00:00Z"})
    }

    #[test]
    fn hunt_exfil_returns_only_exfil_records() {
        let records = vec![
            flagged_record("exfil_signal"),
            unflagged_record(),
        ];
        let result = hunt_filter(records, &HuntSignature::Exfil);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].get("exfil_signal"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn hunt_miner_returns_background_dominant_records() {
        let records = vec![
            flagged_record("background_cpu_dominant"),
            unflagged_record(),
        ];
        let result = hunt_filter(records, &HuntSignature::Miner);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn hunt_all_returns_any_flagged_record() {
        let records = vec![
            flagged_record("exfil_signal"),
            flagged_record("background_cpu_dominant"),
            unflagged_record(),
        ];
        let result = hunt_filter(records, &HuntSignature::All);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn hunt_all_excludes_unflagged() {
        let records = vec![unflagged_record(), unflagged_record()];
        let result = hunt_filter(records, &HuntSignature::All);
        assert!(result.is_empty());
    }

    #[test]
    fn hunt_empty_timeline_returns_empty() {
        let result = hunt_filter(vec![], &HuntSignature::Exfil);
        assert!(result.is_empty());
    }

    #[test]
    fn hunt_suspicious_path_matches_flag() {
        let records = vec![
            flagged_record("suspicious_path"),
            unflagged_record(),
        ];
        let result = hunt_filter(records, &HuntSignature::SuspiciousPath);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn hunt_beaconing_matches_flag() {
        let records = vec![flagged_record("beaconing")];
        let result = hunt_filter(records, &HuntSignature::Beaconing);
        assert_eq!(result.len(), 1);
    }

    // ── compare_databases ─────────────────────────────────────────────────────

    fn stat_record(app_id: i64, bg_cycles: u64, bytes_sent: u64, flags: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "app_id": app_id,
            "total_background_cycles": bg_cycles,
            "total_bytes_sent": bytes_sent,
            "heuristic_flags": flags,
            "flag_count": flags.len(),
        })
    }

    #[test]
    fn compare_detects_new_process() {
        let baseline = vec![stat_record(1, 1000, 0, &[])];
        let suspect  = vec![stat_record(1, 1000, 0, &[]), stat_record(42, 5000, 0, &[])];
        let result = compare_databases(baseline, suspect);
        let new = result.get("new_processes").and_then(|v| v.as_array()).unwrap();
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].get("app_id").and_then(|v| v.as_i64()), Some(42));
    }

    #[test]
    fn compare_detects_departed_process() {
        let baseline = vec![stat_record(1, 1000, 0, &[]), stat_record(7, 500, 0, &[])];
        let suspect  = vec![stat_record(1, 1000, 0, &[])];
        let result = compare_databases(baseline, suspect);
        let departed = result.get("departed_processes").and_then(|v| v.as_array()).unwrap();
        assert_eq!(departed.len(), 1);
        assert_eq!(departed[0].get("app_id").and_then(|v| v.as_i64()), Some(7));
    }

    #[test]
    fn compare_same_databases_no_diff() {
        let stats = vec![stat_record(1, 1000, 500, &[])];
        let result = compare_databases(stats.clone(), stats);
        let new = result.get("new_processes").and_then(|v| v.as_array()).unwrap();
        let departed = result.get("departed_processes").and_then(|v| v.as_array()).unwrap();
        let changed = result.get("changed").and_then(|v| v.as_array()).unwrap();
        assert!(new.is_empty());
        assert!(departed.is_empty());
        assert!(changed.is_empty());
    }

    #[test]
    fn compare_detects_new_flags() {
        let baseline = vec![stat_record(1, 1000, 0, &[])];
        let suspect  = vec![stat_record(1, 1000, 0, &["exfil_signal"])];
        let result = compare_databases(baseline, suspect);
        let changed = result.get("changed").and_then(|v| v.as_array()).unwrap();
        assert_eq!(changed.len(), 1);
        let new_flags = changed[0].get("new_flags").and_then(|v| v.as_array()).unwrap();
        assert!(new_flags.iter().any(|f| f.as_str() == Some("exfil_signal")));
    }

    #[test]
    fn compare_detects_byte_delta() {
        let baseline = vec![stat_record(1, 1000, 100, &[])];
        let suspect  = vec![stat_record(1, 1000, 52_428_900, &[])];
        let result = compare_databases(baseline, suspect);
        let changed = result.get("changed").and_then(|v| v.as_array()).unwrap();
        assert_eq!(changed.len(), 1);
        assert_eq!(
            changed[0].get("delta_bytes_sent").and_then(|v| v.as_i64()),
            Some(52_428_800)
        );
    }

    // ── guid_to_table_name ────────────────────────────────────────────────────

    #[test]
    fn guid_to_table_name_known_guids() {
        assert_eq!(guid_to_table_name("{973F5D5C-1D90-4944-BE8E-24B22A728CF2}"), Some("network"));
        assert_eq!(guid_to_table_name("{5C8CF1C7-7257-4F13-B223-970EF5939312}"), Some("apps"));
        assert_eq!(guid_to_table_name("{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}"), Some("app-timeline"));
        assert_eq!(guid_to_table_name("SruDbIdMapTable"), Some("idmap"));
    }

    #[test]
    fn guid_to_table_name_unknown_returns_none() {
        assert_eq!(guid_to_table_name("{B6D82AF1-FFFF-FFFF-FFFF-FFFFFFFFFFFF}"), None);
        assert_eq!(guid_to_table_name(""), None);
    }

    // ── windows_version_hint ──────────────────────────────────────────────────

    #[test]
    fn windows_version_hint_with_app_timeline() {
        let tables = vec!["apps".to_owned(), "network".to_owned(), "app-timeline".to_owned()];
        let hint = windows_version_hint(&tables);
        assert!(hint.contains("1607"), "hint must mention 1607");
    }

    #[test]
    fn windows_version_hint_without_app_timeline() {
        let tables = vec!["apps".to_owned(), "network".to_owned()];
        let hint = windows_version_hint(&tables);
        assert!(!hint.contains("1607"), "must not mention 1607 without app-timeline");
    }
}
