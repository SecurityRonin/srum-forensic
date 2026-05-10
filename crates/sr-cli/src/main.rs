//! `sr` — SRUM forensic analysis CLI.
//!
//! Subcommands:
//! - `sr network <path>` — parse and print network usage records as JSON
//! - `sr apps <path>`   — parse and print application usage records as JSON
//! - `sr idmap <path>`  — dump the `SruDbIdMapTable` as JSON

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Output format for subcommand results.
#[derive(clap::ValueEnum, Clone, Default, PartialEq)]
enum OutputFormat {
    #[default]
    Json,
    Csv,
    Ndjson,
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

/// Map the CLI `HuntSignature` (with Clap attrs) to `srum_analysis::analysis::HuntSignature`.
fn to_analysis_sig(s: &HuntSignature) -> srum_analysis::analysis::HuntSignature {
    use HuntSignature as C;
    use srum_analysis::analysis::HuntSignature as A;
    match s {
        C::Exfil          => A::Exfil,
        C::Miner          => A::Miner,
        C::Masquerade     => A::Masquerade,
        C::SuspiciousPath => A::SuspiciousPath,
        C::NoFocus        => A::NoFocus,
        C::Phantom        => A::Phantom,
        C::Automated      => A::Automated,
        C::Beaconing      => A::Beaconing,
        C::NotificationC2 => A::NotificationC2,
        C::All            => A::All,
    }
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
    /// Parse energy usage long-term records — same schema, longer accumulation window.
    ///
    /// Records come from the {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT table.
    #[command(name = "energy-lt")]
    EnergyLt {
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
    /// records, injects a `source_table` field on each entry, and sorts by
    /// timestamp. Apps records are automatically flagged with heuristic signals.
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
            for v in values {
                println!("{}", serde_json::to_string(v)?);
            }
        }
    }
    Ok(())
}

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
                let id_map = srum_analysis::load_id_map(&path);
                records.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect()
            } else {
                srum_analysis::records_to_values(records)?
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
                let id_map = srum_analysis::load_id_map(&path);
                records.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect()
            } else {
                srum_analysis::records_to_values(records)?
            };
            // Inject source_table before merging focus so pipeline can identify rows correctly.
            for v in &mut values {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert(
                        srum_analysis::pipeline::TABLE_KEY.to_owned(),
                        "apps".into(),
                    );
                }
            }
            let focus_values: Vec<serde_json::Value> = srum_parser::parse_app_timeline(&path)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|r| serde_json::to_value(r).ok())
                .collect();
            srum_analysis::pipeline::merge_focus_into_apps(&mut values, focus_values);
            print_values(&values, &format)?;
        }
        Cmd::Idmap { path, format } => {
            let entries = srum_parser::parse_id_map(&path)?;
            let values = srum_analysis::records_to_values(entries)?;
            print_values(&values, &format)?;
        }
        Cmd::Connectivity {
            path,
            resolve,
            format,
        } => {
            let records = srum_parser::parse_network_connectivity(&path)?;
            let mut values = srum_analysis::records_to_values(records)?;
            if resolve {
                let id_map = srum_analysis::load_id_map(&path);
                values = values
                    .into_iter()
                    .map(|r| srum_analysis::enrich_connectivity(r, &id_map))
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
            let mut values = srum_analysis::records_to_values(records)?;
            if resolve {
                let id_map = srum_analysis::load_id_map(&path);
                values = values.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect();
            }
            print_values(&values, &format)?;
        }
        Cmd::EnergyLt {
            path,
            resolve,
            format,
        } => {
            let records = srum_parser::parse_energy_lt(&path)?;
            let mut values = srum_analysis::records_to_values(records)?;
            if resolve {
                let id_map = srum_analysis::load_id_map(&path);
                values = values.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect();
            }
            print_values(&values, &format)?;
        }
        Cmd::Notifications {
            path,
            resolve,
            format,
        } => {
            let records = srum_parser::parse_push_notifications(&path)?;
            let mut values = srum_analysis::records_to_values(records)?;
            if resolve {
                let id_map = srum_analysis::load_id_map(&path);
                values = values.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect();
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
                let id_map = srum_analysis::load_id_map(&path);
                records.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect()
            } else {
                srum_analysis::records_to_values(records)?
            };
            print_values(&values, &format)?;
        }
        Cmd::Stats { path, resolve, format } => {
            let id_map = resolve.then(|| srum_analysis::load_id_map(&path));
            let all = srum_analysis::build_timeline(&path, id_map.as_ref());
            let stats = srum_analysis::analysis::build_stats(all);
            print_values(&stats, &format)?;
        }
        Cmd::Sessions { path, format } => {
            let all = srum_analysis::build_timeline(&path, None);
            let sessions = srum_analysis::analysis::build_sessions(&all);
            print_values(&sessions, &format)?;
        }
        Cmd::Timeline {
            path,
            resolve,
            format,
        } => {
            let id_map = resolve.then(|| srum_analysis::load_id_map(&path));
            let all = srum_analysis::build_timeline(&path, id_map.as_ref());
            print_values(&all, &format)?;
        }
        Cmd::Process { app, path, resolve, format } => {
            let id_map = resolve.then(|| srum_analysis::load_id_map(&path));
            let all = srum_analysis::build_timeline(&path, id_map.as_ref());
            let filtered = srum_analysis::analysis::filter_by_app(all, &app);
            print_values(&filtered, &format)?;
        }
        Cmd::Gaps { path, threshold_hours, format } => {
            let all = srum_analysis::build_timeline(&path, None);
            let mut gaps = srum_analysis::analysis::detect_gaps(&all, threshold_hours);

            // AutoIncId gap detection (best-effort, appended after timestamp gaps).
            macro_rules! add_autoinc_gaps {
                ($table:expr, $parser:expr) => {
                    if let Ok(records) = $parser(&path) {
                        let ids: Vec<u32> = records.iter().map(|r| r.auto_inc_id).collect();
                        gaps.extend(srum_analysis::analysis::detect_autoinc_gaps_from_ids($table, &ids));
                    }
                };
            }
            add_autoinc_gaps!("network", srum_parser::parse_network_usage);
            add_autoinc_gaps!("apps",    srum_parser::parse_app_usage);
            add_autoinc_gaps!("energy",  srum_parser::parse_energy_usage);

            print_values(&gaps, &format)?;
        }
        Cmd::Hunt { signature, path, resolve, format } => {
            let id_map = resolve.then(|| srum_analysis::load_id_map(&path));
            let all = srum_analysis::build_timeline(&path, id_map.as_ref());
            let filtered = srum_analysis::analysis::hunt_filter(all, &to_analysis_sig(&signature));
            print_values(&filtered, &format)?;
        }
        Cmd::Compare { baseline, suspect, resolve, format } => {
            let id_map_baseline = resolve.then(|| srum_analysis::load_id_map(&baseline));
            let id_map_suspect  = resolve.then(|| srum_analysis::load_id_map(&suspect));
            let baseline_timeline = srum_analysis::build_timeline(&baseline, id_map_baseline.as_ref());
            let suspect_timeline  = srum_analysis::build_timeline(&suspect,  id_map_suspect.as_ref());
            let baseline_stats = srum_analysis::analysis::build_stats(baseline_timeline);
            let suspect_stats  = srum_analysis::analysis::build_stats(suspect_timeline);
            let result = srum_analysis::analysis::compare_databases(baseline_stats, suspect_stats);
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

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
