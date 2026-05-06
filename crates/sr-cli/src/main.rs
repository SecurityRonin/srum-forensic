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
            let values: Vec<serde_json::Value> = if resolve {
                let id_map = load_id_map(&path);
                records.into_iter().map(|r| enrich(r, &id_map)).collect()
            } else {
                records_to_values(records)?
            };
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
    }
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
