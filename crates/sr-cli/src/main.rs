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
    },
    /// Dump the `SruDbIdMapTable` as JSON — resolves `app_id` / `user_id` integers
    /// to process paths and SIDs.
    Idmap {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
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

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Network { path, resolve } => {
            let records = srum_parser::parse_network_usage(&path)?;
            if resolve {
                let id_map = load_id_map(&path);
                let enriched: Vec<_> = records.into_iter().map(|r| enrich(r, &id_map)).collect();
                println!("{}", serde_json::to_string_pretty(&enriched)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&records)?);
            }
        }
        Cmd::Apps { path, resolve } => {
            let records = srum_parser::parse_app_usage(&path)?;
            if resolve {
                let id_map = load_id_map(&path);
                let enriched: Vec<_> = records.into_iter().map(|r| enrich(r, &id_map)).collect();
                println!("{}", serde_json::to_string_pretty(&enriched)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&records)?);
            }
        }
        Cmd::Idmap { path } => {
            let entries = srum_parser::parse_id_map(&path)?;
            println!("{}", serde_json::to_string_pretty(&entries)?);
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
