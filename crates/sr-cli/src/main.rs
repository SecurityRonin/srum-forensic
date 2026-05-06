//! `sr` — SRUM forensic analysis CLI.
//!
//! Subcommands:
//! - `sr network <path>` — parse and print network usage records as JSON
//! - `sr apps <path>`   — parse and print application usage records as JSON

use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    },
    /// Parse application usage records from SRUDB.dat and print as JSON.
    ///
    /// Records come from the {5C8CF1C7-7257-4F13-B223-970EF5939312} table.
    Apps {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
    },
    /// Dump the `SruDbIdMapTable` as JSON — resolves `app_id` / `user_id` integers
    /// to process paths and SIDs.
    Idmap {
        /// Path to SRUDB.dat (or a forensic copy of it).
        path: PathBuf,
    },
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Network { path } => {
            let records = srum_parser::parse_network_usage(&path)?;
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
        Cmd::Apps { path } => {
            let records = srum_parser::parse_app_usage(&path)?;
            println!("{}", serde_json::to_string_pretty(&records)?);
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
