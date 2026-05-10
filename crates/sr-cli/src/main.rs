//! `sr` — SRUM forensic analysis CLI.
//!
//! Subcommands:
//! - `sr network <path>` — parse and print network usage records as JSON
//! - `sr apps <path>`   — parse and print application usage records as JSON
//! - `sr idmap <path>`  — dump the `SruDbIdMapTable` as JSON

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod cmd;
mod output;

use output::OutputFormat;

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

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Network { path, resolve, format } =>
            cmd::tables::run_network(&path, resolve, &format),
        Cmd::Apps { path, resolve, format } =>
            cmd::tables::run_apps(&path, resolve, &format),
        Cmd::Idmap { path, format } =>
            cmd::tables::run_idmap(&path, &format),
        Cmd::Connectivity { path, resolve, format } =>
            cmd::tables::run_connectivity(&path, resolve, &format),
        Cmd::Energy { path, resolve, format } =>
            cmd::tables::run_energy(&path, resolve, &format),
        Cmd::EnergyLt { path, resolve, format } =>
            cmd::tables::run_energy_lt(&path, resolve, &format),
        Cmd::Notifications { path, resolve, format } =>
            cmd::tables::run_notifications(&path, resolve, &format),
        Cmd::AppTimeline { path, resolve, format } =>
            cmd::tables::run_app_timeline(&path, resolve, &format),
        Cmd::Stats { path, resolve, format } =>
            cmd::analysis::run_stats(&path, resolve, &format),
        Cmd::Sessions { path, format } =>
            cmd::analysis::run_sessions(&path, &format),
        Cmd::Timeline { path, resolve, format } =>
            cmd::analysis::run_timeline(&path, resolve, &format),
        Cmd::Process { app, path, resolve, format } =>
            cmd::analysis::run_process(&app, &path, resolve, &format),
        Cmd::Gaps { path, threshold_hours, format } =>
            cmd::analysis::run_gaps(&path, threshold_hours, &format),
        Cmd::Hunt { signature, path, resolve, format } =>
            cmd::analysis::run_hunt(&to_analysis_sig(&signature), &path, resolve, &format),
        Cmd::Compare { baseline, suspect, resolve, format } =>
            cmd::forensics::run_compare(&baseline, &suspect, resolve, &format),
        Cmd::Metadata { path, format } =>
            cmd::forensics::run_metadata(&path, &format),
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
