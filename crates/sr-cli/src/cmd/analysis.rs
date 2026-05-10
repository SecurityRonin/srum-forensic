use std::path::Path;

use crate::output::{OutputFormat, print_values};

/// Named forensic hunt signature for `sr hunt`.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum HuntSignature {
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
pub fn to_analysis_sig(s: &HuntSignature) -> srum_analysis::analysis::HuntSignature {
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

pub fn run_timeline(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()> {
    let id_map = resolve.then(|| srum_analysis::load_id_map(path));
    let all = srum_analysis::build_timeline(path, id_map.as_ref());
    print_values(&all, format)
}

pub fn run_process(
    app: &str,
    path: &Path,
    resolve: bool,
    format: &OutputFormat,
) -> anyhow::Result<()> {
    let id_map = resolve.then(|| srum_analysis::load_id_map(path));
    let all = srum_analysis::build_timeline(path, id_map.as_ref());
    let filtered = srum_analysis::analysis::filter_by_app(all, app);
    print_values(&filtered, format)
}

pub fn run_stats(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()> {
    let id_map = resolve.then(|| srum_analysis::load_id_map(path));
    let all = srum_analysis::build_timeline(path, id_map.as_ref());
    let stats = srum_analysis::analysis::build_stats(all);
    print_values(&stats, format)
}

pub fn run_sessions(path: &Path, format: &OutputFormat) -> anyhow::Result<()> {
    let all = srum_analysis::build_timeline(path, None);
    let sessions = srum_analysis::analysis::build_sessions(&all);
    print_values(&sessions, format)
}

pub fn run_gaps(
    path: &Path,
    threshold_hours: u64,
    format: &OutputFormat,
) -> anyhow::Result<()> {
    let all = srum_analysis::build_timeline(path, None);
    let mut gaps = srum_analysis::analysis::detect_gaps(&all, threshold_hours);

    // AutoIncId gap detection (best-effort, appended after timestamp gaps).
    macro_rules! add_autoinc_gaps {
        ($table:expr, $parser:expr) => {
            if let Ok(records) = $parser(path) {
                let ids: Vec<u32> = records.iter().map(|r| r.auto_inc_id).collect();
                gaps.extend(srum_analysis::analysis::detect_autoinc_gaps_from_ids($table, &ids));
            }
        };
    }
    add_autoinc_gaps!("network", srum_parser::parse_network_usage);
    add_autoinc_gaps!("apps", srum_parser::parse_app_usage);
    add_autoinc_gaps!("energy", srum_parser::parse_energy_usage);

    print_values(&gaps, format)
}

pub fn run_hunt(
    signature: &HuntSignature,
    path: &Path,
    resolve: bool,
    format: &OutputFormat,
) -> anyhow::Result<()> {
    let id_map = resolve.then(|| srum_analysis::load_id_map(path));
    let all = srum_analysis::build_timeline(path, id_map.as_ref());
    let filtered = srum_analysis::analysis::hunt_filter(all, &to_analysis_sig(signature));
    print_values(&filtered, format)
}
