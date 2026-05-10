use std::path::Path;

use crate::output::{OutputFormat, print_values};

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
    signature: &srum_analysis::analysis::HuntSignature,
    path: &Path,
    resolve: bool,
    format: &OutputFormat,
) -> anyhow::Result<()> {
    let id_map = resolve.then(|| srum_analysis::load_id_map(path));
    let all = srum_analysis::build_timeline(path, id_map.as_ref());
    let filtered = srum_analysis::analysis::hunt_filter(all, signature);
    print_values(&filtered, format)
}
