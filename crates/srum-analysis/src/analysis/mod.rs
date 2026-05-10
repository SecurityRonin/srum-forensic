pub mod compare;
pub mod gaps;
pub mod hunt;
pub mod sessions;
pub mod stats;

pub use compare::compare_databases;
pub use gaps::{detect_autoinc_gaps_from_ids, detect_gaps};
pub use hunt::{filter_by_app, hunt_filter, HuntSignature};
pub use sessions::build_sessions;
pub use stats::build_stats;

/// Absolute difference in seconds between two RFC-3339 timestamps.
/// Returns 0 if either string fails to parse.
pub(crate) fn iso_diff_secs(a: &str, b: &str) -> i64 {
    let parse = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.timestamp())
    };
    match (parse(a), parse(b)) {
        (Some(ta), Some(tb)) => (tb - ta).abs(),
        _ => 0,
    }
}
