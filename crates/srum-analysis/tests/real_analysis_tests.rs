//! Integration tests for srum-analysis against real SRUDB.dat fixtures.

use std::path::Path;
use srum_analysis::{
    analysis::{build_stats, compare_databases},
    pipeline::build_timeline,
};

const APTVM_CLEAN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_aptvm_server2022_clean_SRUDB.dat"
);
const APTVM_1DAY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_aptvm_server2022_1daylater_SRUDB.dat"
);
const CHAINSAW: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/chainsaw_SRUDB.dat"
);

fn fixture_exists(path: &str) -> bool {
    Path::new(path).exists()
}

// ── before/after delta: aptvm_clean vs aptvm_1daylater ───────────────────────

/// After one day of Server 2022 activity, new processes appear in SRUM.
/// compare_databases must surface them in `new_processes`.
#[test]
fn aptvm_1day_introduces_new_processes_relative_to_clean() {
    if !fixture_exists(APTVM_CLEAN) || !fixture_exists(APTVM_1DAY) { return; }

    let clean_timeline = build_timeline(Path::new(APTVM_CLEAN), None);
    let oneday_timeline = build_timeline(Path::new(APTVM_1DAY), None);

    let clean_stats  = build_stats(clean_timeline);
    let oneday_stats = build_stats(oneday_timeline);

    let diff = compare_databases(clean_stats, oneday_stats);

    let new_procs = diff["new_processes"]
        .as_array()
        .expect("diff must have new_processes array");

    assert!(
        !new_procs.is_empty(),
        "aptvm_1day must have new processes relative to clean install (got 0)"
    );
}

/// The clean install has fewer total SRUM records than the 1-day-later snapshot.
#[test]
fn aptvm_1day_has_more_timeline_entries_than_clean() {
    if !fixture_exists(APTVM_CLEAN) || !fixture_exists(APTVM_1DAY) { return; }

    let clean_count = build_timeline(Path::new(APTVM_CLEAN), None).len();
    let oneday_count = build_timeline(Path::new(APTVM_1DAY), None).len();

    assert!(
        oneday_count > clean_count,
        "aptvm_1day must have more SRUM timeline entries than clean install \
         (clean={clean_count}, 1day={oneday_count})"
    );
}

// ── pipeline smoke tests: build_timeline does not panic on any fixture ────────

#[test]
fn chainsaw_build_timeline_returns_non_empty_results() {
    if !fixture_exists(CHAINSAW) { return; }
    let timeline = build_timeline(Path::new(CHAINSAW), None);
    assert!(
        !timeline.is_empty(),
        "chainsaw build_timeline must return records"
    );
}

#[test]
fn aptvm_clean_build_timeline_runs_without_panic() {
    if !fixture_exists(APTVM_CLEAN) { return; }
    // Fresh Server 2022: no app activity, no push/network/energy records.
    // build_timeline must complete without panicking and may return 0 entries.
    let timeline = build_timeline(Path::new(APTVM_CLEAN), None);
    // IdMap is a lookup table, not included in the activity timeline.
    // Verify the count is 0 (all tables absent for a truly fresh install).
    assert_eq!(timeline.len(), 0,
        "aptvm_clean fresh install must have no activity timeline entries");
}
