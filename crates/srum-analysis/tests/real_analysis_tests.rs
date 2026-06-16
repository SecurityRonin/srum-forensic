//! Integration tests for srum-analysis against real SRUDB.dat fixtures.

use srum_analysis::{
    analysis::{build_stats, compare_databases},
    pipeline::build_timeline,
};
use srum_parser::{parse_id_map, parse_network_usage};
use std::path::Path;

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
const BELKASOFT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/srudb/museum_belkasoftctf_win10_SRUDB.dat"
);

fn fixture_exists(path: &str) -> bool {
    Path::new(path).exists()
}

// ── before/after delta: aptvm_clean vs aptvm_1daylater ───────────────────────

/// After one day of Server 2022 activity, new processes appear in SRUM.
/// `compare_databases` must surface them in `new_processes`.
#[test]
fn aptvm_1day_introduces_new_processes_relative_to_clean() {
    if !fixture_exists(APTVM_CLEAN) || !fixture_exists(APTVM_1DAY) {
        return;
    }

    let clean_timeline = build_timeline(Path::new(APTVM_CLEAN), None);
    let oneday_timeline = build_timeline(Path::new(APTVM_1DAY), None);

    let clean_stats = build_stats(clean_timeline);
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
    if !fixture_exists(APTVM_CLEAN) || !fixture_exists(APTVM_1DAY) {
        return;
    }

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
    if !fixture_exists(CHAINSAW) {
        return;
    }
    let timeline = build_timeline(Path::new(CHAINSAW), None);
    assert!(
        !timeline.is_empty(),
        "chainsaw build_timeline must return records"
    );
}

#[test]
fn aptvm_clean_build_timeline_runs_without_panic() {
    if !fixture_exists(APTVM_CLEAN) {
        return;
    }
    // Fresh Server 2022: no app activity, no push/network/energy records.
    // build_timeline must complete without panicking and may return 0 entries.
    let timeline = build_timeline(Path::new(APTVM_CLEAN), None);
    // IdMap is a lookup table, not included in the activity timeline.
    // Verify the count is 0 (all tables absent for a truly fresh install).
    assert_eq!(
        timeline.len(),
        0,
        "aptvm_clean fresh install must have no activity timeline entries"
    );
}

// ── chainsaw: APTSimulator tool presence in ID map ───────────────────────────
//
// APTSimulator (https://github.com/NextronSystems/APTSimulator) ran on the
// machine that produced chainsaw_SRUDB.dat. Its bat scripts document exactly
// which binaries it drops and executes. The SRUM ID map records every process
// that consumed measurable CPU or network I/O, so APTSimulator tools must
// appear there. These tests assert known tool names are present — external
// ground truth from APTSimulator's public source, not from our own code.

#[test]
fn chainsaw_idmap_contains_nbtscan_in_tmp() {
    // APTSimulator drops nbtscan.exe to C:\TMP and runs it against local subnets.
    // Source: test-sets/discovery/nbtscan.bat in the APTSimulator repo.
    if !fixture_exists(CHAINSAW) {
        return;
    }
    let entries = parse_id_map(Path::new(CHAINSAW)).expect("parse_id_map");
    let found = entries.iter().any(|e| {
        let n = e.name.to_lowercase();
        n.contains("nbtscan") && (n.contains("\\tmp\\") || n.contains("/tmp/"))
    });
    assert!(
        found,
        "chainsaw idmap must contain nbtscan.exe in a TMP path (APTSimulator discovery tool)"
    );
}

#[test]
fn chainsaw_idmap_contains_aptsimulator_curl_path() {
    // APTSimulator ships curl.exe under its helpers/ directory and uses it to
    // make C2 HTTP requests. Source: test-sets/command-and-control/*.bat.
    if !fixture_exists(CHAINSAW) {
        return;
    }
    let entries = parse_id_map(Path::new(CHAINSAW)).expect("parse_id_map");
    let found = entries
        .iter()
        .any(|e| e.name.to_lowercase().contains("aptsimulator"));
    assert!(
        found,
        "chainsaw idmap must contain a path with 'aptsimulator' (curl.exe helper dir)"
    );
}

#[test]
fn chainsaw_idmap_contains_renamed_psexec() {
    // APTSimulator renames PsExec to p.exe. Source: test-sets/execution/psexec.bat.
    if !fixture_exists(CHAINSAW) {
        return;
    }
    let entries = parse_id_map(Path::new(CHAINSAW)).expect("parse_id_map");
    let found = entries.iter().any(|e| e.name.contains("p.exe"));
    assert!(
        found,
        "chainsaw idmap must contain p.exe (PsExec renamed by APTSimulator)"
    );
}

#[test]
fn chainsaw_idmap_contains_procdump() {
    // APTSimulator drops procdump64.exe to C:\Users\Public\ and dumps lsass.
    // Source: test-sets/credential-access/lsass-dump.bat.
    if !fixture_exists(CHAINSAW) {
        return;
    }
    let entries = parse_id_map(Path::new(CHAINSAW)).expect("parse_id_map");
    let found = entries
        .iter()
        .any(|e| e.name.to_lowercase().contains("procdump"));
    assert!(
        found,
        "chainsaw idmap must contain procdump64.exe (APTSimulator LSASS dumper)"
    );
}

#[test]
fn chainsaw_idmap_contains_eventcreate() {
    // APTSimulator runs eventcreate.exe to forge event log entries.
    // Source: test-sets/credential-access/wce-1.bat.
    if !fixture_exists(CHAINSAW) {
        return;
    }
    let entries = parse_id_map(Path::new(CHAINSAW)).expect("parse_id_map");
    let found = entries
        .iter()
        .any(|e| e.name.to_lowercase().contains("eventcreate"));
    assert!(
        found,
        "chainsaw idmap must contain eventcreate.exe (APTSimulator fake event log)"
    );
}

// ── chainsaw: APTSimulator tool network activity ──────────────────────────────
//
// APTSimulator tools that make network connections produce SRUM network records.
// The byte counts below were read from the actual fixture and cross-checked
// against what those tools do (nbtscan scans two subnets, nslookup resolves C2
// domains, curl makes HTTP HEAD requests to C2 endpoints).

#[test]
fn chainsaw_nbtscan_network_record_has_nonzero_bytes_sent() {
    // nbtscan scans 192.168.1.0/24 and 10.10.0.0/24 — generates substantial
    // outbound UDP traffic. Network table must record a nonzero bytes_sent.
    if !fixture_exists(CHAINSAW) {
        return;
    }
    let id_map = parse_id_map(Path::new(CHAINSAW)).unwrap_or_default();
    let nbtscan_ids: std::collections::HashSet<i32> = id_map
        .iter()
        .filter(|e| {
            let n = e.name.to_lowercase();
            n.contains("nbtscan") && (n.contains("\\tmp\\") || n.contains("/tmp/"))
        })
        .map(|e| e.id)
        .collect();
    assert!(
        !nbtscan_ids.is_empty(),
        "nbtscan id must be present in idmap"
    );

    let net_records = parse_network_usage(Path::new(CHAINSAW)).expect("parse_network_usage");
    let found = net_records
        .iter()
        .any(|r| nbtscan_ids.contains(&r.app_id) && r.bytes_sent > 0);
    assert!(
        found,
        "chainsaw must have a network record for nbtscan (TMP) with bytes_sent > 0"
    );
}

#[test]
fn chainsaw_nslookup_network_record_present() {
    // APTSimulator uses nslookup to resolve C2 domains (msupdater.com, etc.).
    // Source: test-sets/command-and-control/dns-cache-1.bat.
    if !fixture_exists(CHAINSAW) {
        return;
    }
    let id_map = parse_id_map(Path::new(CHAINSAW)).unwrap_or_default();
    let nslookup_ids: std::collections::HashSet<i32> = id_map
        .iter()
        .filter(|e| e.name.to_lowercase().contains("nslookup"))
        .map(|e| e.id)
        .collect();
    assert!(
        !nslookup_ids.is_empty(),
        "nslookup id must be present in idmap"
    );

    let net_records = parse_network_usage(Path::new(CHAINSAW)).expect("parse_network_usage");
    let found = net_records.iter().any(|r| nslookup_ids.contains(&r.app_id));
    assert!(
        found,
        "chainsaw must have a network record for nslookup (C2 DNS lookups)"
    );
}

// ── chainsaw: suspicious_path heuristic fires on APT-dropped binaries ─────────
//
// nbtscan.exe in C:\TMP is an independently confirmed malicious artefact —
// APTSimulator put it there. suspicious_path must fire on it in the timeline.
// This tests the heuristic against real ground truth, not a synthetic fixture.

#[test]
fn chainsaw_suspicious_path_fires_on_nbtscan_in_tmp() {
    if !fixture_exists(CHAINSAW) {
        return;
    }
    let timeline = build_timeline(Path::new(CHAINSAW), None);
    let found = timeline.iter().any(|r| {
        let app = r
            .get("app_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let flagged = r
            .get("suspicious_path")
            .and_then(serde_json::value::Value::as_bool)
            .unwrap_or(false);
        app.contains("nbtscan") && (app.contains("\\tmp\\") || app.contains("/tmp/")) && flagged
    });
    assert!(
        found,
        "chainsaw timeline must flag nbtscan.exe in TMP with suspicious_path \
         (APTSimulator drops it there — externally confirmed malicious path)"
    );
}

#[test]
fn chainsaw_suspicious_path_fires_on_aptsimulator_curl() {
    // curl.exe is run from the APTSimulator download directory, not a standard
    // system path. suspicious_path must fire on its network record.
    if !fixture_exists(CHAINSAW) {
        return;
    }
    let timeline = build_timeline(Path::new(CHAINSAW), None);
    let found = timeline.iter().any(|r| {
        let app = r
            .get("app_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let flagged = r
            .get("suspicious_path")
            .and_then(serde_json::value::Value::as_bool)
            .unwrap_or(false);
        app.contains("aptsimulator") && flagged
    });
    assert!(
        found,
        "chainsaw timeline must flag curl.exe from APTSimulator helpers dir with suspicious_path"
    );
}

// ── belkasoft: clean developer workstation ground truth ───────────────────────
//
// museum_belkasoftctf_win10_SRUDB.dat is from a Windows 10 RS5 developer
// machine. The machine had no malware; the CTF scenario is investigation of
// a clean workstation. Known processes (chrome, thunderbird, git, VSCodium)
// are confirmed present by reading the fixture; known-malicious APTSimulator
// tools are confirmed absent.

#[test]
fn belkasoft_idmap_contains_chrome_in_program_files() {
    if !fixture_exists(BELKASOFT) {
        return;
    }
    let entries = parse_id_map(Path::new(BELKASOFT)).expect("parse_id_map");
    let found = entries.iter().any(|e| {
        let n = e.name.to_lowercase();
        n.contains("chrome.exe") && n.contains("program files")
    });
    assert!(
        found,
        "belkasoft idmap must contain chrome.exe under Program Files"
    );
}

#[test]
fn belkasoft_idmap_contains_thunderbird_in_program_files() {
    if !fixture_exists(BELKASOFT) {
        return;
    }
    let entries = parse_id_map(Path::new(BELKASOFT)).expect("parse_id_map");
    let found = entries.iter().any(|e| {
        let n = e.name.to_lowercase();
        n.contains("thunderbird.exe") && n.contains("program files")
    });
    assert!(
        found,
        "belkasoft idmap must contain thunderbird.exe under Program Files"
    );
}

#[test]
fn belkasoft_idmap_contains_git_in_program_files() {
    if !fixture_exists(BELKASOFT) {
        return;
    }
    let entries = parse_id_map(Path::new(BELKASOFT)).expect("parse_id_map");
    let found = entries.iter().any(|e| {
        let n = e.name.to_lowercase();
        n.contains("git.exe") && n.contains("program files")
    });
    assert!(
        found,
        "belkasoft idmap must contain git.exe under Program Files"
    );
}

#[test]
fn belkasoft_idmap_contains_vscodium_in_user_documents() {
    // VSCodium was run from the user's Documents folder (not Program Files).
    // This is an unusual installation path that our suspicious_path heuristic
    // should flag — and a verified fact about this fixture.
    if !fixture_exists(BELKASOFT) {
        return;
    }
    let entries = parse_id_map(Path::new(BELKASOFT)).expect("parse_id_map");
    let found = entries.iter().any(|e| {
        let n = e.name.to_lowercase();
        n.contains("vscodium.exe") && n.contains("documents")
    });
    assert!(
        found,
        "belkasoft idmap must contain VSCodium.exe under user Documents folder"
    );
}

#[test]
fn belkasoft_idmap_contains_user_anit_ghosh() {
    // The machine's primary user is anit.ghosh — their SID or name appears in
    // the ID map as a user entry.
    if !fixture_exists(BELKASOFT) {
        return;
    }
    let entries = parse_id_map(Path::new(BELKASOFT)).expect("parse_id_map");
    let found = entries
        .iter()
        .any(|e| e.name.to_lowercase().contains("anit"));
    assert!(
        found,
        "belkasoft idmap must contain the primary user anit.ghosh"
    );
}

#[test]
fn belkasoft_idmap_has_no_apt_tools() {
    // This is a clean developer machine — APTSimulator tools must not appear.
    // Negative assertion: absence of known-malicious binaries confirms the
    // fixture is not contaminated and our parser is not hallucinating entries.
    if !fixture_exists(BELKASOFT) {
        return;
    }
    let entries = parse_id_map(Path::new(BELKASOFT)).expect("parse_id_map");
    let apt_tools = [
        "nbtscan",
        "procdump",
        "mim.exe",
        "p.exe",
        "psexesvc",
        "eventcreate",
    ];
    for tool in &apt_tools {
        let found = entries.iter().any(|e| e.name.to_lowercase().contains(tool));
        assert!(
            !found,
            "belkasoft idmap must not contain {tool} (clean machine, no APT tools)"
        );
    }
}

#[test]
fn belkasoft_suspicious_path_fires_on_vscodium_in_documents() {
    // VSCodium running from the user's Documents folder is a non-standard path.
    // suspicious_path must fire — independently verified by reading the fixture.
    if !fixture_exists(BELKASOFT) {
        return;
    }
    let timeline = build_timeline(Path::new(BELKASOFT), None);
    let found = timeline.iter().any(|r| {
        let app = r
            .get("app_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let flagged = r
            .get("suspicious_path")
            .and_then(serde_json::value::Value::as_bool)
            .unwrap_or(false);
        app.contains("vscodium") && app.contains("documents") && flagged
    });
    assert!(
        found,
        "belkasoft timeline must flag VSCodium.exe in Documents with suspicious_path \
         (non-standard installation path — confirmed by reading the fixture)"
    );
}
