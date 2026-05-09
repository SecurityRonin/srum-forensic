//! Integration tests for the `sr` CLI binary.

use std::process::Command;

fn sr_bin() -> Command {
    let mut bin = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bin.push("../../target/debug/sr");
    Command::new(bin)
}

#[test]
fn sr_help_exits_success() {
    let status = sr_bin()
        .arg("--help")
        .status()
        .expect("failed to run sr --help");
    assert!(status.success(), "sr --help should exit 0");
}

#[test]
fn sr_network_help_exits_success() {
    let status = sr_bin()
        .args(["network", "--help"])
        .status()
        .expect("failed to run sr network --help");
    assert!(status.success(), "sr network --help should exit 0");
}

#[test]
fn sr_apps_help_exits_success() {
    let status = sr_bin()
        .args(["apps", "--help"])
        .status()
        .expect("failed to run sr apps --help");
    assert!(status.success(), "sr apps --help should exit 0");
}

#[test]
fn sr_version_exits_success() {
    let status = sr_bin()
        .arg("--version")
        .status()
        .expect("failed to run sr --version");
    assert!(status.success(), "sr --version should exit 0");
}

#[test]
fn sr_network_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["network", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run sr");
    assert!(!status.success(), "sr must exit nonzero for missing file");
}

#[test]
fn sr_network_nonexistent_stderr_has_lowercase_error_prefix() {
    let out = sr_bin()
        .args(["network", "/nonexistent/SRUDB.dat"])
        .output()
        .expect("run sr");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error:"),
        "stderr must start with 'error:' (lowercase), got: {stderr}"
    );
}

#[test]
fn sr_apps_nonexistent_stderr_has_lowercase_error_prefix() {
    let out = sr_bin()
        .args(["apps", "/nonexistent/SRUDB.dat"])
        .output()
        .expect("run sr");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error:"),
        "stderr must start with 'error:' (lowercase), got: {stderr}"
    );
}

#[test]
fn sr_network_error_stdout_is_empty() {
    let out = sr_bin()
        .args(["network", "/nonexistent/SRUDB.dat"])
        .output()
        .expect("run sr");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.is_empty(),
        "stdout must be empty on error, got: {stdout}"
    );
}

// ── --format flag ────────────────────────────────────────────────────────────

#[test]
fn sr_network_help_shows_format_flag() {
    let out = sr_bin().args(["network", "--help"]).output().expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("format"),
        "sr network --help must document --format, got: {stdout}"
    );
}

#[test]
fn sr_apps_help_shows_format_flag() {
    let out = sr_bin().args(["apps", "--help"]).output().expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("format"),
        "sr apps --help must document --format, got: {stdout}"
    );
}

#[test]
fn sr_idmap_help_shows_format_flag() {
    let out = sr_bin().args(["idmap", "--help"]).output().expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("format"),
        "sr idmap --help must document --format, got: {stdout}"
    );
}

#[test]
fn sr_network_format_csv_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["network", "--format", "csv", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run");
    assert!(!status.success(), "must exit nonzero for missing file");
}

#[test]
fn sr_apps_format_csv_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["apps", "--format", "csv", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run");
    assert!(!status.success(), "must exit nonzero for missing file");
}

// ── --resolve flag ───────────────────────────────────────────────────────────

#[test]
fn sr_network_resolve_help_shows_resolve_flag() {
    let out = sr_bin()
        .args(["network", "--help"])
        .output()
        .expect("run sr network --help");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("resolve"),
        "sr network --help must document --resolve, got: {stdout}"
    );
}

#[test]
fn sr_apps_resolve_help_shows_resolve_flag() {
    let out = sr_bin()
        .args(["apps", "--help"])
        .output()
        .expect("run sr apps --help");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("resolve"),
        "sr apps --help must document --resolve, got: {stdout}"
    );
}

#[test]
fn sr_network_resolve_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["network", "--resolve", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run sr");
    assert!(!status.success());
}

#[test]
fn sr_apps_resolve_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["apps", "--resolve", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run sr");
    assert!(!status.success());
}

// ── sr idmap ─────────────────────────────────────────────────────────────────

#[test]
fn sr_idmap_help_exits_success() {
    let status = sr_bin()
        .args(["idmap", "--help"])
        .status()
        .expect("run sr idmap --help");
    assert!(status.success(), "sr idmap --help should exit 0");
}

#[test]
fn sr_idmap_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["idmap", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run sr idmap");
    assert!(!status.success(), "sr must exit nonzero for missing file");
}

#[test]
fn sr_idmap_nonexistent_stderr_has_lowercase_error_prefix() {
    let out = sr_bin()
        .args(["idmap", "/nonexistent/SRUDB.dat"])
        .output()
        .expect("run sr idmap");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:' prefix, got: {stderr}"
    );
}

#[test]
fn sr_idmap_nonexistent_stdout_is_empty() {
    let out = sr_bin()
        .args(["idmap", "/nonexistent/SRUDB.dat"])
        .output()
        .expect("run sr idmap");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.is_empty(),
        "stdout must be empty on error, got: {stdout}"
    );
}

// ── sr connectivity ──────────────────────────────────────────────────────────

#[test]
fn sr_connectivity_help_exits_success() {
    let status = sr_bin()
        .args(["connectivity", "--help"])
        .status()
        .expect("run sr connectivity --help");
    assert!(status.success(), "sr connectivity --help should exit 0");
}

#[test]
fn sr_connectivity_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["connectivity", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run sr connectivity");
    assert!(!status.success(), "sr must exit nonzero for missing file");
}

#[test]
fn sr_connectivity_nonexistent_stderr_has_error_prefix() {
    let out = sr_bin()
        .args(["connectivity", "/nonexistent/SRUDB.dat"])
        .output()
        .expect("run sr connectivity");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:' prefix, got: {stderr}"
    );
}

// ── sr energy ────────────────────────────────────────────────────────────────

#[test]
fn sr_energy_help_exits_success() {
    let status = sr_bin()
        .args(["energy", "--help"])
        .status()
        .expect("run sr energy --help");
    assert!(status.success(), "sr energy --help should exit 0");
}

#[test]
fn sr_energy_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["energy", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run sr energy");
    assert!(!status.success(), "sr must exit nonzero for missing file");
}

#[test]
fn sr_energy_nonexistent_stderr_has_error_prefix() {
    let out = sr_bin()
        .args(["energy", "/nonexistent/SRUDB.dat"])
        .output()
        .expect("run sr energy");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:' prefix, got: {stderr}"
    );
}

// ── sr notifications ─────────────────────────────────────────────────────────

#[test]
fn sr_notifications_help_exits_success() {
    let status = sr_bin()
        .args(["notifications", "--help"])
        .status()
        .expect("run sr notifications --help");
    assert!(status.success(), "sr notifications --help should exit 0");
}

#[test]
fn sr_notifications_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["notifications", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run sr notifications");
    assert!(!status.success(), "sr must exit nonzero for missing file");
}

#[test]
fn sr_notifications_nonexistent_stderr_has_error_prefix() {
    let out = sr_bin()
        .args(["notifications", "/nonexistent/SRUDB.dat"])
        .output()
        .expect("run sr notifications");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:' prefix, got: {stderr}"
    );
}

// ── sr app-timeline ───────────────────────────────────────────────────────────

#[test]
fn sr_app_timeline_help_exits_success() {
    let status = sr_bin()
        .args(["app-timeline", "--help"])
        .status()
        .expect("run sr app-timeline --help");
    assert!(status.success(), "sr app-timeline --help should exit 0");
}

#[test]
fn sr_app_timeline_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["app-timeline", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run sr app-timeline");
    assert!(!status.success(), "sr must exit nonzero for missing file");
}

#[test]
fn sr_app_timeline_nonexistent_stderr_has_error_prefix() {
    let out = sr_bin()
        .args(["app-timeline", "/nonexistent/SRUDB.dat"])
        .output()
        .expect("run sr app-timeline");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:' prefix, got: {stderr}"
    );
}

#[test]
fn sr_app_timeline_help_shows_format_flag() {
    let out = sr_bin()
        .args(["app-timeline", "--help"])
        .output()
        .expect("run sr app-timeline --help");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("format"),
        "sr app-timeline --help must document --format, got: {stdout}"
    );
}

#[test]
fn sr_app_timeline_help_shows_resolve_flag() {
    let out = sr_bin()
        .args(["app-timeline", "--help"])
        .output()
        .expect("run sr app-timeline --help");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("resolve"),
        "sr app-timeline --help must document --resolve, got: {stdout}"
    );
}

// ── sr timeline ──────────────────────────────────────────────────────────────

#[test]
fn sr_timeline_help_exits_success() {
    let status = sr_bin()
        .args(["timeline", "--help"])
        .status()
        .expect("run sr timeline --help");
    assert!(status.success(), "sr timeline --help should exit 0");
}

#[test]
fn sr_timeline_nonexistent_exits_zero_best_effort() {
    // timeline is best-effort: all tables fail → empty array, exit 0
    let out = sr_bin()
        .args(["timeline", "/nonexistent/SRUDB.dat"])
        .output()
        .expect("run sr timeline");
    assert!(
        out.status.success(),
        "timeline must exit 0 even when all tables fail (best-effort)"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains('['),
        "must output a JSON array even when empty, got: {stdout}"
    );
}

#[test]
fn sr_timeline_format_flag_exists() {
    let out = sr_bin()
        .args(["timeline", "--help"])
        .output()
        .expect("run sr timeline --help");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("format"),
        "sr timeline --help must document --format, got: {stdout}"
    );
}
