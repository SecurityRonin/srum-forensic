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
    assert!(stdout.is_empty(), "stdout must be empty on error, got: {stdout}");
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
    assert!(stdout.is_empty(), "stdout must be empty on error, got: {stdout}");
}
