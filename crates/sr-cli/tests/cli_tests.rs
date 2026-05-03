//! Integration tests for the `sr` CLI binary.

use std::process::Command;

fn sr_bin() -> Command {
    let mut bin = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Navigate to workspace root then to the binary
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
