# Steal Features Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add CSV output, three new SRUM tables (Network Connectivity, Energy Usage, Push Notifications), and a timeline subcommand — features stolen from competitive analysis of srum-dump, SrumQuery, and others.

**Architecture:** Each new table follows the existing three-layer pattern: record type in `srum-core`, decoder + parse function in `srum-parser`, CLI subcommand in `sr-cli`. CSV output is added as a `--format` flag across all subcommands. Timeline merges all tables.

**Tech Stack:** Rust 1.80+, `csv` crate (new), existing `serde_json`, `clap`, `chrono`.

**Wire format note:** Tests use a synthetic flat-binary format (same approach as existing `network.rs`). The real SRUDB.dat uses ESE column structures; the synthetic format is a test-only approximation documented per-module.

**TDD requirement:** Every task MUST have two commits: RED (failing tests only) then GREEN (minimal implementation). No exceptions.

**Commit signing:** `export GITSIGN_CREDENTIAL_CACHE="$HOME/Library/Caches/sigstore/gitsign/cache.sock"` before every `git commit`.

---

## Task 1: CSV output — `--format` flag on all subcommands

**Files:**
- Modify: `Cargo.toml` (workspace) — add `csv = "1"` to `[workspace.dependencies]`
- Modify: `crates/sr-cli/Cargo.toml` — add `csv.workspace = true`
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

**What to build:**

Add `--format <FORMAT>` flag (values: `json`, `csv`; default: `json`) to the `network`, `apps`, `idmap`, and later `connectivity`, `energy`, `notifications`, `timeline` subcommands.

Add a `values_to_csv` helper in `main.rs` that takes `&[serde_json::Value]` and returns `anyhow::Result<String>`:

```rust
fn values_to_csv(values: &[serde_json::Value]) -> anyhow::Result<String> {
    if values.is_empty() {
        return Ok(String::new());
    }
    let headers: Vec<String> = match &values[0] {
        serde_json::Value::Object(m) => m.keys().cloned().collect(),
        _ => anyhow::bail!("expected JSON object for CSV serialisation"),
    };
    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(&headers)?;
    for v in values {
        if let serde_json::Value::Object(m) = v {
            let row: Vec<String> = headers
                .iter()
                .map(|k| match m.get(k) {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(v) => v.to_string(),
                    None => String::new(),
                })
                .collect();
            wtr.write_record(&row)?;
        }
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
```

Add `OutputFormat` enum:
```rust
#[derive(clap::ValueEnum, Clone, Default)]
enum OutputFormat {
    #[default]
    Json,
    Csv,
}
```

Add `--format` to each subcommand variant:
```rust
/// Output format.
#[arg(long, value_enum, default_value_t)]
format: OutputFormat,
```

In each match arm, use the `enrich` helper to produce `Vec<serde_json::Value>` (with or without `--resolve`), then:
```rust
match format {
    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&values)?),
    OutputFormat::Csv  => print!("{}", values_to_csv(&values)?),
}
```

For non-resolve path, convert typed records to `serde_json::Value` via `serde_json::to_value`.

**Step 1: Write failing tests** in `cli_tests.rs`:

```rust
#[test]
fn sr_network_format_csv_help_shows_format_flag() {
    let out = sr_bin().args(["network", "--help"]).output().expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("format"), "must document --format flag");
}

#[test]
fn sr_apps_format_csv_help_shows_format_flag() {
    let out = sr_bin().args(["apps", "--help"]).output().expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("format"), "must document --format flag");
}

#[test]
fn sr_idmap_format_csv_help_shows_format_flag() {
    let out = sr_bin().args(["idmap", "--help"]).output().expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("format"), "must document --format flag");
}

#[test]
fn sr_network_format_csv_nonexistent_exits_nonzero() {
    let status = sr_bin()
        .args(["network", "--format", "csv", "/nonexistent/SRUDB.dat"])
        .status()
        .expect("run");
    assert!(!status.success());
}
```

**Step 2:** Run tests, confirm RED (flag not yet present — `--help` won't contain "format").

**Step 3:** Implement as described above.

**Step 4:** Run tests, confirm GREEN. Run `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`. All must pass.

**Step 5:** RED commit: `test(sr-cli): RED — --format csv flag tests`
**Step 6:** GREEN commit: `feat(sr-cli): GREEN — --format csv/json flag on network, apps, idmap`

---

## Task 2: Network Connectivity table (`sr connectivity`)

**Files:**
- Create: `crates/srum-core/src/connectivity.rs`
- Modify: `crates/srum-core/src/lib.rs`
- Create: `crates/srum-parser/src/connectivity.rs`
- Modify: `crates/srum-parser/src/lib.rs`
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

**Synthetic wire format (28 bytes):**
```
[0..8]   filetime    u64 LE  — FILETIME timestamp
[8..12]  app_id      i32 LE
[12..16] user_id     i32 LE
[16..20] profile_id  i32 LE  — L2 profile ID (network interface/profile)
[20..28] connected_time u64 LE — seconds the connection was active
```

**srum-core** — `crates/srum-core/src/connectivity.rs`:
```rust
//! Network connectivity record — L2 connection sessions per process.
//!
//! Source table: `{DD6636C4-8929-4683-974E-22C046A43763}` in SRUDB.dat.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One SRUM network connectivity record: a process's L2 connection session.
///
/// Forensic value: maps processes to specific network profiles (WiFi SSIDs,
/// VPN adapters) and their connection durations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectivityRecord {
    pub app_id: i32,
    pub user_id: i32,
    pub timestamp: DateTime<Utc>,
    /// L2 profile ID — look up in SruDbIdMapTable for profile name.
    pub profile_id: i32,
    /// Seconds the connection was active in this interval.
    pub connected_time: u64,
}
```

Add to `crates/srum-core/src/lib.rs`:
```rust
pub mod connectivity;
pub use connectivity::NetworkConnectivityRecord;
pub const NETWORK_CONNECTIVITY_RECORD_SIZE: usize = 28;
```

**srum-parser** — `crates/srum-parser/src/connectivity.rs`:

Follow the exact same pattern as `network.rs`. Decode the 28-byte record.

Add to `crates/srum-parser/src/lib.rs`:
```rust
mod connectivity;

pub fn parse_network_connectivity(
    path: &std::path::Path,
) -> anyhow::Result<Vec<srum_core::NetworkConnectivityRecord>> {
    let db = ese_core::EseDatabase::open(path)?;
    collect_table(&db, "{DD6636C4-8929-4683-974E-22C046A43763}", connectivity::decode_connectivity_record)
}
```

**sr-cli** — new subcommand `Connectivity` with `--format` and `--resolve` flags:
```rust
/// Parse network connectivity records — L2 connection sessions per process.
Connectivity {
    path: PathBuf,
    #[arg(long)] resolve: bool,
    #[arg(long, value_enum, default_value_t)] format: OutputFormat,
},
```

**Tests in cli_tests.rs:**
```rust
#[test]
fn sr_connectivity_help_exits_success() { ... }

#[test]
fn sr_connectivity_nonexistent_exits_nonzero() { ... }

#[test]
fn sr_connectivity_nonexistent_stderr_has_error_prefix() { ... }
```

**Step 1:** Write RED tests. Run. Confirm failure (subcommand doesn't exist).
**Step 2:** RED commit: `test(sr-cli): RED — sr connectivity subcommand tests`
**Step 3:** Implement srum-core type, srum-parser decoder, sr-cli subcommand.
**Step 4:** Run full suite + clippy + fmt. All green.
**Step 5:** GREEN commit: `feat: GREEN — sr connectivity — Network Connectivity Usage Monitor table`

---

## Task 3: Energy Usage table (`sr energy`)

**Files:**
- Create: `crates/srum-core/src/energy.rs`
- Modify: `crates/srum-core/src/lib.rs`
- Create: `crates/srum-parser/src/energy.rs`
- Modify: `crates/srum-parser/src/lib.rs`
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

**Synthetic wire format (32 bytes):**
```
[0..8]   filetime        u64 LE — FILETIME timestamp
[8..12]  app_id          i32 LE
[12..16] user_id         i32 LE
[16..24] charge_level    u64 LE — mWh remaining in battery
[24..32] energy_consumed u64 LE — mWh consumed by process in interval
```

**GUID:** `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}`

**srum-core** — `crates/srum-core/src/energy.rs`:
```rust
/// One SRUM energy usage record: battery state and energy consumed per process.
///
/// Forensic value: correlates process activity with battery drain timeline;
/// timestamps power-on/off cycles; detects anomalous overnight power usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnergyUsageRecord {
    pub app_id: i32,
    pub user_id: i32,
    pub timestamp: DateTime<Utc>,
    /// Remaining battery charge at interval end (mWh).
    pub charge_level: u64,
    /// Energy consumed by this process in the interval (mWh).
    pub energy_consumed: u64,
}
```

Add to `lib.rs`: `pub mod energy; pub use energy::EnergyUsageRecord; pub const ENERGY_RECORD_SIZE: usize = 32;`

**srum-parser decoder:** same pattern as network.rs, 32-byte layout.

**CLI subcommand:** `Energy { path, format }` — no `--resolve` (energy records aren't app-attributed in the same way; profile_id is not app_id).

**Tests:** same three-test pattern (help, nonexistent exits nonzero, stderr error prefix).

RED commit: `test(sr-cli): RED — sr energy subcommand tests`
GREEN commit: `feat: GREEN — sr energy — Energy Usage Provider table`

---

## Task 4: Push Notifications table (`sr notifications`)

**Files:**
- Create: `crates/srum-core/src/push_notification.rs`
- Modify: `crates/srum-core/src/lib.rs`
- Create: `crates/srum-parser/src/push_notification.rs`
- Modify: `crates/srum-parser/src/lib.rs`
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

**Synthetic wire format (24 bytes):**
```
[0..8]   filetime           u64 LE
[8..12]  app_id             i32 LE
[12..16] user_id            i32 LE
[16..20] notification_type  u32 LE — notification category (0=toast, 1=badge, 2=tile, 3=raw)
[20..24] count              u32 LE — number of notifications in interval
```

**GUID:** `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}`

**srum-core** — `crates/srum-core/src/push_notification.rs`:
```rust
/// One SRUM push notification record: app notification activity per interval.
///
/// Forensic value: proves app engagement at specific timestamps even without
/// foreground CPU cycles — communication apps receiving C2 instructions show
/// here before the user interacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushNotificationRecord {
    pub app_id: i32,
    pub user_id: i32,
    pub timestamp: DateTime<Utc>,
    /// Notification category (0=toast, 1=badge, 2=tile, 3=raw).
    pub notification_type: u32,
    /// Number of notifications delivered in this interval.
    pub count: u32,
}
```

Add to `lib.rs`: `pub mod push_notification; pub use push_notification::PushNotificationRecord; pub const PUSH_NOTIFICATION_RECORD_SIZE: usize = 24;`

**CLI subcommand:** `Notifications { path, resolve, format }` — supports `--resolve` and `--format`.

**Tests:** same three-test pattern + one for `--resolve` help text.

RED commit: `test(sr-cli): RED — sr notifications subcommand tests`
GREEN commit: `feat: GREEN — sr notifications — Push Notifications WPN Provider table`

---

## Task 5: Timeline subcommand (`sr timeline`)

**Files:**
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

**What to build:**

`sr timeline [--format json|csv] SRUDB.dat`

Reads all five tables (network, apps, connectivity, energy, notifications), merges all records into a single JSON Value array, injects a `"table"` field identifying the source table name (e.g., `"network"`, `"apps"`, `"connectivity"`, `"energy"`, `"notifications"`), then sorts by the `"timestamp"` field (string sort on ISO8601 is lexicographically correct).

Silently skips tables that return errors (best-effort — the database may not have all tables).

Implementation in `run()`:
```rust
Cmd::Timeline { path, format } => {
    let mut all: Vec<serde_json::Value> = Vec::new();
    let tables: &[(&str, fn(&std::path::Path) -> anyhow::Result<Vec<serde_json::Value>>)] = &[
        ("network", |p| records_to_values(srum_parser::parse_network_usage(p)?)),
        ("apps", |p| records_to_values(srum_parser::parse_app_usage(p)?)),
        ("connectivity", |p| records_to_values(srum_parser::parse_network_connectivity(p)?)),
        ("energy", |p| records_to_values(srum_parser::parse_energy_usage(p)?)),
        ("notifications", |p| records_to_values(srum_parser::parse_push_notifications(p)?)),
    ];
    for (name, loader) in tables {
        if let Ok(mut records) = loader(&path) {
            for r in &mut records {
                if let Some(obj) = r.as_object_mut() {
                    obj.insert("table".to_owned(), serde_json::Value::String((*name).to_owned()));
                }
            }
            all.append(&mut records);
        }
    }
    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb)
    });
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&all)?),
        OutputFormat::Csv  => print!("{}", values_to_csv(&all)?),
    }
}
```

Where `records_to_values` is:
```rust
fn records_to_values<T: serde::Serialize>(records: Vec<T>) -> anyhow::Result<Vec<serde_json::Value>> {
    records.into_iter()
        .map(|r| serde_json::to_value(r).map_err(Into::into))
        .collect()
}
```

**Tests:**
```rust
#[test]
fn sr_timeline_help_exits_success() { ... }

#[test]
fn sr_timeline_nonexistent_exits_nonzero() {
    // timeline is best-effort: all tables fail → empty output, exit 0? 
    // Actually: if the file doesn't exist, EseDatabase::open fails for ALL tables.
    // sr timeline /nonexistent should exit 0 with empty array [] (all tables skipped)
    // OR exit 0 with empty output. Let's say: exits 0, stdout is "[]" or empty.
    // Implementation: if all loaders fail, output [] (empty array).
    let out = sr_bin().args(["timeline", "/nonexistent/SRUDB.dat"]).output().expect("run");
    // Best-effort: exits 0 even when all tables fail
    assert!(out.status.success(), "timeline is best-effort, must exit 0 even if all tables fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains('['), "must output a JSON array");
}

#[test]
fn sr_timeline_format_csv_help_shows_format_flag() { ... }
```

RED commit: `test(sr-cli): RED — sr timeline subcommand tests`
GREEN commit: `feat: GREEN — sr timeline — merged chronological view of all SRUM tables`

---

## Post-implementation

After all 5 tasks:
1. `cargo test --workspace` — all tests pass
2. `cargo clippy --workspace --all-targets -- -D warnings` — zero warnings
3. `cargo fmt --all -- --check` — clean
4. Update `README.md` to document new subcommands
5. `git push origin main`
