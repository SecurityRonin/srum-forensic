# Comprehensive SRUM Feature Expansion

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Expand sr from a SRUM parser into a full forensic investigation platform — process-centric views, temporal pattern detection, anti-forensics detection, and MITRE ATT&CK integration.

**Architecture:** All new heuristics are pure functions in forensicnomicon (`~/src/forensicnomicon/src/heuristics/srum.rs`). Signals are wired into sr-cli (`crates/sr-cli/src/main.rs`). Parser changes go in `crates/srum-parser/`. Two separate commits per task: RED (failing tests) then GREEN (implementation).

**Tech Stack:** Rust, clap 4, serde_json, forensicnomicon (external repo at `~/src/forensicnomicon`), ese-core (internal), srum-parser (internal)

**gitsign note:** Run `git commit` normally — gitsign will handle signing automatically per-commit (no credential cache needed in v0.13.0).

---

### Task 1: forensicnomicon — three new SRUM heuristics

**Files:**
- Modify: `~/src/forensicnomicon/src/heuristics/srum.rs`

Add three new pure functions to the existing srum.rs (which already has is_background_cpu_dominant, is_exfil_ratio, is_exfil_volume, is_automated_execution, is_phantom_foreground).

**Step 1a: Write failing tests for `is_suspicious_path`**

```rust
// Suspicious paths: %Temp%, Downloads, UNC, double extension, single-depth root
pub fn is_suspicious_path(path: &str) -> bool { ... }

// Tests to write first:
#[test] fn suspicious_path_temp_dir() { assert!(is_suspicious_path(r"C:\Users\User\AppData\Local\Temp\abc.exe")); }
#[test] fn suspicious_path_downloads() { assert!(is_suspicious_path(r"C:\Users\User\Downloads\tool.exe")); }
#[test] fn suspicious_path_unc() { assert!(is_suspicious_path(r"\\server\share\payload.exe")); }
#[test] fn suspicious_path_double_ext() { assert!(is_suspicious_path(r"C:\Users\User\invoice.pdf.exe")); }
#[test] fn suspicious_path_root_depth_one() { assert!(is_suspicious_path(r"C:\payload.exe")); }
#[test] fn suspicious_path_system32_not_flagged() { assert!(!is_suspicious_path(r"C:\Windows\System32\svchost.exe")); }
#[test] fn suspicious_path_program_files_not_flagged() { assert!(!is_suspicious_path(r"C:\Program Files\Vendor\app.exe")); }
#[test] fn suspicious_path_windows_temp() { assert!(is_suspicious_path(r"C:\Windows\Temp\run.exe")); }
```

Implementation logic for `is_suspicious_path(path: &str) -> bool`:
```rust
let lower = path.to_lowercase();
// UNC path
if lower.starts_with("\\\\") { return true; }
// Temp directories
if lower.contains("\\temp\\") || lower.contains("\\tmp\\") { return true; }
// Downloads
if lower.contains("\\downloads\\") { return true; }
// Windows\Temp
if lower.contains("\\windows\\temp\\") { return true; }
// Double extension: known doc ext before .exe/.dll/.bat/.ps1
let doc_exts = [".pdf.", ".docx.", ".xlsx.", ".doc.", ".xls.", ".pptx.", ".txt.", ".jpg.", ".png."];
let exec_exts = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"];
if exec_exts.iter().any(|e| lower.ends_with(e)) {
    if doc_exts.iter().any(|d| lower.contains(d)) { return true; }
}
// Single depth from drive root: "C:\file.exe" — count backslashes, only 1 separator
let separators = path.chars().filter(|&c| c == '\\').count();
if separators == 1 && path.len() > 3 { return true; } // "C:\" + name
false
```

**Step 1b: Write failing tests for `is_process_masquerade`**

```rust
// Detects process names that are close to system binaries but NOT in system dirs
pub fn is_process_masquerade(binary_name: &str, dir: &str) -> bool { ... }

#[test] fn masquerade_svch0st_not_in_system32() {
    assert!(is_process_masquerade("svch0st.exe", r"C:\Users\User\AppData\Local"));
}
#[test] fn masquerade_lssas_exe() {
    assert!(is_process_masquerade("lssas.exe", r"C:\Windows\Temp"));
}
#[test] fn masquerade_legitimate_svchost_in_system32() {
    assert!(!is_process_masquerade("svchost.exe", r"C:\Windows\System32"));
}
#[test] fn masquerade_legitimate_explorer_in_windows() {
    assert!(!is_process_masquerade("explorer.exe", r"C:\Windows"));
}
#[test] fn masquerade_unrelated_binary_not_flagged() {
    assert!(!is_process_masquerade("myapp.exe", r"C:\Program Files\MyApp"));
}
#[test] fn masquerade_distance_three_not_flagged() {
    assert!(!is_process_masquerade("svchzzz.exe", r"C:\Users\User"));
}
```

Implementation:
```rust
// Known Windows system binaries (lowercase, no path)
const SYSTEM_BINARIES: &[&str] = &[
    "svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe",
    "explorer.exe", "cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe",
    "msiexec.exe", "werfault.exe", "conhost.exe", "dllhost.exe", "taskhost.exe",
    "smss.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe", "sihost.exe",
];
const SYSTEM_DIRS: &[&str] = &[
    "\\windows\\system32", "\\windows\\syswow64", "\\windows\\winsxs",
    "\\windows\\sysnative",
];

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i-1] == b[j-1] { dp[i-1][j-1] }
                       else { 1 + dp[i-1][j].min(dp[i][j-1]).min(dp[i-1][j-1]) };
        }
    }
    dp[m][n]
}

pub fn is_process_masquerade(binary_name: &str, dir: &str) -> bool {
    let lower_name = binary_name.to_lowercase();
    let lower_dir = dir.to_lowercase();
    // If it IS a system binary in a system directory, it's legitimate
    if SYSTEM_DIRS.iter().any(|d| lower_dir.contains(d)) {
        return false;
    }
    // Check edit distance against known system binaries
    SYSTEM_BINARIES.iter().any(|known| {
        levenshtein(&lower_name, known) <= 2 && lower_name != known.to_string()
    })
}
```

Wait - if binary_name == known exactly but not in system dir, that's a masquerade too. Fix: remove the `&& lower_name != known.to_string()` condition, OR keep it and document that exact-name-in-wrong-dir is handled by is_suspicious_path. Let's keep the distance > 0 check so exact matches outside system32 are flagged only by suspicious_path. But actually that's a different signal. Let me keep `lower_name != *known` to avoid flagging `svchost.exe` running from ProgramData (which could be legit). Levenshtein distance 1-2 catches the lookalikes.

**Step 1c: Write failing tests for `is_beaconing`**

```rust
// Detect regular-interval C2 beaconing from a sorted list of Unix timestamps (seconds)
pub fn is_beaconing(timestamps_secs: &[i64]) -> bool { ... }

#[test] fn beaconing_detected_regular_hourly() {
    // Exactly hourly for 10 hours
    let ts: Vec<i64> = (0..10).map(|i| i * 3600).collect();
    assert!(is_beaconing(&ts));
}
#[test] fn beaconing_not_detected_too_few_points() {
    let ts: Vec<i64> = (0..5).map(|i| i * 3600).collect(); // only 4 intervals
    assert!(!is_beaconing(&ts));
}
#[test] fn beaconing_not_detected_irregular() {
    // Wildly irregular intervals
    let ts = vec![0i64, 100, 2000, 50000, 51000, 200000, 201000, 500000];
    assert!(!is_beaconing(&ts));
}
#[test] fn beaconing_not_detected_too_short_interval() {
    // Every 30 seconds — below min interval
    let ts: Vec<i64> = (0..10).map(|i| i * 30).collect();
    assert!(!is_beaconing(&ts));
}
#[test] fn beaconing_not_detected_too_long_interval() {
    // Every 10 hours — above max
    let ts: Vec<i64> = (0..10).map(|i| i * 36000).collect();
    assert!(!is_beaconing(&ts));
}
#[test] fn beaconing_detected_near_regular_five_minute() {
    // Every 5 minutes ± a few seconds
    let ts: Vec<i64> = (0..10).map(|i| i * 300 + (i % 3) as i64).collect();
    assert!(is_beaconing(&ts));
}
```

Implementation:
```rust
pub const BEACON_MIN_INTERVAL_SECS: i64 = 60;
pub const BEACON_MAX_INTERVAL_SECS: i64 = 28_800; // 8 hours
pub const BEACON_MIN_SAMPLES: usize = 5; // need at least 5 intervals (6 timestamps)
pub const BEACON_COV_THRESHOLD: f64 = 0.15;

pub fn is_beaconing(timestamps_secs: &[i64]) -> bool {
    if timestamps_secs.len() < BEACON_MIN_SAMPLES + 1 { return false; }
    let intervals: Vec<f64> = timestamps_secs.windows(2)
        .map(|w| (w[1] - w[0]) as f64)
        .filter(|&iv| iv >= BEACON_MIN_INTERVAL_SECS as f64 && iv <= BEACON_MAX_INTERVAL_SECS as f64)
        .collect();
    if intervals.len() < BEACON_MIN_SAMPLES { return false; }
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean == 0.0 { return false; }
    let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let cov = variance.sqrt() / mean;
    cov < BEACON_COV_THRESHOLD
}
```

**Steps:** Write all tests (RED commit in forensicnomicon repo), then implement all three functions (GREEN commit).

RED commit message: `test(heuristics): RED — is_suspicious_path, is_process_masquerade, is_beaconing`
GREEN commit message: `feat(heuristics): GREEN — is_suspicious_path, is_process_masquerade, is_beaconing`

Run tests: `cd ~/src/forensicnomicon && cargo test -p forensicnomicon heuristics::srum`

---

### Task 2: sr-cli — NDJSON output, SID classification, MITRE ATT&CK annotation

**Files:**
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

**NDJSON output:**
Add `Ndjson` variant to `OutputFormat` enum. In `print_values`, add arm that prints one JSON object per line (no pretty-printing, no array wrapper).

```rust
#[derive(clap::ValueEnum, Clone, Default, PartialEq)]
enum OutputFormat {
    #[default]
    Json,
    Csv,
    Ndjson,
}

// In print_values:
OutputFormat::Ndjson => {
    for v in values {
        println!("{}", serde_json::to_string(v)?);
    }
}
```

**SID classification:**
Add `classify_sid(sid: &str) -> Option<&'static str>` private function. Call it in `enrich()` when `user_name` resolved from idmap looks like a SID (starts with `S-1-`). Inject `account_type` field.

```rust
fn classify_sid(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-5-18" => Some("system"),
        "S-1-5-19" => Some("local_service"),
        "S-1-5-20" => Some("network_service"),
        "S-1-1-0" => Some("everyone"),
        _ if sid.ends_with("-500") && sid.starts_with("S-1-5-21-") => Some("local_admin"),
        _ if sid.starts_with("S-1-5-21-") => Some("domain_user"),
        _ => None,
    }
}
```

In `enrich()`, after inserting `user_name`, check if it's a SID:
```rust
if let Some(name) = ... // resolved user_name
    obj.insert("user_name", ...);
    if name.starts_with("S-1-") {
        if let Some(acct) = classify_sid(name) {
            obj.insert("account_type", Value::String(acct.to_owned()));
        }
    }
}
```

**MITRE ATT&CK annotation:**
Add `mitre_for_flags(obj: &serde_json::Map<...>) -> Vec<&'static str>` that returns technique IDs for any heuristic flags present. Call at end of `apply_heuristics` and `apply_cross_table_signals`.

Mapping:
- `background_cpu_dominant` → `["T1496"]`
- `no_focus_with_cpu` → `["T1564"]`
- `phantom_foreground` → `["T1036"]`
- `automated_execution` → `["T1059"]`
- `exfil_signal` → `["T1048"]`
- `beaconing` → `["T1071"]`
- `notification_c2` → `["T1092"]`
- `suspicious_path` → `["T1036.005"]`
- `masquerade_candidate` → `["T1036.005"]`

If any flags are present, inject `mitre_techniques: ["T1496", ...]` (deduplicated array).

**Tests to write first (all should fail initially):**

```rust
// NDJSON
#[test] fn sr_network_format_ndjson_nonexistent_exits_nonzero() { ... }
#[test] fn sr_timeline_format_ndjson_nonexistent_exits_zero() { ... } // timeline is best-effort

// SID classification unit tests (in mod tests in main.rs)
#[test] fn classify_sid_system() { assert_eq!(classify_sid("S-1-5-18"), Some("system")); }
#[test] fn classify_sid_local_admin() { assert_eq!(classify_sid("S-1-5-21-111-222-333-500"), Some("local_admin")); }
#[test] fn classify_sid_domain_user() { assert_eq!(classify_sid("S-1-5-21-111-222-333-1000"), Some("domain_user")); }
#[test] fn classify_sid_non_sid_returns_none() { assert_eq!(classify_sid("C:\\Windows\\explorer.exe"), None); }

// MITRE annotation unit tests
#[test] fn mitre_annotation_for_background_cpu() {
    let mut values = vec![apps_record_flagged_background_cpu_dominant()];
    apply_heuristics(&mut values);
    let techniques = values[0].get("mitre_techniques").unwrap().as_array().unwrap();
    assert!(techniques.iter().any(|t| t.as_str() == Some("T1496")));
}
```

RED commit: `test(sr-cli): RED — NDJSON format, SID classification, MITRE ATT&CK annotation`
GREEN commit: `feat(sr-cli): GREEN — NDJSON format, SID classification, MITRE ATT&CK annotation`

Run tests: `cargo test -p sr-cli && cargo test -p sr-cli --test cli_tests`

---

### Task 3: sr-cli — suspicious path and masquerade signals in enrich

**Files:**
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

Depends on Task 1 (forensicnomicon heuristics must be committed first).

When `--resolve` is active and `app_id` resolves to a path string, parse the binary name and directory from the path, then:
1. Call `forensicnomicon::heuristics::srum::is_suspicious_path(name)` → inject `suspicious_path: true`
2. Call `forensicnomicon::heuristics::srum::is_process_masquerade(binary_name, dir)` → inject `masquerade_candidate: true`

Path parsing helper:
```rust
fn split_path(path: &str) -> (&str, &str) {
    // Find last \ or /
    let sep = path.rfind(|c| c == '\\' || c == '/').unwrap_or(0);
    (&path[..sep], &path[sep + 1..])
}
```

These fields are added in `enrich()` alongside `app_name`, only when the resolved name looks like a path (contains `\` or `/`).

**Tests:**
```rust
// Unit tests in main.rs
#[test] fn enrich_adds_suspicious_path_for_temp_exe() {
    let mut id_map = HashMap::new();
    id_map.insert(42i32, r"C:\Users\User\AppData\Local\Temp\x.exe".to_owned());
    let record = serde_json::json!({"app_id": 42});
    let enriched = enrich(record, &id_map);
    assert_eq!(enriched.get("suspicious_path"), Some(&serde_json::Value::Bool(true)));
}
#[test] fn enrich_adds_masquerade_for_svch0st() {
    let mut id_map = HashMap::new();
    id_map.insert(43i32, r"C:\Users\User\svch0st.exe".to_owned());
    let record = serde_json::json!({"app_id": 43});
    let enriched = enrich(record, &id_map);
    assert_eq!(enriched.get("masquerade_candidate"), Some(&serde_json::Value::Bool(true)));
}
#[test] fn enrich_no_suspicious_path_for_system32() {
    let mut id_map = HashMap::new();
    id_map.insert(1i32, r"C:\Windows\System32\svchost.exe".to_owned());
    let record = serde_json::json!({"app_id": 1});
    let enriched = enrich(record, &id_map);
    assert_eq!(enriched.get("suspicious_path"), None);
    assert_eq!(enriched.get("masquerade_candidate"), None);
}
```

RED commit: `test(sr-cli): RED — suspicious_path and masquerade_candidate in enrich`
GREEN commit: `feat(sr-cli): GREEN — suspicious_path and masquerade_candidate in enrich`

---

### Task 4: sr-cli — `sr process` subcommand

**Files:**
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

Add `Process` variant to `Cmd`:
```rust
Process {
    path: PathBuf,
    /// App ID (integer) or substring of resolved name to filter by.
    app: String,
    #[arg(long)] resolve: bool,
    #[arg(long, value_enum, default_value_t)] format: OutputFormat,
}
```

Implementation: call `build_timeline(path, id_map)` → filter records where:
- `app_id` as string == `app`, OR
- `app_name` field (if present) contains `app` (substring, case-insensitive)

Output the filtered records (already has `table` field).

**Tests:**
```rust
#[test] fn sr_process_help_exits_success() { ... }
#[test] fn sr_process_nonexistent_exits_zero_best_effort() { ... } // like timeline
#[test] fn sr_process_format_flag_exists() { ... }
#[test] fn sr_process_resolve_flag_exists() { ... }
```

Note: `sr process` on a nonexistent file should exit 0 with empty JSON array (best-effort like timeline), because filtering an empty timeline is valid.

RED commit: `test(sr-cli): RED — sr process subcommand`
GREEN commit: `feat(sr-cli): GREEN — sr process subcommand`

---

### Task 5: sr-cli — `sr stats` and `sr sessions` subcommands

**Files:**
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

**`sr stats`:**
Aggregate per-process statistics from `build_timeline`.

Per-process output fields:
- `app_id`: integer
- `app_name`: string (if resolved)
- `total_background_cycles`: u64
- `total_foreground_cycles`: u64
- `total_bytes_sent`: u64
- `total_bytes_received`: u64
- `active_intervals`: u64 (count of records in any table)
- `first_seen`: ISO8601 string
- `last_seen`: ISO8601 string
- `heuristic_flags`: array of flag names that fired
- `flag_count`: u64

Sort by `flag_count` descending (most suspicious first), then by `total_background_cycles` descending.

**`sr sessions`:**
Derive user keyboard sessions from `user_input_time_ms` aggregated per timestamp (already done by `annotate_user_presence`). A session is a contiguous run of `user_present` timestamps.

Output:
```json
[{"session_start":"...","session_end":"...","duration_hours":N,"input_ms_total":N}]
```

Gap > 2 hours = session boundary.

**Tests:**
```rust
#[test] fn sr_stats_help_exits_success() { ... }
#[test] fn sr_stats_nonexistent_exits_zero_best_effort() { ... }
#[test] fn sr_stats_format_flag_exists() { ... }
#[test] fn sr_sessions_help_exits_success() { ... }
#[test] fn sr_sessions_nonexistent_exits_zero_best_effort() { ... }

// Unit tests for stats aggregation
#[test] fn stats_aggregates_background_cycles() { ... }
#[test] fn stats_collects_heuristic_flags() { ... }

// Unit tests for sessions
#[test] fn sessions_contiguous_hours_form_one_session() { ... }
#[test] fn sessions_gap_over_two_hours_splits_session() { ... }
#[test] fn sessions_empty_input_returns_empty() { ... }
```

RED commit: `test(sr-cli): RED — sr stats and sr sessions subcommands`
GREEN commit: `feat(sr-cli): GREEN — sr stats and sr sessions subcommands`

---

### Task 6: sr-cli — `sr gaps` subcommand

**Files:**
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

Analyze timestamps from `build_timeline` to find temporal gaps.

**Gap types:**
- `system_off`: All tables have no records for ≥ 2 hours in a row
- `selective_gap`: One specific table has a gap while others have records (more suspicious)

**Algorithm:**
1. Collect all (table, timestamp) pairs
2. For each table, sort timestamps
3. Find gaps > THRESHOLD (2h for system_off detection)
4. Cross-check: if all tables have a gap at the same time → system_off; if only some → selective_gap

**Output:**
```json
[
  {"type":"system_off","start":"2024-01-15T03:00:00Z","end":"2024-01-15T09:00:00Z","gap_hours":6},
  {"type":"selective_gap","table":"network","start":"...","end":"...","gap_hours":2}
]
```

**Tests:**
```rust
#[test] fn sr_gaps_help_exits_success() { ... }
#[test] fn sr_gaps_nonexistent_exits_zero_best_effort() { ... } // best-effort

// Unit tests
#[test] fn gaps_empty_timeline_produces_no_gaps() { ... }
#[test] fn gaps_contiguous_records_no_gaps() { ... }
#[test] fn gaps_detects_system_off_gap_all_tables() { ... }
#[test] fn gaps_detects_selective_gap_one_table() { ... }
```

RED commit: `test(sr-cli): RED — sr gaps subcommand`
GREEN commit: `feat(sr-cli): GREEN — sr gaps subcommand`

---

### Task 7: sr-cli — `sr hunt` subcommand

**Files:**
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

Named hunt patterns that filter `build_timeline` output:

```rust
#[derive(clap::ValueEnum, Clone)]
enum HuntSignature {
    Exfil,           // exfil_signal == true
    Miner,           // background_cpu_dominant == true  
    Masquerade,      // masquerade_candidate == true
    SuspiciousPath,  // suspicious_path == true
    NoFocus,         // no_focus_with_cpu == true
    Phantom,         // phantom_foreground == true
    Automated,       // automated_execution == true
    All,             // any heuristic flag present
}

Process {
    signature: HuntSignature,
    path: PathBuf,
    #[arg(long)] resolve: bool,
    #[arg(long, value_enum, default_value_t)] format: OutputFormat,
}
```

**Tests:**
```rust
#[test] fn sr_hunt_help_exits_success() { ... }
#[test] fn sr_hunt_exfil_nonexistent_exits_zero_best_effort() { ... }
#[test] fn sr_hunt_miner_nonexistent_exits_zero_best_effort() { ... }

// Unit tests for hunt filters
#[test] fn hunt_exfil_returns_only_exfil_records() { ... }
#[test] fn hunt_miner_returns_only_background_dominant_records() { ... }
#[test] fn hunt_all_returns_any_flagged_record() { ... }
#[test] fn hunt_empty_timeline_returns_empty_array() { ... }
```

RED commit: `test(sr-cli): RED — sr hunt subcommand with named signatures`
GREEN commit: `feat(sr-cli): GREEN — sr hunt subcommand with named signatures`

---

### Task 8: sr-cli — `sr compare` subcommand

**Files:**
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

Compare two SRUDB files and surface what changed.

```rust
Compare {
    baseline: PathBuf,
    suspect: PathBuf,
    #[arg(long)] resolve: bool,
    #[arg(long, value_enum, default_value_t)] format: OutputFormat,
}
```

Implementation: build two timelines (with resolve), group by `app_name` (or `app_id` if not resolved), compute diff:
- `new_processes`: in suspect not in baseline
- `departed_processes`: in baseline not in suspect
- `changed`: processes in both with significant changes (new heuristic flags, Δbytes_sent > 0)

**Output:**
```json
{
  "new_processes": [{"app_id":42,"app_name":"...", "records":[...]}],
  "departed_processes": [...],
  "changed": [{"app_id":1,"app_name":"...","new_flags":["exfil_signal"],"delta_bytes_sent":52428800}]
}
```

**Tests:**
```rust
#[test] fn sr_compare_help_exits_success() { ... }
#[test] fn sr_compare_both_nonexistent_exits_zero_best_effort() { ... }

// Unit tests
#[test] fn compare_new_process_detected() { ... }
#[test] fn compare_departed_process_detected() { ... }
#[test] fn compare_same_databases_no_diff() { ... }
#[test] fn compare_changed_flags_detected() { ... }
```

RED commit: `test(sr-cli): RED — sr compare subcommand`
GREEN commit: `feat(sr-cli): GREEN — sr compare subcommand`

---

### Task 9: sr-cli — `sr metadata` subcommand

**Files:**
- Modify: `Cargo.toml` (workspace) — add `sha2 = "0.10"` and `hex = "0.4"`
- Modify: `crates/sr-cli/Cargo.toml` — add sha2, hex
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

The metadata subcommand reads the database without parsing records — it uses `EseDatabase::catalog_entries()` to enumerate all tables.

```rust
Metadata {
    path: PathBuf,
    #[arg(long, value_enum, default_value_t)] format: OutputFormat,
}
```

**Output:**
```json
{
  "file_path": "...",
  "sha256": "abc123...",
  "file_size_bytes": 12345678,
  "known_tables": ["network","apps","connectivity","energy","notifications","app-timeline"],
  "unknown_tables": ["{B6D82AF1-552B-4788-A31B-4B54E7F0A137}"],
  "record_counts": {"network": 4800, "apps": 9200, ...},
  "temporal_span": {"first": "...", "last": "..."},
  "windows_version_hint": "Windows 10 1607+ (app-timeline table present)"
}
```

Known table GUID → friendly name mapping (from forensicnomicon::srum constants):
- `{973F5D5C-1D90-4944-BE8E-24B22A728CF2}` → "network"
- `{5C8CF1C7-7257-4F13-B223-970EF5939312}` → "apps"
- etc.

To enumerate tables: `EseDatabase::catalog_entries()?.into_iter().filter(|e| e.object_type == 1)` gives all table entries with `object_name`.

Record counts: call each `parse_*` function and count results (already doing this implicitly — or use `table_records().count()`).

SHA-256: read the file with `std::fs::read()` and hash with sha2.

**Tests:**
```rust
#[test] fn sr_metadata_help_exits_success() { ... }
#[test] fn sr_metadata_nonexistent_exits_nonzero() { ... }  // unlike timeline, hard error for missing file
#[test] fn sr_metadata_nonexistent_stderr_has_error_prefix() { ... }

// Unit tests
#[test] fn metadata_classifies_known_guid() { ... }
#[test] fn metadata_reports_unknown_guid() { ... }
```

RED commit: `test(sr-cli): RED — sr metadata subcommand`
GREEN commit: `feat(sr-cli): GREEN — sr metadata subcommand`

---

### Task 10: sr-cli — beaconing signal wired into timeline

**Files:**
- Modify: `crates/sr-cli/src/main.rs`

Depends on Task 1 (is_beaconing must exist in forensicnomicon).

Add `apply_beaconing_signals(all: &mut Vec<serde_json::Value>)`:
1. Collect network records, group by `app_id`
2. For each app, extract sorted timestamps as `Vec<i64>` (parse ISO8601 → unix timestamp)
3. Call `forensicnomicon::heuristics::srum::is_beaconing(&timestamps)`
4. If true, inject `beaconing: true` on ALL network records for that app

Call `apply_beaconing_signals` in `build_timeline` after `apply_cross_table_signals`.

Also update MITRE annotation: if `beaconing: true`, add `T1071` to `mitre_techniques`.

**Tests:**
```rust
// Unit tests in main.rs
#[test] fn beaconing_signal_injected_for_regular_hourly_network() {
    let mut values = vec![
        net_record_at("2024-01-01T00:00:00Z", 42, 1000, 100),
        net_record_at("2024-01-01T01:00:00Z", 42, 1000, 100),
        // ... 8 more hourly records for app_id 42
    ];
    apply_beaconing_signals(&mut values);
    assert_eq!(values[0].get("beaconing"), Some(&Value::Bool(true)));
}
#[test] fn beaconing_signal_not_injected_for_irregular_network() { ... }
#[test] fn beaconing_not_injected_for_apps_records() { ... }  // only network records
```

RED commit: `test(sr-cli): RED — beaconing signal in timeline`
GREEN commit: `feat(sr-cli): GREEN — beaconing signal in timeline`

---

### Task 11: sr-cli — notification-as-C2 cross-table signal

**Files:**
- Modify: `crates/sr-cli/src/main.rs`

Add `apply_notification_c2_signal(all: &mut Vec<serde_json::Value>)`:
1. Build map: `(app_id, timestamp) → notification_count` from notification records
2. For each apps record at same `(app_id, timestamp)`:
   - If `notification_count > N` (say 10 per hour)
   - AND `background_cycles > 0`
   - AND `focus_time_ms` is absent or == 0
   → inject `notification_c2: true`

Also update MITRE annotation: `notification_c2` → `T1092`.

Call in `build_timeline` after `apply_beaconing_signals`.

**Tests:**
```rust
#[test] fn notification_c2_flagged_when_high_notifications_and_background_cpu() {
    let mut values = vec![
        notif_record("2024-01-01T08:00:00Z", 42, 50),  // 50 notifications
        apps_record_with_bg("2024-01-01T08:00:00Z", 42, 5_000_000, 0),
    ];
    apply_notification_c2_signal(&mut values);
    let apps = values.iter().find(|v| v.get("table").and_then(|t| t.as_str()) == Some("apps")).unwrap();
    assert_eq!(apps.get("notification_c2"), Some(&Value::Bool(true)));
}
#[test] fn notification_c2_not_flagged_with_low_notification_count() { ... }
#[test] fn notification_c2_not_flagged_when_foreground_cpu_dominant() { ... }
```

RED commit: `test(sr-cli): RED — notification-as-C2 cross-table signal`
GREEN commit: `feat(sr-cli): GREEN — notification-as-C2 cross-table signal`

---

### Task 12: srum-parser — AutoIncId exposure and gap detection

**Files:**
- Modify: `crates/srum-core/src/app_usage.rs` (and other record files)
- Modify: `crates/srum-parser/src/app_usage.rs` (and other parsers)
- Modify: `crates/srum-core/src/lib.rs`
- Modify: `crates/sr-cli/src/main.rs` (wire into sr gaps)

This task exposes the ESE `AutoIncId` column from each table's records, then uses it in `sr gaps` to detect deleted records.

**Step 1:** Add `auto_inc_id: u32` field to `AppUsageRecord`, `NetworkUsageRecord`, and other records in srum-core. Annotate with `#[serde(skip)]` so it doesn't appear in JSON output by default.

**Step 2:** Parse the `AutoIncId` column (byte offset 0, u32 LE) in each srum-parser decoder.

**Step 3:** Add `detect_autoinc_gaps` function in sr-cli that groups records by table and finds AutoIncId discontinuities.

**Step 4:** Include AutoIncId gaps in `sr gaps` output as `{"type":"autoinc_gap","table":"apps","gap_start":1043,"gap_end":1054,"deleted_count":12}`.

Check byte layout by looking at existing parsers (they already parse bytes 0..4 for AutoIncId but may be skipping it).

RED commit: `test(srum-parser): RED — AutoIncId exposure and gap detection`
GREEN commit: `feat(srum-parser): GREEN — AutoIncId exposure and gap detection`

---

### Task 13: srum-parser — Energy Usage Long-Term table

**Files:**
- Create: `crates/srum-parser/src/energy_lt.rs`
- Modify: `crates/srum-parser/src/lib.rs`
- Create: `crates/srum-core/src/energy_lt.rs`  
- Modify: `crates/srum-core/src/lib.rs`
- Modify: `crates/sr-cli/src/main.rs` — add `sr energy-lt` subcommand
- Modify: `crates/sr-cli/tests/cli_tests.rs`

The Energy Usage Long-Term table GUID suffix is `LT` — the full table name in forensicnomicon is `TABLE_ENERGY_USAGE_LT`. Check `forensicnomicon::srum` for the constant.

If the LT constant doesn't exist in forensicnomicon, add it:
```rust
// In forensicnomicon or locally in srum-parser
pub const TABLE_ENERGY_USAGE_LT: &str = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT";
```

The LT table has the same column layout as the standard energy table. Use the same decoder with a different table name.

`EnergyLtRecord` can be a type alias for `EnergyUsageRecord` or a distinct struct.

Add `parse_energy_lt` function to srum-parser.

Add `sr energy-lt` subcommand to sr-cli (same as `sr energy` but using `parse_energy_lt`).

RED commit: `test(srum-parser): RED — Energy LT table parser and sr energy-lt subcommand`
GREEN commit: `feat(srum-parser): GREEN — Energy LT table parser and sr energy-lt subcommand`

---

## Running All Tests

After all tasks:
```bash
cd ~/src/forensicnomicon && cargo test
cd ~/src/srum-forensic && cargo test
cargo test -p sr-cli --test cli_tests
```
