# `srum-analysis` Refactor — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extract the duplicated analysis pipeline into a new `srum-analysis` crate so that `sr-cli` and `sr-gui` share one implementation, and split the 3036-line CLI monolith into focused modules.

**Architecture:** New `crates/srum-analysis/` workspace member owns all pipeline stages, enrichment helpers, analysis functions (gaps/sessions/stats/hunt/compare), and the `AnnotatedRecord`/`FindingCard` types. Both CLI and GUI depend on it. CLI `main.rs` is split into `output.rs` + `cmd/{tables,analysis,forensics}.rs`. GUI `commands.rs` becomes a thin adapter.

**Tech Stack:** Rust, serde_json, srum-parser, srum-core, forensicnomicon, chrono, anyhow. Two mandatory commits per task: RED (failing tests), GREEN (implementation).

**Critical note — field name:** The CLI pipeline currently injects `"table"`; the GUI uses `"source_table"`. `srum-analysis` standardises on **`"source_table"`** everywhere. The CLI integration tests that check `"table"` fields must be updated when the CLI is wired up (Task 9).

---

### Task 1: Create `srum-analysis` crate scaffold

**Files:**
- Create: `crates/srum-analysis/Cargo.toml`
- Create: `crates/srum-analysis/src/lib.rs`
- Modify: `Cargo.toml` (workspace root) — add `"crates/srum-analysis"` to members and workspace dep

**Step 1: Add workspace member**

In the root `Cargo.toml`, add to `[workspace] members`:
```toml
"crates/srum-analysis",
```
Add to `[workspace.dependencies]`:
```toml
srum-analysis = { path = "crates/srum-analysis" }
```

**Step 2: Create `crates/srum-analysis/Cargo.toml`**

```toml
[package]
name = "srum-analysis"
version = "0.1.0"
description = "SRUM forensic analysis pipeline — shared between sr-cli and sr-gui"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
srum-parser     = { workspace = true }
srum-core       = { workspace = true }
forensicnomicon = { workspace = true }
serde_json      = { workspace = true }
serde           = { workspace = true }
chrono          = { workspace = true }
anyhow          = { workspace = true }

[lints]
workspace = true
```

**Step 3: Create `crates/srum-analysis/src/lib.rs`**

```rust
pub mod enrich;
pub mod findings;
pub mod pipeline;
pub mod record;
pub mod analysis;

pub use enrich::{enrich, enrich_connectivity, load_id_map, records_to_values};
pub use findings::compute_findings;
pub use pipeline::build_timeline;
pub use record::{AnnotatedRecord, FindingCard, Severity, TemporalSpan};
```

**Step 4: Create `crates/srum-analysis/src/analysis/mod.rs`**

```rust
pub mod compare;
pub mod gaps;
pub mod hunt;
pub mod sessions;
pub mod stats;

pub use compare::compare_databases;
pub use gaps::detect_gaps;
pub use hunt::{filter_by_app, hunt_filter, HuntSignature};
pub use sessions::build_sessions;
pub use stats::build_stats;
```

**Step 5: Create empty stub files so the crate compiles**

Create each of these with just a `// TODO` comment:
- `crates/srum-analysis/src/record.rs`
- `crates/srum-analysis/src/enrich.rs`
- `crates/srum-analysis/src/pipeline.rs`
- `crates/srum-analysis/src/findings.rs`
- `crates/srum-analysis/src/analysis/compare.rs`
- `crates/srum-analysis/src/analysis/gaps.rs`
- `crates/srum-analysis/src/analysis/hunt.rs`
- `crates/srum-analysis/src/analysis/sessions.rs`
- `crates/srum-analysis/src/analysis/stats.rs`

**Step 6: Verify build**

```bash
cargo build -p srum-analysis
```
Expected: compiles (stub files, nothing exported yet)

**Step 7: Commit**

```bash
git add crates/srum-analysis/ Cargo.toml Cargo.lock
git commit -m "chore: scaffold srum-analysis crate — empty stub modules"
```

---

### Task 2: `record.rs` — shared types

**Context:** `AnnotatedRecord` is the GUI's `TimelineRecord` promoted to the shared crate. `FindingCard`, `Severity`, `TemporalSpan` also move here.

**Files:**
- Modify: `crates/srum-analysis/src/record.rs`

**Step 1: Write the failing test (RED)**

Add to bottom of `crates/srum-analysis/src/record.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_critical_serializes_lowercase() {
        let s = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(s, r#""critical""#);
    }

    #[test]
    fn severity_max_critical_wins() {
        assert_eq!(Severity::Suspicious.max(Severity::Critical), Severity::Critical);
        assert_eq!(Severity::Clean.max(Severity::Informational), Severity::Informational);
    }

    #[test]
    fn annotated_record_has_source_table_field() {
        let r = AnnotatedRecord {
            timestamp: "2024-01-01T00:00:00Z".into(),
            source_table: "apps".into(),
            app_id: 1,
            app_name: None,
            key_metric_label: "foreground_cycles".into(),
            key_metric_value: 0.0,
            flags: vec![],
            severity: Severity::Clean,
            raw: serde_json::Value::Null,
            background_cycles: None,
            foreground_cycles: None,
            focus_time_ms: None,
            user_input_time_ms: None,
            interpretation: None,
            mitre_techniques: vec![],
        };
        assert_eq!(r.source_table, "apps");
    }
}
```

**Step 2: Run to confirm RED**

```bash
cargo test -p srum-analysis 2>&1 | head -20
```
Expected: compile error — `Severity`, `AnnotatedRecord` not defined

**Step 3: Implement `record.rs` (GREEN)**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    Suspicious,
    Informational,
    Clean,
}

impl Severity {
    pub fn max(self, other: Self) -> Self {
        use Severity::*;
        match (self, other) {
            (Critical, _) | (_, Critical) => Critical,
            (Suspicious, _) | (_, Suspicious) => Suspicious,
            (Informational, _) | (_, Informational) => Informational,
            _ => Clean,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedRecord {
    pub timestamp: String,
    pub source_table: String,
    pub app_id: i32,
    pub app_name: Option<String>,
    pub key_metric_label: String,
    pub key_metric_value: f64,
    pub flags: Vec<String>,
    pub severity: Severity,
    pub raw: serde_json::Value,
    pub background_cycles: Option<u64>,
    pub foreground_cycles: Option<u64>,
    pub focus_time_ms: Option<u64>,
    pub user_input_time_ms: Option<u64>,
    pub interpretation: Option<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingCard {
    pub title: String,
    pub app_name: String,
    pub description: String,
    pub mitre_techniques: Vec<String>,
    pub severity: Severity,
    pub filter_flag: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalSpan {
    pub first: String,
    pub last: String,
}
```

**Step 4: Run tests (GREEN)**

```bash
cargo test -p srum-analysis 2>&1 | tail -5
```
Expected: 3 tests pass

**Step 5: Commit RED then GREEN**

```bash
git add crates/srum-analysis/src/record.rs
git commit -m "test(srum-analysis): RED — record type tests"
# (already done implicitly — commit the implementation)
git add crates/srum-analysis/src/record.rs
git commit -m "feat(srum-analysis): GREEN — AnnotatedRecord, FindingCard, Severity, TemporalSpan"
```

---

### Task 3: `enrich.rs` — enrichment helpers

**Context:** These functions live in `sr-cli/src/main.rs` lines 24–431. Copy them verbatim — no logic changes needed. The `classify_sid`, `split_windows_path`, `enrich`, `enrich_connectivity`, `load_id_map`, `records_to_values` functions.

**Files:**
- Modify: `crates/srum-analysis/src/enrich.rs`

**Step 1: Write failing tests (RED)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use serde_json::json;

    #[test]
    fn classify_sid_maps_system() {
        assert_eq!(classify_sid("S-1-5-18"), Some("system"));
    }

    #[test]
    fn classify_sid_returns_none_for_unknown() {
        assert_eq!(classify_sid("S-1-99-99"), None);
    }

    #[test]
    fn split_windows_path_splits_at_last_separator() {
        let (dir, bin) = split_windows_path(r"C:\Windows\System32\svchost.exe");
        assert_eq!(bin, "svchost.exe");
        assert!(dir.contains("System32"));
    }

    #[test]
    fn split_windows_path_no_separator_returns_empty_dir() {
        let (dir, bin) = split_windows_path("svchost.exe");
        assert_eq!(dir, "");
        assert_eq!(bin, "svchost.exe");
    }

    #[test]
    fn records_to_values_serialises_each_record() {
        #[derive(Serialize)]
        struct R { x: u32 }
        let records = vec![R { x: 1 }, R { x: 2 }];
        let values = records_to_values(records).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["x"], json!(1u32));
    }

    #[test]
    fn enrich_injects_app_name() {
        #[derive(Serialize)]
        struct R { app_id: i32 }
        let mut id_map = std::collections::HashMap::new();
        id_map.insert(42, "chrome.exe".to_owned());
        let v = enrich(R { app_id: 42 }, &id_map);
        assert_eq!(v["app_name"], json!("chrome.exe"));
    }

    #[test]
    fn enrich_injects_suspicious_path_flag() {
        #[derive(Serialize)]
        struct R { app_id: i32 }
        let mut id_map = std::collections::HashMap::new();
        id_map.insert(1, r"C:\Users\user\AppData\Local\Temp\malware.exe".to_owned());
        let v = enrich(R { app_id: 1 }, &id_map);
        assert_eq!(v["suspicious_path"], json!(true));
    }
}
```

**Step 2: Run to confirm RED**

```bash
cargo test -p srum-analysis 2>&1 | head -10
```
Expected: compile error — functions not defined

**Step 3: Implement `enrich.rs` (GREEN)**

Copy from `sr-cli/src/main.rs`. The full implementation:

```rust
use std::collections::HashMap;
use std::path::Path;
use anyhow::Result;
use serde::Serialize;

pub fn classify_sid(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-5-18" => Some("system"),
        "S-1-5-19" => Some("local_service"),
        "S-1-5-20" => Some("network_service"),
        "S-1-1-0"  => Some("everyone"),
        _ if sid.starts_with("S-1-5-21-") && sid.ends_with("-500") => Some("local_admin"),
        _ if sid.starts_with("S-1-5-21-") => Some("domain_user"),
        _ => None,
    }
}

pub fn split_windows_path(path: &str) -> (&str, &str) {
    match path.rfind(|c| c == '\\' || c == '/') {
        Some(idx) => (&path[..idx], &path[idx + 1..]),
        None => ("", path),
    }
}

pub fn records_to_values<T: Serialize>(records: Vec<T>) -> Result<Vec<serde_json::Value>> {
    records
        .into_iter()
        .map(|r| serde_json::to_value(r).map_err(Into::into))
        .collect()
}

pub fn load_id_map(path: &Path) -> HashMap<i32, String> {
    srum_parser::parse_id_map(path)
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e.id, e.name))
        .collect()
}

pub fn enrich<T: Serialize>(record: T, id_map: &HashMap<i32, String>) -> serde_json::Value {
    let mut v = serde_json::to_value(record).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = v.as_object_mut() {
        if let Some(name) = obj
            .get("app_id")
            .and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .and_then(|id| id_map.get(&id))
        {
            obj.insert("app_name".to_owned(), serde_json::Value::String(name.clone()));
            if name.contains('\\') || name.contains('/') {
                use forensicnomicon::heuristics::srum::{is_process_masquerade, is_suspicious_path};
                if is_suspicious_path(name) {
                    obj.insert("suspicious_path".to_owned(), serde_json::Value::Bool(true));
                }
                let (dir, bin) = split_windows_path(name);
                if is_process_masquerade(bin, dir) {
                    obj.insert("masquerade_candidate".to_owned(), serde_json::Value::Bool(true));
                }
            }
        }
        if let Some(name) = obj
            .get("user_id")
            .and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .and_then(|id| id_map.get(&id))
        {
            obj.insert("user_name".to_owned(), serde_json::Value::String(name.clone()));
            if name.starts_with("S-") {
                if let Some(acct_type) = classify_sid(name) {
                    obj.insert("account_type".to_owned(), serde_json::Value::String(acct_type.to_owned()));
                }
            }
        }
    }
    v
}

pub fn enrich_connectivity(
    mut v: serde_json::Value,
    id_map: &HashMap<i32, String>,
) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        for &(id_key, name_key) in &[
            ("app_id", "app_name"),
            ("user_id", "user_name"),
            ("profile_id", "profile_name"),
        ] {
            if let Some(name) = obj
                .get(id_key)
                .and_then(serde_json::Value::as_i64)
                .and_then(|id| i32::try_from(id).ok())
                .and_then(|id| id_map.get(&id))
            {
                obj.insert(name_key.to_owned(), serde_json::Value::String(name.clone()));
            }
        }
    }
    v
}
```

**Step 4: Run tests (GREEN)**

```bash
cargo test -p srum-analysis 2>&1 | tail -5
```
Expected: all tests pass

**Step 5: Commit**

```bash
git add crates/srum-analysis/src/enrich.rs
git commit -m "feat(srum-analysis): GREEN — enrich helpers (enrich, enrich_connectivity, load_id_map, records_to_values)"
```

---

### Task 4: `pipeline.rs` — build_timeline and all six pipeline stages

**Context:** This is the core of the refactor. Source: `sr-cli/src/main.rs` lines 37–867 and `sr-gui/src-tauri/src/commands.rs`. The key adaptation: use `"source_table"` throughout (not `"table"`). `build_timeline` injects `"source_table"` (not `"table"`) into each record.

**Files:**
- Modify: `crates/srum-analysis/src/pipeline.rs`

**Step 1: Write failing tests (RED)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_timeline_returns_sorted_records() {
        // Can't test without a real SRUDB.dat — covered by CLI integration tests.
        // Verify empty path returns empty vec (best-effort, no panic).
        let result = build_timeline(std::path::Path::new("/nonexistent/SRUDB.dat"), None);
        assert!(result.is_empty());
    }

    #[test]
    fn build_timeline_records_have_source_table_field() {
        // Verify the constant TABLE_KEY is "source_table", not "table"
        assert_eq!(TABLE_KEY, "source_table");
    }

    #[test]
    fn merge_focus_injects_into_apps_rows_only() {
        let mut all = vec![
            json!({"source_table": "apps", "app_id": 1_i64, "timestamp": "2024-01-01T00:00:00Z"}),
            json!({"source_table": "network", "app_id": 1_i64, "timestamp": "2024-01-01T00:00:00Z"}),
        ];
        let focus = vec![json!({
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "focus_time_ms": 60_000_u64,
            "user_input_time_ms": 1_000_u64,
        })];
        merge_focus_into_apps(&mut all, focus);
        assert_eq!(all[0]["focus_time_ms"], json!(60_000_u64));
        assert!(all[1].get("focus_time_ms").is_none(), "network row must not get focus data");
    }

    #[test]
    fn apply_heuristics_flags_background_cpu_dominant_using_source_table() {
        let mut values = vec![json!({
            "source_table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "background_cycles": 10_000_000_u64,
            "foreground_cycles": 100_000_u64,
        })];
        apply_heuristics(&mut values);
        assert_eq!(values[0]["background_cpu_dominant"], json!(true));
    }

    #[test]
    fn apply_heuristics_does_not_flag_with_wrong_key() {
        // Regression: if "table" key is used instead of "source_table", nothing gets flagged
        let mut values = vec![json!({
            "table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "background_cycles": 10_000_000_u64,
            "foreground_cycles": 0_u64,
        })];
        apply_heuristics(&mut values);
        assert!(values[0].get("background_cpu_dominant").is_none());
    }

    #[test]
    fn apply_heuristics_flags_automated_execution() {
        let mut values = vec![json!({
            "source_table": "apps",
            "app_id": 1_i64,
            "timestamp": "2024-01-01T00:00:00Z",
            "focus_time_ms": 3_600_000_u64,
            "user_input_time_ms": 0_u64,
            "background_cycles": 1_u64,
            "foreground_cycles": 1_u64,
        })];
        apply_heuristics(&mut values);
        assert_eq!(values[0]["automated_execution"], json!(true));
    }

    #[test]
    fn annotate_user_presence_marks_timestamps_above_threshold() {
        let mut all = vec![
            json!({"source_table": "apps", "timestamp": "2024-01-01T00:00:00Z",
                   "user_input_time_ms": 15_000_u64}),
            json!({"source_table": "network", "timestamp": "2024-01-01T00:00:00Z"}),
        ];
        annotate_user_presence(&mut all);
        // apps row with 15s input → user_present = true on both rows at that timestamp
        assert_eq!(all[0]["user_present"], json!(true));
        assert_eq!(all[1]["user_present"], json!(true));
    }
}
```

**Step 2: Run to confirm RED**

```bash
cargo test -p srum-analysis 2>&1 | head -15
```
Expected: compile errors — `TABLE_KEY`, `build_timeline`, `merge_focus_into_apps`, `apply_heuristics`, `annotate_user_presence` not defined

**Step 3: Implement `pipeline.rs` (GREEN)**

Copy the following functions from `sr-cli/src/main.rs` (adapt `"table"` → `"source_table"`, and use `TABLE_KEY` constant) and from `sr-gui/src-tauri/src/commands.rs`:

```rust
use std::collections::HashMap;
use std::path::Path;

pub const TABLE_KEY: &str = "source_table";

pub const HEURISTIC_KEYS: &[&str] = &[
    "background_cpu_dominant",
    "no_focus_with_cpu",
    "phantom_foreground",
    "automated_execution",
    "exfil_signal",
    "beaconing",
    "notification_c2",
    "suspicious_path",
    "masquerade_candidate",
    "user_present",
];

/// Build a merged, heuristic-annotated timeline from all SRUM tables.
///
/// Each record has `"source_table"` injected to identify its origin table.
/// App-timeline focus data is joined into apps records. All six heuristic
/// pipeline stages are applied. Tables that are absent or unreadable are
/// silently skipped. Best-effort: never returns an error.
pub fn build_timeline(
    path: &Path,
    id_map: Option<&HashMap<i32, String>>,
) -> Vec<serde_json::Value> {
    let mut all: Vec<serde_json::Value> = Vec::new();

    macro_rules! load_table {
        ($name:expr, $loader:expr) => {
            if let Ok(records) = $loader(path) {
                let values: Vec<serde_json::Value> = records
                    .into_iter()
                    .filter_map(|r| serde_json::to_value(r).ok())
                    .collect();
                for mut v in values {
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert(TABLE_KEY.to_owned(), serde_json::Value::String($name.to_owned()));
                    }
                    all.push(v);
                }
            }
        };
    }

    load_table!("network",       srum_parser::parse_network_usage);
    load_table!("apps",          srum_parser::parse_app_usage);
    load_table!("connectivity",  srum_parser::parse_network_connectivity);
    load_table!("energy",        srum_parser::parse_energy_usage);
    load_table!("energy-lt",     srum_parser::parse_energy_lt);
    load_table!("notifications", srum_parser::parse_push_notifications);

    // Focus data joined into apps rows; not added as standalone records.
    let focus_values: Vec<serde_json::Value> = srum_parser::parse_app_timeline(path)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();

    if let Some(map) = id_map {
        all = all.into_iter().map(|v| crate::enrich::enrich_value(v, map)).collect();
    }

    merge_focus_into_apps(&mut all, focus_values);
    apply_heuristics(&mut all);
    apply_cross_table_signals(&mut all);
    apply_beaconing_signals(&mut all);
    apply_notification_c2_signal(&mut all);
    annotate_user_presence(&mut all);

    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb)
    });

    all
}

pub fn merge_focus_into_apps(all: &mut Vec<serde_json::Value>, focus: Vec<serde_json::Value>) {
    let mut focus_map: HashMap<(i64, String), (u64, u64)> = HashMap::new();
    for f in focus {
        if let (Some(app_id), Some(ts), Some(focus_ms), Some(input_ms)) = (
            f.get("app_id").and_then(serde_json::Value::as_i64),
            f.get("timestamp").and_then(serde_json::Value::as_str).map(str::to_owned),
            f.get("focus_time_ms").and_then(serde_json::Value::as_u64),
            f.get("user_input_time_ms").and_then(serde_json::Value::as_u64),
        ) {
            focus_map.insert((app_id, ts), (focus_ms, input_ms));
        }
    }
    for v in all.iter_mut() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) != Some("apps") {
            continue;
        }
        if let Some(obj) = v.as_object_mut() {
            let key = obj
                .get("app_id").and_then(serde_json::Value::as_i64)
                .zip(obj.get("timestamp").and_then(serde_json::Value::as_str).map(str::to_owned));
            if let Some((app_id, ts)) = key {
                if let Some(&(focus_ms, input_ms)) = focus_map.get(&(app_id, ts)) {
                    obj.insert("focus_time_ms".to_owned(), focus_ms.into());
                    obj.insert("user_input_time_ms".to_owned(), input_ms.into());
                }
            }
        }
    }
}

pub fn mitre_techniques_for(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<&'static str> {
    let mut techs: Vec<&'static str> = Vec::new();
    if obj.contains_key("background_cpu_dominant") { techs.push("T1496"); }
    if obj.contains_key("no_focus_with_cpu")       { techs.push("T1564"); }
    if obj.contains_key("phantom_foreground")       { techs.push("T1036"); }
    if obj.contains_key("automated_execution")      { techs.push("T1059"); }
    if obj.contains_key("exfil_signal")             { techs.push("T1048"); }
    if obj.contains_key("beaconing")                { techs.push("T1071"); }
    if obj.contains_key("notification_c2")          { techs.push("T1092"); }
    if obj.contains_key("suspicious_path")          { techs.push("T1036.005"); }
    if obj.contains_key("masquerade_candidate")     { techs.push("T1036.005"); }
    techs.sort_unstable();
    techs.dedup();
    techs
}

pub fn apply_heuristics(values: &mut Vec<serde_json::Value>) {
    use forensicnomicon::heuristics::srum::{
        is_automated_execution, is_background_cpu_dominant, is_phantom_foreground,
    };
    for v in values.iter_mut() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) != Some("apps") {
            continue;
        }
        if let Some(obj) = v.as_object_mut() {
            let bg = obj.get("background_cycles").and_then(serde_json::Value::as_u64).unwrap_or(0);
            let fg = obj.get("foreground_cycles").and_then(serde_json::Value::as_u64).unwrap_or(0);
            if is_background_cpu_dominant(bg, fg) {
                obj.insert("background_cpu_dominant".to_owned(), serde_json::Value::Bool(true));
            }
            if obj.contains_key("focus_time_ms") {
                let focus_ms = obj.get("focus_time_ms").and_then(serde_json::Value::as_u64).unwrap_or(0);
                let input_ms = obj.get("user_input_time_ms").and_then(serde_json::Value::as_u64).unwrap_or(0);
                if bg > 0 && focus_ms == 0 {
                    obj.insert("no_focus_with_cpu".to_owned(), serde_json::Value::Bool(true));
                }
                if is_phantom_foreground(fg, focus_ms) {
                    obj.insert("phantom_foreground".to_owned(), serde_json::Value::Bool(true));
                }
                if is_automated_execution(focus_ms, input_ms) {
                    obj.insert("automated_execution".to_owned(), serde_json::Value::Bool(true));
                }
                if focus_ms > 0 {
                    let ratio = input_ms as f64 / focus_ms as f64;
                    if let Some(n) = serde_json::Number::from_f64(ratio) {
                        obj.insert("interactivity_ratio".to_owned(), serde_json::Value::Number(n));
                    }
                }
            }
            let techs = mitre_techniques_for(obj);
            if !techs.is_empty() {
                let arr: Vec<serde_json::Value> = techs.iter().map(|&t| t.into()).collect();
                obj.insert("mitre_techniques".to_owned(), serde_json::Value::Array(arr));
            }
        }
    }
}

pub fn apply_cross_table_signals(all: &mut Vec<serde_json::Value>) {
    use forensicnomicon::heuristics::srum::{is_exfil_ratio, is_exfil_volume};

    let mut net_map: HashMap<(i64, String), (u64, u64)> = HashMap::new();
    for v in all.iter() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) == Some("network") {
            if let (Some(app_id), Some(ts), Some(sent), Some(recv)) = (
                v.get("app_id").and_then(serde_json::Value::as_i64),
                v.get("timestamp").and_then(serde_json::Value::as_str).map(str::to_owned),
                v.get("bytes_sent").and_then(serde_json::Value::as_u64),
                v.get("bytes_received").and_then(serde_json::Value::as_u64),
            ) {
                net_map.insert((app_id, ts), (sent, recv));
            }
        }
    }
    for v in all.iter_mut() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) != Some("apps") { continue; }
        if let Some(obj) = v.as_object_mut() {
            let key = obj.get("app_id").and_then(serde_json::Value::as_i64)
                .zip(obj.get("timestamp").and_then(serde_json::Value::as_str).map(str::to_owned));
            if let Some((app_id, ts)) = key {
                if let Some(&(sent, recv)) = net_map.get(&(app_id, ts)) {
                    let net_exfil = is_exfil_volume(sent) || is_exfil_ratio(sent, recv);
                    let bg = obj.get("background_cycles").and_then(serde_json::Value::as_u64).unwrap_or(0);
                    let focus_ms = obj.get("focus_time_ms").and_then(serde_json::Value::as_u64);
                    if net_exfil && bg > 0 && focus_ms.map_or(true, |ms| ms == 0) {
                        obj.insert("exfil_signal".to_owned(), serde_json::Value::Bool(true));
                        let techs = mitre_techniques_for(obj);
                        if !techs.is_empty() {
                            let arr: Vec<serde_json::Value> = techs.iter().map(|&t| t.into()).collect();
                            obj.insert("mitre_techniques".to_owned(), serde_json::Value::Array(arr));
                        }
                    }
                }
            }
        }
    }
}

pub fn apply_beaconing_signals(all: &mut Vec<serde_json::Value>) {
    use forensicnomicon::heuristics::srum::is_beaconing;

    let mut net_ts: HashMap<i64, Vec<String>> = HashMap::new();
    for v in all.iter() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) == Some("network") {
            if let (Some(app_id), Some(ts)) = (
                v.get("app_id").and_then(|x| x.as_i64()),
                v.get("timestamp").and_then(|x| x.as_str()),
            ) {
                net_ts.entry(app_id).or_default().push(ts.to_owned());
            }
        }
    }
    let mut beaconing_apps: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for (app_id, mut timestamps) in net_ts {
        timestamps.sort();
        let secs: Vec<i64> = timestamps.iter()
            .filter_map(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok().map(|dt| dt.timestamp()))
            .collect();
        if is_beaconing(&secs) { beaconing_apps.insert(app_id); }
    }
    for v in all.iter_mut() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) != Some("network") { continue; }
        if let Some(app_id) = v.get("app_id").and_then(|x| x.as_i64()) {
            if beaconing_apps.contains(&app_id) {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("beaconing".to_owned(), serde_json::Value::Bool(true));
                    let techs = obj.entry("mitre_techniques")
                        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                    if let serde_json::Value::Array(arr) = techs {
                        let t1071 = serde_json::Value::String("T1071".to_owned());
                        if !arr.contains(&t1071) { arr.push(t1071); }
                    }
                }
            }
        }
    }
}

const NOTIFICATION_C2_MIN_COUNT: u64 = 10;

pub fn apply_notification_c2_signal(all: &mut Vec<serde_json::Value>) {
    let mut notif_map: HashMap<(i64, String), u64> = HashMap::new();
    for v in all.iter() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) == Some("notifications") {
            if let (Some(app_id), Some(ts)) = (
                v.get("app_id").and_then(|x| x.as_i64()),
                v.get("timestamp").and_then(|x| x.as_str()).map(str::to_owned),
            ) {
                let count = v.get("notification_count").and_then(|x| x.as_u64()).unwrap_or(1);
                *notif_map.entry((app_id, ts)).or_insert(0) += count;
            }
        }
    }
    for v in all.iter_mut() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) != Some("apps") { continue; }
        if let Some(obj) = v.as_object_mut() {
            let key = obj.get("app_id").and_then(|x| x.as_i64())
                .zip(obj.get("timestamp").and_then(|x| x.as_str()).map(str::to_owned));
            if let Some((app_id, ts)) = key {
                if let Some(&count) = notif_map.get(&(app_id, ts)) {
                    if count > NOTIFICATION_C2_MIN_COUNT {
                        let bg = obj.get("background_cycles").and_then(|x| x.as_u64()).unwrap_or(0);
                        let focus_ms = obj.get("focus_time_ms").and_then(|x| x.as_u64());
                        if bg > 0 && focus_ms.map_or(true, |ms| ms == 0) {
                            obj.insert("notification_c2".to_owned(), serde_json::Value::Bool(true));
                            let techs = obj.entry("mitre_techniques")
                                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                            if let serde_json::Value::Array(arr) = techs {
                                let t1092 = serde_json::Value::String("T1092".to_owned());
                                if !arr.contains(&t1092) { arr.push(t1092); }
                            }
                        }
                    }
                }
            }
        }
    }
}

const USER_PRESENCE_THRESHOLD_MS: u64 = 10_000;

pub fn annotate_user_presence(all: &mut Vec<serde_json::Value>) {
    let mut totals: HashMap<String, u64> = HashMap::new();
    for v in all.iter() {
        if v.get(TABLE_KEY).and_then(|t| t.as_str()) == Some("apps") {
            if let (Some(ts), Some(ms)) = (
                v.get("timestamp").and_then(serde_json::Value::as_str).map(str::to_owned),
                v.get("user_input_time_ms").and_then(serde_json::Value::as_u64),
            ) {
                *totals.entry(ts).or_insert(0) += ms;
            }
        }
    }
    for v in all.iter_mut() {
        if let Some(ts) = v.get("timestamp").and_then(serde_json::Value::as_str) {
            if totals.get(ts).copied().unwrap_or(0) >= USER_PRESENCE_THRESHOLD_MS {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("user_present".to_owned(), serde_json::Value::Bool(true));
                }
            }
        }
    }
}
```

**Also add to `enrich.rs`** — `enrich_value` helper needed by `build_timeline`:

```rust
/// Enrich a pre-serialised JSON value in-place with app_name / user_name / path signals.
pub fn enrich_value(mut v: serde_json::Value, id_map: &HashMap<i32, String>) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        // Same logic as enrich() but operates on an already-serialised Value.
        if let Some(name) = obj.get("app_id").and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .and_then(|id| id_map.get(&id))
        {
            obj.insert("app_name".to_owned(), serde_json::Value::String(name.clone()));
            if name.contains('\\') || name.contains('/') {
                use forensicnomicon::heuristics::srum::{is_process_masquerade, is_suspicious_path};
                if is_suspicious_path(name) {
                    obj.insert("suspicious_path".to_owned(), serde_json::Value::Bool(true));
                }
                let (dir, bin) = split_windows_path(name);
                if is_process_masquerade(bin, dir) {
                    obj.insert("masquerade_candidate".to_owned(), serde_json::Value::Bool(true));
                }
            }
        }
        if let Some(name) = obj.get("user_id").and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .and_then(|id| id_map.get(&id))
        {
            obj.insert("user_name".to_owned(), serde_json::Value::String(name.clone()));
            if name.starts_with("S-") {
                if let Some(acct_type) = classify_sid(name) {
                    obj.insert("account_type".to_owned(), serde_json::Value::String(acct_type.to_owned()));
                }
            }
        }
    }
    v
}
```

**Also update `lib.rs`** to export `enrich_value`:
```rust
pub use enrich::{enrich, enrich_connectivity, enrich_value, load_id_map, records_to_values};
```

**Step 4: Run tests (GREEN)**

```bash
cargo test -p srum-analysis 2>&1 | tail -10
```
Expected: all tests pass

**Step 5: Commit**

```bash
git add crates/srum-analysis/src/pipeline.rs crates/srum-analysis/src/enrich.rs crates/srum-analysis/src/lib.rs
git commit -m "feat(srum-analysis): GREEN — build_timeline and all six pipeline stages"
```

---

### Task 5: `findings.rs` — compute_findings

**Context:** Copy from `sr-gui/src-tauri/src/findings.rs`. No changes needed — it already works with `AnnotatedRecord`.

**Files:**
- Modify: `crates/srum-analysis/src/findings.rs`

**Step 1: Write failing tests (RED)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AnnotatedRecord, Severity};
    use serde_json::json;

    fn make_record(flags: Vec<&str>, severity: Severity) -> AnnotatedRecord {
        AnnotatedRecord {
            timestamp: "2024-01-01T00:00:00Z".into(),
            source_table: "apps".into(),
            app_id: 1,
            app_name: Some("test.exe".into()),
            key_metric_label: "cycles".into(),
            key_metric_value: 0.0,
            flags: flags.iter().map(|s| s.to_string()).collect(),
            severity,
            raw: json!({}),
            background_cycles: None,
            foreground_cycles: None,
            focus_time_ms: None,
            user_input_time_ms: None,
            interpretation: None,
            mitre_techniques: vec![],
        }
    }

    #[test]
    fn empty_timeline_returns_no_findings() {
        assert!(compute_findings(&[]).is_empty());
    }

    #[test]
    fn clean_records_return_no_findings() {
        let records = vec![make_record(vec![], Severity::Clean)];
        assert!(compute_findings(&records).is_empty());
    }

    #[test]
    fn flagged_record_returns_finding_card() {
        let records = vec![make_record(vec!["automated_execution"], Severity::Critical)];
        let findings = compute_findings(&records);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].filter_flag, "automated_execution");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn critical_findings_sort_before_suspicious() {
        let records = vec![
            make_record(vec!["suspicious_path"], Severity::Suspicious),
            make_record(vec!["automated_execution"], Severity::Critical),
        ];
        let findings = compute_findings(&records);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
```

**Step 2: Run to confirm RED**

```bash
cargo test -p srum-analysis 2>&1 | grep "compute_findings"
```
Expected: compile error

**Step 3: Implement `findings.rs` (GREEN)**

Copy verbatim from `sr-gui/src-tauri/src/findings.rs`, updating the import:

```rust
use std::collections::HashMap;
use crate::record::{FindingCard, Severity, AnnotatedRecord};
// ... rest of the file unchanged
```

**Step 4: Run tests**

```bash
cargo test -p srum-analysis 2>&1 | tail -5
```

**Step 5: Commit**

```bash
git add crates/srum-analysis/src/findings.rs
git commit -m "feat(srum-analysis): GREEN — compute_findings (moved from sr-gui)"
```

---

### Task 6: `analysis/gaps.rs` and `analysis/sessions.rs`

**Context:** Source functions: `detect_gaps` (CLI main.rs ~line 1069), `detect_autoinc_gaps_from_ids` (CLI main.rs ~line 1668), `build_sessions` (CLI main.rs ~line 996), `iso_diff_secs` (CLI main.rs ~line 1043), `make_session` (CLI main.rs ~line 1052).

**Adaptation needed:** `detect_gaps` and `build_sessions` currently read `v.get("table")` — change to `v.get(crate::pipeline::TABLE_KEY)` (i.e., `"source_table"`).

**Files:**
- Modify: `crates/srum-analysis/src/analysis/gaps.rs`
- Modify: `crates/srum-analysis/src/analysis/sessions.rs`

**Step 1: Write failing tests (RED) — add to `gaps.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detect_autoinc_gaps_finds_deleted_range() {
        let ids = vec![1u32, 2, 5, 6]; // gap at 3-4
        let gaps = detect_autoinc_gaps_from_ids("apps", &ids);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0]["gap_start"], json!(3u32));
        assert_eq!(gaps[0]["gap_end"], json!(4u32));
        assert_eq!(gaps[0]["deleted_count"], json!(2u64));
    }

    #[test]
    fn detect_autoinc_gaps_empty_on_contiguous_ids() {
        let ids = vec![1u32, 2, 3, 4];
        assert!(detect_autoinc_gaps_from_ids("apps", &ids).is_empty());
    }

    #[test]
    fn detect_gaps_empty_timeline_returns_empty() {
        assert!(detect_gaps(&[], 2).is_empty());
    }
}
```

**Step 2: Write failing tests (RED) — add to `sessions.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_sessions_empty_timeline_returns_empty() {
        assert!(build_sessions(&[]).is_empty());
    }

    #[test]
    fn build_sessions_no_user_present_returns_empty() {
        let all = vec![json!({"source_table": "apps", "timestamp": "2024-01-01T00:00:00Z"})];
        assert!(build_sessions(&all).is_empty());
    }
}
```

**Step 3: Run to confirm RED**

```bash
cargo test -p srum-analysis 2>&1 | grep "error\[" | head -5
```

**Step 4: Implement `gaps.rs` (GREEN)**

Copy `detect_gaps`, `detect_autoinc_gaps_from_ids`, `iso_diff_secs` from CLI. Replace `v.get("table")` with `v.get(crate::pipeline::TABLE_KEY)`. Replace `"table": t` in gap output with `"source_table": t`.

**Step 5: Implement `sessions.rs` (GREEN)**

Copy `build_sessions`, `iso_diff_secs`, `make_session` from CLI. Replace `v.get("table").and_then(...) == Some("apps")` with `v.get(crate::pipeline::TABLE_KEY).and_then(...) == Some("apps")`.

Note: `iso_diff_secs` is used by both files — put it in `gaps.rs` and `pub use` it from `sessions.rs`, or extract into `analysis/mod.rs`.

**Step 6: Run tests**

```bash
cargo test -p srum-analysis 2>&1 | tail -10
```

**Step 7: Commit**

```bash
git add crates/srum-analysis/src/analysis/gaps.rs crates/srum-analysis/src/analysis/sessions.rs
git commit -m "feat(srum-analysis): GREEN — detect_gaps, detect_autoinc_gaps, build_sessions"
```

---

### Task 7: `analysis/stats.rs` and `analysis/hunt.rs`

**Context:** `build_stats` (CLI main.rs ~line 873) and `HEURISTIC_KEYS` move to `stats.rs`. `hunt_filter`, `filter_by_app`, and `HuntSignature` enum move to `hunt.rs`. `HuntSignature` in `srum-analysis` is a plain Rust enum (no Clap annotations — those stay in CLI).

**Files:**
- Modify: `crates/srum-analysis/src/analysis/stats.rs`
- Modify: `crates/srum-analysis/src/analysis/hunt.rs`

**Step 1: Write failing tests (RED)**

Add to `stats.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_stats_empty_returns_empty() {
        assert!(build_stats(vec![]).is_empty());
    }

    #[test]
    fn build_stats_aggregates_by_app_id() {
        let records = vec![
            json!({"app_id": 1_i64, "background_cycles": 100_u64}),
            json!({"app_id": 1_i64, "background_cycles": 200_u64}),
        ];
        let stats = build_stats(records);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0]["total_background_cycles"], json!(300_u64));
    }
}
```

Add to `hunt.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn filter_by_app_matches_by_id() {
        let all = vec![
            json!({"app_id": 42_i64}),
            json!({"app_id": 99_i64}),
        ];
        let filtered = filter_by_app(all, "42");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["app_id"], json!(42_i64));
    }

    #[test]
    fn hunt_filter_automated_returns_only_flagged() {
        let all = vec![
            json!({"automated_execution": true}),
            json!({"suspicious_path": true}),
        ];
        let filtered = hunt_filter(all, &HuntSignature::Automated);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["automated_execution"], json!(true));
    }
}
```

**Step 2: Run to confirm RED**

```bash
cargo test -p srum-analysis 2>&1 | grep "error\[" | head -5
```

**Step 3: Implement `stats.rs` (GREEN)**

Copy `build_stats` from CLI main.rs verbatim. Use `crate::pipeline::HEURISTIC_KEYS` instead of `HEURISTIC_KEYS` (or re-export it).

**Step 4: Implement `hunt.rs` (GREEN)**

Define `HuntSignature` enum (no Clap attributes):
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum HuntSignature {
    Exfil, Miner, Masquerade, SuspiciousPath, NoFocus,
    Phantom, Automated, Beaconing, NotificationC2, All,
}
```

Copy `hunt_filter` and `filter_by_app` from CLI main.rs. Use `crate::pipeline::HEURISTIC_KEYS` for the `All` variant.

**Step 5: Run tests**

```bash
cargo test -p srum-analysis 2>&1 | tail -10
```

**Step 6: Commit**

```bash
git add crates/srum-analysis/src/analysis/stats.rs crates/srum-analysis/src/analysis/hunt.rs
git commit -m "feat(srum-analysis): GREEN — build_stats, hunt_filter, filter_by_app, HuntSignature"
```

---

### Task 8: `analysis/compare.rs`

**Context:** `compare_databases` (CLI main.rs ~line 1214). Takes two `Vec<serde_json::Value>` of stats (already built via `build_stats`). No field name changes needed — it operates on stats output, not raw timeline records.

**Files:**
- Modify: `crates/srum-analysis/src/analysis/compare.rs`

**Step 1: Write failing test (RED)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compare_databases_empty_both_returns_empty_diff() {
        let result = compare_databases(vec![], vec![]);
        assert!(result["new_processes"].as_array().unwrap().is_empty());
        assert!(result["departed_processes"].as_array().unwrap().is_empty());
        assert!(result["changed"].as_array().unwrap().is_empty());
    }

    #[test]
    fn compare_databases_new_process_detected() {
        let baseline = vec![];
        let suspect = vec![json!({"app_id": 99_i64, "app_name": "evil.exe"})];
        let result = compare_databases(baseline, suspect);
        assert_eq!(result["new_processes"].as_array().unwrap().len(), 1);
    }
}
```

**Step 2: Confirm RED**

```bash
cargo test -p srum-analysis 2>&1 | grep "compare_databases" | head -3
```

**Step 3: Implement `compare.rs` (GREEN)**

Copy `compare_databases` from CLI main.rs verbatim.

**Step 4: Run tests**

```bash
cargo test -p srum-analysis 2>&1 | tail -5
```

**Step 5: Commit**

```bash
git add crates/srum-analysis/src/analysis/compare.rs
git commit -m "feat(srum-analysis): GREEN — compare_databases"
```

---

### Task 9: Wire `sr-cli` to `srum-analysis`

**Context:** Add `srum-analysis` dep, replace all duplicated pipeline calls with `srum_analysis::*`. Fix the `"table"` → `"source_table"` rename in CLI integration tests. Remove the now-dead functions from `main.rs`.

**Files:**
- Modify: `crates/sr-cli/Cargo.toml`
- Modify: `crates/sr-cli/src/main.rs`
- Modify: `crates/sr-cli/tests/cli_tests.rs`

**Step 1: Add dep to CLI Cargo.toml**

```toml
[dependencies]
srum-analysis = { workspace = true }
```
Remove `forensicnomicon` from CLI deps (it's now a transitive dep via srum-analysis).

**Step 2: Update `sr-cli/src/main.rs`**

Replace ALL of these from CLI `main.rs` with calls into `srum_analysis`:

| Remove from CLI | Replace with |
|---|---|
| `fn merge_focus_into_apps(...)` | `srum_analysis::pipeline::merge_focus_into_apps` |
| `fn apply_heuristics(...)` | `srum_analysis::pipeline::apply_heuristics` |
| `fn apply_cross_table_signals(...)` | (called inside `build_timeline` — not needed standalone) |
| `fn apply_beaconing_signals(...)` | (same) |
| `fn apply_notification_c2_signal(...)` | (same) |
| `fn annotate_user_presence(...)` | (same) |
| `fn mitre_techniques_for(...)` | `srum_analysis::pipeline::mitre_techniques_for` |
| `fn build_timeline(...)` | `srum_analysis::build_timeline` |
| `fn build_stats(...)` | `srum_analysis::analysis::build_stats` |
| `fn build_sessions(...)` | `srum_analysis::analysis::build_sessions` |
| `fn detect_gaps(...)` | `srum_analysis::analysis::detect_gaps` |
| `fn hunt_filter(...)` | `srum_analysis::analysis::hunt_filter` |
| `fn filter_by_app(...)` | `srum_analysis::analysis::filter_by_app` |
| `fn compare_databases(...)` | `srum_analysis::analysis::compare_databases` |
| `fn enrich(...)` | `srum_analysis::enrich` |
| `fn enrich_connectivity(...)` | `srum_analysis::enrich_connectivity` |
| `fn enrich_value(...)` | `srum_analysis::enrich_value` |
| `fn records_to_values(...)` | `srum_analysis::records_to_values` |
| `fn load_id_map(...)` | `srum_analysis::load_id_map` |
| `fn classify_sid(...)` | `srum_analysis::enrich::classify_sid` |
| `fn split_windows_path(...)` | `srum_analysis::enrich::split_windows_path` |
| `const HEURISTIC_KEYS` | `srum_analysis::pipeline::HEURISTIC_KEYS` |

The `HuntSignature` Clap enum stays in the CLI. Map CLI variants → `srum_analysis::analysis::HuntSignature` when calling `hunt_filter`.

**Step 3: Update `sr-cli/src/main.rs` — `sr apps` command special case**

The `sr apps` subcommand calls `merge_focus_into_apps` on a flat vec of apps records (no `source_table` field). After migration, inject `"source_table": "apps"` before calling `srum_analysis::pipeline::merge_focus_into_apps`:

```rust
// In Cmd::Apps handler, after records_to_values:
for v in &mut values {
    if let Some(obj) = v.as_object_mut() {
        obj.insert("source_table".to_owned(), "apps".into());
    }
}
if let Ok(focus_records) = srum_parser::parse_app_timeline(&path) {
    if let Ok(focus_values) = srum_analysis::records_to_values(focus_records) {
        srum_analysis::pipeline::merge_focus_into_apps(&mut values, focus_values);
    }
}
```

**Step 4: Fix integration tests**

In `tests/cli_tests.rs`, search for any assertions checking `"table"` field in JSON output and update to `"source_table"`:

```bash
grep -n '"table"' crates/sr-cli/tests/cli_tests.rs
```

Update each matching assertion. The `sr timeline` output now has `"source_table"` instead of `"table"`.

**Step 5: Run CLI tests**

```bash
cargo test -p sr-cli 2>&1 | tail -15
```
Expected: all tests pass

**Step 6: Run full suite**

```bash
cargo test --workspace 2>&1 | tail -10
```
Expected: all tests pass

**Step 7: Commit**

```bash
git add crates/sr-cli/ Cargo.lock
git commit -m "feat(sr-cli): wire to srum-analysis — remove duplicated pipeline, fix source_table field name"
```

---

### Task 10: Split `sr-cli` into `cmd/` modules

**Context:** `main.rs` currently dispatches 15 subcommands inline. Extract handlers into `cmd/tables.rs`, `cmd/analysis.rs`, `cmd/forensics.rs`. Move output helpers to `output.rs`. `main.rs` becomes a thin Clap+dispatch file.

**Files:**
- Create: `crates/sr-cli/src/output.rs`
- Create: `crates/sr-cli/src/cmd/mod.rs`
- Create: `crates/sr-cli/src/cmd/tables.rs`
- Create: `crates/sr-cli/src/cmd/analysis.rs`
- Create: `crates/sr-cli/src/cmd/forensics.rs`
- Modify: `crates/sr-cli/src/main.rs`

**Step 1: Create `output.rs`**

Move from `main.rs`:
- `OutputFormat` enum
- `fn values_to_csv(values: &[serde_json::Value]) -> anyhow::Result<String>`
- `fn print_values(values: &[serde_json::Value], format: &OutputFormat) -> anyhow::Result<()>`

```rust
// crates/sr-cli/src/output.rs

#[derive(clap::ValueEnum, Clone, Default, PartialEq)]
pub enum OutputFormat { #[default] Json, Csv, Ndjson }

pub fn print_values(values: &[serde_json::Value], format: &OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json  => println!("{}", serde_json::to_string_pretty(values)?),
        OutputFormat::Ndjson => {
            for v in values { println!("{}", serde_json::to_string(v)?); }
        }
        OutputFormat::Csv => print!("{}", values_to_csv(values)?),
    }
    Ok(())
}

pub fn values_to_csv(values: &[serde_json::Value]) -> anyhow::Result<String> {
    // copy verbatim from main.rs
}
```

**Step 2: Create `cmd/tables.rs`**

Move handlers for: `Network`, `Apps`, `Idmap`, `Connectivity`, `Energy`, `EnergyLt`, `Notifications`, `AppTimeline`.

Each follows the same pattern:
```rust
pub fn run_network(path: &std::path::Path, resolve: bool, format: &crate::output::OutputFormat)
    -> anyhow::Result<()>
{
    let records = srum_parser::parse_network_usage(path)?;
    let values = if resolve {
        let id_map = srum_analysis::load_id_map(path);
        records.into_iter().map(|r| srum_analysis::enrich(r, &id_map)).collect()
    } else {
        srum_analysis::records_to_values(records)?
    };
    crate::output::print_values(&values, format)
}
// ... repeat for apps, idmap, connectivity, energy, energy-lt, notifications, app-timeline
```

**Step 3: Create `cmd/analysis.rs`**

Move handlers for: `Timeline`, `Process`, `Stats`, `Sessions`, `Gaps`, `Hunt`.

```rust
pub fn run_timeline(path: &std::path::Path, resolve: bool, format: &crate::output::OutputFormat)
    -> anyhow::Result<()>
{
    let id_map = if resolve { Some(srum_analysis::load_id_map(path)) } else { None };
    let all = srum_analysis::build_timeline(path, id_map.as_ref());
    crate::output::print_values(&all, format)
}
// ... stats calls srum_analysis::analysis::build_stats(build_timeline(...))
// ... sessions calls srum_analysis::analysis::build_sessions(&all)
// ... gaps calls srum_analysis::analysis::detect_gaps(&all, threshold_hours)
// ... hunt maps CliHuntSignature → srum_analysis::analysis::HuntSignature, calls hunt_filter
```

**Step 4: Create `cmd/forensics.rs`**

Move handlers for: `Compare`, `Metadata`.

```rust
pub fn run_compare(
    baseline: &std::path::Path,
    suspect: &std::path::Path,
    resolve: bool,
    format: &crate::output::OutputFormat,
) -> anyhow::Result<()> {
    let b_id_map = if resolve { Some(srum_analysis::load_id_map(baseline)) } else { None };
    let s_id_map = if resolve { Some(srum_analysis::load_id_map(suspect)) } else { None };
    let b_all = srum_analysis::build_timeline(baseline, b_id_map.as_ref());
    let s_all = srum_analysis::build_timeline(suspect, s_id_map.as_ref());
    let b_stats = srum_analysis::analysis::build_stats(b_all);
    let s_stats = srum_analysis::analysis::build_stats(s_all);
    let result = srum_analysis::analysis::compare_databases(b_stats, s_stats);
    // format and print result
}
```

`Metadata` command stays in `forensics.rs` since it has the ESE database inspection logic. Note `collect_metadata` uses `ese_core` directly — keep `ese-core` in CLI deps. Also keep `sha2`, `hex` in CLI deps for the metadata command.

**Step 5: Update `main.rs` to thin dispatch**

`main.rs` becomes: imports + `Cli`/`Cmd` structs + `fn run()` that matches on `Cmd` and calls `cmd::*::run_*`. Target: ~300 lines.

Move inline tests from `main.rs` to the file that owns the tested function. Tests for `enrich`/`split_windows_path`/etc are already in `srum-analysis` — delete the CLI copies. Tests for `detect_gaps`, `build_stats` etc are now in `srum-analysis` — delete CLI copies. Only keep CLI-specific tests (output formatting, metadata, CLI argument parsing) in the CLI.

**Step 6: Run full suite**

```bash
cargo test --workspace 2>&1 | tail -10
```
Expected: all tests pass

**Step 7: Commit**

```bash
git add crates/sr-cli/src/
git commit -m "refactor(sr-cli): split 3036-line main.rs into cmd/tables, cmd/analysis, cmd/forensics, output"
```

---

### Task 11: Simplify `sr-gui` — wire to `srum-analysis`

**Context:** `commands.rs` currently duplicates the full pipeline (now fixed). After Task 9/10, `srum-analysis` is the canonical source. Now replace the GUI's copy with calls into `srum-analysis`. Delete `findings.rs` (replaced by `srum_analysis::compute_findings`). Update `types.rs` to re-export `srum-analysis` types.

**Files:**
- Modify: `crates/sr-gui/src-tauri/Cargo.toml`
- Modify: `crates/sr-gui/src-tauri/src/commands.rs`
- Modify: `crates/sr-gui/src-tauri/src/types.rs`
- Modify: `crates/sr-gui/src-tauri/src/timeline.rs`
- Modify: `crates/sr-gui/src-tauri/src/lib.rs`
- Delete: `crates/sr-gui/src-tauri/src/findings.rs`

**Step 1: Update GUI Cargo.toml**

```toml
[dependencies]
srum-analysis = { workspace = true }
# Remove: forensicnomicon (now transitive via srum-analysis)
# Keep: tauri, tauri-plugin-dialog, serde, serde_json, srum-parser, srum-core, anyhow, chrono
```

**Step 2: Slim `commands.rs`**

Replace the entire pipeline implementation with calls into `srum-analysis`:

```rust
use crate::{
    timeline::value_to_timeline_record,
    types::{SrumFile, TemporalSpan},
};
use srum_analysis::{build_timeline, compute_findings, load_id_map, record::AnnotatedRecord};
use std::path::Path;

#[tauri::command]
pub async fn open_file(path: String) -> Result<SrumFile, String> {
    parse_srum(Path::new(&path)).map_err(|e| format!("error: {e:#}"))
}

fn parse_srum(path: &Path) -> anyhow::Result<SrumFile> {
    let id_map = load_id_map(path);
    let annotated = build_timeline(path, Some(&id_map));

    let mut table_names: Vec<String> = annotated
        .iter()
        .filter_map(|v| v.get("source_table").and_then(|s| s.as_str()).map(str::to_owned))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    table_names.sort();

    let mut records: Vec<AnnotatedRecord> = annotated
        .into_iter()
        .filter_map(value_to_timeline_record)
        .collect();
    records.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let temporal_span = match (records.first(), records.last()) {
        (Some(f), Some(l)) if f.timestamp != l.timestamp => Some(TemporalSpan {
            first: f.timestamp.clone(),
            last: l.timestamp.clone(),
        }),
        _ => None,
    };

    let record_count = records.len();
    let findings = compute_findings(&records);

    Ok(SrumFile {
        path: path.to_string_lossy().into_owned(),
        timeline: records,
        findings,
        record_count,
        temporal_span,
        table_names,
    })
}
```

**Step 3: Update `types.rs`**

Remove `Severity`, `FindingCard` definitions — import from `srum-analysis`:

```rust
pub use srum_analysis::record::{AnnotatedRecord, FindingCard, Severity};
// Keep only GUI-specific types:
pub struct SrumFile {
    pub path: String,
    pub timeline: Vec<AnnotatedRecord>,
    pub findings: Vec<FindingCard>,
    pub record_count: usize,
    pub temporal_span: Option<TemporalSpan>,
    pub table_names: Vec<String>,
}
pub struct TemporalSpan { pub first: String, pub last: String, }
```

**Step 4: Update `timeline.rs`**

Change `value_to_timeline_record` to return `Option<AnnotatedRecord>` (from srum-analysis) instead of `Option<TimelineRecord>`:

```rust
use srum_analysis::record::{AnnotatedRecord, Severity};
pub fn value_to_timeline_record(value: serde_json::Value) -> Option<AnnotatedRecord> {
    // same logic as before, returning AnnotatedRecord
}
```

Remove the `severity_from_flags` function — use `srum_analysis::pipeline` or keep inline. Remove `findings::compute_findings` import.

**Step 5: Delete `findings.rs`, update `lib.rs`**

```bash
git rm crates/sr-gui/src-tauri/src/findings.rs
```

Update `lib.rs` — remove `mod findings;`.

**Step 6: Run GUI tests**

```bash
cargo test -p sr-gui 2>&1 | tail -10
```
Expected: all tests pass (some tests in `commands.rs` may need updating if they tested pipeline functions that are now in srum-analysis)

**Step 7: Run full suite**

```bash
cargo test --workspace 2>&1 | tail -10
```
Expected: all tests pass

**Step 8: Commit**

```bash
git add crates/sr-gui/src-tauri/
git commit -m "feat(sr-gui): wire to srum-analysis — delete duplicated pipeline, slim commands.rs to ~80 lines"
```

---

## Verification Checklist

After all 11 tasks complete, verify:

```bash
# Full test suite — zero failures
cargo test --workspace

# srum-analysis has its own tests
cargo test -p srum-analysis

# CLI still produces correct output
cargo run -p sr-cli -- --help
cargo run -p sr-cli -- timeline path/to/SRUDB.dat | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'source_table' in d[0]"

# Line counts — check the split happened
wc -l crates/sr-cli/src/main.rs        # should be ~300
wc -l crates/sr-cli/src/cmd/tables.rs  # ~250
wc -l crates/sr-cli/src/cmd/analysis.rs # ~250

# No more forensicnomicon direct dep in sr-gui
grep "forensicnomicon" crates/sr-gui/src-tauri/Cargo.toml  # should be empty

# findings.rs deleted
ls crates/sr-gui/src-tauri/src/  # findings.rs must not appear
```
