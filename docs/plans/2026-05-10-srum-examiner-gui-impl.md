# SRUM Examiner GUI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build SRUM Examiner — a Tauri 2.0 + React native GUI that parses SRUDB.dat, surfaces forensic conclusions as color-coded finding cards, and shows a unified investigation timeline with inline heuristic flags.

**Architecture:** Tauri 2.0 Rust backend embeds srum-parser directly (no subprocess). React/Vite frontend holds the full parsed dataset in memory and filters client-side. Two-layer layout: conclusion cards strip (~20% height) above a full-width investigation timeline (~80%).

**Tech Stack:** Rust + Tauri 2.0, React 18 + Vite + TypeScript, TanStack Table v8, Recharts, Tailwind CSS v3, tauri-plugin-dialog.

**Design reference:** `docs/plans/2026-05-10-srum-examiner-gui-design.md`

**TDD note:** Rust backend pure functions (timeline builder, finding card computation) follow strict RED → GREEN. Tauri command wrappers and React components are tested manually; E2E tests are out of scope for this plan.

**Two commits per Rust task:** RED commit (failing tests + stub) then GREEN commit (implementation that passes).

---

### Task 1: Add sr-gui workspace member and scaffold directory structure

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `crates/sr-gui/src-tauri/Cargo.toml`
- Create: `crates/sr-gui/src-tauri/build.rs`
- Create: `crates/sr-gui/src-tauri/src/main.rs`
- Create: `crates/sr-gui/src-tauri/src/lib.rs`
- Create: `crates/sr-gui/src-tauri/tauri.conf.json`
- Create: `crates/sr-gui/package.json`
- Create: `crates/sr-gui/index.html`
- Create: `crates/sr-gui/vite.config.ts`
- Create: `crates/sr-gui/tsconfig.json`
- Create: `crates/sr-gui/tailwind.config.js`
- Create: `crates/sr-gui/postcss.config.js`

**Step 1: Add workspace member**

In `Cargo.toml` root, add to `members`:
```toml
members = [
    "crates/ese-core",
    "crates/ese-integrity",
    "crates/ese-carver",
    "crates/ese-test-fixtures",
    "crates/srum-core",
    "crates/srum-parser",
    "crates/sr-cli",
    "crates/sr-gui/src-tauri",   # ← add this
]
```

Also add to `[workspace.dependencies]`:
```toml
tauri             = { version = "2", features = ["dialog"] }
tauri-build       = { version = "2" }
tauri-plugin-dialog = "2"
```

**Step 2: Create `crates/sr-gui/src-tauri/Cargo.toml`**

```toml
[package]
name = "sr-gui"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "SRUM Examiner — graphical SRUM forensic investigation tool"

[lib]
crate-type = ["lib", "cdylib", "staticlib"]

[dependencies]
tauri              = { workspace = true }
tauri-plugin-dialog = { workspace = true }
serde              = { workspace = true }
serde_json         = { workspace = true }
srum-parser        = { workspace = true }
srum-core          = { workspace = true }
forensicnomicon    = { workspace = true }
anyhow             = { workspace = true }
chrono             = { workspace = true }

[build-dependencies]
tauri-build = { workspace = true }

[lints]
workspace = true
```

**Step 3: Create `crates/sr-gui/src-tauri/build.rs`**

```rust
fn main() {
    tauri_build::build()
}
```

**Step 4: Create `crates/sr-gui/src-tauri/src/main.rs`**

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    sr_gui_lib::run()
}
```

**Step 5: Create `crates/sr-gui/src-tauri/src/lib.rs`**

```rust
mod commands;
mod findings;
mod timeline;

pub use commands::*;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![commands::open_file])
        .run(tauri::generate_context!())
        .expect("error running SRUM Examiner");
}
```

**Step 6: Create `crates/sr-gui/src-tauri/tauri.conf.json`**

```json
{
  "productName": "SRUM Examiner",
  "version": "0.1.0",
  "identifier": "com.securityronin.srum-examiner",
  "build": {
    "frontendDist": "../dist",
    "devUrl": "http://localhost:1420",
    "beforeDevCommand": "npm run dev",
    "beforeBuildCommand": "npm run build"
  },
  "app": {
    "windows": [
      {
        "title": "SRUM Examiner",
        "width": 1400,
        "height": 900,
        "minWidth": 1024,
        "minHeight": 600,
        "resizable": true
      }
    ],
    "security": {
      "csp": null
    }
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": [
      "icons/32x32.png",
      "icons/128x128.png",
      "icons/128x128@2x.png",
      "icons/icon.icns",
      "icons/icon.ico"
    ],
    "windows": {
      "wix": {}
    }
  }
}
```

**Step 7: Create `crates/sr-gui/package.json`**

```json
{
  "name": "srum-examiner",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "tauri": "tauri"
  },
  "dependencies": {
    "@tauri-apps/api": "^2",
    "@tauri-apps/plugin-dialog": "^2",
    "@tanstack/react-table": "^8",
    "react": "^18",
    "react-dom": "^18",
    "recharts": "^2"
  },
  "devDependencies": {
    "@tauri-apps/cli": "^2",
    "@types/react": "^18",
    "@types/react-dom": "^18",
    "@vitejs/plugin-react": "^4",
    "autoprefixer": "^10",
    "postcss": "^8",
    "tailwindcss": "^3",
    "typescript": "^5",
    "vite": "^5"
  }
}
```

**Step 8: Create `crates/sr-gui/vite.config.ts`**

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(async () => ({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ['**/src-tauri/**'],
    },
  },
}));
```

**Step 9: Create `crates/sr-gui/index.html`**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SRUM Examiner</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

**Step 10: Create `crates/sr-gui/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"]
}
```

**Step 11: Create `crates/sr-gui/tailwind.config.js`**

```js
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {},
  },
  plugins: [],
};
```

**Step 12: Create `crates/sr-gui/postcss.config.js`**

```js
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
```

**Step 13: Verify workspace builds**

```bash
cd crates/sr-gui && npm install
cargo check -p sr-gui
```

Expected: no errors (lib.rs and commands.rs don't exist yet — create empty stubs if needed).

**Step 14: Commit**

```bash
git add crates/sr-gui/ Cargo.toml Cargo.lock
git commit -m "chore: scaffold crates/sr-gui Tauri 2.0 workspace member"
```

---

### Task 2: Rust data types — TimelineRecord, FindingCard, SrumFile

**Files:**
- Create: `crates/sr-gui/src-tauri/src/types.rs`
- Modify: `crates/sr-gui/src-tauri/src/lib.rs`

These are the data types that flow from Rust → JSON → TypeScript. Getting them right now prevents rework later.

**Step 1: Create `crates/sr-gui/src-tauri/src/types.rs`**

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
    /// Merge two severities — higher wins.
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

/// One record in the unified investigation timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineRecord {
    pub timestamp: String,
    pub source_table: String,
    pub app_id: i32,
    pub app_name: Option<String>,
    pub key_metric_label: String,
    pub key_metric_value: f64,
    pub flags: Vec<String>,
    pub severity: Severity,
    /// Full raw record for the detail panel.
    pub raw: serde_json::Value,
    // 4-way signal — present only when both App Resource Usage and App Timeline data exist.
    pub background_cycles: Option<u64>,
    pub foreground_cycles: Option<u64>,
    pub focus_time_ms: Option<u64>,
    pub user_input_time_ms: Option<u64>,
    /// Pre-computed plain-English interpretation for the detail panel.
    pub interpretation: Option<String>,
    pub mitre_techniques: Vec<String>,
}

/// One finding card shown in the dashboard strip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCard {
    pub title: String,
    pub app_name: String,
    pub description: String,
    pub mitre_techniques: Vec<String>,
    pub severity: Severity,
    /// The flag name used to filter the timeline when this card is clicked.
    pub filter_flag: String,
    /// Number of records matching this finding.
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalSpan {
    pub first: String,
    pub last: String,
}

/// The full parsed SRUM file — returned from the `open_file` Tauri command.
#[derive(Debug, Serialize, Deserialize)]
pub struct SrumFile {
    pub path: String,
    pub timeline: Vec<TimelineRecord>,
    pub findings: Vec<FindingCard>,
    pub record_count: usize,
    pub temporal_span: Option<TemporalSpan>,
    pub table_names: Vec<String>,
}
```

**Step 2: Add `mod types;` to `lib.rs`**

```rust
mod commands;
mod findings;
mod timeline;
pub mod types;
```

**Step 3: Write tests for `Severity::max`**

Add to `types.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_max_critical_wins() {
        assert_eq!(Severity::Critical.max(Severity::Clean), Severity::Critical);
        assert_eq!(Severity::Clean.max(Severity::Critical), Severity::Critical);
    }

    #[test]
    fn severity_max_suspicious_over_informational() {
        assert_eq!(
            Severity::Suspicious.max(Severity::Informational),
            Severity::Suspicious
        );
    }

    #[test]
    fn severity_max_clean_clean() {
        assert_eq!(Severity::Clean.max(Severity::Clean), Severity::Clean);
    }
}
```

**Step 4: Run tests**

```bash
cargo test -p sr-gui
```

Expected: 3 passed.

**Step 5: Commit**

```bash
git add crates/sr-gui/src-tauri/src/types.rs crates/sr-gui/src-tauri/src/lib.rs
git commit -m "feat(sr-gui): data types — TimelineRecord, FindingCard, SrumFile"
```

---

### Task 3: Rust — timeline builder (RED)

**Files:**
- Create: `crates/sr-gui/src-tauri/src/timeline.rs`

The timeline builder takes parsed SRUM records (all tables), merges them into a unified chronological list, applies heuristics, and returns `Vec<TimelineRecord>`. This is the core data transformation.

**Step 1: Write failing tests first**

Create `crates/sr-gui/src-tauri/src/timeline.rs` with stub + tests:

```rust
use crate::types::{Severity, TimelineRecord};

/// Severity from a set of flag names.
pub fn severity_from_flags(flags: &[String]) -> Severity {
    todo!()
}

/// Plain-English interpretation for a timeline record.
pub fn interpret(record: &TimelineRecord) -> Option<String> {
    todo!()
}

/// Convert raw serde_json::Value (from srum-parser JSON output) into a TimelineRecord.
/// Returns None if the record has no timestamp field.
pub fn value_to_timeline_record(
    value: serde_json::Value,
    source_table: &str,
) -> Option<TimelineRecord> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn severity_from_no_flags_is_clean() {
        assert_eq!(severity_from_flags(&[]), Severity::Clean);
    }

    #[test]
    fn severity_from_automated_execution_is_critical() {
        let flags = vec!["automated_execution".to_string()];
        assert_eq!(severity_from_flags(&flags), Severity::Critical);
    }

    #[test]
    fn severity_from_suspicious_path_is_suspicious() {
        let flags = vec!["suspicious_path".to_string()];
        assert_eq!(severity_from_flags(&flags), Severity::Suspicious);
    }

    #[test]
    fn severity_from_beaconing_is_critical() {
        let flags = vec!["beaconing".to_string()];
        assert_eq!(severity_from_flags(&flags), Severity::Critical);
    }

    #[test]
    fn severity_from_mixed_flags_takes_highest() {
        let flags = vec![
            "suspicious_path".to_string(),
            "automated_execution".to_string(),
        ];
        assert_eq!(severity_from_flags(&flags), Severity::Critical);
    }

    #[test]
    fn value_to_timeline_record_network_record() {
        let val = json!({
            "timestamp": "2024-06-15T08:00:00Z",
            "app_id": 42,
            "app_name": "chrome.exe",
            "bytes_sent": 1_000_000,
            "bytes_recv": 500_000,
        });
        let rec = value_to_timeline_record(val, "network").unwrap();
        assert_eq!(rec.source_table, "network");
        assert_eq!(rec.app_id, 42);
        assert_eq!(rec.key_metric_label, "bytes_sent");
        assert_eq!(rec.key_metric_value, 1_000_000.0);
    }

    #[test]
    fn value_to_timeline_record_missing_timestamp_returns_none() {
        let val = json!({ "app_id": 1 });
        assert!(value_to_timeline_record(val, "network").is_none());
    }

    #[test]
    fn interpret_automated_execution() {
        let rec = TimelineRecord {
            timestamp: "2024-01-01T00:00:00Z".into(),
            source_table: "apps".into(),
            app_id: 1,
            app_name: Some("powershell.exe".into()),
            key_metric_label: "foreground_cycles".into(),
            key_metric_value: 0.0,
            flags: vec!["automated_execution".into()],
            severity: Severity::Critical,
            raw: serde_json::Value::Null,
            background_cycles: Some(5_000_000),
            foreground_cycles: Some(0),
            focus_time_ms: Some(3_600_000),
            user_input_time_ms: Some(0),
            interpretation: None,
            mitre_techniques: vec![],
        };
        let text = interpret(&rec).unwrap();
        assert!(
            text.contains("focus") || text.contains("input"),
            "interpretation must mention focus or input: {text}"
        );
    }
}
```

**Step 2: Run tests to verify RED**

```bash
cargo test -p sr-gui timeline
```

Expected: FAIL — `todo!()` panics in all tests.

**Step 3: Commit RED**

```bash
git add crates/sr-gui/src-tauri/src/timeline.rs crates/sr-gui/src-tauri/src/lib.rs
git commit -m "test(sr-gui): RED — timeline builder"
```

---

### Task 4: Rust — timeline builder (GREEN)

**Files:**
- Modify: `crates/sr-gui/src-tauri/src/timeline.rs`

**Step 1: Implement `severity_from_flags`**

```rust
pub fn severity_from_flags(flags: &[String]) -> Severity {
    const CRITICAL: &[&str] = &[
        "automated_execution",
        "beaconing",
        "masquerade_candidate",
        "selective_gap",
        "notification_c2",
    ];
    const SUSPICIOUS: &[&str] = &[
        "background_cpu_dominant",
        "exfil_signal",
        "exfil_ratio",
        "no_focus_with_cpu",
        "phantom_foreground",
        "suspicious_path",
    ];
    const INFORMATIONAL: &[&str] = &["autoinc_gap"];

    let mut severity = Severity::Clean;
    for flag in flags {
        let s = if CRITICAL.contains(&flag.as_str()) {
            Severity::Critical
        } else if SUSPICIOUS.contains(&flag.as_str()) {
            Severity::Suspicious
        } else if INFORMATIONAL.contains(&flag.as_str()) {
            Severity::Informational
        } else {
            Severity::Clean
        };
        severity = severity.max(s);
    }
    severity
}
```

**Step 2: Implement `value_to_timeline_record`**

```rust
pub fn value_to_timeline_record(
    value: serde_json::Value,
    source_table: &str,
) -> Option<TimelineRecord> {
    let obj = value.as_object()?;
    let timestamp = obj.get("timestamp")?.as_str()?.to_string();

    let app_id = obj.get("app_id").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let app_name = obj.get("app_name").and_then(|v| v.as_str()).map(str::to_string);

    // Key metric: pick the most relevant numeric field per table.
    let (key_metric_label, key_metric_value) = key_metric(obj, source_table);

    // Collect heuristic flags: any boolean field with value true.
    let flags: Vec<String> = obj
        .iter()
        .filter_map(|(k, v)| {
            if v.as_bool() == Some(true) {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();

    let severity = severity_from_flags(&flags);

    // 4-way signal.
    let background_cycles = obj.get("background_cycles").and_then(|v| v.as_u64());
    let foreground_cycles = obj.get("foreground_cycles").and_then(|v| v.as_u64());
    let focus_time_ms = obj.get("focus_time_ms").and_then(|v| v.as_u64());
    let user_input_time_ms = obj.get("user_input_time_ms").and_then(|v| v.as_u64());

    // MITRE techniques: array field.
    let mitre_techniques: Vec<String> = obj
        .get("mitre_techniques")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let mut rec = TimelineRecord {
        timestamp,
        source_table: source_table.to_string(),
        app_id,
        app_name,
        key_metric_label,
        key_metric_value,
        flags,
        severity,
        raw: value,
        background_cycles,
        foreground_cycles,
        focus_time_ms,
        user_input_time_ms,
        interpretation: None,
        mitre_techniques,
    };
    rec.interpretation = interpret(&rec);
    Some(rec)
}

fn key_metric(obj: &serde_json::Map<String, serde_json::Value>, table: &str) -> (String, f64) {
    let candidates: &[&str] = match table {
        "network" => &["bytes_sent", "bytes_recv"],
        "apps" => &["background_cycles", "foreground_cycles"],
        "energy" | "energy-lt" => &["energy_consumed", "charge_level"],
        "notifications" => &["notification_count"],
        "connectivity" => &["connected_time_ms"],
        "app-timeline" => &["focus_time_ms", "user_input_time_ms"],
        _ => &[],
    };
    for &label in candidates {
        if let Some(v) = obj.get(label).and_then(|v| v.as_f64()) {
            return (label.to_string(), v);
        }
    }
    ("value".to_string(), 0.0)
}
```

**Step 3: Implement `interpret`**

```rust
pub fn interpret(rec: &TimelineRecord) -> Option<String> {
    if rec.flags.is_empty() {
        return None;
    }

    let name = rec.app_name.as_deref().unwrap_or("this process");

    if rec.flags.contains(&"automated_execution".to_string()) {
        let focus_min = rec.focus_time_ms.unwrap_or(0) / 60_000;
        return Some(format!(
            "{name} held focus for {focus_min} minutes with zero keyboard or mouse input. \
             Consistent with scripted or automated execution — no human was present."
        ));
    }
    if rec.flags.contains(&"beaconing".to_string()) {
        return Some(format!(
            "{name} made network connections at regular intervals. \
             Regular timing is a hallmark of command-and-control beaconing."
        ));
    }
    if rec.flags.contains(&"background_cpu_dominant".to_string()) {
        return Some(format!(
            "{name} consumed significant CPU in the background with little or no foreground activity. \
             Possible mining, covert computation, or malware hiding behind a cover process."
        ));
    }
    if rec.flags.contains(&"phantom_foreground".to_string()) {
        return Some(format!(
            "{name} was billed foreground CPU cycles but the Application Timeline records no focus time. \
             Possible SetForegroundWindow abuse to appear interactive while running covertly."
        ));
    }
    if rec.flags.contains(&"exfil_signal".to_string()) {
        let sent_mb = rec
            .raw
            .get("bytes_sent")
            .and_then(|v| v.as_f64())
            .map(|b| b / 1_048_576.0)
            .unwrap_or(0.0);
        return Some(format!(
            "{name} sent {sent_mb:.1} MB with no corresponding foreground or focus activity. \
             Data transfer occurring while the user was not interacting — possible exfiltration."
        ));
    }
    if rec.flags.contains(&"suspicious_path".to_string()) {
        return Some(format!(
            "{name} ran from a suspicious location (temp directory, downloads, UNC path, \
             or root of a drive). Legitimate software rarely executes from these locations."
        ));
    }
    if rec.flags.contains(&"masquerade_candidate".to_string()) {
        return Some(format!(
            "The process name is very similar to a known Windows system binary but ran from \
             an unexpected directory. Possible process name masquerading."
        ));
    }
    if rec.flags.contains(&"notification_c2".to_string()) {
        return Some(format!(
            "{name} generated an unusually high number of push notifications with background CPU \
             and no user focus. Notifications may be used as a covert C2 channel."
        ));
    }

    Some(format!("Heuristic flags: {}.", rec.flags.join(", ")))
}
```

**Step 4: Run tests to verify GREEN**

```bash
cargo test -p sr-gui timeline
```

Expected: all tests pass.

**Step 5: Commit GREEN**

```bash
git add crates/sr-gui/src-tauri/src/timeline.rs
git commit -m "feat(sr-gui): GREEN — timeline builder (severity, interpret, value_to_timeline_record)"
```

---

### Task 5: Rust — finding cards computation (RED + GREEN)

**Files:**
- Create: `crates/sr-gui/src-tauri/src/findings.rs`

Finding cards are pre-computed conclusions shown in the dashboard strip. Each card represents the most significant occurrence of a heuristic flag across all timeline records, expressed in plain English.

**Step 1: Write tests**

Create `crates/sr-gui/src-tauri/src/findings.rs`:

```rust
use crate::types::{FindingCard, Severity, TimelineRecord};

/// Compute dashboard finding cards from the full timeline.
/// Cards are sorted: Critical first, then Suspicious, then Informational.
/// One card per unique flag type (aggregated across all apps).
pub fn compute_findings(timeline: &[TimelineRecord]) -> Vec<FindingCard> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;
    use serde_json::json;

    fn make_record(app_name: &str, flags: Vec<&str>, severity: Severity) -> TimelineRecord {
        TimelineRecord {
            timestamp: "2024-01-01T00:00:00Z".into(),
            source_table: "apps".into(),
            app_id: 1,
            app_name: Some(app_name.into()),
            key_metric_label: "foreground_cycles".into(),
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
    fn empty_timeline_produces_no_findings() {
        assert!(compute_findings(&[]).is_empty());
    }

    #[test]
    fn clean_records_produce_no_findings() {
        let timeline = vec![make_record("chrome.exe", vec![], Severity::Clean)];
        assert!(compute_findings(&timeline).is_empty());
    }

    #[test]
    fn automated_execution_flag_produces_card() {
        let timeline = vec![make_record(
            "powershell.exe",
            vec!["automated_execution"],
            Severity::Critical,
        )];
        let findings = compute_findings(&timeline);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].filter_flag, "automated_execution");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn critical_cards_come_before_suspicious() {
        let timeline = vec![
            make_record("chrome.exe", vec!["suspicious_path"], Severity::Suspicious),
            make_record("cmd.exe", vec!["automated_execution"], Severity::Critical),
        ];
        let findings = compute_findings(&timeline);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Suspicious);
    }

    #[test]
    fn count_aggregates_across_records() {
        let timeline = vec![
            make_record("powershell.exe", vec!["beaconing"], Severity::Critical),
            make_record("powershell.exe", vec!["beaconing"], Severity::Critical),
            make_record("powershell.exe", vec!["beaconing"], Severity::Critical),
        ];
        let findings = compute_findings(&timeline);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].count, 3);
    }
}
```

**Step 2: Run to verify RED**

```bash
cargo test -p sr-gui findings
```

Expected: FAIL — `todo!()` panics.

**Step 3: Commit RED**

```bash
git add crates/sr-gui/src-tauri/src/findings.rs
git commit -m "test(sr-gui): RED — finding cards computation"
```

**Step 4: Implement `compute_findings`**

```rust
use std::collections::HashMap;
use crate::types::{FindingCard, Severity, TimelineRecord};

pub fn compute_findings(timeline: &[TimelineRecord]) -> Vec<FindingCard> {
    // Group by flag. For each flag, track: count, best app name, severity, MITRE techniques.
    let mut by_flag: HashMap<String, FlagAgg> = HashMap::new();

    for rec in timeline {
        for flag in &rec.flags {
            let agg = by_flag.entry(flag.clone()).or_insert_with(|| FlagAgg {
                count: 0,
                app_name: rec.app_name.clone().unwrap_or_else(|| format!("ID {}", rec.app_id)),
                severity: rec.severity.clone(),
                mitre: rec.mitre_techniques.clone(),
            });
            agg.count += 1;
        }
    }

    let mut cards: Vec<FindingCard> = by_flag
        .into_iter()
        .filter_map(|(flag, agg)| {
            let (title, description) = card_text(&flag, &agg);
            Some(FindingCard {
                title,
                app_name: agg.app_name,
                description,
                mitre_techniques: agg.mitre,
                severity: agg.severity,
                filter_flag: flag,
                count: agg.count,
            })
        })
        .collect();

    // Sort: Critical → Suspicious → Informational → Clean, then by count desc.
    cards.sort_by(|a, b| {
        severity_order(&a.severity)
            .cmp(&severity_order(&b.severity))
            .then(b.count.cmp(&a.count))
    });
    cards
}

struct FlagAgg {
    count: usize,
    app_name: String,
    severity: Severity,
    mitre: Vec<String>,
}

fn severity_order(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::Suspicious => 1,
        Severity::Informational => 2,
        Severity::Clean => 3,
    }
}

fn card_text(flag: &str, agg: &FlagAgg) -> (String, String) {
    match flag {
        "automated_execution" => (
            "AUTOMATED EXECUTION".into(),
            format!("{} occurrence(s) — process held focus with zero user input", agg.count),
        ),
        "beaconing" => (
            "POSSIBLE BEACONING".into(),
            format!("{} occurrence(s) — regular network intervals detected", agg.count),
        ),
        "background_cpu_dominant" => (
            "BACKGROUND CPU DOMINANT".into(),
            format!("{} occurrence(s) — CPU in background exceeds foreground", agg.count),
        ),
        "exfil_signal" => (
            "EXFILTRATION SIGNAL".into(),
            format!("{} occurrence(s) — large outbound transfer, no user activity", agg.count),
        ),
        "suspicious_path" => (
            "SUSPICIOUS PROCESS PATH".into(),
            format!("{} occurrence(s) — executed from temp/downloads/UNC", agg.count),
        ),
        "masquerade_candidate" => (
            "PROCESS MASQUERADE".into(),
            format!("{} occurrence(s) — name similar to system binary, wrong directory", agg.count),
        ),
        "phantom_foreground" => (
            "PHANTOM FOREGROUND".into(),
            format!("{} occurrence(s) — foreground CPU with no focus time", agg.count),
        ),
        "notification_c2" => (
            "NOTIFICATION C2 CHANNEL".into(),
            format!("{} occurrence(s) — high notification volume, background CPU, no focus", agg.count),
        ),
        "selective_gap" => (
            "ANTI-FORENSICS INDICATOR".into(),
            format!("{} gap(s) — records deleted selectively, not system shutdown", agg.count),
        ),
        _ => (
            flag.to_uppercase().replace('_', " "),
            format!("{} occurrence(s)", agg.count),
        ),
    }
}
```

**Step 5: Run to verify GREEN**

```bash
cargo test -p sr-gui findings
```

Expected: all tests pass.

**Step 6: Commit GREEN**

```bash
git add crates/sr-gui/src-tauri/src/findings.rs
git commit -m "feat(sr-gui): GREEN — finding cards computation"
```

---

### Task 6: Rust — Tauri `open_file` command

**Files:**
- Create: `crates/sr-gui/src-tauri/src/commands.rs`

This is the bridge between the Rust data layer and the React frontend. It parses all SRUM tables, builds the timeline, computes findings, and returns a `SrumFile`.

**Step 1: Create `crates/sr-gui/src-tauri/src/commands.rs`**

```rust
use crate::{
    findings::compute_findings,
    timeline::value_to_timeline_record,
    types::{SrumFile, TemporalSpan, TimelineRecord},
};
use std::path::Path;

#[tauri::command]
pub async fn open_file(path: String) -> Result<SrumFile, String> {
    let p = Path::new(&path);
    parse_srum(p).map_err(|e| format!("error: {e:#}"))
}

fn parse_srum(path: &Path) -> anyhow::Result<SrumFile> {
    use forensicnomicon::srum::TABLE_ID_MAP;

    // Parse ID map for name resolution.
    let id_map = srum_parser::parse_id_map(path).unwrap_or_default();
    let name_for = |id: i32| -> Option<String> {
        id_map.iter().find(|e| e.id == id).map(|e| e.name.clone())
    };

    let mut all: Vec<serde_json::Value> = vec![];

    // Collect all tables — silently skip missing tables (not all SRUM DBs have all tables).
    let tables: &[(&str, Box<dyn Fn(&Path) -> anyhow::Result<Vec<serde_json::Value>>>)] = &[
        ("network",       Box::new(|p| records_to_values(srum_parser::parse_network_usage(p)?))),
        ("apps",          Box::new(|p| records_to_values(srum_parser::parse_app_usage(p)?))),
        ("energy",        Box::new(|p| records_to_values(srum_parser::parse_energy_usage(p)?))),
        ("energy-lt",     Box::new(|p| records_to_values(srum_parser::parse_energy_lt(p)?))),
        ("connectivity",  Box::new(|p| records_to_values(srum_parser::parse_network_connectivity(p)?))),
        ("notifications", Box::new(|p| records_to_values(srum_parser::parse_push_notifications(p)?))),
        ("app-timeline",  Box::new(|p| records_to_values(srum_parser::parse_app_timeline(p)?))),
    ];

    let mut table_names: Vec<String> = vec![];

    for (table_name, parser) in tables {
        match parser(path) {
            Ok(mut rows) => {
                if !rows.is_empty() {
                    table_names.push(table_name.to_string());
                    // Inject source_table and resolved app_name.
                    for row in &mut rows {
                        if let Some(obj) = row.as_object_mut() {
                            let app_id = obj.get("app_id").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                            if let Some(name) = name_for(app_id) {
                                obj.insert("app_name".to_string(), serde_json::Value::String(name));
                            }
                        }
                    }
                    all.extend(rows);
                }
            }
            Err(_) => {} // table absent or unreadable — skip
        }
    }

    // Convert to TimelineRecord.
    let mut timeline: Vec<TimelineRecord> = all
        .into_iter()
        .filter_map(|v| {
            let table = v
                .get("source_table")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            value_to_timeline_record(v, &table)
        })
        .collect();

    // Sort chronologically.
    timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Temporal span.
    let temporal_span = match (timeline.first(), timeline.last()) {
        (Some(first), Some(last)) => Some(TemporalSpan {
            first: first.timestamp.clone(),
            last: last.timestamp.clone(),
        }),
        _ => None,
    };

    let record_count = timeline.len();
    let findings = compute_findings(&timeline);

    Ok(SrumFile {
        path: path.to_string_lossy().into_owned(),
        timeline,
        findings,
        record_count,
        temporal_span,
        table_names,
    })
}

fn records_to_values<T: serde::Serialize>(records: Vec<T>) -> anyhow::Result<Vec<serde_json::Value>> {
    records
        .into_iter()
        .map(|r| serde_json::to_value(r).map_err(Into::into))
        .collect()
}
```

**NOTE:** The table injection for `source_table` happens before `value_to_timeline_record`. Add source_table to each row's JSON object before passing it:

In the loop above, after injecting `app_name`, also add:
```rust
obj.insert("source_table".to_string(), serde_json::Value::String(table_name.to_string()));
```

**Step 2: Build to verify no compile errors**

```bash
cargo build -p sr-gui
```

Expected: builds successfully (warnings OK).

**Step 3: Commit**

```bash
git add crates/sr-gui/src-tauri/src/commands.rs
git commit -m "feat(sr-gui): Tauri open_file command — parse all SRUM tables, build SrumFile"
```

---

### Task 7: React app shell — dark theme, color constants, skeleton layout

**Files:**
- Create: `crates/sr-gui/src/main.tsx`
- Create: `crates/sr-gui/src/App.tsx`
- Create: `crates/sr-gui/src/colors.ts`
- Create: `crates/sr-gui/src/types.ts`
- Create: `crates/sr-gui/src/index.css`

**Step 1: Create `src/colors.ts`**

The color system from the design doc — single source of truth.

```typescript
export const COLORS = {
  // Severity
  critical:      '#FF4757',
  suspicious:    '#FFA502',
  informational: '#1E90FF',
  clean:         '#2ED573',
  meta:          '#747D8C',

  // Backgrounds
  bg:            '#1A1B1E',
  bgCard:        '#25262B',
  bgHover:       '#2C2D32',
  border:        '#373A40',

  // Text
  textPrimary:   '#C1C2C5',
  textSecondary: '#909296',

  // Table source labels
  sources: {
    network:        '#5352ED',
    apps:           '#2ED573',
    energy:         '#FFA502',
    'energy-lt':    '#FFD43B',
    'app-timeline': '#FF6B81',
    notifications:  '#70A1FF',
    connectivity:   '#ECCC68',
    idmap:          '#747D8C',
  } as Record<string, string>,
} as const;

export type Severity = 'critical' | 'suspicious' | 'informational' | 'clean';

export function severityColor(s: string): string {
  switch (s) {
    case 'Critical':      return COLORS.critical;
    case 'Suspicious':    return COLORS.suspicious;
    case 'Informational': return COLORS.informational;
    default:              return COLORS.clean;
  }
}

export function sourceColor(table: string): string {
  return COLORS.sources[table] ?? COLORS.meta;
}
```

**Step 2: Create `src/types.ts`**

Mirror of the Rust types:

```typescript
export type Severity = 'Critical' | 'Suspicious' | 'Informational' | 'Clean';

export interface TimelineRecord {
  timestamp: string;
  source_table: string;
  app_id: number;
  app_name: string | null;
  key_metric_label: string;
  key_metric_value: number;
  flags: string[];
  severity: Severity;
  raw: Record<string, unknown>;
  background_cycles: number | null;
  foreground_cycles: number | null;
  focus_time_ms: number | null;
  user_input_time_ms: number | null;
  interpretation: string | null;
  mitre_techniques: string[];
}

export interface FindingCard {
  title: string;
  app_name: string;
  description: string;
  mitre_techniques: string[];
  severity: Severity;
  filter_flag: string;
  count: number;
}

export interface TemporalSpan {
  first: string;
  last: string;
}

export interface SrumFile {
  path: string;
  timeline: TimelineRecord[];
  findings: FindingCard[];
  record_count: number;
  temporal_span: TemporalSpan | null;
  table_names: string[];
}
```

**Step 3: Create `src/index.css`**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  --bg: #1A1B1E;
  --bg-card: #25262B;
  --text: #C1C2C5;
  --border: #373A40;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: 'JetBrains Mono', 'Fira Code', monospace, sans-serif;
  font-size: 13px;
  overflow: hidden;
}

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #373A40; border-radius: 3px; }
```

**Step 4: Create `src/main.tsx`**

```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
```

**Step 5: Create `src/App.tsx`** (skeleton — file open state only)

```tsx
import { useState } from 'react';
import { SrumFile } from './types';

export default function App() {
  const [srumFile, setSrumFile] = useState<SrumFile | null>(null);

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', background: '#1A1B1E' }}>
      {!srumFile ? (
        <DropZone onFile={setSrumFile} />
      ) : (
        <>
          <Dashboard findings={srumFile.findings} onFilterChange={() => {}} />
          <Timeline records={srumFile.timeline} />
        </>
      )}
    </div>
  );
}

// Placeholder components — implemented in later tasks.
function DropZone({ onFile }: { onFile: (f: SrumFile) => void }) {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <p style={{ color: '#747D8C' }}>SRUM Examiner — open a SRUDB.dat to begin</p>
    </div>
  );
}

function Dashboard({ findings, onFilterChange }: { findings: any[]; onFilterChange: (flag: string | null) => void }) {
  return <div style={{ height: '20%', borderBottom: '1px solid #373A40' }}>Dashboard</div>;
}

function Timeline({ records }: { records: any[] }) {
  return <div style={{ flex: 1 }}>Timeline ({records.length} records)</div>;
}
```

**Step 6: Install npm dependencies and verify dev server starts**

```bash
cd crates/sr-gui && npm install
npm run dev
```

Expected: Vite dev server starts on http://localhost:1420. Open in browser — sees the placeholder UI.

**Step 7: Commit**

```bash
git add crates/sr-gui/src/
git commit -m "feat(sr-gui): React app shell — dark theme, color constants, skeleton layout"
```

---

### Task 8: File open flow — drag-drop zone and Tauri dialog

**Files:**
- Create: `crates/sr-gui/src/components/DropZone.tsx`
- Modify: `crates/sr-gui/src/App.tsx`

**Step 1: Create `src/components/DropZone.tsx`**

```tsx
import { useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { invoke } from '@tauri-apps/api/core';
import { SrumFile } from '../types';
import { COLORS } from '../colors';

interface Props {
  onFile: (f: SrumFile) => void;
}

export function DropZone({ onFile }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function openFile() {
    const selected = await open({
      title: 'Open SRUDB.dat',
      filters: [{ name: 'SRUM Database', extensions: ['dat', 'DAT'] }],
      multiple: false,
    });
    if (!selected || typeof selected !== 'string') return;
    await parseFile(selected);
  }

  async function parseFile(path: string) {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<SrumFile>('open_file', { path });
      onFile(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 24,
      }}
    >
      <h1 style={{ color: COLORS.textPrimary, fontSize: 28, fontWeight: 700, margin: 0 }}>
        SRUM Examiner
      </h1>
      <p style={{ color: COLORS.textSecondary, margin: 0 }}>
        Forensic analysis of Windows SRUM activity databases
      </p>
      <button
        onClick={openFile}
        disabled={loading}
        style={{
          padding: '12px 32px',
          background: COLORS.informational,
          color: '#fff',
          border: 'none',
          borderRadius: 6,
          cursor: loading ? 'not-allowed' : 'pointer',
          fontSize: 14,
          fontWeight: 600,
        }}
      >
        {loading ? 'Parsing…' : 'Open SRUDB.dat'}
      </button>
      {error && (
        <p style={{ color: COLORS.critical, maxWidth: 480, textAlign: 'center' }}>{error}</p>
      )}
    </div>
  );
}
```

**Step 2: Update `App.tsx` to use the real DropZone**

```tsx
import { useState } from 'react';
import { SrumFile } from './types';
import { DropZone } from './components/DropZone';

export default function App() {
  const [srumFile, setSrumFile] = useState<SrumFile | null>(null);
  const [flagFilter, setFlagFilter] = useState<string | null>(null);

  const filtered = srumFile
    ? flagFilter
      ? srumFile.timeline.filter(r => r.flags.includes(flagFilter))
      : srumFile.timeline
    : [];

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', background: '#1A1B1E' }}>
      {!srumFile ? (
        <DropZone onFile={setSrumFile} />
      ) : (
        <>
          {/* Dashboard and Timeline added in Tasks 9–12 */}
          <div style={{ color: '#C1C2C5', padding: 16 }}>
            Loaded: {srumFile.path} — {srumFile.record_count} records
          </div>
        </>
      )}
    </div>
  );
}
```

**Step 3: Test manually**

```bash
cd crates/sr-gui && npm run tauri dev
```

Expected: app opens, click "Open SRUDB.dat", pick any file, see record count. If no SRUDB.dat is available, confirm the error message appears with the `error:` prefix styling.

**Step 4: Commit**

```bash
git add crates/sr-gui/src/components/DropZone.tsx crates/sr-gui/src/App.tsx
git commit -m "feat(sr-gui): file open flow — DropZone with Tauri dialog and open_file invoke"
```

---

### Task 9: Dashboard finding cards strip

**Files:**
- Create: `crates/sr-gui/src/components/Dashboard.tsx`
- Modify: `crates/sr-gui/src/App.tsx`

**Step 1: Create `src/components/Dashboard.tsx`**

```tsx
import { FindingCard } from '../types';
import { COLORS, severityColor } from '../colors';

interface Props {
  findings: FindingCard[];
  activeFlag: string | null;
  onFilter: (flag: string | null) => void;
}

export function Dashboard({ findings, activeFlag, onFilter }: Props) {
  if (findings.length === 0) {
    return (
      <div style={{
        height: 120,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        borderBottom: `1px solid ${COLORS.border}`,
        color: COLORS.clean,
        fontWeight: 600,
      }}>
        ✓ No suspicious activity detected
      </div>
    );
  }

  return (
    <div style={{
      height: 140,
      borderBottom: `1px solid ${COLORS.border}`,
      display: 'flex',
      alignItems: 'center',
      gap: 12,
      padding: '0 16px',
      overflowX: 'auto',
      flexShrink: 0,
    }}>
      {findings.map(card => (
        <FindingCardComponent
          key={card.filter_flag}
          card={card}
          active={activeFlag === card.filter_flag}
          onClick={() => onFilter(activeFlag === card.filter_flag ? null : card.filter_flag)}
        />
      ))}
    </div>
  );
}

function FindingCardComponent({
  card,
  active,
  onClick,
}: {
  card: FindingCard;
  active: boolean;
  onClick: () => void;
}) {
  const color = severityColor(card.severity);

  return (
    <button
      onClick={onClick}
      style={{
        minWidth: 220,
        maxWidth: 260,
        height: 108,
        background: active ? `${color}22` : COLORS.bgCard,
        border: `1px solid ${active ? color : COLORS.border}`,
        borderLeft: `4px solid ${color}`,
        borderRadius: 6,
        padding: '10px 14px',
        cursor: 'pointer',
        textAlign: 'left',
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
      }}
    >
      <div style={{ color, fontSize: 11, fontWeight: 700, letterSpacing: 1 }}>
        {card.title}
      </div>
      <div style={{ color: COLORS.textPrimary, fontSize: 13, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {card.app_name}
      </div>
      <div style={{ color: COLORS.textSecondary, fontSize: 11, flex: 1 }}>
        {card.description}
      </div>
      {card.mitre_techniques.length > 0 && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {card.mitre_techniques.slice(0, 3).map(t => (
            <span key={t} style={{
              fontSize: 9,
              background: '#373A40',
              color: COLORS.textSecondary,
              padding: '1px 5px',
              borderRadius: 3,
            }}>{t}</span>
          ))}
        </div>
      )}
    </button>
  );
}
```

**Step 2: Wire Dashboard into App.tsx**

```tsx
import { Dashboard } from './components/Dashboard';
// In the JSX, replace the placeholder div with:
<Dashboard
  findings={srumFile.findings}
  activeFlag={flagFilter}
  onFilter={setFlagFilter}
/>
```

**Step 3: Test manually**

```bash
npm run tauri dev
```

Open a SRUDB.dat with known suspicious activity. Confirm: finding cards appear at top in severity order (red Critical first), clicking a card highlights it, clicking again deselects.

**Step 4: Commit**

```bash
git add crates/sr-gui/src/components/Dashboard.tsx crates/sr-gui/src/App.tsx
git commit -m "feat(sr-gui): dashboard finding cards strip with severity colors and filter toggle"
```

---

### Task 10: Timeline table — TanStack Table with color coding

**Files:**
- Create: `crates/sr-gui/src/components/Timeline.tsx`
- Modify: `crates/sr-gui/src/App.tsx`

**Step 1: Create `src/components/Timeline.tsx`**

```tsx
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  flexRender,
  createColumnHelper,
  SortingState,
} from '@tanstack/react-table';
import { useState, useRef } from 'react';
import { TimelineRecord } from '../types';
import { COLORS, severityColor, sourceColor } from '../colors';

const col = createColumnHelper<TimelineRecord>();

const columns = [
  col.accessor('timestamp', {
    header: 'Timestamp',
    size: 180,
    cell: info => (
      <span style={{ color: COLORS.meta, fontFamily: 'monospace' }}>
        {info.getValue().replace('T', ' ').replace('Z', '')}
      </span>
    ),
  }),
  col.accessor('source_table', {
    header: 'Source',
    size: 110,
    cell: info => (
      <span style={{
        color: sourceColor(info.getValue()),
        fontWeight: 600,
        fontSize: 11,
        textTransform: 'uppercase',
        letterSpacing: 0.5,
      }}>
        {info.getValue()}
      </span>
    ),
  }),
  col.accessor('app_name', {
    header: 'Application',
    size: 200,
    cell: info => (
      <span style={{ color: COLORS.textPrimary }}>
        {info.getValue() ?? `ID ${info.row.original.app_id}`}
      </span>
    ),
  }),
  col.display({
    id: 'key_metric',
    header: 'Key Metric',
    size: 160,
    cell: info => {
      const r = info.row.original;
      return (
        <span style={{ color: COLORS.textSecondary }}>
          {r.key_metric_label}: {r.key_metric_value.toLocaleString()}
        </span>
      );
    },
  }),
  col.accessor('flags', {
    header: 'Flags',
    size: 200,
    cell: info => {
      const flags = info.getValue();
      if (!flags.length) return null;
      return (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {flags.slice(0, 3).map(f => (
            <span key={f} style={{
              fontSize: 9,
              background: `${severityColor(info.row.original.severity)}33`,
              color: severityColor(info.row.original.severity),
              padding: '2px 6px',
              borderRadius: 3,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: 0.5,
            }}>{f.replace(/_/g, ' ')}</span>
          ))}
        </div>
      );
    },
  }),
];

interface Props {
  records: TimelineRecord[];
  onSelect: (record: TimelineRecord) => void;
}

export function Timeline({ records, onSelect }: Props) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [selected, setSelected] = useState<string | null>(null);

  const table = useReactTable({
    data: records,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return (
    <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        borderBottom: `1px solid ${COLORS.border}`,
        background: COLORS.bgCard,
        flexShrink: 0,
      }}>
        {table.getHeaderGroups().map(hg =>
          hg.headers.map(header => (
            <div
              key={header.id}
              onClick={header.column.getToggleSortingHandler()}
              style={{
                width: header.getSize(),
                padding: '8px 12px',
                color: COLORS.meta,
                fontSize: 11,
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: 1,
                cursor: header.column.getCanSort() ? 'pointer' : 'default',
                userSelect: 'none',
                flexShrink: 0,
              }}
            >
              {flexRender(header.column.columnDef.header, header.getContext())}
              {header.column.getIsSorted() === 'asc' ? ' ↑' : header.column.getIsSorted() === 'desc' ? ' ↓' : ''}
            </div>
          ))
        )}
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {table.getRowModel().rows.map(row => {
          const rec = row.original;
          const isSelected = selected === row.id;
          const color = severityColor(rec.severity);
          const hasFlags = rec.flags.length > 0;

          return (
            <div
              key={row.id}
              onClick={() => {
                setSelected(row.id);
                onSelect(rec);
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                borderLeft: hasFlags ? `4px solid ${color}` : '4px solid transparent',
                background: isSelected ? `${color}15` : 'transparent',
                borderBottom: `1px solid ${COLORS.border}`,
                cursor: 'pointer',
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => {
                if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = COLORS.bgHover;
              }}
              onMouseLeave={e => {
                if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = 'transparent';
              }}
            >
              {row.getVisibleCells().map(cell => (
                <div
                  key={cell.id}
                  style={{
                    width: cell.column.getSize(),
                    padding: '7px 12px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    flexShrink: 0,
                  }}
                >
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
```

**Step 2: Wire Timeline into App.tsx**

```tsx
import { Timeline } from './components/Timeline';
import { useState } from 'react';
import { TimelineRecord } from './types';

// Add to App state:
const [selectedRecord, setSelectedRecord] = useState<TimelineRecord | null>(null);

// In JSX:
<Timeline records={filtered} onSelect={setSelectedRecord} />
```

**Step 3: Test manually — open a real SRUDB.dat**

Verify: rows appear, flagged rows have colored left border, clicking a row highlights it, columns sort on click, source table labels are color-coded.

**Step 4: Commit**

```bash
git add crates/sr-gui/src/components/Timeline.tsx crates/sr-gui/src/App.tsx
git commit -m "feat(sr-gui): timeline table with TanStack Table, severity borders, source colors"
```

---

### Task 11: Filter bar

**Files:**
- Create: `crates/sr-gui/src/components/FilterBar.tsx`
- Modify: `crates/sr-gui/src/App.tsx`

**Step 1: Create `src/components/FilterBar.tsx`**

```tsx
import { COLORS } from '../colors';

interface Props {
  appFilter: string;
  tableFilter: string;
  flagFilter: string;
  tables: string[];
  onAppFilter: (v: string) => void;
  onTableFilter: (v: string) => void;
  onFlagFilter: (v: string) => void;
  onClear: () => void;
  totalRecords: number;
  filteredRecords: number;
}

const INPUT_STYLE: React.CSSProperties = {
  background: '#25262B',
  border: `1px solid ${COLORS.border}`,
  borderRadius: 4,
  color: COLORS.textPrimary,
  padding: '4px 10px',
  fontSize: 12,
  outline: 'none',
};

const FLAG_OPTIONS = [
  '', 'automated_execution', 'beaconing', 'background_cpu_dominant',
  'exfil_signal', 'suspicious_path', 'masquerade_candidate',
  'phantom_foreground', 'notification_c2', 'selective_gap',
];

export function FilterBar({
  appFilter, tableFilter, flagFilter, tables,
  onAppFilter, onTableFilter, onFlagFilter, onClear,
  totalRecords, filteredRecords,
}: Props) {
  return (
    <div style={{
      display: 'flex',
      gap: 12,
      alignItems: 'center',
      padding: '8px 16px',
      background: COLORS.bgCard,
      borderBottom: `1px solid ${COLORS.border}`,
      flexShrink: 0,
    }}>
      <input
        placeholder="App name…"
        value={appFilter}
        onChange={e => onAppFilter(e.target.value)}
        style={{ ...INPUT_STYLE, width: 180 }}
      />
      <select value={tableFilter} onChange={e => onTableFilter(e.target.value)} style={{ ...INPUT_STYLE, width: 130 }}>
        <option value="">All tables</option>
        {tables.map(t => <option key={t} value={t}>{t}</option>)}
      </select>
      <select value={flagFilter} onChange={e => onFlagFilter(e.target.value)} style={{ ...INPUT_STYLE, width: 200 }}>
        {FLAG_OPTIONS.map(f => (
          <option key={f} value={f}>{f ? f.replace(/_/g, ' ') : 'All flags'}</option>
        ))}
      </select>
      {(appFilter || tableFilter || flagFilter) && (
        <button onClick={onClear} style={{
          background: 'transparent',
          border: `1px solid ${COLORS.border}`,
          color: COLORS.textSecondary,
          borderRadius: 4,
          padding: '4px 10px',
          cursor: 'pointer',
          fontSize: 12,
        }}>Clear</button>
      )}
      <span style={{ marginLeft: 'auto', color: COLORS.meta, fontSize: 11 }}>
        {filteredRecords === totalRecords
          ? `${totalRecords} records`
          : `${filteredRecords} of ${totalRecords} records`}
      </span>
    </div>
  );
}
```

**Step 2: Wire FilterBar into App.tsx**

Add filter state:
```tsx
const [appFilter, setAppFilter] = useState('');
const [tableFilter, setTableFilter] = useState('');
const [flagFilter2, setFlagFilter2] = useState('');

const filtered = srumFile
  ? srumFile.timeline.filter(r => {
      if (appFilter && !r.app_name?.toLowerCase().includes(appFilter.toLowerCase())) return false;
      if (tableFilter && r.source_table !== tableFilter) return false;
      if (flagFilter && !r.flags.includes(flagFilter)) return false;
      if (flagFilter2 && !r.flags.includes(flagFilter2)) return false;
      return true;
    })
  : [];
```

Add to JSX between Dashboard and Timeline:
```tsx
<FilterBar
  appFilter={appFilter}
  tableFilter={tableFilter}
  flagFilter={flagFilter2}
  tables={srumFile?.table_names ?? []}
  onAppFilter={setAppFilter}
  onTableFilter={setTableFilter}
  onFlagFilter={setFlagFilter2}
  onClear={() => { setAppFilter(''); setTableFilter(''); setFlagFilter2(''); }}
  totalRecords={srumFile?.record_count ?? 0}
  filteredRecords={filtered.length}
/>
```

**Step 3: Test manually** — verify filters combine correctly and record count updates.

**Step 4: Commit**

```bash
git add crates/sr-gui/src/components/FilterBar.tsx crates/sr-gui/src/App.tsx
git commit -m "feat(sr-gui): filter bar — app name, table, flag filter with record counter"
```

---

### Task 12: Record detail panel with 4-way signal bar

**Files:**
- Create: `crates/sr-gui/src/components/RecordDetail.tsx`
- Create: `crates/sr-gui/src/components/SignalChart.tsx`
- Modify: `crates/sr-gui/src/App.tsx`

**Step 1: Create `src/components/SignalChart.tsx`**

The 4-way signal bar — the tool's hero visualization.

```tsx
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { COLORS } from '../colors';

interface Props {
  backgroundCycles: number | null;
  foregroundCycles: number | null;
  focusTimeMs: number | null;
  userInputTimeMs: number | null;
}

export function SignalChart({ backgroundCycles, foregroundCycles, focusTimeMs, userInputTimeMs }: Props) {
  const data = [
    { name: 'BG CPU', value: backgroundCycles ?? 0, color: COLORS.critical, label: 'Background CPU cycles' },
    { name: 'FG CPU', value: foregroundCycles ?? 0, color: COLORS.suspicious, label: 'Foreground CPU cycles' },
    { name: 'Focus', value: focusTimeMs ?? 0, color: COLORS.informational, label: 'Focus time (ms)' },
    { name: 'Input', value: userInputTimeMs ?? 0, color: COLORS.clean, label: 'User input time (ms)' },
  ].filter(d => d.value > 0 || [backgroundCycles, foregroundCycles, focusTimeMs, userInputTimeMs].some(v => v !== null));

  if (data.every(d => d.value === 0)) {
    return <p style={{ color: COLORS.meta, fontSize: 12 }}>4-way signal data not available for this record.</p>;
  }

  return (
    <div>
      <p style={{ color: COLORS.meta, fontSize: 11, margin: '0 0 8px', letterSpacing: 1, textTransform: 'uppercase' }}>
        Activity Signal
      </p>
      <ResponsiveContainer width="100%" height={120}>
        <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16 }}>
          <XAxis type="number" hide />
          <YAxis type="category" dataKey="name" width={55} tick={{ fill: COLORS.meta, fontSize: 11 }} />
          <Tooltip
            formatter={(value: number, _: string, entry: any) => [
              value.toLocaleString(),
              entry.payload.label,
            ]}
            contentStyle={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 4 }}
          />
          <Bar dataKey="value" radius={[0, 3, 3, 0]}>
            {data.map(entry => (
              <Cell key={entry.name} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <p style={{ color: COLORS.meta, fontSize: 10, marginTop: 6 }}>
        Red = background (automated) · Amber = foreground (visible) · Blue = focus (user present) · Green = input (user active)
      </p>
    </div>
  );
}
```

**Step 2: Create `src/components/RecordDetail.tsx`**

```tsx
import { TimelineRecord } from '../types';
import { SignalChart } from './SignalChart';
import { COLORS, severityColor, sourceColor } from '../colors';

interface Props {
  record: TimelineRecord;
  onClose: () => void;
}

export function RecordDetail({ record, onClose }: Props) {
  const color = severityColor(record.severity);

  return (
    <div style={{
      width: 380,
      height: '100%',
      background: COLORS.bgCard,
      borderLeft: `1px solid ${COLORS.border}`,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
      flexShrink: 0,
    }}>
      {/* Header */}
      <div style={{
        padding: '12px 16px',
        borderBottom: `1px solid ${COLORS.border}`,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <span style={{ color: COLORS.textPrimary, fontWeight: 600, fontSize: 13 }}>
          {record.app_name ?? `ID ${record.app_id}`}
        </span>
        <button onClick={onClose} style={{
          background: 'transparent',
          border: 'none',
          color: COLORS.meta,
          cursor: 'pointer',
          fontSize: 18,
          lineHeight: 1,
        }}>×</button>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '16px' }}>
        {/* Metadata */}
        <Row label="Timestamp" value={record.timestamp.replace('T', ' ').replace('Z', ' UTC')} />
        <Row
          label="Source"
          value={record.source_table}
          valueColor={sourceColor(record.source_table)}
        />
        <Row label="Key metric" value={`${record.key_metric_label}: ${record.key_metric_value.toLocaleString()}`} />

        {/* Interpretation */}
        {record.interpretation && (
          <div style={{
            margin: '16px 0',
            padding: 12,
            background: `${color}15`,
            borderLeft: `3px solid ${color}`,
            borderRadius: 4,
          }}>
            <p style={{ margin: 0, color: COLORS.textPrimary, fontSize: 12, lineHeight: 1.6 }}>
              {record.interpretation}
            </p>
          </div>
        )}

        {/* 4-way signal */}
        <div style={{ margin: '16px 0' }}>
          <SignalChart
            backgroundCycles={record.background_cycles}
            foregroundCycles={record.foreground_cycles}
            focusTimeMs={record.focus_time_ms}
            userInputTimeMs={record.user_input_time_ms}
          />
        </div>

        {/* Flags */}
        {record.flags.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <p style={{ color: COLORS.meta, fontSize: 11, margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: 1 }}>
              Heuristic Flags
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {record.flags.map(f => (
                <span key={f} style={{
                  padding: '3px 8px',
                  background: `${color}22`,
                  color,
                  borderRadius: 4,
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                }}>{f.replace(/_/g, ' ')}</span>
              ))}
            </div>
          </div>
        )}

        {/* MITRE */}
        {record.mitre_techniques.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <p style={{ color: COLORS.meta, fontSize: 11, margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: 1 }}>
              MITRE ATT&CK
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {record.mitre_techniques.map(t => (
                <span key={t} style={{
                  padding: '3px 8px',
                  background: '#373A40',
                  color: COLORS.textSecondary,
                  borderRadius: 4,
                  fontSize: 11,
                }}>{t}</span>
              ))}
            </div>
          </div>
        )}

        {/* Raw fields */}
        <details style={{ marginTop: 8 }}>
          <summary style={{ color: COLORS.meta, fontSize: 11, cursor: 'pointer', textTransform: 'uppercase', letterSpacing: 1 }}>
            Raw Fields
          </summary>
          <pre style={{
            marginTop: 8,
            padding: 10,
            background: '#1A1B1E',
            borderRadius: 4,
            fontSize: 10,
            color: COLORS.textSecondary,
            overflowX: 'auto',
            maxHeight: 300,
          }}>
            {JSON.stringify(record.raw, null, 2)}
          </pre>
        </details>
      </div>
    </div>
  );
}

function Row({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
      <span style={{ color: COLORS.meta, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</span>
      <span style={{ color: valueColor ?? COLORS.textPrimary, fontSize: 12, textAlign: 'right', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{value}</span>
    </div>
  );
}
```

**Step 3: Wire RecordDetail into App.tsx**

Wrap the Timeline + RecordDetail in a horizontal flex container:

```tsx
{/* Main content area */}
<div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
  <Timeline records={filtered} onSelect={setSelectedRecord} />
  {selectedRecord && (
    <RecordDetail record={selectedRecord} onClose={() => setSelectedRecord(null)} />
  )}
</div>
```

**Step 4: Test manually** — click any flagged record, verify:
- Side panel slides in from the right
- Interpretation text is present for flagged records
- 4-way signal bar shows colored segments
- MITRE tags appear
- Raw fields are expandable

**Step 5: Commit**

```bash
git add crates/sr-gui/src/components/RecordDetail.tsx crates/sr-gui/src/components/SignalChart.tsx crates/sr-gui/src/App.tsx
git commit -m "feat(sr-gui): record detail panel with 4-way signal bar and plain-English interpretation"
```

---

### Task 13: GitHub Actions CI — cross-platform Tauri builds

**Files:**
- Create: `.github/workflows/gui-release.yml`

Modelled on blazehash's `release.yml`. Tauri's bundler handles platform-native outputs.

**Step 1: Create `.github/workflows/gui-release.yml`**

```yaml
name: SRUM Examiner Release

on:
  push:
    tags: ["gui-v*"]

permissions:
  contents: write

jobs:
  build:
    strategy:
      matrix:
        include:
          - target: aarch64-apple-darwin
            os: macos-latest
          - target: x86_64-apple-darwin
            os: macos-15
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-22.04
          - target: x86_64-pc-windows-msvc
            os: windows-latest

    runs-on: ${{ matrix.os }}

    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Install Linux system deps (WebKit2GTK)
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: crates/sr-gui/package-lock.json

      - name: Install npm dependencies
        working-directory: crates/sr-gui
        run: npm ci

      - name: Build Tauri app
        uses: tauri-apps/tauri-action@v0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          projectPath: crates/sr-gui
          tauriScript: npm run tauri
          args: -- --target ${{ matrix.target }}

      - uses: actions/upload-artifact@v4
        with:
          name: srum-examiner-${{ matrix.target }}
          path: |
            crates/sr-gui/src-tauri/target/${{ matrix.target }}/release/bundle/**/*.msi
            crates/sr-gui/src-tauri/target/${{ matrix.target }}/release/bundle/**/*.dmg
            crates/sr-gui/src-tauri/target/${{ matrix.target }}/release/bundle/**/*.AppImage
            crates/sr-gui/src-tauri/target/${{ matrix.target }}/release/bundle/**/*.deb

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          pattern: srum-examiner-*
          path: artifacts
          merge-multiple: true

      - name: Generate checksums
        run: |
          cd artifacts
          find . -type f | xargs sha256sum > checksums.txt

      - uses: softprops/action-gh-release@v2
        with:
          files: |
            artifacts/**
          generate_release_notes: true
```

**Step 2: Commit**

```bash
git add .github/workflows/gui-release.yml
git commit -m "ci: GitHub Actions cross-platform Tauri build for SRUM Examiner"
```

---

### Task 14: Distribution — winget, Homebrew cask, Cloudsmith .deb

**Files:**
- Create: `.github/workflows/gui-distribute.yml`

**Step 1: Create `.github/workflows/gui-distribute.yml`**

```yaml
name: SRUM Examiner Distribution

on:
  workflow_run:
    workflows: ["SRUM Examiner Release"]
    types: [completed]
    branches: ["main"]

jobs:
  winget:
    runs-on: windows-latest
    continue-on-error: true
    steps:
      - uses: vedantmgoyal9/winget-releaser@v2
        with:
          identifier: SecurityRonin.SRUMExaminer
          installers-regex: '\.msi$'
          token: ${{ secrets.WINGET_TOKEN }}
          fork-user: securityronin-bot

  cloudsmith:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          pattern: srum-examiner-x86_64-unknown-linux-gnu
          path: debs
          merge-multiple: true

      - name: Install Cloudsmith CLI
        run: pip install --user cloudsmith-cli==1.16.0

      - name: Push .deb to Cloudsmith
        env:
          CLOUDSMITH_API_KEY: ${{ secrets.CLOUDSMITH_API_KEY }}
        run: |
          find debs -name '*.deb' | while read f; do
            cloudsmith push deb securityronin/srum-examiner/any-distro/any-version "$f"
          done
```

**Step 2: Create Homebrew cask formula** in the SecurityRonin/homebrew-tap repository.

The cask formula (add to tap repo, not this one):

```ruby
cask "srum-examiner" do
  version "0.1.0"
  sha256 arm:   "PLACEHOLDER_ARM64_SHA256",
         intel: "PLACEHOLDER_X86_64_SHA256"

  url "https://github.com/SecurityRonin/srum-forensic/releases/download/gui-v#{version}/SRUM.Examiner_#{version}_aarch64.dmg",
      arm:   true,
      intel: false
  url "https://github.com/SecurityRonin/srum-forensic/releases/download/gui-v#{version}/SRUM.Examiner_#{version}_x64.dmg",
      arm:   false,
      intel: true

  name "SRUM Examiner"
  desc "Graphical SRUM forensic investigation tool"
  homepage "https://github.com/SecurityRonin/srum-forensic"

  app "SRUM Examiner.app"
end
```

SHA256 values are updated automatically by the release workflow dispatch (extend the existing `gui-release.yml` `release` job to dispatch to the tap repo the same way blazehash does).

**Step 3: Commit**

```bash
git add .github/workflows/gui-distribute.yml
git commit -m "ci: winget, Cloudsmith, and Homebrew cask distribution for SRUM Examiner"
```

---

## Running All Tests

```bash
# Rust backend unit tests
cargo test -p sr-gui

# Full workspace (make sure sr-gui doesn't break anything)
cargo test

# Frontend type-check
cd crates/sr-gui && npx tsc --noEmit

# Manual integration test (requires Tauri dev environment)
cd crates/sr-gui && npm run tauri dev
```

---

## Acceptance Criteria

- [ ] Open a real SRUDB.dat → loading completes, record count shown
- [ ] Finding cards appear at top, color-coded by severity (Critical=red, Suspicious=amber)
- [ ] Clicking a finding card filters the timeline to that flag
- [ ] Timeline rows have colored left borders matching their severity
- [ ] Source table labels are color-coded (network=indigo, apps=green, etc.)
- [ ] Clicking a timeline row opens the right-side detail panel
- [ ] Detail panel shows the 4-way signal bar for apps/app-timeline records
- [ ] Detail panel shows plain-English interpretation for flagged records
- [ ] FilterBar (app name, table, flag) all filter the timeline in real time
- [ ] `cargo test -p sr-gui` passes all Rust unit tests
- [ ] `tauri build` produces platform-native installer on macOS, Windows, Linux
