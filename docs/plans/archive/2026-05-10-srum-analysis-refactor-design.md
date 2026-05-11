# `srum-analysis` Refactor — Design

**Date:** 2026-05-10
**Status:** Approved

---

## Goal

Eliminate the duplicated analysis pipeline between `sr-cli` and `sr-gui` by extracting it into a new `srum-analysis` crate. Split the 3036-line `sr-cli/src/main.rs` monolith into focused modules. Both binaries call into `srum-analysis` — one source of truth for all forensic heuristics.

---

## Problem

Two critical issues drive this refactor:

1. **Duplication.** The six pipeline stages (`merge_focus_into_apps`, `apply_heuristics`, `apply_cross_table_signals`, `apply_beaconing_signals`, `apply_notification_c2_signal`, `annotate_user_presence`) plus `mitre_techniques_for` exist in both `sr-cli/src/main.rs` and `sr-gui/src-tauri/src/commands.rs`. A heuristic fix must be applied to both files separately.

2. **Monolith.** `sr-cli/src/main.rs` is 3036 lines — Clap structs, 15 subcommand handlers, pipeline stages, output helpers, and 600+ lines of tests, all in one file.

---

## Architecture

### Dependency graph (after)

```
ese-core
  └─ srum-core
       └─ srum-parser
            └─ srum-analysis      ← new
                 ├─ sr-cli
                 └─ sr-gui/src-tauri
```

`forensicnomicon` is a peer dependency of `srum-analysis` (not promoted to the chain; it's a sibling library of heuristic predicates).

---

## Section 1: New `srum-analysis` Crate

### Location

`crates/srum-analysis/` — new workspace member.

### Module layout

```
crates/srum-analysis/src/
  lib.rs            pub mod declarations; re-exports of public surface
  pipeline.rs       build_timeline(), all 6 pipeline stages, mitre_techniques_for()
  enrich.rs         enrich(), enrich_connectivity(), records_to_values(),
                    classify_sid(), split_windows_path()
  record.rs         AnnotatedRecord, FindingCard, TemporalSpan, Severity
  findings.rs       compute_findings()
  analysis/
    mod.rs
    gaps.rs         detect_gaps_in_timeline(), detect_autoinc_gaps_from_ids()
    sessions.rs     derive_sessions()
    stats.rs        compute_stats()
    hunt.rs         filter_by_signature(), HuntSignature enum
    compare.rs      compare_databases()
```

### Public API surface

```rust
// Primary entry point — builds an annotated timeline from a SRUDB.dat path
pub fn build_timeline(path: &Path, id_map: Option<&HashMap<i32, String>>)
    -> Vec<serde_json::Value>;

// Typed output for GUI consumption
pub struct AnnotatedRecord { /* replaces GUI's TimelineRecord */ }
pub struct FindingCard      { /* replaces GUI's FindingCard   */ }
pub fn compute_findings(records: &[AnnotatedRecord]) -> Vec<FindingCard>;
```

### `Cargo.toml` dependencies

```toml
[dependencies]
srum-parser     = { workspace = true }
srum-core       = { workspace = true }
forensicnomicon = { workspace = true }
serde_json      = { workspace = true }
serde           = { workspace = true }
chrono          = { workspace = true }
anyhow          = { workspace = true }
```

### Field name standardisation

The CLI pipeline currently injects `"table"` as the JSON source discriminator; the GUI uses `"source_table"`. `srum-analysis` standardises on **`"source_table"`** — more descriptive and consistent with how the GUI already labels records.

**Impact:** `sr timeline` JSON output renames `"table"` → `"source_table"`. Minor breaking change; improves field name clarity.

---

## Section 2: CLI Module Split

### Layout

```
crates/sr-cli/src/
  main.rs           Clap structs (Cli, Cmd, all arg variants), fn main(), fn run()
  output.rs         OutputFormat enum, print_records(), values_to_csv(), print_output()
  cmd/
    mod.rs
    tables.rs       network, apps, idmap, connectivity, energy, energy-lt,
                    notifications, app-timeline
                    (8 single-table dump commands — parse → enrich → print)
    analysis.rs     timeline, process, stats, sessions, gaps, hunt
                    (6 cross-table commands — all call srum_analysis::build_timeline)
    forensics.rs    compare, metadata
                    (2 multi-file / structural commands)
```

### `main.rs` target size

After split: ~250 lines (Clap structs + dispatch match + `fn main`).

### Command function signatures

```rust
// tables.rs
pub fn run_network(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()>;
// ... (same pattern for all 8 single-table commands)

// analysis.rs
pub fn run_timeline(path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()>;
pub fn run_stats   (path: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()>;
// ...

// forensics.rs
pub fn run_compare (baseline: &Path, suspect: &Path, resolve: bool, format: &OutputFormat) -> anyhow::Result<()>;
pub fn run_metadata(path: &Path, format: &OutputFormat) -> anyhow::Result<()>;
```

### Tests

Unit tests currently inline in `main.rs` move into the file that owns the tested function. Integration tests in `tests/cli_tests.rs` are unchanged.

### Cargo.toml changes

`sr-cli` drops `forensicnomicon` as a direct dep (pipeline moves to `srum-analysis`). Adds `srum-analysis = { workspace = true }`.

---

## Section 3: GUI Simplification

### Before vs. after

| File | Before | After |
|---|---|---|
| `commands.rs` | 525 lines — full pipeline duplicated | ~80 lines — calls `srum_analysis::build_timeline` |
| `findings.rs` | 175 lines — duplicate `compute_findings` | **deleted** — moved to `srum-analysis` |
| `types.rs` | 92 lines — all types incl. Severity etc. | ~40 lines — SrumFile, TemporalSpan (GUI-only) |
| `timeline.rs` | 271 lines — value_to_timeline_record + tests | ~120 lines — thin adapter only |

### `commands.rs` after

```rust
#[tauri::command]
pub async fn open_file(path: String) -> Result<SrumFile, String> {
    let p = Path::new(&path);
    parse_srum(p).map_err(|e| format!("error: {e:#}"))
}

fn parse_srum(path: &Path) -> anyhow::Result<SrumFile> {
    let id_map = srum_analysis::load_id_map(path);
    let timeline_json = srum_analysis::build_timeline(path, Some(&id_map));
    let records = timeline_json
        .into_iter()
        .filter_map(|v| value_to_timeline_record(v))
        .collect::<Vec<_>>();
    // sort, span, findings — thin wiring only
}
```

### `Cargo.toml` changes

- Add: `srum-analysis = { workspace = true }`
- Remove: `forensicnomicon` (no longer needed directly)

---

## What Does NOT Change

- `srum-parser` — unchanged (pure parsing, no analysis)
- `srum-core` — unchanged (pure data types)
- `forensicnomicon` — unchanged (pure heuristic predicates)
- `ese-core`, `ese-carver`, `ese-integrity` — unchanged
- All existing public CLI output formats (JSON, CSV, NDJSON) — unchanged except `sr timeline` field rename
- All existing tests — moved but not changed in logic

---

## Migration Notes

### `sr timeline` output change

The `"table"` field in records becomes `"source_table"`. Consumers of `sr timeline --format json` must update field references. All other subcommands are unaffected (they don't inject a table discriminator field).

### `HuntSignature` enum

Currently defined in `sr-cli/src/main.rs` as a Clap value enum. The `filter_by_signature` function moves to `srum-analysis`. The Clap-annotated enum wrapper stays in the CLI (it's a presentation concern); `srum-analysis` defines a plain `HuntSignature` that the CLI maps to.

---

## Testing Strategy

- `srum-analysis` gets its own unit tests (moved from `main.rs` and `commands.rs`) plus new integration tests against the existing fixture SRUDB.dat files
- CLI integration tests in `tests/cli_tests.rs` provide regression coverage for all 15 subcommands
- GUI Rust tests (22 currently) continue to cover the adapter layer
- No new test fixtures needed — existing fixtures cover the full pipeline
