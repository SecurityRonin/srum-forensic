[![Stars](https://img.shields.io/github/stars/SecurityRonin/srum-forensic?style=flat-square)](https://github.com/SecurityRonin/srum-forensic/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/srum-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/srum-forensic/actions/workflows/ci.yml)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](#install)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

# srum-forensic

**Parse Windows SRUM activity logs. Detect malware patterns. No Windows required.**

Every running process leaves evidence in `SRUDB.dat` — network bytes sent, CPU cycles burned, foreground time, focus duration, user input time — recorded hourly by Windows since 8.1. Every DFIR practitioner knows this. Almost no tool parses it from a Linux analysis workstation without a Python runtime or COM interop.

`sr` does it with a single Rust binary. It also applies forensic heuristics — background CPU dominance, phantom foreground anomalies, automated execution detection, cross-table exfiltration signals — directly in the parse path so you get actionable flags without writing your own correlation logic.

```bash
cargo install srum-forensic
sr timeline --resolve /mnt/evidence/SRUDB.dat | jq '.[] | select(.exfil_signal == true)'
```

**[Full documentation →](https://securityronin.github.io/srum-forensic/)**

---

## Install

**Cargo**
```bash
cargo install srum-forensic
```

**From source**
```bash
git clone https://github.com/SecurityRonin/srum-forensic.git
cd srum-forensic
cargo build --release
./target/release/sr --help
```

---

## What You Can Extract

Each subcommand maps 1:1 to a single SRUM table. `sr timeline` merges all of them.

| Subcommand | SRUM Table | What It Shows |
|---|---|---|
| `sr network` | Network Data Usage | Per-process bytes sent/received per hour |
| `sr apps` | Application Resource Usage | Per-process CPU cycles, merged focus and input time, heuristic flags |
| `sr connectivity` | Network Connectivity | Profile connection time per app |
| `sr energy` | Energy Usage | Charge level and energy consumed per app |
| `sr notifications` | Push Notifications | Notification type and count per app |
| `sr app-timeline` | Application Timeline | In-focus duration and user input time per app (Windows 10 1607+) |
| `sr idmap` | SruDbIdMapTable | Integer ID → process name / SID mapping |
| `sr timeline` | All of the above | Unified chronological view, all tables merged, all heuristics applied |

All subcommands accept `--format json` (default) or `--format csv`.
`network`, `apps`, `connectivity`, `notifications`, and `app-timeline` accept `--resolve` to inline names from the ID map.

---

## Forensic Heuristics

`sr apps` and `sr timeline` automatically apply heuristics from [forensicnomicon](https://github.com/SecurityRonin/forensicnomicon). Flags are injected as extra fields on the records that trigger them — nothing is emitted when the condition is not met.

### Per-record signals (apps records)

| Field | Type | Condition |
|---|---|---|
| `background_cpu_dominant` | `true` | `background_cycles > 0` AND (`foreground_cycles == 0` OR `bg/fg ≥ 10×`). Background CPU dominates — possible mining or cover-UI malware. |
| `no_focus_with_cpu` | `true` | `background_cycles > 0` AND `focus_time_ms == 0`. Process consumed CPU but the user never focused it. Only emitted when Application Timeline data is present. |
| `phantom_foreground` | `true` | `foreground_cycles ≥ 1 000` AND `focus_time_ms == 0`. The CPU scheduler billed foreground cycles but the Application Timeline records no focus. Possible `SetForegroundWindow` abuse. Only emitted when Application Timeline data is present. |
| `automated_execution` | `true` | `focus_time_ms ≥ 60 000` AND `user_input_time_ms == 0`. App held focus for ≥ 1 minute with zero keyboard/mouse input — likely scripted. Only emitted when Application Timeline data is present. |
| `interactivity_ratio` | `f64` | `user_input_time_ms / focus_time_ms`. Low values (near 0.0) indicate an app that held focus without human interaction. Only emitted when `focus_time_ms > 0`. |

**Three-state design:** heuristics that depend on Application Timeline data are only emitted when that data is present in the record. An absent field means the data was unavailable (older SRUM database or missing table), not that the condition is false.

### Cross-table signals (timeline only)

| Field | Type | Condition |
|---|---|---|
| `exfil_signal` | `true` | Apps record has `background_cycles > 0` AND (`focus_time_ms == 0` or absent) AND a network record for the same `(app_id, timestamp)` triggers the exfiltration volume or ratio threshold. Three-way signature of data theft. |
| `user_present` | `true` | The total `user_input_time_ms` across all app records in this interval exceeds 10 seconds. Applied to **all record types** in the interval — lets you distinguish user-driven activity from autonomous machine behaviour. |

---

## Hunt Examples

### Find processes with no user focus but active CPU

```bash
# Potential background malware — ran CPU but user never interacted with it
sr apps --resolve SRUDB.dat \
  | jq '.[] | select(.no_focus_with_cpu == true) | {app_name, timestamp, background_cycles}'
```

### Detect cover-UI malware (decoy window hiding background work)

```bash
# 10:1 background-to-foreground CPU ratio — malware pattern
sr apps SRUDB.dat \
  | jq '.[] | select(.background_cpu_dominant == true and .phantom_foreground == true)'
```

### Find the exfiltration fingerprint

```bash
# Background-only process + network exfil in the same interval
sr timeline --resolve SRUDB.dat \
  | jq '.[] | select(.exfil_signal == true) | {app_name, timestamp, bytes_sent}'
```

### Prove autonomous machine behaviour

```bash
# Events that occurred when no human was present at the keyboard
sr timeline SRUDB.dat \
  | jq '.[] | select(.user_present == null and .table == "network")'
```

### Build a unified activity timeline

```bash
# All SRUM evidence sorted chronologically — one command
sr timeline SRUDB.dat | jq '.[] | select(.table == "network")'
```

### Hunt lateral movement — who sent how much, from which process

```bash
# Every process that sent data — resolved names, sorted by bytes, highest first
sr network --resolve --format csv SRUDB.dat \
  | sort -t, -k5 -rn \
  | head -20
```

### Feed your SIEM

```bash
sr network SRUDB.dat --format csv >> srum_network.csv
sr apps    SRUDB.dat              >> srum_apps.ndjson
```

All subcommands output JSON arrays by default. Pass `--format csv` for flat CSV. Pipe JSON to `jq -c '.[]'` for NDJSON, redirect to files, or POST directly to Elasticsearch. The schema is stable and documented.

---

## What's Different

Every alternative either requires Windows, needs a Python environment, or costs money. This one is a static binary you compile once and copy anywhere — and it applies forensic heuristics in the parse path so you don't have to.

| | srum-forensic | KAPE + EZTools | python-libESE | Arsenal SRUM |
|--|:-:|:-:|:-:|:-:|
| Runs on Linux / macOS | ✓ | — | ✓ | — |
| Single static binary | ✓ | — | — | — |
| No Python runtime | ✓ | — | — | ✓ |
| Free & open source | ✓ | partial | ✓ | — |
| JSON output | ✓ | — | — | — |
| CSV output | ✓ | ✓ | — | ✓ |
| 6 SRUM tables | ✓ | ✓ | — | ✓ |
| Application Timeline | ✓ | — | — | — |
| Focus + input time merged into apps | ✓ | — | — | — |
| Inline ID resolution | ✓ | — | — | — |
| Unified timeline | ✓ | — | — | — |
| Forensic heuristics (7 signals) | ✓ | — | — | — |
| Cross-table exfiltration detection | ✓ | — | — | — |
| User presence annotation | ✓ | — | — | — |
| Pipe-friendly | ✓ | — | — | — |
| Zero-copy mmap I/O | ✓ | — | — | — |
| ESE parsed in Rust | ✓ | — | — | — |
| Structural integrity checks | ✓ | — | — | — |
| Forensic copy support | ✓ | ✓ | ✓ | ✓ |

---

## Structural Integrity Checks

`ese-integrity` checks three structural anomalies at the binary level — raw facts, not forensic conclusions:

**Dirty shutdown** — `db_state == 2` means the database was never cleanly closed. Could be a crash. Could be a process kill timed to prevent the final flush.

**Timestamp skew** — page `db_time` fields are compared to the file header. A page newer than its own header was written after the header was sealed — a structural anomaly that warrants further investigation.

**Slack-space residue** — the region between the last record and the tag array is scanned for non-zero bytes. Residual data here means records were deleted without zeroing — fragments of evicted evidence remain.

`ese-carver` goes further: when a record was split across a page boundary by the ESE engine, it detects the split and reconstructs the original bytes, recovering data that appears incomplete in any linear page scan.

---

## Output Schema

### `sr network <path>`

Records from the `{973F5D5C-1D90-4944-BE8E-24B22A728CF2}` SRUM table.

```json
[
  {
    "timestamp": "2024-06-15T08:00:00Z",
    "app_id": 42,
    "user_id": 1,
    "bytes_sent": 1048576,
    "bytes_recv": 8388608
  }
]
```

### `sr apps <path>`

Records from the `{5C8CF1C7-7257-4F13-B223-970EF5939312}` SRUM table. Application Timeline data (`focus_time_ms`, `user_input_time_ms`) is automatically merged in when available. Heuristic flags are injected on records that meet their conditions.

```json
[
  {
    "timestamp": "2024-06-15T08:00:00Z",
    "app_id": 42,
    "user_id": 1,
    "foreground_cycles": 12500000,
    "background_cycles": 450000000,
    "focus_time_ms": 0,
    "user_input_time_ms": 0,
    "background_cpu_dominant": true,
    "no_focus_with_cpu": true,
    "phantom_foreground": true
  },
  {
    "timestamp": "2024-06-15T09:00:00Z",
    "app_id": 7,
    "user_id": 1,
    "foreground_cycles": 8000000,
    "background_cycles": 200000,
    "focus_time_ms": 3600000,
    "user_input_time_ms": 840000,
    "interactivity_ratio": 0.233
  }
]
```

`app_id` and `user_id` are integer keys into the `SruDbIdMapTable`. Pass `--resolve`
to inline the names directly into the output — no jq, no temp files:

```bash
sr network        --resolve SRUDB.dat
sr apps           --resolve SRUDB.dat
sr connectivity   --resolve SRUDB.dat
sr notifications  --resolve SRUDB.dat
sr app-timeline   --resolve SRUDB.dat
```

Resolution is best-effort: records whose IDs are absent from the map keep their
raw integer values and no `app_name`/`user_name` field is injected.

### `sr app-timeline <path>`

Records from the `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}` SRUM table (Application Timeline). Available since Windows 10 Anniversary Update (1607). Shows exactly how long each app held keyboard/mouse focus and received active user input per interval.

```json
[
  {
    "timestamp": "2024-06-15T08:00:00Z",
    "app_id": 42,
    "user_id": 1,
    "focus_time_ms": 1800000,
    "user_input_time_ms": 420000
  }
]
```

`sr apps` automatically merges this data into app resource records — use `sr app-timeline` when you want the raw table directly.

### `sr connectivity <path>`

Records from the `{DD6636C4-8929-4683-974E-22C046A43763}` SRUM table.

```json
[
  {
    "timestamp": "2024-06-15T08:00:00Z",
    "app_id": 42,
    "user_id": 1,
    "profile_id": 3,
    "connected_time": 3600
  }
]
```

### `sr energy <path>`

Records from the `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` SRUM table.

```json
[
  {
    "timestamp": "2024-06-15T08:00:00Z",
    "app_id": 42,
    "user_id": 1,
    "charge_level": 87,
    "energy_consumed": 12400
  }
]
```

### `sr notifications <path>`

Records from the `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` SRUM table.

```json
[
  {
    "timestamp": "2024-06-15T08:00:00Z",
    "app_id": 42,
    "user_id": 1,
    "notification_type": 1,
    "count": 7
  }
]
```

### `sr timeline <path>`

Merges all tables into a single chronological stream. Each record includes a `"table"` field identifying its source. Apps records receive merged focus data and all per-record heuristic flags. Cross-table signals (`exfil_signal`, `user_present`) are applied to the full merged set. Exits 0 even if individual tables fail (best-effort).

```json
[
  {
    "table": "network",
    "timestamp": "2024-06-15T07:00:00Z",
    "app_id": 42,
    "bytes_sent": 209715200,
    "bytes_recv": 512,
    "user_present": true
  },
  {
    "table": "apps",
    "timestamp": "2024-06-15T07:00:00Z",
    "app_id": 42,
    "foreground_cycles": 0,
    "background_cycles": 98000000,
    "focus_time_ms": 0,
    "user_input_time_ms": 0,
    "background_cpu_dominant": true,
    "no_focus_with_cpu": true,
    "exfil_signal": true,
    "user_present": true
  }
]
```

Pass `--format csv` to any subcommand for flat CSV output instead of JSON:

```bash
sr network  --format csv SRUDB.dat > network.csv
sr timeline --format csv SRUDB.dat > timeline.csv
```

### `sr idmap <path>`

```json
[
  { "id": 42, "name": "\\Device\\HarddiskVolume3\\Windows\\svchost.exe" },
  { "id": 1,  "name": "S-1-5-21-1234567890-123456789-1234567890-1001" }
]
```

---

## Crate Structure

This is a Cargo workspace. Use the crates independently in your own tools:

<details>
<summary>Show crate layout</summary>

| Crate | What it does |
|-------|-------------|
| [`ese-core`](crates/ese-core/) | ESE/JET Blue binary format parser — memory-mapped page I/O, B-tree walking, catalog, zero-copy `raw_page_slice` |
| [`ese-integrity`](crates/ese-integrity/) | Structural anomaly detection — dirty state, timestamp skew, slack-space scanning |
| [`ese-carver`](crates/ese-carver/) | Page carving — detect and reconstruct records split across page boundaries |
| [`srum-core`](crates/srum-core/) | SRUM record type definitions — `NetworkUsageRecord`, `AppUsageRecord`, `AppTimelineRecord`, `NetworkConnectivityRecord`, `EnergyUsageRecord`, `PushNotificationRecord`, `IdMapEntry` |
| [`srum-parser`](crates/srum-parser/) | High-level API — `parse_network_usage`, `parse_app_usage`, `parse_app_timeline`, `parse_network_connectivity`, `parse_energy_usage`, `parse_push_notifications`, `parse_id_map` |
| [`sr-cli`](crates/sr-cli/) | `sr` binary — `network`, `apps`, `app-timeline`, `connectivity`, `energy`, `notifications`, `timeline`, `idmap` subcommands; `--format json/csv`; `--resolve`; forensic heuristics |
| [`ese-test-fixtures`](crates/ese-test-fixtures/) | Shared test fixture builders — dev-dependency only, never ships |

</details>

```toml
# Use the parser in your own project
[dependencies]
srum-parser = "0.1"
```

---

## Performance

`ese-core` memory-maps the database file once at open time (`memmap2`). All subsequent page reads — integrity checks, record iteration, carving — slice directly into the OS-managed mapping with no additional syscalls or heap allocation per page. The OS page cache handles read-ahead and eviction; the tool itself never touches the file descriptor again after `open()`.

This matters in practice: a 200 MB `SRUDB.dat` is mapped in one `mmap(2)` call. A linear integrity scan over all pages costs zero `read(2)` syscalls. The focus-merge in `sr timeline` is a single O(n) pass over all records — no O(n²) re-scanning.

---

## SRUM Background

Windows System Resource Usage Monitor (`srum`) has been running since Windows 8.1. It records a snapshot every hour to `C:\Windows\System32\sru\SRUDB.dat` — an ESE (Extensible Storage Engine, also called JET Blue) database, the same format used by Exchange, Active Directory, and Windows Search.

On a live system the file is locked by `svchost.exe`. Forensic analysis always operates on a copy: VSS snapshot, image acquisition, or memory-assisted extraction.

The database contains multiple tables identified by GUID. This tool currently supports:

- `{973F5D5C-1D90-4944-BE8E-24B22A728CF2}` — Network Data Usage (`sr network`)
- `{5C8CF1C7-7257-4F13-B223-970EF5939312}` — Application Resource Usage (`sr apps`)
- `{DD6636C4-8929-4683-974E-22C046A43763}` — Network Connectivity (`sr connectivity`)
- `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` — Energy Usage (`sr energy`)
- `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` — Push Notifications (`sr notifications`)
- `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}` — Application Timeline (`sr app-timeline`); available since Windows 10 1607
- `SruDbIdMapTable` — Integer ID → process name / SID mapping (`sr idmap`)

The Application Timeline table records two fields that no other table provides: `InFocusDurationMS` (how long each app held keyboard/mouse focus) and `UserInputMS` (how long there was actual user input while the app was focused). Combined with CPU cycle counts from the App Resource Usage table, these fields enable the `phantom_foreground`, `no_focus_with_cpu`, `automated_execution`, and `interactivity_ratio` heuristics.

---

## Acknowledgements

**Mark Russinovich** and the Windows Internals team whose documentation of ESE/JET Blue made this possible without reverse engineering.

**Yogesh Khatri** (@SwiftForensics) whose [srum-dump](https://github.com/MarkBaggett/srum-dump) Python tool proved the forensic value of SRUM data and documented the table schemas.

**Mark Baggett** whose original Python scripts brought SRUM analysis into mainstream DFIR workflows.

The Rust [binrw](https://github.com/jam1garner/binrw) team for making binary parsing declarative and safe.

---

[Privacy Policy](https://securityronin.github.io/srum-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/srum-forensic/terms/) · © 2026 Security Ronin Ltd.
