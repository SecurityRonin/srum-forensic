[![Stars](https://img.shields.io/github/stars/SecurityRonin/srum-forensic?style=flat-square)](https://github.com/SecurityRonin/srum-forensic/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/srum-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/srum-forensic/actions/workflows/ci.yml)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](#install)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

# srum-forensic

**Did a human engage with that app — or did it run itself? SRUM has the answer.**

Most forensic tools can tell you an app was running at a given time. `sr` tells you whether a human was actually at the keyboard using it.

Windows records two fields that no other SRUM parser surfaces for forensic use: `InFocusDurationMS` — how long an app held keyboard and mouse focus — and `UserInputMS` — how long there was genuine user input while it was focused. Combined with CPU cycles and network bytes from the other SRUM tables, these fields draw a sharp line between:

- A process that **ran in the background** with zero human interaction (malware, scheduled tasks, C2 beaconing)
- An app that **a human actively used** (focus time, keystrokes, mouse clicks recorded)

This distinction answers questions that raw process execution logs never can: Was the user present during the incident window? Was that browser session user-driven or automated? Did the suspect actually interact with that exfiltration tool, or did it run itself silently?

`sr` is a single static Rust binary. It parses `SRUDB.dat` directly — no Windows, no Python, no COM interop — and applies 10 forensic heuristics in the parse path, including cross-table exfiltration signals and per-interval user presence annotation.

```bash
cargo install srum-forensic

# Was anyone at the keyboard during this incident window?
sr timeline --resolve SRUDB.dat \
  | jq '.[] | select(.timestamp | startswith("2024-11-14T02")) | {app_name, user_present, focus_time_ms, user_input_time_ms}'

# Find processes that ran but no human ever interacted with them
sr apps --resolve SRUDB.dat \
  | jq '.[] | select(.no_focus_with_cpu == true) | {app_name, timestamp, background_cycles}'
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

## Human Engagement vs. Process Execution

This is the forensically critical distinction `sr` makes that other SRUM tools do not.

Windows Application Timeline (`sr app-timeline`) records two fields per app per interval:

| Field | What it measures |
|---|---|
| `focus_time_ms` | Milliseconds the app window held keyboard/mouse focus |
| `user_input_time_ms` | Milliseconds of actual keyboard/mouse input while focused |
| `interactivity_ratio` | `user_input_time_ms / focus_time_ms` — near 1.0 = human; near 0.0 = automated |

`sr apps` automatically merges these into every app resource record. The result is a record that tells you not just how much CPU a process burned — but whether a human was the one driving it.

**Reading the signals:**

```
focus_time_ms = 0,    user_input_time_ms = 0  → process ran, user never opened the window
focus_time_ms > 0,    user_input_time_ms = 0  → window was in front, no input — possible automated or scripted execution
focus_time_ms > 0,    user_input_time_ms > 0  → human was actively engaged
interactivity_ratio ≈ 0.8                     → 80% of focus time had keyboard/mouse input — clearly human-driven
```

The `user_present` cross-table signal extends this to the entire interval: if any app in a given hour had substantial user input, **all records** in that interval are annotated `user_present: true`. This lets you filter any table — network, energy, notifications — by whether a human was present.

```bash
# Network traffic that moved while no human was at the keyboard
sr timeline SRUDB.dat \
  | jq '.[] | select(.source_table == "network" and .user_present == null)'

# Prove the user was active during the 14:00 hour
sr timeline --resolve SRUDB.dat \
  | jq '[.[] | select(.timestamp | startswith("2024-06-15T14")) | select(.user_present == true)] | length'
```

---

## What You Can Extract

Each subcommand maps 1:1 to a single SRUM table. `sr timeline` merges all of them.

| Subcommand | SRUM Table | What It Shows |
|---|---|---|
| `sr network` | Network Data Usage | Per-process bytes sent/received per hour |
| `sr apps` | Application Resource Usage | Per-process CPU cycles; focus and user input time merged in; all heuristic flags |
| `sr connectivity` | Network Connectivity | Profile connection time per app |
| `sr energy` | Energy Usage | Charge level and energy consumed per app |
| `sr notifications` | Push Notifications | Notification type and count per app |
| `sr app-timeline` | Application Timeline | Raw focus duration and user input time per app (Windows 10 1607+) |
| `sr idmap` | SruDbIdMapTable | Integer ID → process name / SID mapping |
| `sr timeline` | All of the above | Unified chronological view, all tables merged, all heuristics applied |

All subcommands accept `--format json` (default) or `--format csv`.
`network`, `apps`, `connectivity`, `notifications`, and `app-timeline` accept `--resolve` to inline names from the ID map.

---

## Forensic Heuristics

`sr apps` and `sr timeline` automatically apply heuristics from [forensicnomicon](https://github.com/SecurityRonin/forensicnomicon). Flags are injected as extra boolean fields on records that meet their condition — nothing is emitted when the condition is false. Numeric signals (`interactivity_ratio`) are always injected when the required data is present.

### Engagement and execution signals (apps records)

These heuristics answer the "was a human there?" question at the per-record level.

| Field | Type | Condition |
|---|---|---|
| `automated_execution` | `true` | `focus_time_ms ≥ 60 000` AND `user_input_time_ms == 0`. App held focus for ≥ 1 minute with zero keyboard/mouse input — scripted or unattended execution. |
| `phantom_foreground` | `true` | `foreground_cycles ≥ 1 000` AND `focus_time_ms == 0`. The CPU scheduler billed foreground cycles but no focus time was recorded. Possible `SetForegroundWindow` abuse — process manipulating its own billing without genuine user interaction. |
| `no_focus_with_cpu` | `true` | `background_cycles > 0` AND `focus_time_ms == 0`. Process consumed CPU but never had user focus. |
| `background_cpu_dominant` | `true` | `background_cycles > 0` AND (`foreground_cycles == 0` OR `bg/fg ≥ 10×`). Background CPU dominates — consistent with mining, covert computation, or malware hiding behind a cover UI. |
| `interactivity_ratio` | `f64` | `user_input_time_ms / focus_time_ms`. Values near 0.0 indicate an app that held focus without human interaction. Only emitted when `focus_time_ms > 0`. |

**Three-state design:** heuristics that depend on Application Timeline data are only emitted when that data is present in the record. An absent field means the data was unavailable (older SRUM database or missing table), not that the condition is false.

### Network and behaviour signals (apps records)

| Field | Type | Condition |
|---|---|---|
| `suspicious_path` | `true` | Process path is in a temp directory, downloads folder, UNC path, or root of a drive. |
| `masquerade_candidate` | `true` | Process name closely resembles a known Windows system binary but ran from an unexpected location. |
| `beaconing` | `true` | Process made network connections at statistically regular intervals — hallmark of C2 beaconing. |

### Cross-table signals (timeline only)

| Field | Type | Condition |
|---|---|---|
| `exfil_signal` | `true` | App has `background_cycles > 0` AND `focus_time_ms == 0` AND a network record for the same `(app_id, timestamp)` shows significant outbound data. Three-way signature: no user focus, background-only CPU, large outbound transfer. |
| `notification_c2` | `true` | App generated an unusually high push notification count with background CPU and no user focus. Possible covert C2 channel via the notification subsystem. |
| `user_present` | `true` | Total `user_input_time_ms` across all app records in this interval exceeds 10 seconds. Applied to **all record types** in the interval — distinguishes user-driven activity from autonomous machine behaviour. |

---

## Hunt Examples

### Was anyone at the keyboard? (alibi reconstruction)

```bash
# All activity during the 2 AM incident hour — did the user_present flag fire?
sr timeline --resolve SRUDB.dat \
  | jq '.[] | select(.timestamp | startswith("2024-11-14T02")) | {source_table, app_name, user_present, focus_time_ms, user_input_time_ms}'
```

### Prove user engagement with a specific app

```bash
# Show every hour chrome.exe had active keyboard/mouse input
sr apps --resolve SRUDB.dat \
  | jq '.[] | select(.app_name | test("chrome"; "i")) | select(.user_input_time_ms > 0) | {timestamp, focus_time_ms, user_input_time_ms, interactivity_ratio}'
```

### Find processes that ran but the user never touched

```bash
# Potential background malware — CPU consumed, user never interacted
sr apps --resolve SRUDB.dat \
  | jq '.[] | select(.no_focus_with_cpu == true) | {app_name, timestamp, background_cycles}'
```

### Detect automated execution (scripted/scheduled, not human-driven)

```bash
# Held focus for over a minute, zero keyboard/mouse input — not a human
sr apps --resolve SRUDB.dat \
  | jq '.[] | select(.automated_execution == true) | {app_name, timestamp, focus_time_ms, user_input_time_ms}'
```

### Detect cover-UI malware (decoy window hiding background work)

```bash
# 10:1 background-to-foreground CPU ratio + false foreground claim
sr apps SRUDB.dat \
  | jq '.[] | select(.background_cpu_dominant == true and .phantom_foreground == true)'
```

### Find the exfiltration fingerprint

```bash
# Background-only process + significant outbound transfer in the same interval
sr timeline --resolve SRUDB.dat \
  | jq '.[] | select(.exfil_signal == true) | {app_name, timestamp, bytes_sent, focus_time_ms}'
```

### Network traffic when no human was present

```bash
# Data moved while the user was away from the keyboard
sr timeline SRUDB.dat \
  | jq '.[] | select(.source_table == "network" and .user_present == null)'
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

Every alternative either requires Windows, needs a Python environment, or costs money. None of them surfaces Application Timeline engagement data in their forensic output. `sr` is a static binary you compile once and copy anywhere — and it applies heuristics in the parse path, including the engagement signals that answer whether a human was actually present.

| | srum-forensic | KAPE + EZTools | python-libESE | Arsenal SRUM |
|--|:-:|:-:|:-:|:-:|
| Runs on Linux / macOS | ✅ | — | ✅ | — |
| Single static binary | ✅ | — | — | — |
| No Python runtime | ✅ | — | — | ✅ |
| Free & open source | ✅ | partial | ✅ | — |
| JSON output | ✅ | — | — | — |
| CSV output | ✅ | ✅ | — | ✅ |
| 6 SRUM tables | ✅ | ✅ | — | ✅ |
| Application Timeline | ✅ | — | — | — |
| Focus + input time merged into apps | ✅ | — | — | — |
| User engagement detection | ✅ | — | — | — |
| Inline ID resolution | ✅ | — | — | — |
| Unified timeline | ✅ | — | — | — |
| Forensic heuristics (10 signals) | ✅ | — | — | — |
| Cross-table exfiltration detection | ✅ | — | — | — |
| User presence annotation | ✅ | — | — | — |
| Pipe-friendly | ✅ | — | — | — |
| Zero-copy mmap I/O | ✅ | — | — | — |
| ESE parsed in Rust | ✅ | — | — | — |
| Structural integrity checks | ✅ | — | — | — |
| Forensic copy support | ✅ | ✅ | ✅ | ✅ |

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

Merges all tables into a single chronological stream. Each record includes a `"source_table"` field identifying its source. Apps records receive merged focus data and all per-record heuristic flags. Cross-table signals (`exfil_signal`, `user_present`) are applied to the full merged set. Exits 0 even if individual tables fail (best-effort).

```json
[
  {
    "source_table": "network",
    "timestamp": "2024-06-15T07:00:00Z",
    "app_id": 42,
    "bytes_sent": 209715200,
    "bytes_recv": 512,
    "user_present": true
  },
  {
    "source_table": "apps",
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
| [`srum-analysis`](crates/srum-analysis/) | Forensic analysis pipeline — `build_timeline`, all 10 heuristics, cross-table signals, `compute_findings`, gap/session/stats/hunt/compare analysis |
| [`sr-cli`](crates/sr-cli/) | `sr` binary — `network`, `apps`, `app-timeline`, `connectivity`, `energy`, `notifications`, `timeline`, `idmap` subcommands; `--format json/csv`; `--resolve` |
| [`ese-test-fixtures`](crates/ese-test-fixtures/) | Shared test fixture builders — dev-dependency only, never ships |

</details>

```toml
# Use the parser in your own project
[dependencies]
srum-parser   = "0.1"
srum-analysis = "0.1"
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

The Application Timeline table records two fields that no other SRUM parser exposes for forensic use: `InFocusDurationMS` (how long each app held keyboard/mouse focus) and `UserInputMS` (how long there was actual user input while the app was focused). These fields are the foundation of the engagement-detection heuristics — `automated_execution`, `phantom_foreground`, `no_focus_with_cpu`, `interactivity_ratio` — and of the `user_present` cross-table annotation. No other open-source SRUM tool merges this data into the analysis output.

---

## Acknowledgements

**Mark Russinovich** and the Windows Internals team whose documentation of ESE/JET Blue made this possible without reverse engineering.

**Yogesh Khatri** (@SwiftForensics) whose [srum-dump](https://github.com/MarkBaggett/srum-dump) Python tool proved the forensic value of SRUM data and documented the table schemas.

**Mark Baggett** whose original Python scripts brought SRUM analysis into mainstream DFIR workflows.

The Rust [binrw](https://github.com/jam1garner/binrw) team for making binary parsing declarative and safe.

---

[Privacy Policy](https://securityronin.github.io/srum-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/srum-forensic/terms/) · © 2026 Security Ronin Ltd.
