[![Stars](https://img.shields.io/github/stars/SecurityRonin/srum-forensic?style=flat-square)](https://github.com/SecurityRonin/srum-forensic/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/srum-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/srum-forensic/actions/workflows/ci.yml)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](#install)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

# srum-forensic

**Parse Windows SRUM activity logs. Check ESE structural integrity. No Windows required.**

Every running process leaves evidence in `SRUDB.dat` — network bytes sent, CPU cycles burned, foreground time, background time — recorded hourly by Windows since 8.1. Every DFIR practitioner knows this. Almost no tool parses it from a Linux analysis workstation without a Python runtime or COM interop.

`sr` does it with a single Rust binary. And it tells you when the database has been tampered with.

```bash
cargo install srum-forensic
sr network /mnt/evidence/SRUDB.dat | jq '.[] | select(.bytes_sent > 1000000)'
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

| Subcommand | SRUM Table | What It Shows |
|---|---|---|
| `sr network` | Network Data Usage | Per-process bytes sent/received per hour |
| `sr apps` | Application Resource Usage | Per-process foreground/background CPU cycles |
| `sr connectivity` | Network Connectivity | Profile connection time per app |
| `sr energy` | Energy Usage | Charge level and energy consumed per app |
| `sr notifications` | Push Notifications | Notification type and count per app |
| `sr idmap` | SruDbIdMapTable | Integer ID → process name / SID mapping |
| `sr timeline` | All of the above | Unified chronological view, all tables merged |

All subcommands accept `--format json` (default) or `--format csv`.
`network`, `apps`, `connectivity`, and `notifications` accept `--resolve` to inline names from the ID map.

### Hunt lateral movement — who sent how much, from which process

```bash
# Every process that sent data — resolved names, sorted by bytes, highest first
sr network --resolve --format csv SRUDB.dat \
  | sort -t, -k5 -rn \
  | head -20
```

SRUM records per-process network usage every hour. Unusual bytes on a dormant host — exfil, C2 beacons, or an admin tool running where it shouldn't — show up immediately.

### Profile execution — what ran, for how long

```bash
# All background CPU cycles — ransomware loves these
sr apps SRUDB.dat \
  | jq '.[] | select(.background_cycles > 0) | {app_id, background_cycles, timestamp}'
```

Application usage records track foreground and background CPU cycles for every executable. Background activity with no corresponding foreground session is a red flag.

### Build a unified activity timeline

```bash
# All SRUM evidence sorted chronologically — one command
sr timeline SRUDB.dat | jq '.[] | select(.table == "network")'
```

`sr timeline` loads all tables in a single pass, merges them, and sorts by timestamp. Useful for reconstructing an incident timeline without running five separate commands and manually correlating the output.

### Feed your SIEM

```bash
sr network SRUDB.dat --format csv >> srum_network.csv
sr apps    SRUDB.dat              >> srum_apps.ndjson
```

All subcommands output JSON arrays by default. Pass `--format csv` for flat CSV. Pipe JSON to `jq -c '.[]'` for NDJSON, redirect to files, or POST directly to Elasticsearch. The schema is stable and documented.

---

## What's Different

Every alternative either requires Windows, needs a Python environment, or costs money. This one is a static binary you compile once and copy anywhere.

| | srum-forensic | KAPE + EZTools | python-libESE | Arsenal SRUM |
|--|:-:|:-:|:-:|:-:|
| Runs on Linux / macOS | ✓ | — | ✓ | — |
| Single static binary | ✓ | — | — | — |
| No Python runtime | ✓ | — | — | ✓ |
| Free & open source | ✓ | partial | ✓ | — |
| JSON output | ✓ | — | — | — |
| CSV output | ✓ | ✓ | — | ✓ |
| 5 SRUM tables | ✓ | ✓ | — | ✓ |
| Inline ID resolution | ✓ | — | — | — |
| Unified timeline | ✓ | — | — | — |
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

Records from the `{5C8CF1C7-7257-4F13-B223-970EF5939312}` SRUM table.

```json
[
  {
    "timestamp": "2024-06-15T08:00:00Z",
    "app_id": 42,
    "user_id": 1,
    "foreground_cycles": 12500000,
    "background_cycles": 450000
  }
]
```

`app_id` and `user_id` are integer keys into the `SruDbIdMapTable`. Pass `--resolve`
to inline the names directly into the output — no jq, no temp files:

```bash
sr network       --resolve SRUDB.dat
sr apps          --resolve SRUDB.dat
sr connectivity  --resolve SRUDB.dat
sr notifications --resolve SRUDB.dat
```

Resolution is best-effort: records whose IDs are absent from the map keep their
raw integer values and no `app_name`/`user_name` field is injected.

### `sr network --resolve <path>`

```json
[
  {
    "timestamp": "2024-06-15T08:00:00Z",
    "app_id": 42,
    "app_name": "\\Device\\HarddiskVolume3\\Windows\\svchost.exe",
    "user_id": 1,
    "user_name": "S-1-5-21-1234567890-123456789-1234567890-1001",
    "bytes_sent": 1048576,
    "bytes_recv": 8388608
  }
]
```

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

Merges all tables, sorted by timestamp. Each record includes a `"table"` field
identifying its source. Exits 0 even if individual tables fail (best-effort).

```json
[
  {
    "table": "network",
    "timestamp": "2024-06-15T07:00:00Z",
    "app_id": 42,
    "bytes_sent": 512,
    "bytes_recv": 1024
  },
  {
    "table": "apps",
    "timestamp": "2024-06-15T08:00:00Z",
    "app_id": 42,
    "foreground_cycles": 12500000,
    "background_cycles": 0
  }
]
```

Pass `--format csv` to any subcommand for flat CSV output instead of JSON:

```bash
sr network --format csv SRUDB.dat > network.csv
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
| [`srum-core`](crates/srum-core/) | SRUM record type definitions — `NetworkUsageRecord`, `AppUsageRecord`, `NetworkConnectivityRecord`, `EnergyUsageRecord`, `PushNotificationRecord`, `IdMapEntry` |
| [`srum-parser`](crates/srum-parser/) | High-level API — `parse_network_usage`, `parse_app_usage`, `parse_network_connectivity`, `parse_energy_usage`, `parse_push_notifications`, `parse_id_map` |
| [`sr-cli`](crates/sr-cli/) | `sr` binary — `network`, `apps`, `connectivity`, `energy`, `notifications`, `timeline`, `idmap` subcommands; `--format json/csv`; `--resolve` |
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

This matters in practice: a 200 MB `SRUDB.dat` is mapped in one `mmap(2)` call. A linear integrity scan over all pages costs zero `read(2)` syscalls.

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
- `SruDbIdMapTable` — Integer ID → process name / SID mapping (`sr idmap`)

---

## Acknowledgements

**Mark Russinovich** and the Windows Internals team whose documentation of ESE/JET Blue made this possible without reverse engineering.

**Yogesh Khatri** (@SwiftForensics) whose [srum-dump](https://github.com/MarkBaggett/srum-dump) Python tool proved the forensic value of SRUM data and documented the table schemas.

**Mark Baggett** whose original Python scripts brought SRUM analysis into mainstream DFIR workflows.

The Rust [binrw](https://github.com/jam1garner/binrw) team for making binary parsing declarative and safe.

---

[Privacy Policy](https://securityronin.github.io/srum-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/srum-forensic/terms/) · © 2026 Security Ronin Ltd.
