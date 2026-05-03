[![Crates.io](https://img.shields.io/crates/v/srum-forensic.svg)](https://crates.io/crates/srum-forensic)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/srum-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/srum-forensic/actions/workflows/ci.yml)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

# srum-forensic

**Parse Windows SRUM activity logs. No Windows required.**

Every running process leaves evidence in `SRUDB.dat` — network bytes sent, CPU cycles burned, foreground time, background time — recorded hourly by Windows since 8.1. Every DFIR practitioner knows this. Almost no tool parses it from a Linux analysis workstation without a Python runtime or COM interop.

`sr` does it with a single Rust binary.

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

## Three Things You Do With This

### Hunt lateral movement — who sent how much, from which process

```bash
# Every process that sent data — sorted by bytes, highest first
sr network SRUDB.dat \
  | jq -r '.[] | [.app_id, .bytes_sent, .bytes_recv, .timestamp] | @tsv' \
  | sort -t$'\t' -k2 -rn \
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

### Feed your SIEM

```bash
sr network SRUDB.dat >> srum_network.ndjson
sr apps SRUDB.dat    >> srum_apps.ndjson
```

Both subcommands output JSON arrays. Pipe to `jq -c '.[]'` for NDJSON, redirect to files, or POST directly to Elasticsearch. The schema is stable and documented.

---

## What's Different

Every alternative either requires Windows, needs a Python environment, or costs money. This one is a static binary you compile once and copy anywhere.

| | srum-forensic | KAPE + EZTools | python-libESE | Arsenal SRUM |
|--|:-:|:-:|:-:|:-:|
| Runs on Linux / macOS | Y | — | Y | — |
| Single static binary | Y | — | — | — |
| No Python runtime | Y | — | — | Y |
| Free & open source | Y | partial | Y | — |
| JSON output | Y | — | — | — |
| Pipe-friendly | Y | — | — | — |
| ESE parsed in Rust | Y | — | — | — |
| Forensic copy support | Y | Y | Y | Y |

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

`app_id` and `user_id` are integer keys into the `SruDbIdMapTable`. Run `sr idmap <path>` to resolve them to process names and SIDs.

---

## Crate Structure

This is a Cargo workspace — use the crates independently in your own tools:

| Crate | What it does |
|-------|-------------|
| [`ese-core`](crates/ese-core/) | ESE/JET Blue binary format parser — page reading, B-tree walking |
| [`srum-core`](crates/srum-core/) | SRUM record type definitions — `NetworkUsageRecord`, `AppUsageRecord`, `IdMapEntry` |
| [`srum-parser`](crates/srum-parser/) | High-level API — `parse_network_usage(path)`, `parse_app_usage(path)` |
| [`sr-cli`](crates/sr-cli/) | `sr` binary — wraps srum-parser, outputs JSON |

```toml
# Use the parser in your own project
[dependencies]
srum-parser = "0.1"
```

---

## SRUM Background

Windows System Resource Usage Monitor (`srum`) has been running since Windows 8.1. It records a snapshot every hour to `C:\Windows\System32\sru\SRUDB.dat` — an ESE (Extensible Storage Engine, also called JET Blue) database, the same format used by Exchange, Active Directory, and Windows Search.

On a live system the file is locked by `svchost.exe`. Forensic analysis always operates on a copy: VSS snapshot, image acquisition, or memory-assisted extraction.

The database contains multiple tables identified by GUID. This tool currently supports:

- `{973F5D5C-1D90-4944-BE8E-24B22A728CF2}` — Network Data Usage
- `{5C8CF1C7-7257-4F13-B223-970EF5939312}` — Application Resource Usage
- `SruDbIdMapTable` — Integer ID → process name / SID mapping

---

## Acknowledgements

**Mark Russinovich** and the Windows Internals team whose documentation of ESE/JET Blue made this possible without reverse engineering.

**Yogesh Khatri** (@SwiftForensics) whose [srum-dump](https://github.com/MarkBaggett/srum-dump) Python tool proved the forensic value of SRUM data and documented the table schemas.

**Mark Baggett** whose original Python scripts brought SRUM analysis into mainstream DFIR workflows.

The Rust [binrw](https://github.com/jam1garner/binrw) team for making binary parsing declarative and safe.

---

[Privacy Policy](https://securityronin.github.io/srum-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/srum-forensic/terms/) · © 2026 Security Ronin Ltd.
