# srum-forensic

**Did a human engage with that app — or did it run itself? SRUM has the answer.**

Most forensic tools can tell you an app was running at a given time. `srum4n6` tells you whether a human was actually at the keyboard using it.

Windows records two fields that no other SRUM parser surfaces for forensic use: `InFocusDurationMS` — how long an app held keyboard and mouse focus — and `UserInputMS` — how long there was genuine user input while it was focused. Combined with CPU cycles and network bytes from the other SRUM tables, these fields draw a sharp line between:

- A process that **ran in the background** with zero human interaction (malware, scheduled tasks, C2 beaconing)
- An app that **a human actively used** (focus time, keystrokes, mouse clicks recorded)

`srum4n6` is a single static Rust binary. It parses `SRUDB.dat` directly — no Windows, no Python, no COM interop — and applies 10 forensic heuristics in the parse path, including cross-table exfiltration signals and per-interval user presence annotation.

## Quick start

```bash
cargo install srum-forensic

# Was anyone at the keyboard during this incident window?
srum4n6 timeline --resolve SRUDB.dat \
  | jq '.[] | select(.timestamp | startswith("2024-11-14T02")) | {app_name, user_present, focus_time_ms, user_input_time_ms}'

# Find processes that ran but no human ever interacted with them
srum4n6 apps --resolve SRUDB.dat \
  | jq '.[] | select(.no_focus_with_cpu == true) | {app_name, timestamp, background_cycles}'
```

## The crates

This is a Cargo workspace; the crates are usable independently:

- `ese-core` — ESE/JET Blue binary format parser: memory-mapped page I/O, B-tree walking, catalog, zero-copy `raw_page_slice`
- `ese-integrity` — structural anomaly detection: dirty state, timestamp skew, slack-space scanning
- `ese-carver` — page carving: detect and reconstruct records split across page boundaries
- `srum-core` — SRUM record type definitions
- `srum-parser` — high-level parse API
- `srum-analysis` — forensic analysis pipeline: `build_timeline`, the 10 heuristics, cross-table signals, `compute_findings`
- `srum-cli` — the `srum4n6` binary

## Structural integrity checks

`ese-integrity` checks three structural anomalies at the binary level — raw facts, not forensic conclusions: **dirty shutdown** (`db_state == 2`), **timestamp skew** (a page written after its header was sealed), and **slack-space residue** (records deleted without zeroing). See the [Validation](validation-report.md) report for evidence against real artifacts.

## Where this fits

`srum-forensic` is the SRUM PARSER for the SecurityRonin forensic family — it interprets ESE page bytes as `SrumRecord`s and emits findings onto the shared [`forensicnomicon`](https://crates.io/crates/forensicnomicon) reporting vocabulary so they aggregate with the rest of the fleet.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/srum-forensic) · © 2026 Security Ronin Ltd
