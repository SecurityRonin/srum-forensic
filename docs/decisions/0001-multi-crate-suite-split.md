# 1. Multi-crate suite split by concern

Date: 2026-07-24
Status: Accepted

## Context

SRUM analysis spans several distinct concerns: the record data types, the raw
`SRUDB.dat` record decoder, a static table/column schema lookup, the forensic
analysis pipeline (heuristics, ID resolution, timeline building), and two front
ends — a CLI and a GUI. A single crate would couple the medium-agnostic parser
to the binaries and force a Rust consumer that only wants the SRUM record types
to compile the whole surface (including the Tauri GUI stack).

## Decision

Split the workspace into six crates by concern (root `Cargo.toml` `members`):

- `srum-core` — pure record types + FILETIME/OLE-date conversions, no parsing
  (`crates/srum-core/src/lib.rs`: "pure data types with no parsing logic").
- `srum-parser` — decodes SRUM records from ESE database files.
- `srum-schema` — thin compile-time GUID→name and column-schema lookup.
- `srum-analysis` — the forensic analysis pipeline, deliberately
  **shared between `srum-cli` and `srum-gui`** (crate description) so both front
  ends run identical heuristics.
- `srum-cli` — the `srum4n6` binary.
- `srum-gui` — the Tauri "SRUM Examiner" front end.

The suite uses the distinctive `srum-` prefix (Pattern B, multi-crate suite,
per `ronin-issen/CLAUDE.md` "Crate naming grammar"). There is deliberately **no
`srum-forensic` crate** — the repo name is the umbrella, not a crate.

## Consequences

The analysis pipeline is a single source of truth the CLI and GUI both consume,
so a heuristic fix reaches both at once. Each library crate is independently
publishable and versioned (`srum-core` 0.2, `srum-parser` 0.3, `srum-schema`
0.1, `srum-analysis` 0.4). The layering must stay acyclic: types flow up from
`srum-core` through `srum-parser`/`srum-schema` into `srum-analysis`, and only
the front ends depend on the pipeline.
