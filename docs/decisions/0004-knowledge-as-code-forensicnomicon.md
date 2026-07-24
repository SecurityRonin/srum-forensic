# 4. Format constants, schema, and heuristic thresholds live in forensicnomicon

Date: 2026-07-24
Status: Accepted

## Context

SRUM table GUIDs, per-table column schemas, and the thresholds behind the
exfiltration heuristics (bytes-sent volume, sent/received ratio) are facts about
the format and the analytic model — not parsing algorithm. Baking them into the
parser or analysis crates as magic constants would duplicate them across the
fleet and let them drift out of sync with the rest of the SRUM tooling.

## Decision

Source these facts from the `forensicnomicon` KNOWLEDGE leaf (the fleet's
zero-dependency, compile-time artifact-spec crate):

- **Table GUIDs**: `srum-parser` imports `forensicnomicon::srum::{TABLE_NETWORK_USAGE,
  TABLE_APP_RESOURCE_USAGE, TABLE_ID_MAP, ...}` (`crates/srum-parser/src/lib.rs`)
  instead of hard-coding GUID strings.
- **Heuristic predicates**: the analysis pipeline calls
  `forensicnomicon::heuristics::srum::{is_exfil_volume, is_exfil_ratio}`
  (`crates/srum-analysis/src/pipeline.rs`) rather than defining local thresholds.
- **Schema lookup**: `srum-schema` is a thin compile-time layer built on
  `forensicnomicon` (`crates/srum-schema/Cargo.toml`), exposing GUID→name and
  column definitions with zero lookup-time allocation.

`forensicnomicon` is consumed as the published registry crate (commit `32e3ec4`).

## Consequences

Table identity and heuristic thresholds are versioned in one place; a
`forensicnomicon` minor bump propagates a corrected GUID or a re-tuned exfil
threshold to every consumer. The analysis crate carries no format magic. The
cost is that changing a threshold is a `forensicnomicon` release, not a local
edit — deliberate, so the whole fleet moves together.
