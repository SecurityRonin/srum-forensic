# 5. srum-analysis findings convert to the canonical forensicnomicon::report model

Date: 2026-07-24
Status: Accepted

## Context

Every analyzer in the fleet should be able to emit its findings in the single
`forensicnomicon::report` vocabulary so that ORCHESTRATION (Issen) and a future
GUI can render them uniformly instead of N bespoke `XxxAnalysis` types
(`ronin-issen/CLAUDE.md` "The Reporting Model"). `srum-analysis` produces its own
triage `FindingCard` type, which the front ends render directly.

## Decision

`srum-analysis` keeps `FindingCard` as its analysis-facing output:
`compute_findings` (`crates/srum-analysis/src/findings.rs`) aggregates per-flag
`FindingCard`s, and the front ends consume that vector as-is (the GUI takes
`Vec<FindingCard>` from `compute_findings` in
`crates/srum-gui/src-tauri/src/commands.rs`).

For fleet aggregation, `FindingCard::to_finding(Source)`
(`crates/srum-analysis/src/record.rs`) converts a triage card into a canonical
`forensicnomicon::report::Finding` — mapping the triage severity
(`Clean`/`Informational`/`Suspicious`/`Critical`) onto the shared 5-level scale
and emitting a `SRUM-<filter_flag>` code (Threat category when MITRE techniques
are present, else code-classified). This was added as a purely **additive**
conversion helper (commit `1e11c59` "feat(srum-analysis)!: FindingCard ->
canonical report::Finding", whose own message notes "Additive — existing API
unchanged", `srum-analysis` 0.1.0 -> 0.2.0 minor bump; `bf1d27e` the RED test).
`FindingCard`/`Severity`/`TemporalSpan` were retained and no consumer was broken.

## Consequences

A SRUM triage card can drop into an Issen `Report` alongside every other analyzer
via `to_finding`, inheriting the shared `Severity`/`Category`/`code` conventions
and the "observation, never a legal conclusion" discipline. Because the helper is
additive, front ends that render `FindingCard` were unaffected. The orchestration
wiring that calls `to_finding` is not yet in place — today the conversion is
exercised only by a unit test
(`crates/srum-analysis/tests/finding_card_tests.rs`), and the shipping front-end
output remains `Vec<FindingCard>`.
