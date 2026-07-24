# 7. Crate/binary naming: the srum-* suite and the srum4n6 CLI

Date: 2026-07-24
Status: Accepted

## Context

Early revisions named the front-end crates `sr-cli` and `sr-gui` with a `sr`
binary. A two-letter `sr` prefix is not self-describing on crates.io — read bare
in search or a dependency list it claims nothing — and the `sr` binary name
collides with common tooling and reads as noise to an examiner. The fleet naming
grammar (`ronin-issen/CLAUDE.md`) requires a distinctive, self-describing prefix
and the `<x>4n6` front-end binary convention.

## Decision

Rename the suite to the `srum-` prefix — `srum-core`, `srum-parser`,
`srum-schema`, `srum-analysis`, `srum-cli`, `srum-gui` — and name the CLI binary
`srum4n6` (`crates/srum-cli/Cargo.toml` `[[bin]] name = "srum4n6"`), following
the `br4n6`/`ev4n6`/`disk4n6` convention (commits `0855c55` "sr-cli -> srum-cli
(bin srum4n6), sr-gui -> srum-gui" and `24ce340` "complete srum4n6 rename").
`srum` is a distinctive prefix that stands alone, so this is Pattern B with the
short prefix; there is no `srum-forensic` crate — the repo is the umbrella.

## Consequences

The crate names are self-describing on crates.io and the binary name matches the
fleet `<x>4n6` muscle memory. The repo directory name `srum-forensic` is the
umbrella, deliberately not a crate. Residual doc lag: `docs/validation-report.md`
still refers to the tool as `sr` (its header predates the rename) — a doc-only
inconsistency, not a code one.
