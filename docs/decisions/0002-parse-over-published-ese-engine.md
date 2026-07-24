# 2. Parse SRUM over the published ESE engine crates

Date: 2026-07-24
Status: Accepted

## Context

`SRUDB.dat` is an ESE (JET Blue / `.edb`) database: reading it means B-tree and
page navigation, catalog resolution, and page-checksum validation — a large
untrusted-input surface. The fleet already owns that engine in the
`ese-forensic` repo (`ese-core` reader + `ese-integrity` auditor). Early
revisions of this repo carried a bundled local copy of that engine.

## Decision

`srum-parser` depends on the **published** fleet ESE crates rather than a
bundled reader: `ese-core = "0.2"` and `forensicnomicon = "1"` are runtime deps;
`ese-integrity = "0.3"` and `ese-test-fixtures` (dev-only, `publish = false`,
git rev-pinned) are dev-dependencies (`crates/srum-parser/Cargo.toml`;
`Cargo.toml` `[workspace.dependencies]`). The local ESE copies were dropped
(commit `d5d4a54` "depend on published ese-* crates, drop local copies"), and
`forensicnomicon` was migrated from a path dep to the registry crate (commit
`32e3ec4`). This follows the constitution's "prefer our own crates" and "prefer
the published registry crate over a path dependency" rules.

`srum-parser` is therefore the PARSER layer over the CONTAINER/engine: the
container robustness burden (panic-free, fuzzed, bounds-checked B-tree/page
reads) lives **upstream in `ese-forensic`**. This is why `srum-forensic` itself
declares no `[workspace.lints.rust]` `unsafe_code = "forbid"` and no
`unwrap_used`/`expect_used` panic lints, and ships no `fuzz/` targets — the
attacker-controllable page/B-tree parsing it would need to fuzz is not in this
repo.

## Consequences

No duplicate ESE engine to maintain; an upstream `ese-core`/`ese-integrity` fix
reaches SRUM by a version bump. The cost is a dependency on the published `ese-*`
crates plus one dev-only git rev-pin for the fixture builder. This repo's
robustness posture is inherited from `ese-forensic`'s Paranoid-Gatekeeper
guarantees — with the caveat that `srum-parser`'s own record-delta decoders
still bounds-check by hand (ADR 0003), so the panic-free property is verified per
decoder, not enforced fleet-wide by a workspace lint here.
