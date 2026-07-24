# 6. jiff as the timestamp library (migrated from chrono)

Date: 2026-07-24
Status: Accepted

## Context

SRUM records carry two Windows time encodings: FILETIME (100-ns ticks since
1601-01-01) on most tables and OLE Automation Dates (an `f64` of days since
1899-12-30) on the raw ESE network/app records. Converting these to a real
timestamp for serialization needs a date/time library, and the choice is a
public-API commitment because `srum-core`'s conversion helpers return that
library's type.

## Decision

Use `jiff` (with the `serde` feature) as the workspace time library
(`Cargo.toml` `[workspace.dependencies]` `jiff = { version = "0.2", features =
["serde"] }`), matching the fleet standard. `srum-core` exposes
`filetime_to_datetime` and `ole_date_to_datetime` returning `jiff::Timestamp`,
with the `FILETIME_EPOCH_OFFSET` constant centralized in one place
(`crates/srum-core/src/lib.rs`). This replaced an earlier `chrono` dependency in
a deliberate breaking change (commit `3572c78` "refactor!: migrate chrono → jiff
(breaking public API)").

## Consequences

One time library across the SRUM crates and consistent with the rest of the
fleet. The migration was a breaking change for any consumer built against the
`chrono` types the conversion helpers used to return. The non-finite OLE-date
path clamps to the epoch rather than panicking (unit-tested:
`ole_date_to_datetime_non_finite_clamps_to_epoch`), keeping the conversion total.
