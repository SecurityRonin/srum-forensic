# Ralph Agent Task — srum-forensic

Implement features from user stories using strict TDD until all stories pass.

## Project

Rust workspace at the repo root. Four crates:
- `crates/ese-core` — ESE binary format parser
- `crates/srum-core` — record type definitions
- `crates/srum-parser` — high-level parse API
- `crates/sr-cli` — `sr` binary

Test commands:
- Single crate: `cargo test -p ese-core`
- Full workspace: `cargo test --workspace`
- Build check: `cargo build --workspace`
- Clippy: `cargo clippy --workspace --all-targets -- -D warnings`

## Mandatory TDD Protocol

**CLAUDE.md in this repo enforces strict Red-Green-Refactor. Every cycle requires two separate commits:**

1. **RED commit** — failing tests only, no implementation. Prefix: `test(red):`
2. **GREEN commit** — minimal implementation that makes tests pass. Prefix: `feat:`

Never write implementation before tests. A compilation failure is a valid RED state in Rust.

## Workflow Per Iteration

1. Read `scripts/ralph/log.md` to understand what previous iterations completed.

2. Open `docs/user-stories/` and find stories with `"passes": false`. Process them in dependency order:
   - `ese-page-header.json` → `ese-page-tags.json` → `ese-catalog.json` → `ese-btree-walk.json`
   - Then `srum-network-parsing.json`, `srum-app-parsing.json`, `srum-idmap.json`

3. If all stories have `"passes": true`:
   - Output: `<promise>FINISHED</promise>`

4. Pick the **first unfinished story** in dependency order.

5. For each acceptance criterion:
   - Write a failing test (RED) — run `cargo test -p <crate>` and confirm it fails
   - Commit: `test(red): <crate> — <brief description>`
   - Write minimal implementation (GREEN) — run `cargo test -p <crate>` and confirm it passes
   - Commit: `feat: GREEN — <crate> <brief description>`

6. After all criteria in the story pass:
   - Run `cargo test --workspace` — confirm zero failures
   - Run `cargo clippy --workspace --all-targets -- -D warnings` — fix any warnings
   - Update the story's `"passes"` field to `true`
   - Append a summary to `scripts/ralph/log.md`
   - Commit the story and log update: `chore: mark <story> passing`

7. End the iteration. Next iteration picks up the next story.

## ESE Format Reference

Pages are fixed-size (page_size from header, typically 4096 bytes). Page 0 is the header; data pages start at page 1.

**Page header (40 bytes, Vista+ "new" format):**
- Offset 0x00 (4): checksum (XOR-based, skip validation for now)
- Offset 0x04 (8): database time
- Offset 0x0C (4): previous page number (0xFFFFFFFF = none)
- Offset 0x10 (4): next page number (0xFFFFFFFF = none)
- Offset 0x14 (4): father data page (FDP) object ID
- Offset 0x18 (2): available data size
- Offset 0x1A (2): available uncommitted data
- Offset 0x1C (2): available data offset
- Offset 0x1E (2): available page tag count
- Offset 0x20 (4): page flags

**Page flag constants:**
- `0x0001` = Root page
- `0x0002` = Leaf page
- `0x0004` = Parent page (internal B-tree node)
- `0x0008` = Empty page
- `0x0400` = Space tree page

**Tag array (at end of page, growing downward):**
- Tags are stored from the END of the page, each tag is 4 bytes
- Tag: bits 0-14 = value offset, bits 16-30 = value size, bit 15 and 31 = flags
- Tag 0 is the page header tag (skip it for data records)
- Tags are at: `page_data[page_size - (i+1)*4 ..]` for tag index i

**Catalog (page 4):**
- Root of the ESE catalog B-tree
- Each catalog record has fixed columns: object type (1=table, 2=column, etc.), object ID, parent ID, name (variable)
- Column IDs of interest: 1=ObjType, 2=ObjId, 3=ParentObjId, 128+=variable (name at column 255 typically)

**Windows FILETIME:**
- 64-bit LE integer: 100-nanosecond intervals since 1601-01-01 00:00:00 UTC
- Convert to Unix timestamp: `(filetime - 116444736000000000) / 10_000_000`

## Notes

- Build synthetic ESE test fixtures in test helpers, not external files
- All types must implement `Debug`; network/app records need `serde::Serialize`
- Keep each impl minimal — only what tests require

## Completion

When ALL user stories have `"passes": true`:

<promise>FINISHED</promise>
