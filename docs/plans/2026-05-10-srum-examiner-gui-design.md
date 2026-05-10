# SRUM Examiner — GUI Design

**Date:** 2026-05-10
**Status:** Approved

---

## Goal

Build **SRUM Examiner**: a cross-platform native GUI application that makes SRUM forensic analysis accessible to in-house corporate DFIR specialists — analysts who run the same investigation patterns daily but are not CLI-fluent. The tool surfaces conclusions, not raw data.

---

## Target User

**In-house corporate DFIR specialist.** Not a freelance IR responder (those find and adopt `sr` directly — a marketing problem, not a design problem). The in-house specialist:

- Knows what SRUM is and what it records
- Runs the same investigation workflows repeatedly: misconduct, malware, exfiltration
- Is not versatile across tooling — needs the tool to meet them where they are
- Needs to hand findings to management, legal, or HR in plain language
- Works on a dedicated analysis workstation (not air-gapped, but offline-capable)

---

## Architecture

### Crate layout

New `crates/sr-gui` workspace member. Tauri 2.0 app — Rust process is the application host and data layer; React (Vite + TypeScript) is the UI.

```
crates/sr-gui/
  src-tauri/
    src/
      commands.rs     ← #[tauri::command]: open_file, get_timeline, get_stats
      main.rs
    Cargo.toml        ← deps: srum-parser, srum-core, forensicnomicon
    tauri.conf.json
  src/
    App.tsx
    components/
      Dashboard.tsx     ← finding cards strip
      Timeline.tsx      ← main investigation table (TanStack Table)
      RecordDetail.tsx  ← right-side panel on row click
      SignalChart.tsx   ← 4-way signal bar (Recharts)
      FilterBar.tsx     ← app / time range / table / flag filters
```

### Data flow

1. Analyst opens SRUDB.dat via native file picker (Tauri dialog API)
2. Tauri `open_file` command calls `srum_parser::parse_*` for all tables directly — no subprocess, no PATH dependency
3. Rust builds unified timeline in memory, applies all heuristics, computes finding cards
4. Serialises once to JSON → React holds entire dataset in state
5. All filtering, sorting, column toggling is client-side — zero round trips after initial parse

### Why embed srum-parser directly

Zero latency, no shell spawning, no `sr` on PATH requirement. The SRUM Examiner binary *is* the parser. Same forensicnomicon heuristics as the CLI, always in sync.

---

## UI Layout

### Dashboard strip (~20% of screen height)

**Conclusions first, data second.** Cards are computed at parse time from the heuristic output. Each card states a forensic conclusion in plain English, ranked by confidence. Clicking a card filters the timeline to that signal.

Example cards:

```
┌──────────────────────────────┐  ┌──────────────────────────────┐  ┌──────────────────────────────┐
│ ● AUTOMATED EXECUTION        │  │ ● POSSIBLE BEACONING         │  │ ● EXFILTRATION SIGNAL        │
│ powershell.exe               │  │ svchost.exe                  │  │ chrome.exe                   │
│ 4h 23m focus, zero input     │  │ 5-min intervals × 47         │  │ 2.3 GB sent, no fg activity  │
│ T1059 · T1086                │  │ T1071                        │  │ T1048                        │
└──────────────────────────────┘  └──────────────────────────────┘  └──────────────────────────────┘
```

Cards scroll horizontally for many findings. Empty state: "No suspicious activity detected." Cards are color-coded by severity (see Color System).

### Timeline (~80% of screen height)

Full-width table. Each row = one SRUM record from any table. Columns:

| Column | Content |
|---|---|
| Timestamp | ISO 8601, local timezone |
| Source | Table name (color-coded label) |
| App | Resolved name from ID map |
| Key metric | Bytes / CPU cycles / focus ms (contextual per table) |
| Flags | Heuristic badge icons |

Rows with active flags have a left-border stripe in the highest-severity flag color. Unflagged rows have no border — they visually recede so flagged rows pop.

**Row click → right-side panel** (slides in without leaving the timeline):

- **4-way signal bar** — four horizontal segments: background CPU · foreground CPU · focus time · user input time. The gaps between segments are where the forensic story lives.
- **Plain-English interpretation** — e.g. "This process held focus for 45 minutes but received no keyboard or mouse input. Consistent with scripted execution."
- MITRE ATT&CK technique tags
- Raw field values for analysts who want them

**Filter bar** above timeline: app name (typeahead), time range picker, table selector, flag filter. All filtering is instant — no round trips.

---

## Visual Design Language

### Philosophy

Color is semantic, not decorative. Every color means something specific. The analyst's eye goes straight to the problem without reading a word. Inspired by btop's approach to making dense data instantly scannable.

**Dark background** — forensics tools live in dimmed labs and night shifts.

### Severity palette

| Color | Hex | Meaning | Applied to |
|---|---|---|---|
| Red | `#FF4757` | Critical — high-confidence threat | Automated execution, beaconing, exfil signal |
| Amber | `#FFA502` | Suspicious — warrants investigation | Suspicious path, masquerade candidate, notification C2 |
| Blue | `#1E90FF` | Informational — anomalous but ambiguous | Low interactivity ratio, autoinc gaps |
| Green | `#2ED573` | Clean — no flags | Unflagged records |
| Gray | `#747D8C` | Metadata / structural | Timestamps, column headers, table source labels |

### 4-way signal bar

Each segment uses the severity palette with deliberate forensic meaning:

```
Background CPU   Foreground CPU     Focus time       User input time
[████ red ████] [███ amber ████] [██ blue ███████] [█ green █████████]
 (automated)      (visible)         (user present)    (user active)
```

Wide red + no green = process ran without the user. Equal segments across all four = normal interactive use. The story is visible before reading a word.

### Table source colors

Each SRUM table gets a distinct dim color label so the analyst instantly knows the source:

| Table | Color |
|---|---|
| network | `#5352ED` indigo |
| apps | `#2ED573` green |
| energy | `#FFA502` amber |
| app-timeline | `#FF6B81` pink |
| notifications | `#70A1FF` sky blue |
| connectivity | `#ECCC68` yellow |

### Dashboard cards

Colored left border + subtle tinted background matching severity. The color is the first thing the eye registers — the text explains it.

---

## Distribution

Modelled directly on blazehash. `tauri build` generates platform-native installers.

| Platform | Output | Channel |
|---|---|---|
| Windows x64 | `.msi` (WiX) + `.exe` (NSIS) | winget (`SecurityRonin.SRUMExaminer`), GitHub release |
| macOS arm64 + x64 | `.dmg` with `.app` bundle | Homebrew cask, GitHub release |
| Linux x64 + arm64 | `.AppImage` (universal) + `.deb` | Cloudsmith apt repo, GitHub release |

**Linux note:** Tauri requires `libwebkit2gtk-4.1` for web rendering. The `.AppImage` bundles it (works anywhere). The `.deb` declares it as a system dependency. Windows uses system WebView2 (ships with Win 10/11). macOS uses system WebKit. No extra dependencies on either.

**GitHub Actions matrix:** same `v*` tag trigger as blazehash. Dispatch to Homebrew cask tap on release. `winget-releaser` action for Windows. Cloudsmith CLI push for Linux `.deb` packages.

**Coexistence:** Package name `sr-gui`, app name `SRUM Examiner`. Installs alongside the `sr` CLI — both can coexist on the same workstation.

---

## What This Tool Does That Nothing Else Does

The forensic value proposition is the **4-way signal join** — no existing SRUM tool visualises all four measurements simultaneously:

| Measurement | Source table | What it tells you |
|---|---|---|
| `background_cycles` | App Resource Usage | CPU used when app not in foreground |
| `foreground_cycles` | App Resource Usage | CPU used when app window was topmost |
| `focus_time_ms` | App Timeline | Milliseconds user's input was routed to this app |
| `user_input_time_ms` | App Timeline | Milliseconds user actually produced keyboard/mouse input |

The gaps between these four measurements resolve questions that no other artefact can answer:

- High `foreground_cycles`, zero `focus_time_ms` → phantom foreground (possible `SetForegroundWindow` abuse)
- High `focus_time_ms`, zero `user_input_time_ms` → passive viewing (user watched but didn't interact)
- High `focus_time_ms`, zero `user_input_time_ms`, high `background_cycles` → automated execution (scripted, no human present)
- High `user_input_time_ms` → human was actively typing and clicking

SRUM Examiner makes this join visible as a colored bar. The forensic conclusion is immediate and does not require the analyst to understand the underlying data model.
