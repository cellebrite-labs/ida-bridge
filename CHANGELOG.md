# Changelog

## [Unreleased]

### Added
- Added `ida-bridge remote start-idalib` and `ida-bridge remote stop` for managing headless idalib processes on the bridge server's host. Remote launches support existing IDBs, binary-to-IDB creation, loader selectors, bridge-host Python selection, readiness waits, and JSON output.
- Added bridge-owned child tracking, reaping, graceful quit correlation, and validated bridge-host PID escalation. Remote lifecycle never starts UI IDA and never saves on stop.

### Changed
- Bumped the websocket protocol to version 5 with strict `start_idalib` and `stop_idalib` request/response models.

## [0.6.0] - 2026-09-03

### Added
- Linux support. See README "Manual setup".
- `--skip-initial-auto-analysis` on `start-idalib` and `exec-idb`: skip the runner's initial `ida_auto.auto_wait()` so we can deal with a malformed input that hangs auto-analysis.
  Contributed by @T3rm1at0r in https://github.com/cellebrite-labs/ida-bridge/pull/3.

### Changed
- `supervisor start-ui` injects `IDAPYTHON_VENV_EXECUTABLE` into IDA's environment. Windows and Linux; macOS unchanged.

### Fixed
- `supervisor start-ui --ida` rejects a path that cannot be executed, instead of failing inside `Popen`.

## [0.5.0] - 2026-09-01

### Added
- Windows support for the host CLI: `server`, `exec`, `exec-idb`, and `supervisor start-ui` / `start-idalib` / `stop` / `save`. Platform-aware log directory, process control, server PID discovery, IDB lock probe, and IDA install detection. `ida-setup` remains macOS-only; see README "Manual setup".
  Contributed by @T3rm1at0r in https://github.com/cellebrite-labs/ida-bridge/pull/2.

### Changed
- Prerequisites are no longer macOS-only.

## [0.4.2] - 2026-08-03

### Changed
- Updated public setup instructions with the ida-docs companion skill, public clone URL, and macOS support requirement.

## [0.4.1] - 2026-07-30

### Added
- Added a manual setup guide to `README.md` for installs that do not use ida-setup.
- Added skill write examples for item comments, function flags, and type renames.

### Removed
- Removed the bundled `ida-bridge` launcher script from the skill; the installed package provides the CLI entry point.

### Fixed
- Fixed `exec-idb --force` deleting an output IDB that IDA had open, by checking OS advisory locks on the IDB and the companion files IDA unpacks it into.
- Fixed `UPDATE` statements that assigned an identity column silently retargeting the write to a different row; they now raise.

## [0.4.0] - 2026-06-23

### Changed
- exec is now stateless by default; stateful reuse is explicit via `--stateful`/`--session-id`.
- Rewrote the ida-bridge skill.
- Plain-text exec output now uses labeled sections (result, stdout, stderr, traceback).
- Renamed the `strings` table column `content` to `string_value` to align with the `string_refs` view.
- Argument and result variable name/type edits now go through `funcs.prototype` instead of `ctree_lvars`.

### Added
- Writable `names.name`: name or rename any address, including data globals.
- `sql_functions` table for discovering scalar functions.
- `type_name` column on `xrefs` with readable ref kinds (`call`, `jump`, `read`, `write`).
- `tid_name` scalar resolving a type/member tid to `Struct` or `Struct.field`.

### Removed
- Removed four snippets now covered by the SQL surface (decompile, user comments, struct modify, UI jump).

### Fixed
- UI scalars: correct view targeting, statement-line landing, and NULL on empty selection.
- Per-instance launch logs are now pruned instead of growing without bound.

## [0.3.1] - 2026-05-26

### Added
- Fixed-layout structs: new structs default to fixed layout so size is stable across member mutations. `is_fixed` and `size` columns on `types` table are writable for explicit control.

## [0.3.0] - 2026-05-26

### Changed
- Renamed scalars: added `_at` suffix for ea lookups, `ui_` prefix for GUI functions.
- Removed `comment_at` scalar; use `comments` table instead.
- Added type ordinal pitfall: deleting and recreating types destroys xrefs; always UPDATE in place.
- Added `bin_search` composition examples and `comments` table CRUD examples to skill reference.

## [0.2.3] - 2026-05-13

### Changed
- Simplified skill routing rules; clarified that create-IDB one-shot needs no code or SQL flags.

## [0.2.2] - 2026-05-04

### Fixed
- Fixed package publication in CI.

## [0.2.1] - 2026-05-04

### Changed
- Distribution package renamed to `labs-ida-bridge`; import name (`ida_bridge`) and CLI command (`ida-bridge`) are unchanged.

## [0.2.0] - 2026-05-04

### Added
- SQL query interface for IDB data. Read and write IDA database contents through standard SQL — functions, instructions, types, structs, enums, decompiler output, comments, cross-references, and more. Includes scalar helpers for address resolution, type parsing, decompilation, and memory reads.
- `exec-idb` command for one-shot headless workflows: start idalib, execute code, stop — no persistent server needed.
- `--sql` flag on `exec` and `exec-idb` to run SQL queries directly from the CLI.
- Session ownership model for multi-agent coordination, with `takeover` transfer and a dedicated `quit` RPC.
- Snippet library: reusable IDAPython scripts for decompiler output, callee types, struct modification, IDB triage, and unmapped reference detection.
- Support for multiple `-f` flags and combined `--file` + `--code` in `exec` and `exec-idb`.
- Headless dyld single-module loading.

### Changed
- Pseudocode table restructured to per-line rows with ea mapping, 1-based line numbers, and interleaved code and comments.
- SQL transport hex-formats addresses, sizes, and flags.
- Build backend switched from hatchling to setuptools with setuptools-scm for git-derived versioning.

### Removed
- CLI `eval` mode, `server restart/run`, `supervisor log`, `list --kind agent`.
- Auto-save on `supervisor stop` (save is now explicit).

### Fixed
- Ghost decompiler comments persisting after DELETE.
- Function pointer and array type parsing failures.
- Zombie process detection in `_is_pid_alive`.
- `idb.save()` dispatch under idalib.

## [0.1.4] - 2026-02-18

### Added
- `idb` helper namespace in exec environment with `idb.save()` and `idb.quit()`.
- UI "show me" workflow documented in skill (window focus + jumpto pattern).
- IDB lock troubleshooting: guard against opening an already-open IDB.

### Changed
- `supervisor stop` graceful wait bumped from 5s to 20s.
- `supervisor stop` proceeds with quit even if save fails.
- New IDBs created from input files are now compressed (`-P+`).
- Connection retry logs throttled to one-shot announcements.

### Removed
- `_ida_bridge_shutdown()` — replaced by `idb.save()` + `idb.quit()`.

## [0.1.3] - 2026-02-16

### Fixed
- Fixed `supervisor stop` graceful quit never succeeding — used `_ida_bridge_shutdown()` instead of `idc.qexit(0)` which killed IDA before the RPC response was sent.
- Fixed `supervisor stop` unable to resolve PIDs/client IDs — now queries bridge metadata with wait-and-escalate (quit → SIGTERM → SIGKILL).

## [0.1.2] - 2026-02-15

### Added
- Added an “Exec pitfalls” section to the ida-bridge skill with common `exec` gotchas and recommended practices.

## [0.1.1] - 2026-02-12

Add versioning and changelog.

## [0.1.0] - 2026-02-12

Initial versioned release.
