---
name: ida-bridge
description: "Query and manipulate IDA Pro databases (idb): SQL queries, IDAPython exec, and IDB lifecycle."
---

# ida-bridge

Query and manipulate IDA Pro databases through the installed and configured `ida-bridge` CLI. See the repository `README.md` for setup.

The bridge server must be running before IDA starts: `ida-bridge server start`.
When IDA opens an IDB, whether UI or headless, it connects to the bridge server automatically.
Each connected IDA instance has one open IDB.
Multiple IDA instances can connect to the bridge, but you target a specific instance by its `client_id`.

## Operating model

### Routing rule
- Single action on an IDB: `ida-bridge exec-idb --idb /path/to.i64 ...` (one-shot: starts idalib, executes, stops).
- Multiple actions or iterative exploration: launch a persistent IDA instance. Do not loop `exec-idb` against the same IDB; that repays startup/teardown every call.

### One-shot
- Create IDB from binary: `ida-bridge exec-idb --input /path/to/binary --out-idb /path/to.i64 --save` (no code, no SQL).
- Quick probe: `ida-bridge exec-idb --idb /path/to.i64 --sql "SELECT COUNT(*) FROM funcs"`

### Persistent IDA instance
- Reuse before starting: `ida-bridge list` shows running instances by `client_id`. If your target IDB is already open, target that `client_id` instead of starting another -- opening the same IDB twice fails on the IDB lock.
- Start a new UI IDA: `ida-bridge supervisor start-ui --idb /path/to.i64`
- Start a new idalib (headless): `ida-bridge supervisor start-idalib --idb /path/to.i64`
- Both start commands wait until the IDA instance connects to the bridge.
- On connection, they print instance info: `client_id`, `idb_path`, `pid`, `log`. No need to sleep or list afterwards -- read `client_id` from the output and continue.
- UI IDA connects as soon as the IDB is open but continues auto-analysis. For new IDBs, if results look incomplete, run `import ida_auto; ida_auto.auto_wait()` in exec.
- idalib waits for auto-analysis to finish before connecting -- it is ready to query on arrival. For malformed input that hangs analysis, skip it with the `--skip-initial-auto-analysis` flag; expect a mostly unexplored IDB.
- CLI waits up to 300s for the first client connection. Override with `--wait-s` for large binaries. If the wait expires (`status: waiting`, no `client_id`), analysis is still running -- find the instance with `ida-bridge list` once it connects instead of restarting.

### Lifecycle
- Stop: `ida-bridge supervisor stop <client_id>` (no session-id needed; does not auto-save).
- Save stateless: `ida-bridge supervisor save <client_id>`.
- Save through an existing stateful session: `ida-bridge supervisor save <client_id> --stateful --session-id <sid>`.
- Diagnose a launch that fails to connect: open the log file at the path printed in the error message.

## Execution

### Prefer SQL
Use SQL for everything it can express. Fall back to IDAPython only when SQL cannot.

When writing IDAPython, load `ida-docs` first -- your IDA API knowledge is 8.x, current is 9.x -- you cannot produce working code without it.

Import each `ida_*` module you use; IDA no longer pre-imports them. An `AttributeError` on a module usually means the symbol lives in another module (often moved across versions) -- resolve it in ida-docs rather than guessing.

### Command syntax
Both `exec` and `exec-idb` accept these execution inputs:

- `--sql` (SQL query): `ida-bridge exec <client_id> --sql "SELECT start_ea, name FROM funcs LIMIT 10"`
- `-f` (Python script file): `ida-bridge exec <client_id> -f <ida-bridge-skill>/snippets/idb_triage.py -f path/to/helper.py`
- `-c` (inline code): `ida-bridge exec <client_id> -c 'import idaapi; _result_ = idaapi.get_kernel_version()'`
  - Multi-line `-c`: a literal `\n` in a shell string is backslash-n, not a newline -- use real line breaks or a `-f` file.
- Combined: `ida-bridge exec <client_id> --sql "SELECT start_ea, name FROM funcs LIMIT 5" -f helpers.py -c '_result_ = process(_result_)'`
- Execution order: `--sql` first, then `-f` file(s) (in order), then `-c`. Each stage sees state from previous stages.

### Exec environment
- One `exec` / `exec-idb` invocation becomes one Python payload inside IDA. The CLI assembles it in order: `--sql`, each `-f`, then `-c`; all stages run in the same globals.
- Globals persist across calls only in a stateful session (`--stateful --session-id`), until `reset`; there imports, variables, and functions remain available, so use named variables for persistent state. Stateless calls start fresh each time.
- `-f` executes the file's top-level code as Python; it is not imported as a module. Use files to define helpers, then call them from `-c` or later execs. `if __name__ == "__main__"` blocks do not run.
- The exec globals are not a real module, so features that resolve via `__module__` (e.g. dataclasses) may misbehave -- prefer plain dicts and functions.
- `_result_` is the per-call return channel. If set, it is popped after the call, serialized, and returned to the CLI; it does not persist. Keep it flat -- serialization truncates at depth 4.
- `--sql` alone returns the SQL result under `--- result ---`; address columns are rendered as hex strings.
- `--sql` with `-f`/`-c` initializes `_result_` as a plain dict (`columns`, `rows`) with address values as raw ints so Python can compute with them. Later `-f`/`-c` code may replace `_result_`.
- Never call `qexit()` from exec code -- it can kill IDA before the bridge replies. Use `supervisor stop` for lifecycle; if you must exit from within exec, use `idb.quit()`.

### Stateless vs stateful

Default `exec` is stateless: each request gets a fresh Python environment. The bridge serializes all requests through a queue, so several agents can share one stateless instance. Prefer stateless for nearly all work.

Stateful is rarely necessary:
- Within one request, `--sql`, each `-f`, and `-c` already share one environment, so multi-step logic in a single round-trip needs no stateful.
- IDA caches analysis and decompilation across requests regardless of exec env, so re-running `decompile()` or re-querying is cheap, not a recompute.
- Stateful buys one thing: a Python namespace that survives across separate CLI round-trips. Use it only when a later request needs an in-memory Python value you cannot cheaply rebuild.

Going stateful is an exclusive claim, not a private workspace:
- `exec --stateful --session-id <sid>` claims the instance on the first stateful exec. Use a fresh random id: `SID=sess-$(openssl rand -hex 4)`.
- While owned, every other exec is rejected -- including other agents' stateless probes -- until you release, someone takes over, it expires after about an hour idle, or IDA reconnects.
- Not durable: if the session expires from inactivity, the environment resets and your accumulated state is gone.
- It evicts co-tenant agents, so keep the window short and release when done: `ida-bridge reset <client_id> --session-id <sid> --release`. Plain `reset` clears the env but keeps the claim.

Contention (agents cannot coordinate):
- Use your own session-id; never adopt one seen in `list`.
- If a previously-working exec returns `SESSION_CONFLICT`, or `list` shows a foreign owner, another agent has gone stateful here. Do not take it over on your own -- stop and ask the user. Take over only if the user tells you to: `ida-bridge reset <client_id> --session-id <new-sid> --takeover`.
- `RELEASE_PENDING` / `TAKEOVER_PENDING`: a transition is in flight; retry shortly. `SESSION_LOCKED`: ownership is wedged; restart the instance.

Shared instance means shared IDB: co-tenants edit the same database, so another agent may rename, retype, or comment things while you work. If results look inconsistent, ask the user whether another agent is active.

### Hangs and timeouts

- Exec runs on IDA's main thread and cannot be interrupted. The WebSocket connection runs on a separate thread, so a live connection does not imply exec is responsive.
- Each request retains and mirrors at most 1 MiB per stdout/stderr stream. Excess output is discarded after an `[ida-bridge output truncated]` marker, but the underlying code continues to run.
- UI IDA only: many ops (opening a binary, a write, a plugin, decompiling) can pop a modal dialog that blocks exec until a human dismisses it. If a UI-IDA exec hangs, a dialog could be the reason -- ask the user to check.
- Default timeout is 60s (`--timeout-s`); raise it only for known-heavy ops, and use `--timeout-s 0` only to wait indefinitely.
- On timeout, do not blindly retry the same command:
  - Confirm the instance still exists: `ida-bridge list`.
  - If the code is likely hung (unbounded loop/scan), stop immediately: `ida-bridge supervisor stop <client_id>` (then restart and fix the script).
  - If the code is likely just slow, probe sequentially (do not spam; probes queue): `ida-bridge exec <client_id> --timeout-s 30 -c '_result_=1'` up to 3 times. If probes keep timing out past your budget, stop and restart.

### CLI output
- Default output is sectioned human output. First line is `exec: ok` or `exec: error`.
- On success, structured data returned through `_result_` appears under `--- result ---`. If there is no result section, the command succeeded but returned no structured data.
- stdout/stderr from code executed inside IDA are captured and returned under `--- stdout ---` / `--- stderr ---`. `print()` writes to stdout. Treat these sections as logs; put machine-consumable data in `_result_`.
- A stdout or stderr section ending with `[ida-bridge output truncated]` reached its 1 MiB limit. Narrow the script's logging instead of retrying for more output.
- On failure, read `error code`, `error message`, and `hint` first. `--- traceback ---` is from code executed inside IDA (`--sql`, `-f`, `-c`). `--- bridge trace ---` is bridge/protocol/routing diagnostic context.
- Use `--json` only when a script/tool needs the raw response envelope.

### Headless input options

For headless `--input` flows (`exec-idb` or `supervisor start-idalib`), some input formats need selector flags. Existing `--idb` flows do not.

- Fat Mach-O: pass `--arch <slice>`. Use `lipo -archs <bin>` to list slices; choose the requested/target architecture, ask if unclear.
- DYLD cache single-module: pass `--dyld-module <image-path-inside-cache>` with the cache as `--input`, e.g. `/System/Library/Frameworks/Foundation.framework/Foundation`.
- Do not combine `--arch` and `--dyld-module`.
- After a DYLD single-module IDB exists, use the `dscu` snippet to load more cache content incrementally instead of recreating a larger database.

### Snippets
Curated IDAPython for tasks SQL cannot express, under `<ida-bridge-skill>/snippets/`. Load them with `-f` (see Command syntax); read a snippet's module docstring for its API: `sed -n '1,/^"""/p' <ida-bridge-skill>/snippets/<snippet>.py`.

- `idb_triage.py`: extraction with no SQL equivalent -- Objective-C metadata, linkage tables, init/fini arrays, coverage stats.
- `dscu.py`: load DYLD shared cache modules/sections incrementally -- essential for iOS reversing on single-module dyldcache IDBs.
- `hexrays_callee_type.py`: type indirect/unresolved calls for the decompiler.
- `unmapped_refs.py`: find code/data refs to addresses outside loaded segments.

## SQL basics

These rules affect every ida-bridge SQL query.

For the full per-table reference -- columns, pushdown, scalars, and views -- use `<ida-bridge-skill>/references/sql-reference.md` plus `sqlite_master` and `PRAGMA table_info`.

### Discovery and result handling

- Normal SQLite works, including schema discovery (`sqlite_master`, `PRAGMA table_info(<table>)`), joins, subqueries, CTEs, aggregates, `UNION`, `ORDER BY`, `LIMIT`, `LIKE`, `GLOB`, `IN`, and `BETWEEN`. For view definitions, query `sqlite_master.sql`.
- Each `--sql` execution returns one result set: `{"columns": [...], "rows": [...]}`. There is no warnings field, side channel, or truncation. Results over 10,000 rows raise an error.
- For multi-statement `--sql`, keep at most one row-producing statement. Use many plain `INSERT`/`UPDATE`/`DELETE` statements if needed, but only one `SELECT`, `VALUES`, or statement with `RETURNING`. For multiple independent reads, use separate `--sql` calls or combine them into one `SELECT`.
- On unfamiliar or large IDBs, start with counts, summaries, and bounded samples; use `LIMIT` while exploring and do not dump full tables.
- Combine SQL with `-c` for post-processing when SQL gets you close. With `--sql` plus `-c`, `_result_` is a dict with `columns` and `rows` for the Python stage.

### Integers and hex display

Plain SQL integers print as decimals, but decimal addresses, sizes, and flags are hard to read in RE. For `--sql`-only output, the CLI renders registered hex-like columns as `0x...` strings. When `--sql` is combined with `-f`/`-c`, `_result_` contains the original raw Python integers.

- Address arguments must be SQLite integers. Use `0xfffffe0007004000`, not `'0xfffffe0007004000'`.
- Do not wrap raw address columns with `hex()` just for display. Use `hex()` for computed expressions that may lose hex/provenance metadata, such as `func_start(ea) AS f`, `start_ea + 0`, or aggregates.
- `hex()` here is the ida-bridge override, not SQLite's builtin: it returns `0x`-prefixed lowercase (`hex(255)` -> `'0xff'`, not `'FF'`) and takes integers only.

SQLite `INTEGER` is signed. High-bit addresses compare and sort with signed SQLite semantics, which can matter for kernel addresses. Prefer scoped predicates (`segment`, `func_ea`, explicit ranges) over global address ordering when high-bit addresses are involved.

### Scope and cost

ida-bridge tables are virtual tables backed by IDA/Hex-Rays APIs, not stored SQLite tables. An unscoped query can decompile many functions or walk every item/xref in the IDB. Some tables reject unbounded scans; others allow them but can be expensive.

- `LIMIT` caps returned rows; it does not satisfy required scope or avoid setup, joins, sorting, or decompilation.
- First narrow to a bounded seed: an address or range, function, segment, type, pattern, or xref target. Then add joins or scalar enrichment.
- On broad scans, select only needed columns instead of `SELECT *`; some tables compute extra columns lazily.
- These tables require scoped queries: `pseudocode`, `ctree_lvars`, `blocks`, `cfg_edges`, and `bin_search`.
- Do not join two unbounded expensive surfaces; constrain one side first. Views like `callers`, `callees`, and `string_refs` inherit underlying table cost.
- `decompile(ea)` has no pushdown guard; in scans it can run once per evaluated row. Narrow candidates first unless you intend mass decompilation.

### Scalar helpers

Per-row IDA API calls; use after table scope, not as a substitute. Most return NULL on missing data.

Discover scalars from SQL: `SELECT name, signature, description FROM sql_functions` (filter by convention, e.g. `WHERE name LIKE 'read\_%' ESCAPE '\'`). The naming convention also predicts them: `*_at` look up at an address, `read_*` read memory, `*_flag` name-to-bitmask, `ui_*` GUI-only.

Flag helpers return bitmasks: `flags & func_flag('thunk') != 0`. Pass an empty string to get an error listing valid names.

## Orientation

- Given an address, identify the containing function, segment, item type, and current listing line: `SELECT hex(0x...) AS ea, hex(func_start(0x...)) AS func_ea, name_at(func_start(0x...)) AS func_name, segment_at(0x...) AS segment, item_type_at(0x...) AS item_type, disasm_at(0x...) AS line`.
- `heads` is the item map -- every defined item (code and data) in address order, for exploring regions rather than functions: data/struct layout including unnamed items, orphan code (`type = 'code' AND func_ea IS NULL`), and undefined gaps. Pushdown: `segment`, `func_ea`, or address range.

## Decompiler

### Read the decompilation

Decompiler work needs a defined function and successful decompilation. Table reads raise on decompile failure; `decompile(ea)` returns NULL when `ea` is outside a function or decompilation fails.

- Decompiler output is cached per function. Writes to that function's decompiler state (`pseudocode`, `ctree_lvars`, `funcs.prototype`) invalidate its cache; upstream type/global/callee changes may not. If pseudocode or lvars look stale, run `SELECT mark_cfunc_dirty(func_start(0x...))` and query again.

Use `decompile(ea)` for whole-function text. Use `pseudocode` for bounded reads, search, or address mapping. `ORDER BY n` preserves rendered order.

- Whole function text: `SELECT decompile(0x...) AS text`.
- Bounded function scan: `SELECT line FROM pseudocode WHERE func_ea = func_start(0x...) ORDER BY n LIMIT 80`.
- Chunked read by row range: `SELECT n, line FROM pseudocode WHERE func_ea = func_start(0x...) AND n BETWEEN N AND N + 80 ORDER BY n`.
- Address-mapped rows: `SELECT ea, line FROM pseudocode WHERE ea = 0x... ORDER BY n`.
- Search rendered output: `SELECT n, ea, line FROM pseudocode WHERE func_ea = func_start(0x...) AND line LIKE '%pattern%' ORDER BY n LIMIT 50`.

If exact `ea` returns no rows, the address may be entry/prologue/unmapped in pseudocode; use a bounded function scan or disassembly. Add `AND line != ''` when blank rows waste space.

### Signature and locals

- Inspect locals and arguments for the containing function: `SELECT idx, name, type, size, is_arg, is_result, is_stk_var, is_reg_var, stkoff, comment FROM ctree_lvars WHERE func_ea = func_start(0x...) ORDER BY is_arg DESC, idx`.
- For non-argument, non-result locals, writable columns are `name`, `type`, and `comment`: `UPDATE ctree_lvars SET name = 'new_name', comment = 'meaning' WHERE func_ea = func_start(0x...) AND idx = N`.
- For arguments and result variables, only `comment` is writable through `ctree_lvars`. Change argument names/types, return type, calling convention, or parameter lists through `funcs.prototype`: `UPDATE funcs SET prototype = 'int init(int argc, char **argv)' WHERE start_ea = func_start(0x...)` (NULL clears the stored type).
- Function attribute bits are writable through `funcs.flags`, read-modify-write with the flag helper. The common edit is marking a callee non-returning (`noret` is `FUNC_NORET`): `UPDATE funcs SET flags = flags | func_flag('noret') WHERE start_ea = func_start(0x...)`; clear a bit with `flags & ~func_flag('noret')`.
- `comment` is only the user lvar comment. Hex-Rays may render generated storage annotations in pseudocode declarations, such as registers, stack offsets, `BYREF`, or `MAPDST`; use `is_reg_var`, `is_stk_var`, and `stkoff` for storage context.
- Use `idx` only after selecting the current `ctree_lvars` rows. It can change after local retyping, function prototype/type changes, or re-decompilation; name- and comment-only edits do not, so batch those without re-querying.
- Retype one non-argument, non-result local at a time, using the observed `size` and storage as a sanity check: `UPDATE ctree_lvars SET type = 'struct foo *' WHERE func_ea = func_start(0x...) AND idx = N`. Re-query `ctree_lvars` and pseudocode before changing another local in the same function.

### Comments

Decompiler comments are a separate surface from disassembly item comments (the `comments` table); this is the pseudocode side.

- Read context before writing; add `LIMIT` or an `n` range for large functions: `SELECT n, type, ea, placement, line, valid_placements, is_orphan FROM pseudocode WHERE func_ea = func_start(0x...) ORDER BY n`.
- A rendered decompiler comment needs a code-row anchor. Use a `type = 'code'` row with non-NULL `ea`, and choose one placement listed in that row's comma-separated `valid_placements`; not every address can anchor a decompiler comment.
- Common placements: `semi` is a trailing/end-of-statement comment; `block1` is a standalone comment before the code row. `valid_placements` can contain other placement types as well.
- Insert: `INSERT INTO pseudocode (func_ea, ea, placement, line) VALUES (func_start(0x...), 0x..., 'semi', 'why this matters')`.
- Use `n` only for ordering and context reads. Do not use it as row identity; it can shift after comment writes, type/prototype changes, or re-decompilation.
- To edit/delete existing comments, first select `type = 'comment'` rows: `SELECT n, ea, placement, line, is_orphan FROM pseudocode WHERE func_ea = func_start(0x...) AND type = 'comment' ORDER BY n`. Then update by anchor: `UPDATE pseudocode SET line = 'better note' WHERE ea = 0x... AND type = 'comment' AND placement = 'semi'`; use the same predicate for `DELETE`. Code rows are rendered output and are read-only.
- `is_orphan = 1` means that the current pseudocode no longer has a renderable code location for its `(ea, placement)` anchor. This commonly follows type/prototype changes or forced re-decompilation. If the comment still applies, fix it by updating `ea` and/or `placement` to a valid code-row anchor. If no valid anchor clearly matches, ask before deleting or moving it.

## Disassembly

- Correlate a decompiler line to its anchor instruction via `ea` -- only addresses that anchor a rendered line, not every instruction the decompiler used, often repeated across lines: `SELECT n, ea, line, disasm_at(ea) AS disasm FROM pseudocode WHERE func_ea = func_start(0x...) AND type = 'code' AND ea IS NOT NULL ORDER BY n`.
- Read the complete 1:1 instruction stream from `instructions`. Scope by function (`func_ea`), exact address, or range (`address BETWEEN lo AND hi`); do not full-scan on large IDBs: `SELECT address, mnemonic, disasm, size FROM instructions WHERE func_ea = func_start(0x...) ORDER BY address`.
- Map control flow from `blocks` and `cfg_edges` (both require `func_ea` pushdown). LEFT JOIN keeps edgeless return blocks; `edge_type`: `flow` (sole successor), `true`/`false` (conditional taken/fall-through), `switch` (3+ way): `SELECT b.start_ea, b.end_ea, e.dst_block, e.edge_type FROM blocks b LEFT JOIN cfg_edges e ON e.func_ea = b.func_ea AND e.src_block = b.start_ea WHERE b.func_ea = func_start(0x...) ORDER BY b.start_ea, e.dst_block`.
- Item comments attach to a disassembly address, keyed by `(address, repeatable)`: `INSERT INTO comments (address, text, repeatable) VALUES (0x..., 'why this matters', 0)`; edit with `UPDATE comments SET text = 'better note' WHERE address = 0x... AND repeatable = 0`; clear with `text = ''` or `DELETE` using the same predicate. `text` is the only writable column -- `address` and `repeatable` identify the row.

## Cross-references

- Trace call edges with views: `SELECT * FROM callers WHERE func_addr = 0x...`, `SELECT * FROM callees WHERE func_addr = 0x...`.
- Use raw `xrefs` for all refs to an address; `is_code` splits code from data, and `type_name` names the kind (code: `call`, `jump`, `flow`; data: `offset`, `write`, `read`): `SELECT from_ea, type_name, name_at(from_func) AS func, disasm_at(from_ea) AS at FROM xrefs WHERE to_ea = 0x... ORDER BY from_ea`. Who writes a global: add `AND type_name = 'write'`.

### Type and member references

xrefs to/from type or type member have a special `ea` (tid) living in the unmapped type-id space (`0xff...`).
`name_at`/`segment_at` are NULL on tids, and `tid_name()` resolves a tid to `Struct` or `Struct.field`.
These refs exist only where IDA applied a struct offset in disassembly or a plugin recorded accesses from decompiled code.

- What a function touches: `SELECT type_name, COALESCE(name_at(to_ea), tid_name(to_ea)) AS target FROM xrefs WHERE from_func = 0x... AND is_code = 0` (real globals vs type/member refs: `tid_name(to_ea) IS NULL`).
- Who uses a struct field: `SELECT x.type_name, x.from_ea, name_at(x.from_func) AS func FROM types_struct_members m JOIN xrefs x ON x.to_ea = m.tid WHERE m.type_name = 'T' AND m.member_name = 'f'` (add `AND x.type_name = 'write'` for writers; join `types.tid` for any field).

## Search

- Find string usage: `SELECT string_value, func_name, ref_addr FROM string_refs WHERE string_value LIKE '%error%' LIMIT 50`.
- List strings, including unreferenced ones: `SELECT address, length, string_value FROM strings WHERE string_value LIKE '%error%' LIMIT 50`.
- Search names and symbols: `SELECT address, name, demangle(name) AS demangled FROM names WHERE name LIKE '_$s%' LIMIT 50`; user/tool names: `SELECT address, name FROM names WHERE is_auto = 0 LIMIT 50`.
- Search bytes: `SELECT address, segment_at(address) AS segment, name_at(func_start(address)) AS func FROM bin_search WHERE pattern = '7F 23 03 D5' LIMIT 50`. `pattern` uses IDA hex-byte syntax and supports `?` wildcards.

## Types

- Inspect a type: full C declaration in one shot via `SELECT definition FROM types WHERE name = 'T'`; or structured -- `SELECT ordinal, name, kind, size, member_count FROM types WHERE name LIKE '%session%'`, `SELECT member_name, offset, size, member_type, tid FROM types_struct_members WHERE type_name = 'T' ORDER BY offset`, `SELECT value_name, value FROM types_enum_values WHERE type_name = 'E'`.
- Apply an existing type at an address (function, global, or data): `SELECT set_type(0x..., 'struct dispatch_table *')`; read it with `type_at(0x...)`, clear with `set_type(0x..., NULL)`. For a function prefer `funcs.prototype`, for a decompiler local `ctree_lvars.type`.
- Edit types in place (`UPDATE types`, or `parse_type` with the same name -- both replace at the existing ordinal) rather than delete/recreate. Deleting a type orphans every reference to its ordinal: prototypes show `#NNN`, members go `size = -1`, and the breakage cascades to containing types.
- Retype a member: `UPDATE types_struct_members SET member_type = 'uint64_t *' WHERE type_name = 'T' AND offset = 0x10`. Retyping (or deleting) a member silently resizes the struct and shifts offsets in every parent that embeds it, unless it is pinned (`is_fixed = 1`). Bridge-created structs are pinned already; pin a pre-existing struct before mutating its members.
- Rename and renumber in place: `UPDATE types SET name = 'session_t' WHERE ordinal = N`; `UPDATE types_struct_members SET member_name = 'flags' WHERE type_ordinal = N AND member_index = I`; `UPDATE types_enum_values SET value_name = 'E_OK', value = 0 WHERE type_ordinal = N AND value_index = I`. `comment` is writable on members and enum values as well.
- Do not use anonymous typedef declarations like `typedef struct { ... } name;`; use named declarations like `struct name { ... };` instead. Anonymous typedefs make IDA create an anonymous struct plus a typedef.

## UI

Use UI helpers only in UI IDA for user-facing navigation/selection. They raise in headless runs.

- Navigate the user's view: `SELECT ui_open_disasm(0x...)`, `SELECT ui_open_pseudocode(0x...)`. A pseudocode line-level `ea` scrolls to that line, so navigation composes with a query: `SELECT ui_open_pseudocode(ea) FROM pseudocode WHERE line LIKE '%pattern%' LIMIT 1`.
- Read active selection when the user says "look at this": `SELECT ui_get_selection()`. Returns JSON with the selected range and lines (pseudocode: `func_ea`, line range, text; disasm: ea range, instructions). Returns NULL if nothing is selected.

## Cross-cutting notes

- Write discipline: SQL writes mutate the IDB. Do not broad-write from exploratory queries; first select the exact rows, then write with the same scoped predicate.
- Comment-surface routing: function comments use `funcs.comment` / `funcs.rpt_comment`; disassembly item comments use `comments`; decompiler comments use `pseudocode` comment rows.
- Name-surface routing: name a data global through `names.name` (`UPDATE names SET name = 'g_config' WHERE address = 0x...`, empty string clears a user name); name a function through `funcs.name`. `names.is_auto` is read-only.
- Writable surfaces (all else is read-only): `UPDATE funcs` for name/prototype/comments/flags; `names.name` to name any address (data globals); item comments in `comments`; decompiler comment rows in `pseudocode`; non-argument/non-result lvar name/type/comment and arg/result lvar comments in `ctree_lvars`; local types and members through `types`, `types_struct_members`, `types_enum_values`; address types through `set_type`; parsed declarations through `parse_type` / `parse_types`. `types_func_args` is read-only.
- Batch writes use normal SQLite syntax, but virtual-table writes are not atomic. If one row fails, assume earlier rows in that statement already applied.
