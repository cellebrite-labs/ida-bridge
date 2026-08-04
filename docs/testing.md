# Testing

## Test scope

### Unit (`tests/unit/`)

Pure logic; no IDA.

- host-side pure logic: protocol models, CLI parsing, serialization, file format detection
- SQL infrastructure: transport row cap, `QueryError` paths, column metadata consistency, constraint plan validation
- APSW/SQLite boundary: u64 signed reinterpretation, type provenance through expressions
- pushdown rejection: required WHERE missing, invalid constraint types
- scalar functions: NULL propagation, type validation, composition (lightweight data dicts, not IDA module stubs)

### Integration (`tests/integration/`)

Bridge server with mock WebSocket clients.

- handshake and client registration
- request routing and response correlation (request types, flow matrix)
- stateful session ownership: acquire, release, conflicts
- connection lifecycle: reconnect, disconnect, ping timeout
- backpressure and failures: queue-full, send failures
- concurrency: multiple agents against one target

### E2E (`tests/e2e/`)

Full stack: bridge, real idalib, real binaries.

- table/view read behavior: schema, columns, filtering, pushdown, hex transport
- write paths: funcs, pseudocode, types, struct members, enum values
- error behavior against real IDA: bad SQL, missing tables, invalid names
- scalar functions against real data
- cross-table queries: joins, subqueries, composite patterns
- runtime lifecycle and loaders: idalib connect/exec/reset/shutdown, fat Mach-O arch selection, IDB create/reopen roundtrip

## IDA mock boundary

The SQL layer runs inside IDA. Mocking `ida_*` modules in unit tests creates a parallel model that drifts from real behavior, breaks on refactors, and catches nothing the e2e suite misses.

If a test needs IDA to be meaningful, it belongs in e2e.

### Avoid

- mocking IDA modules for SQL read/write behavior -- the e2e already proves it
- exact `EXPLAIN QUERY PLAN` index numbers -- assert "not full-scan" instead
- duplicating e2e coverage in unit tests -- maintenance cost without added confidence

## E2E

E2E tests require a working IDA/idalib setup.
Running the suite starts an ephemeral bridge server per run; no background `ida-bridge server` is needed.

### Fixture model

SQL e2e coverage is parametrized over a discovered fixture bank: every `*.i64`
under `tests/fixtures/idbs/` (`idbs/heavy/` with `--e2e-heavy`).

Directory structure:
```
src/      committed C/C++ sources
bins/     compiled binary variants      (gitignored)
idbs/     IDBs the SQL suite discovers   (gitignored: build.py output + drop-ins)
```

Tests assert shape-independent invariants (row counts `> 0`, distinct keys, cross-table consistency), so any valid IDB works; capability-specific tests skip at runtime when a feature is absent (e.g. no imports).
Write tests run on temp copies of the IDBs.
Some behavior tests reference a specific named binary from `bins/` instead of the discovered fixture bank.

`tests/e2e/conftest.py` uses two scopes:

- module-scoped shared instances for non-destructive tests (amortizes idalib startup across the module)
- function-scoped instances for destructive tests (such as shutdown)

### Fixture generation

Requires a C compiler toolchain and a running bridge server that `exec-idb` connects to.

- macOS: `clang`/`clang++`/`lipo`/`strip` (Xcode command line tools), including the
  fat-Mach-O (`lipo`) and dyld-cache fixtures.
- Windows: use `clang-cl`/`cl` (MSVC-style) instead of `clang` and drop `lipo` (no fat
  binaries on Windows). macOS-format fixtures (fat Mach-O, DYLD cache) are inherently
  macOS files and are not built on Windows; the generic SQL e2e suite runs against the
  Windows-built fixtures.

`tests/fixtures/build.py` is the fixture generator; a fresh checkout runs it once to populate `idbs/`:

- compiles `src/*.c[pp]` into a variant matrix under `bins/` (arch / opt / stripped / debug)
- drives `ida-bridge exec-idb` to create IDBs under `idbs/`
- both `bins/` and `idbs/` are gitignored

```bash
uv run python tests/fixtures/build.py            # build missing/stale
uv run python tests/fixtures/build.py --force     # rebuild everything
```

### Adding a fixture

Reproducible from source:
1. Add a source to `tests/fixtures/src/`.
2. Add a `Binary`/`Idb` entry to `tests/fixtures/build.py` (choose arch, opt level, stripped, debug).
   `debug` makes IDA import the source's types (e.g. enums) into the IDB.
3. Run `uv run python tests/fixtures/build.py`.

Not reproducible (e.g. a platform-specific target):
1. Drop the `.i64` into `tests/fixtures/idbs/` (or `idbs/heavy/` if large).
2. Discovery and the invariant suite pick it up automatically.

### Fixture selection

- default: `uv run --group test pytest -q tests/e2e` (fixtures under `idbs/`)
- include heavy fixtures: add `--e2e-heavy`, which also runs `idbs/heavy/`

Keep the default set lean. Put large/heavy fixtures (e.g. kernelcache) under `idbs/heavy/`.

### Desired fixture coverage

Over time the fixture bank should cover different binary classes and analysis conditions, not just more copies of the same kind of target.

Useful fixture types to add:
- dyld shared cache framework
- kernelcache
- standalone KEXT
- bootloader
- ROM
- embedded firmware
- very stripped binary
- debug / rich type-info build (have)
- Objective-C-heavy binary
- Swift-heavy binary
- C++-heavy binary

### Coverage gaps

- Windows fixture generation (MSVC-style compile, no fat Mach-O / dyld cache) — see fixture generation above
- raw blob/shellcode loader path
- 32-bit `.idb` open path
- IDA 8.x `.i64` migration/open path
