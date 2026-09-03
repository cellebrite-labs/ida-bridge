# IDA Bridge

Bridge between agents and IDA Pro.
Execute IDAPython and SQL queries against live IDA databases.
Supports UI IDA (plugin) and headless idalib.
Designed to be driven by AI agents.

Agent skill and references: `skills/ida-bridge/`.

## Prerequisites

- IDA Pro >= 9.0
- macOS, Windows, or Linux
- [ida-docs](https://github.com/cellebrite-labs/ida-docs) agent skill (for agent-authored IDAPython)
- [ida-setup](https://github.com/cellebrite-labs/ida-setup) (macOS only; automates the manual setup below)

## Installation (macOS)

On macOS `ida-setup` automates IDA Python env setup and plugin install.
On Windows and Linux, follow [Manual setup](#manual-setup).

```bash
# clone repo
git clone https://github.com/cellebrite-labs/ida-bridge.git
cd ida-bridge

# install ida-bridge cli
uv tool install -e .

# install ida-bridge plugin into IDA Python venv (macOS)
ida-setup plugin install -e .

# install pi agent skills
pi install .
pi install https://github.com/cellebrite-labs/ida-docs
```

## Manual setup

On macOS, `ida-setup` is the easy mode: it sets up a venv, installs packages and plugins.
On Windows and Linux, or if you don't use `ida-setup`, follow the instructions below.
macOS and Linux commands are identical unless noted; Windows commands are PowerShell.

The steps below assume a clone of this repo as your working directory, if you don't have one yet:

```
git clone https://github.com/cellebrite-labs/ida-bridge.git
cd ida-bridge
```

Four pieces need to end up in place:

1. host CLI, so the agent can run `ida-bridge` commands
2. two agent skills: one to operate ida-bridge, one for writing correct IDAPython code
3. IDA UI plugin, so IDA UI is reachable
4. IDA headless, so the headless runner can drive IDA

Locations of interest:
- IDA's per-user directory: `~/.idapro/` on macOS and Linux, `%APPDATA%\Hex-Rays\IDA Pro\` on Windows
- the IDA venv, shared by IDA UI and the headless runner: `~/.idapro/venv` on macOS and Linux,
  `$env:USERPROFILE\.idapro\venv` on Windows

### Python

`ida-bridge` needs Python 3.12 or newer.
On Windows, install it from [python.org](https://www.python.org/downloads/).
On Debian and Ubuntu, `python3 -m venv` needs the `python3-venv` package installed.

If you manage several Python versions, the Python you create the venv with (next step) has to be the same as the Python IDA uses.
Use `idapyswitch` to change the Python IDA uses if needed.
If they are not the same, IDA will fail to use the venv properly.

Validate the version of interpreter you will build the venv from:
- macOS and Linux: `python3 -c "import sys; print(sys.version)"`
- Windows: `python -c "import sys; print(sys.version)"`

Windows trap: `%LOCALAPPDATA%\Microsoft\WindowsApps` holds `python.exe` and `python3.exe` aliases.
Both are Microsoft Store stubs: they print "Python was not found" or open the Store instead of
running Python.

### Create the IDA venv

macOS and Linux: `python3 -m venv ~/.idapro/venv`
Windows: `python -m venv "$env:USERPROFILE\.idapro\venv"`

Install ida-bridge and idalib into it; both IDA UI and the headless runner will use this venv:

macOS and Linux: `~/.idapro/venv/bin/python3 -m pip install -e . idapro`
Windows: `& "$env:USERPROFILE\.idapro\venv\Scripts\python.exe" -m pip install -e . idapro`

Validate:
- macOS and Linux: `~/.idapro/venv/bin/python3 -c "import ida_bridge, idapro"`
- Windows: `& "$env:USERPROFILE\.idapro\venv\Scripts\python.exe" -c "import ida_bridge, idapro"`

### Point IDA UI at the venv

IDA has builtin support for venvs. On startup it reads the `IDAPYTHON_VENV_EXECUTABLE` variable and if present uses the venv path supplied.
For IDA instances you start from Finder, Explorer, or a desktop launcher this var has to be present in the desktop environment.
Exporting it in a shell does not reach an IDA started from the desktop.

macOS:
GUI apps read launchd's per-user environment, not shell startup files.

You can set the var like this:
```bash
launchctl setenv IDAPYTHON_VENV_EXECUTABLE ~/.idapro/venv/bin/python3
```

That lasts until logout. To make it persistent you need to setup a user LaunchAgent running the same command at login.
Check `ida-setup` code to see how the plist looks and how to make it auto-load.

Read the var with `launchctl asuser $(id -u) launchctl getenv IDAPYTHON_VENV_EXECUTABLE`.

Windows:
`[Environment]::SetEnvironmentVariable("IDAPYTHON_VENV_EXECUTABLE", "$env:USERPROFILE\.idapro\venv\Scripts\python.exe", "User")`

Read it back with `[Environment]::GetEnvironmentVariable("IDAPYTHON_VENV_EXECUTABLE", "User")`.

Linux:
Assuming you run a systemd session (GNOME, KDE).

Add a session env var:
```bash
mkdir -p ~/.config/environment.d
printf 'IDAPYTHON_VENV_EXECUTABLE=${HOME}/.idapro/venv/bin/python3\n' > ~/.config/environment.d/ida-bridge.conf
```

Then log out and back in.
Desktop apps inherit the session's environment, and the session reads these files only when it starts.

If you have an alias to launch IDA from shell, export the var in the shell.

Read the var with: `systemctl --user show-environment | grep IDAPYTHON_VENV_EXECUTABLE`

Validate: start IDA yourself and run `import sys; print(sys.version, sys.prefix)` in its Python
console. It should print the venv path rather than the base interpreter, and a version matching the
one the venv was built from.

### Host CLI

This one is straightforward -- an editable install of the ida-bridge CLI:

```
uv tool install -e .
# or: pip install -e .   -- installs into the active interpreter rather than an isolated one
```

Validate by running `ida-bridge server status` -- it should report that the server is not running.

### Agent skills

Clone ida-docs next to this repo, keeping this repo as the working directory:
`git clone https://github.com/cellebrite-labs/ida-docs.git ../ida-docs`

Then link both skill directories into the agent's skills directory.
The commands below use pi's (`~/.pi/agent/skills/`); for codex use `~/.codex/skills/`, for Claude Code `~/.claude/skills/`.

macOS and Linux:

```bash
mkdir -p ~/.pi/agent/skills
ln -s "$PWD/skills/ida-bridge" ~/.pi/agent/skills/
ln -s "$PWD/../ida-docs/skills/ida-docs" ~/.pi/agent/skills/
```

On Windows use a directory junction:

```powershell
# pi
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.pi\agent\skills" | Out-Null
New-Item -ItemType Junction -Path "$env:USERPROFILE\.pi\agent\skills\ida-bridge" -Target "$PWD\skills\ida-bridge"
New-Item -ItemType Junction -Path "$env:USERPROFILE\.pi\agent\skills\ida-docs" -Target "$PWD\..\ida-docs\skills\ida-docs"
```

Junctions work on NTFS only, for directories, on local volumes.
Copying the directories works too, but then updates have to be re-copied.

Validate: run the agent and tell it to start ida-bridge server -- it should run `ida-bridge server start`.

### IDA UI plugin

Put the plugin file where IDA looks for it, creating the `plugins` directory if it isn't there:

macOS and Linux:
```bash
mkdir -p ~/.idapro/plugins
ln -s "$PWD/src/ida_bridge/ida_bridge_plugin.py" ~/.idapro/plugins/
```

Windows:
The options are to copy the file or create a symlink.
Copy does not update when the original file is updated by git.
Symlink keeps it current, but needs to be run in Admin PowerShell.

Create plugins directory if absent:
```powershell
New-Item -ItemType Directory -Force -Path "$env:APPDATA\Hex-Rays\IDA Pro\plugins" | Out-Null
```

Symlink:
```powershell
# run in Admin PowerShell
# `cd` to the repo clone there first -- an elevated shell starts in system32.
New-Item -ItemType SymbolicLink -Path "$env:APPDATA\Hex-Rays\IDA Pro\plugins\ida_bridge_plugin.py" -Target "$PWD\src\ida_bridge\ida_bridge_plugin.py"
```

OR

Copy:
```powershell
Copy-Item "$PWD\src\ida_bridge\ida_bridge_plugin.py" "$env:APPDATA\Hex-Rays\IDA Pro\plugins\"
```

Validated by the final check below.

### IDA headless (idalib)

The headless runner drives IDA through `idalib`. It uses the venv from above --
`~/.idapro/venv/bin/python3` on macOS and Linux, `~/.idapro/venv/Scripts/python.exe` on Windows --
which already has `ida_bridge` and `idapro` in it.

Validated by the final check below.

### Final check

Proves headless and UI IDA run at once.
IDA locks an open database, so the two instances need separate files.

macOS:
```bash
ida-bridge server start                                        # the bridge must run first
ida-bridge exec-idb --input /bin/ls --arch arm64 --out-idb /tmp/ls.i64 --save   # binary -> IDB
cp /tmp/ls.i64 /tmp/ls-ui.i64                                  # second copy, IDA locks an open IDB
ida-bridge supervisor start-idalib --idb /tmp/ls.i64           # headless instance
ida-bridge supervisor start-ui --idb /tmp/ls-ui.i64            # UI instance
ida-bridge list                                                # both appear, with their client_ids
ida-bridge supervisor stop <client_id>                         # once per client
```

Windows:
```powershell
ida-bridge server start                                        # the bridge must run first
ida-bridge exec-idb --input C:\Windows\System32\notepad.exe --out-idb "$env:TEMP\notepad.i64" --save   # binary -> IDB
Copy-Item "$env:TEMP\notepad.i64" "$env:TEMP\notepad-ui.i64"   # second copy, IDA locks an open IDB
ida-bridge supervisor start-idalib --idb "$env:TEMP\notepad.i64"     # headless instance
ida-bridge supervisor start-ui --idb "$env:TEMP\notepad-ui.i64"      # UI instance
ida-bridge list                                                # both appear, with their client_ids
ida-bridge supervisor stop <client_id>                         # once per client
```

Linux:
```bash
ida-bridge server start                                        # the bridge must run first
ida-bridge exec-idb --input /bin/ls --out-idb /tmp/ls.i64 --save   # binary -> IDB (ELF, no --arch)
cp /tmp/ls.i64 /tmp/ls-ui.i64                                  # second copy, IDA locks an open IDB
ida-bridge supervisor start-idalib --idb /tmp/ls.i64           # headless instance
ida-bridge supervisor start-ui --idb /tmp/ls-ui.i64            # UI instance, needs a graphical session
ida-bridge list                                                # both appear, with their client_ids
ida-bridge supervisor stop <client_id>                         # once per client
```

`start-idalib` and `start-ui` print the client id, IDB path, PID and log path. On failure the log
path is printed, check it for troubleshooting.

`--arch` is needed only for fat Mach-O inputs; `exec-idb` reports the available slices if omitted
(use `x86_64` on an Intel Mac).

Leave the bridge server running afterwards -- that is its normal state.

### Troubleshooting

- The editable install (`uv tool install -e .` or `pip install -e .`) fails with
  `LookupError: setuptools-scm was unable to detect version`:
  `git` is not on PATH for that shell. Install it, or open a new shell if you installed it
  after the shell started.
- `import idapro` fails: idalib is not activated. Activation records the IDA install path in
  `ida-config.json` in IDA's per-user directory; `hcli ida install --set-default` writes it, as
  does `py-activate-idalib.py` from `idalib/python/` in the IDA install. `IDADIR` can point at a
  non-default install directory.
- `idapro` behaves differently than expected, or its version does not match what you installed:
  IDA ships its own `idapro` wheel under `idalib/python/`, which can differ from the PyPI release
  (IDA 9.4 ships 0.0.9, PyPI has 0.0.10). Check which one is in the venv with
  `pip show idapro`.
- Windows linking: creating a symlink needs Developer Mode or an elevated shell. A directory
  junction (`New-Item -ItemType Junction`) needs neither, which is why the skill directories are
  linked that way; junctions cannot link a single file, so the plugin is symlinked from an
  elevated shell or copied.
- `python3 -m venv` fails with `ensurepip is not available`: Debian and Ubuntu ship `ensurepip`
  separately. Install `python3-venv` and create the venv again.
- `start-ui` refuses with `no display: start-ui needs DISPLAY or WAYLAND_DISPLAY`: it is running
  without a graphical session, over SSH for example. IDA would start with no window and never
  connect, so it stops before launching.

## How it works

The bridge server must be running first: `ida-bridge server start`.
When IDA opens an IDB -- UI or headless -- it connects to the bridge server automatically.

The CLI gives agents control over connected instances:
- `ida-bridge list` -- see which IDAs are connected and which IDBs they have open
- `ida-bridge exec` -- execute IDAPython or SQL on a specific IDA instance
- `ida-bridge supervisor start-idalib` / `start-ui` -- launch new IDA instances on the CLI host
- `ida-bridge supervisor stop` / `save` -- stop or save instances in a local workflow
- `ida-bridge remote start-idalib` / `stop` -- manage headless idalib on the bridge host

This lets an agent discover available targets, run queries or code against them, and manage their lifecycle -- all through CLI.

### Remote bridge host

When the bridge server runs on another machine, point the local CLI at its TCP socket with `IDA_BRIDGE_HOST` and `IDA_BRIDGE_PORT` (or at the local endpoint of a TCP/SSH tunnel). Remote lifecycle supports headless idalib only; it does not start UI IDA.

```bash
# These paths and --python are resolved on the bridge server's machine.
IDA_BRIDGE_HOST=bridge.example IDA_BRIDGE_PORT=8765 \
  ida-bridge remote start-idalib --idb /srv/idbs/sample.i64 --json

IDA_BRIDGE_HOST=bridge.example IDA_BRIDGE_PORT=8765 \
  ida-bridge remote start-idalib \
    --input /srv/binaries/sample \
    --out-idb /srv/idbs/sample.i64 \
    --python /srv/ida-venv/bin/python \
    --force --arch arm64

IDA_BRIDGE_HOST=bridge.example IDA_BRIDGE_PORT=8765 \
  ida-bridge remote stop <client_id-or-pid>
```

`remote start-idalib` accepts the same headless input options as the local supervisor: `--idb` or `--input` with `--out-idb`, plus `--force`, `--arch`, `--dyld-module`, `--python`, and `--wait-s`. It returns `status: connected` with a `client_id`, or `status: waiting` if the bridge-host child is still analyzing when the wait expires.

`remote stop` asks a connected idalib to quit, then escalates against its PID on the bridge host. It rejects UI clients and unknown numeric PIDs, and it does not save. Save first with `ida-bridge supervisor save <client_id>` or an explicit `idb.save()` exec when changes must persist. The bridge has no authentication, so expose this capability only over a trusted network or tunnel.

## Agent usage

The ida-bridge skill (`skills/ida-bridge/SKILL.md`) contains the operational knowledge: command patterns, SQL schema, session management, and pitfalls.

When SQL cannot express an operation, ida-bridge tells the agent to load `ida-docs` before writing IDAPython. ida-docs checks the current IDA 9.x API against the official SDK instead of relying on stale model knowledge.

You can ask the agent to:
- open an IDB or create one from a binary
- search strings, find callers, trace cross-references
- annotate functions, set types, rename variables
- decompile and analyze specific functions
- query anything in the IDB through SQL

The agent handles the CLI invocations, session lifecycle, and SQL/IDAPython choice on its own. You describe the RE task; it drives IDA.

## One-shot vs persistent

Most of the work happens iteratively via `exec` against running IDA instance -- exploring a binary, building annotations over time, etc.

`exec-idb` is available for one-off queries, quick probes, or create-and-save flows.
It is fire-and-forget: start IDA, run code or SQL, exit (`--save` if needed).

## Runtime and sessions

`exec` is stateless by default: each request gets a fresh Python environment. Use this for independent SQL and IDAPython probes.

Use `exec --stateful --session-id <sid>` only when later calls need variables, imports, or helpers from earlier calls. A stateful exec claims the target exec environment for that session. The same session reuses the environment; other sessions and stateless execs are rejected until ownership is released, taken over, expires, or the IDA instance reconnects.

Use `reset <target> --session-id <sid>` to clear a stateful environment while keeping ownership. Use `reset <target> --session-id <sid> --release` when finished. Use `reset <target> --session-id <new-sid> --takeover` to intentionally replace another owner.

## Why SQL

Agents have outdated knowledge of the IDAPython API. They write IDAPython for IDA 8.x.
This wastes time on repeated failures and risks corrupting the database.

The SQL interface sidesteps this: agents write standard SQL, which is converted to correct IDAPython calls internally.
Agents are already fluent with SQL -- no new skills to learn, no IDA API to get wrong.

Example: `SELECT name, start_ea FROM funcs WHERE name LIKE '%auth%' LIMIT 10`

ida-bridge's SQL interface follows the IDA-over-SQL approach created by Elias Bachaalany ([@allthingsida](https://github.com/allthingsida) / [@0xeb](https://github.com/0xeb)) in [idasql](https://github.com/allthingsida/idasql) and the [libxsql](https://github.com/0xeb/libxsql) family.
We studied his design while building ours.
Credit for establishing SQL as a reverse-engineering interface for IDA is his.

## Execution modes

A single `exec` call can combine multiple modes:
- `--sql` -- runs first, results available to subsequent code
- `-f` -- uploads and runs files in order; can specify multiple
- `-c` -- inline code, runs last

Execution order is `--sql` -> `-f` (in order) -> `-c`.
Results carry between parts, so you can query with SQL, process with a file, and finalize with inline code.

In stateless execs, files passed with `-f` are available only within that request. In stateful execs, functions and variables they define remain available to later calls in the same session.

## DYLD cache single-module IDBs

Apple's dyld shared cache bundles hundreds of system libraries together.
To analyze a single library, IDA needs to extract it during IDB creation.

Pass the cache as `--input`, the target image as `--dyld-module`, and an output path as `--out-idb`:

`ida-bridge supervisor start-idalib --input /path/to/dyld_shared_cache_arm64e --out-idb /tmp/Foundation.i64 --dyld-module /System/Library/Frameworks/Foundation.framework/Foundation`

One-shot create-and-save:

`ida-bridge exec-idb --input /path/to/dyld_shared_cache_arm64e --out-idb /tmp/Foundation.i64 --dyld-module /System/Library/Frameworks/Foundation.framework/Foundation --save`

Headless only (idalib). UI IDA handles dyld module selection through its own GUI.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IDA_BRIDGE_HOST` | `127.0.0.1` | bridge server bind host and client default host |
| `IDA_BRIDGE_PORT` | `8765` | bridge server bind port and client default port |
| `IDA_BRIDGE_WS_MAX_SIZE` | `67108864` | max incoming websocket message size in bytes |
| `IDA_BRIDGE_LOG_FILE` | `~/Library/Logs/ida-bridge/server.log` (macOS) / `%LOCALAPPDATA%\ida-bridge\logs\server.log` (Windows) / `$XDG_STATE_HOME/ida-bridge/logs/server.log`, default `~/.local/state/...` (Linux) | structured server log (rotated); raw stdout/stderr go to the sibling `server.out` |
| `IDA_BRIDGE_LOG_MAX_BYTES` | `10485760` | log rotation threshold in bytes |
| `IDA_BRIDGE_LOG_BACKUP_COUNT` | `3` | number of rotated log files to keep |
| `IDA_BRIDGE_LOG_DIR` | `~/Library/Logs/ida-bridge` (macOS) / `%LOCALAPPDATA%\ida-bridge\logs` (Windows) / `$XDG_STATE_HOME/ida-bridge/logs`, default `~/.local/state/...` (Linux) | base directory for all bridge logs (server log + per-instance launch logs `idaui-<pid>.log` / `idalib-<pid>.log`) |
| `IDA_BRIDGE_LOG_KEEP` | `30` | dead per-instance logs retained per kind (live instances always kept) |
| `IDA_BRIDGE_LOG_PRUNE_INTERVAL_S` | `3600` | how often the server sweeps dead per-instance logs |
| `IDA_BRIDGE_STATEFUL_TTL_S` | `3600` | seconds before idle stateful ownership expires |

## Docs

- `docs/protocol.md` -- wire contract
- `docs/arch.md` -- architecture and ownership of concerns
- `docs/testing.md` -- test layout and fixture model
- `docs/sql-interface-design.md` -- SQL contract and boundaries

## Testing

```bash
# All tests
uv run --group test pytest -q tests/

# Unit + integration only
uv run --group test pytest -q tests/unit tests/integration

# E2E only (default fixture set)
uv run --group test pytest -q tests/e2e

# E2E including heavy fixtures (idbs/heavy/)
uv run --group test pytest -q tests/e2e --e2e-heavy
```

## Development

When changing code:
- bridge/server changes: restart the bridge server
- UI/plugin-side changes: restart IDA
- idalib-side changes: restart the runner

Hot reload is not supported.
