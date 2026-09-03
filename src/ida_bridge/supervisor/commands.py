"""Supervisor commands: start-ui, start-idalib, stop, save."""

import argparse
import asyncio
from dataclasses import dataclass
import json as json_mod
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any

from ida_bridge import logs, proc, protocol

from . import bridge, ida_resolve

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _snapshot_or_fail(cmd_name: str) -> set[str] | int:
    """Snapshot existing bridge clients; return exit code on failure."""
    try:
        return asyncio.run(bridge.snapshot_existing())
    except Exception as exc:
        print(
            f"bridge server must be running to use {cmd_name}.\nerror: {exc}",
            file=sys.stderr,
        )
        return 2


def _bind_log_to_pid(tmp_log: Path, prefix: str, pid: int) -> str:
    """Rename a placeholder log to its canonical pid name (``<prefix>-<pid>.log``).

    The pid name mirrors the client_id and lets retention detect live instances. The
    writer keeps the -L/stdout fd open, so it goes on writing the same inode after the
    rename (POSIX). Returns the path in use -- the final name, or the placeholder if the
    rename fails.
    """
    final = str(logs.log_dir() / f"{prefix}-{pid}.log")
    try:
        tmp_log.rename(final)
        return final
    except OSError:
        return str(tmp_log)


def _starting_log_path(prefix: str) -> Path:
    """Placeholder log path used before the instance pid is known."""
    log_dir = logs.log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / f"{prefix}-starting-{int(time.time())}.log"


def _output(data: dict[str, Any], *, json_mode: bool) -> None:
    """Print structured output as JSON or human-readable key: value lines."""
    if json_mode:
        print(json_mod.dumps(data))
    else:
        for k, v in data.items():
            if v is not None:
                print(f"{k}: {v}")


# ---------------------------------------------------------------------------
# start-ui
# ---------------------------------------------------------------------------


def _clean_env() -> dict[str, str]:
    """Return a sanitized environment for launching UI IDA.

    Removes venv/python variables that could cause IDA's Python to resolve a
    different interpreter than intended, and scrubs the venv script directory
    from PATH. Points IDA at the same venv the headless runner uses, unless the
    caller already chose one.
    """
    result = dict(os.environ)

    venv = result.pop("VIRTUAL_ENV", None)
    result.pop("__PYVENV_LAUNCHER__", None)
    result.pop("PYTHONHOME", None)
    result.pop("PYTHONPATH", None)

    if venv:
        venv_bins = {Path(venv, "bin").resolve(), Path(venv, "Scripts").resolve()}
        path = result.get("PATH")
        if path:
            parts = [p for p in path.split(os.pathsep) if p and Path(p).resolve() not in venv_bins]
            result["PATH"] = os.pathsep.join(parts)

    if not result.get("IDAPYTHON_VENV_EXECUTABLE") and IDALIB_VENV_PYTHON.is_file():
        result["IDAPYTHON_VENV_EXECUTABLE"] = str(IDALIB_VENV_PYTHON)

    return result


def _same_path(left: str, right: str) -> bool:
    """Compare filesystem paths using the current platform's case semantics."""
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def cmd_start_ui(args: argparse.Namespace) -> int:
    if sys.platform not in ("darwin", "win32", "linux"):
        print("start-ui currently supports macOS, Windows, and Linux only.", file=sys.stderr)
        return 2

    if sys.platform == "linux" and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        # IDA would start, fail to open a window, and surface as a connect timeout.
        print("no display: start-ui needs DISPLAY or WAYLAND_DISPLAY set.", file=sys.stderr)
        return 2

    # Validate and resolve paths.
    idb_path: str | None = None
    input_path: str | None = None

    if args.idb:
        if args.out_idb:
            print("--out-idb is only valid with --input", file=sys.stderr)
            return 2
        idb_path = str(Path(args.idb).expanduser().resolve())
        if not os.path.exists(idb_path):
            print(f"IDB not found: {idb_path}", file=sys.stderr)
            return 2
    else:
        input_path = str(Path(args.input).expanduser().resolve())
        if not os.path.exists(input_path):
            print(f"Input file not found: {input_path}", file=sys.stderr)
            return 2
        if args.out_idb:
            idb_path = str(Path(args.out_idb).expanduser().resolve())

    tmp_log = _starting_log_path("idaui")

    if args.ida:
        app = Path(args.ida).expanduser().resolve()
        if sys.platform == "win32":
            # X_OK is meaningless on Windows -- it is True for any existing file.
            if not app.is_file() or app.suffix.lower() != ".exe":
                raise SystemExit(f"--ida must point to the IDA executable (ida.exe): {app}")
        elif sys.platform == "linux":
            if not app.is_file() or not os.access(app, os.X_OK):
                raise SystemExit(f"--ida must point to the IDA executable (ida): {app}")
        elif not app.exists() or app.suffix != ".app":
            raise SystemExit(f"--ida must point to a .app bundle: {app}")
    else:
        app = ida_resolve.find_ida()

    existing = _snapshot_or_fail("start-ui")
    if isinstance(existing, int):
        return existing

    args_list: list[str] = [f"-L{tmp_log}"]
    if input_path is not None:
        args_list.append("-P+")
        if idb_path is not None:
            args_list.append(f"-o{idb_path}")
        args_list.append(input_path)
    else:
        assert idb_path is not None
        args_list.append(idb_path)

    launched_pid: int | None = None
    if sys.platform == "win32":
        # Direct exe launch. CREATE_NEW_PROCESS_GROUP detaches from this
        # console without hiding the GUI window. Popen gives us a child PID.
        child = subprocess.Popen(
            [str(app), *args_list],
            env=_clean_env(),
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        launched_pid = child.pid
        print("running:", " ".join([str(app), *args_list]), file=sys.stderr, flush=True)
    elif sys.platform == "linux":
        # Direct launch, so Popen gives us a child PID to match on. New session so
        # IDA outlives the CLI.
        child = subprocess.Popen(
            [str(app), *args_list],
            env=_clean_env(),
            **proc.detached_popen_kwargs(),
        )
        launched_pid = child.pid
        print("running:", " ".join([str(app), *args_list]), file=sys.stderr, flush=True)
    else:
        # LaunchServices (Finder-like; inherits launchd env, e.g. plist-set vars).
        cmd = ["open", "-n", "-a", str(app), "--args", *args_list]
        print("running:", " ".join(cmd), file=sys.stderr, flush=True)
        res = subprocess.run(cmd, env=_clean_env(), check=False)
        if res.returncode != 0:
            return int(res.returncode)

    # Match a new IDA client. Prefer pid when we spawned the process ourselves.
    # `open -n -a` does not return a child pid, so macOS falls back to basename.
    want_name = Path(idb_path or input_path or "").name

    def _match_ui(c: protocol.ClientInfo) -> bool:
        meta = c.meta or {}
        if launched_pid is not None and meta.get("pid") == launched_pid:
            return True
        got = Path(meta.get("idb_path") or "").name
        if want_name and got and want_name not in got and got not in want_name:
            return False
        return True

    matched = asyncio.run(bridge.poll_for_new_client(existing, _match_ui, timeout_s=float(args.wait_s), interval_s=0.5))

    if matched is None:
        print(
            "launched IDA, but could not observe a new client via the bridge.\n"
            "- verify the plugin is installed and deps are present\n"
            f"log: {tmp_log}",
            file=sys.stderr,
        )
        return 2

    pid = matched.meta.get("pid") if matched.meta else None
    if not isinstance(pid, int):
        print(f"connected client has no pid metadata: {matched.client_id}\nlog: {tmp_log}", file=sys.stderr)
        return 2

    log_path = _bind_log_to_pid(tmp_log, "idaui", pid)

    idb_path = (matched.meta or {}).get("idb_path")
    _output({"client_id": matched.client_id, "idb_path": idb_path, "pid": pid, "log": log_path}, json_mode=args.json)
    return 0


# ---------------------------------------------------------------------------
# start-idalib
# ---------------------------------------------------------------------------


class StartError(Exception):
    """Failed to start an idalib instance."""


@dataclass
class IdalibStartResult:
    pid: int
    client_id: str | None  # None if process alive but not yet connected.
    log_path: str
    idb_path: str | None = None


@dataclass
class SpawnedIdalib:
    """A bridge-host idalib child and the paths resolved for its launch."""

    process: Any
    expected_idb_path: str
    log_path: str

    @property
    def pid(self) -> int:
        return int(self.process.pid)


@dataclass(frozen=True)
class _IdalibLaunch:
    argv: list[str]
    expected_idb_path: str


def _idalib_runner_path() -> Path:
    # idalib_runner.py lives alongside the supervisor package's parent.
    return Path(__file__).resolve().parent.parent / "idalib_runner.py"


def default_idalib_python() -> Path:
    """Default interpreter for the headless runner (``~/.idapro/venv`` layout)."""
    root = Path.home() / ".idapro" / "venv"
    if sys.platform == "win32":
        return root / "Scripts" / "python.exe"
    return root / "bin" / "python3"


IDALIB_VENV_PYTHON = default_idalib_python()


def _resolve_python(python: str | None) -> str:
    """Resolve the python interpreter for idalib. Raises StartError on failure."""
    if python is None:
        if IDALIB_VENV_PYTHON.exists() and os.access(IDALIB_VENV_PYTHON, os.X_OK):
            return str(IDALIB_VENV_PYTHON)
        raise StartError(
            f"idalib venv python not found: {IDALIB_VENV_PYTHON}\n\n"
            "Either:\n"
            "  - Create ~/.idapro/venv with idapro + ida-bridge installed (see README)\n"
            "  - Or pass --python /path/to/python explicitly"
        )
    resolved = str(Path(python).expanduser())
    if os.path.isfile(resolved) and os.access(resolved, os.X_OK):
        return resolved
    which = shutil.which(python)
    if which:
        return which
    raise StartError(f"python not found or not executable: {python}")


def _prepare_idalib_launch(
    *,
    idb: str | None,
    input_file: str | None,
    out_idb: str | None,
    force: bool,
    arch: str | None,
    dyld_module: str | None,
    python: str | None,
    skip_initial_auto_analysis: bool = False,
) -> _IdalibLaunch:
    python_path = _resolve_python(python)

    runner = _idalib_runner_path()
    if not runner.exists():
        raise StartError(f"idalib runner not found: {runner}")

    idb_path: str | None = None
    input_path: str | None = None
    resolved_out_idb: str | None = None

    if idb:
        if out_idb is not None or force or arch is not None or dyld_module is not None:
            raise StartError("--out-idb, --force, --arch, and --dyld-module are only valid with --input")
        idb_path = str(Path(idb).expanduser().resolve())
        if not os.path.exists(idb_path):
            raise StartError(f"IDB not found: {idb_path}")
    elif input_file:
        if arch is not None and dyld_module is not None:
            raise StartError("--arch cannot be combined with --dyld-module")
        input_path = str(Path(input_file).expanduser().resolve())
        if not os.path.exists(input_path):
            raise StartError(f"Input file not found: {input_path}")
        if not out_idb:
            raise StartError("--out-idb is required with --input")
        resolved_out_idb = str(Path(out_idb).expanduser().resolve())
        if os.path.exists(resolved_out_idb) and not force:
            raise StartError(f"refusing to overwrite existing out-idb (use --force): {resolved_out_idb}")

        from ida_bridge.input_formats import dyld_cache_arch, fat_macho_arches

        input_file_path = Path(input_path)
        if dyld_module is not None and dyld_cache_arch(input_file_path) is None:
            raise StartError("--dyld-module requires a dyld_shared_cache input")

        arches = fat_macho_arches(input_file_path)
        if arches is not None and not arch:
            available = ", ".join(arches)
            raise StartError(f"fat Mach-O with slices: {available}. Use --arch to select one.")
    else:
        raise StartError("one of --idb or --input is required")

    argv: list[str] = [python_path, str(runner)]
    if idb_path is not None:
        argv.extend(["--idb", idb_path])
        expected_idb_path = idb_path
    else:
        assert input_path is not None and resolved_out_idb is not None
        argv.extend(["--input", input_path, "--out-idb", resolved_out_idb])
        if force:
            argv.append("--force")
        if arch:
            argv.extend(["--arch", arch])
        if dyld_module:
            argv.extend(["--dyld-module", dyld_module])
        expected_idb_path = resolved_out_idb
    if skip_initial_auto_analysis:
        argv.append("--skip-initial-auto-analysis")

    return _IdalibLaunch(argv=argv, expected_idb_path=expected_idb_path)


def _spawn_prepared_idalib(
    launch: _IdalibLaunch,
    *,
    bridge_host: str | None = None,
    bridge_port: int | None = None,
) -> SpawnedIdalib:
    if (bridge_host is None) != (bridge_port is None):
        raise ValueError("bridge_host and bridge_port must be provided together")

    env = None
    if bridge_host is not None and bridge_port is not None:
        env = dict(os.environ)
        env["IDA_BRIDGE_HOST"] = bridge_host
        env["IDA_BRIDGE_PORT"] = str(bridge_port)

    tmp_log = _starting_log_path("idalib")
    with open(tmp_log, "w") as log_fh:
        child = subprocess.Popen(
            launch.argv,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            env=env,
            **proc.detached_popen_kwargs(),
        )

    log_path = _bind_log_to_pid(tmp_log, "idalib", child.pid)
    return SpawnedIdalib(process=child, expected_idb_path=launch.expected_idb_path, log_path=log_path)


def spawn_idalib(
    *,
    idb: str | None = None,
    input_file: str | None = None,
    out_idb: str | None = None,
    force: bool = False,
    arch: str | None = None,
    dyld_module: str | None = None,
    python: str | None = None,
    bridge_host: str | None = None,
    bridge_port: int | None = None,
) -> SpawnedIdalib:
    """Validate and start an idalib worker on the current host without polling a bridge."""
    if (bridge_host is None) != (bridge_port is None):
        raise ValueError("bridge_host and bridge_port must be provided together")
    launch = _prepare_idalib_launch(
        idb=idb,
        input_file=input_file,
        out_idb=out_idb,
        force=force,
        arch=arch,
        dyld_module=dyld_module,
        python=python,
    )
    return _spawn_prepared_idalib(launch, bridge_host=bridge_host, bridge_port=bridge_port)


def matches_spawned_idalib(client: protocol.ClientInfo, spawned: SpawnedIdalib) -> bool:
    """Return whether a connected client is the runner represented by ``spawned``."""
    meta = client.meta or {}
    if meta.get("runtime") != "idalib":
        return False
    got_pid = meta.get("pid")
    if got_pid == spawned.pid:
        return True
    # Windows venv python.exe is a redirector: Popen.pid is the stub,
    # os.getpid() inside the runner is the real interpreter.
    if sys.platform != "win32":
        return False
    if isinstance(got_pid, int) and proc.is_pid_in_tree(spawned.pid, got_pid):
        return True
    got_path = meta.get("idb_path")
    return isinstance(got_path, str) and _same_path(got_path, spawned.expected_idb_path)


def bind_spawned_idalib_log(spawned: SpawnedIdalib, pid: int) -> str:
    """Bind a spawned runner log to the PID reported by the connected runtime."""
    spawned.log_path = _bind_log_to_pid(Path(spawned.log_path), "idalib", pid)
    return spawned.log_path


def start_idalib(
    *,
    idb: str | None = None,
    input_file: str | None = None,
    out_idb: str | None = None,
    force: bool = False,
    arch: str | None = None,
    dyld_module: str | None = None,
    python: str | None = None,
    wait_s: float = 300.0,
    skip_initial_auto_analysis: bool = False,
) -> IdalibStartResult:
    """Start an idalib worker and poll until it connects to the bridge.

    Returns an IdalibStartResult. If ``client_id`` is None, the process
    started but did not connect within ``wait_s`` (may still be analyzing).

    Raises StartError on validation/startup failures.
    """
    launch = _prepare_idalib_launch(
        idb=idb,
        input_file=input_file,
        out_idb=out_idb,
        force=force,
        arch=arch,
        dyld_module=dyld_module,
        python=python,
        skip_initial_auto_analysis=skip_initial_auto_analysis,
    )

    existing = asyncio.run(bridge.snapshot_existing())
    spawned: SpawnedIdalib | None = None
    try:
        spawned = _spawn_prepared_idalib(launch)
        matched = asyncio.run(
            bridge.poll_for_new_client(
                existing,
                lambda client: matches_spawned_idalib(client, spawned),
                timeout_s=wait_s,
                abort=lambda: spawned.process.poll() is not None,
            )
        )
    except BaseException:
        # Unexpected failure after spawn must not leak the runner (or its
        # Windows venv child). Intentional "still waiting" returns below.
        if spawned is not None:
            proc.terminate_pid(spawned.pid, timeout_s=2.0)
        raise

    result_pid = spawned.pid
    if matched is not None:
        connected_pid = (matched.meta or {}).get("pid")
        if isinstance(connected_pid, int):
            result_pid = connected_pid
    log_path = bind_spawned_idalib_log(spawned, result_pid)

    if matched is None:
        return_code = spawned.process.poll()
        if return_code is None and proc.is_pid_alive(spawned.pid):
            return IdalibStartResult(
                pid=spawned.pid,
                client_id=None,
                log_path=log_path,
                idb_path=spawned.expected_idb_path,
            )
        raise StartError(f"idalib runner exited early with code {return_code}\nlog: {log_path}")

    return IdalibStartResult(
        pid=result_pid,
        client_id=matched.client_id,
        log_path=log_path,
        idb_path=(matched.meta or {}).get("idb_path"),
    )


def cmd_start_idalib(args: argparse.Namespace) -> int:
    try:
        result = start_idalib(
            idb=args.idb,
            input_file=args.input,
            out_idb=args.out_idb,
            force=args.force,
            arch=args.arch,
            dyld_module=args.dyld_module,
            python=args.python,
            wait_s=float(args.wait_s),
            skip_initial_auto_analysis=args.skip_initial_auto_analysis,
        )
    except StartError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if result.client_id is None:
        print(
            f"idalib runner started (pid={result.pid}) but did not connect to the bridge within {args.wait_s}s.\n"
            "This is expected for large binaries (initial auto-analysis takes time).\n"
            "If you suspect the binary is malformed and analysis hangs, stop it "
            f"(`ida-bridge supervisor stop {result.pid}`), then start again with --skip-initial-auto-analysis.",
            file=sys.stderr,
        )
        _output(
            {"client_id": None, "pid": result.pid, "log": result.log_path, "status": "waiting"}, json_mode=args.json
        )
        return 0

    _output(
        {"client_id": result.client_id, "idb_path": result.idb_path, "pid": result.pid, "log": result.log_path},
        json_mode=args.json,
    )
    return 0


# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------


def _extract_pid_from_client_id(client_id: str) -> int | None:
    """Extract PID from conventional client_ids like ``idalib-12345`` or ``idaui-12345``."""
    for prefix in ("idalib-", "idaui-"):
        if client_id.startswith(prefix):
            suffix = client_id[len(prefix) :]
            if suffix.isdigit():
                return int(suffix)
    return None


def _resolve_from_bridge_list(
    client_id: str | None,
    pid: int | None,
) -> tuple[str | None, int | None]:
    """Try to fill in missing client_id/pid by querying the bridge client list."""
    if client_id is not None and pid is not None:
        return client_id, pid

    try:
        clients = asyncio.run(bridge.list_ida_clients())
    except Exception:
        return client_id, pid
    if clients is None:
        return client_id, pid

    for c in clients:
        meta = c.meta or {}
        if client_id is not None and c.client_id == client_id:
            got = meta.get("pid")
            return client_id, got if isinstance(got, int) else None
        if pid is not None and meta.get("pid") == pid:
            return str(c.client_id), pid

    return client_id, pid


def _stop_result(method: str, *, json_mode: bool) -> None:
    """Output stop result — JSON mode or descriptive human text."""
    if json_mode:
        print(json_mod.dumps({"ok": True, "method": method}))
        return
    if method in ("quit", "already_dead"):
        print("stopped")
    elif method == "sigterm":
        print("stopped (SIGTERM)")
    elif method == "sigkill":
        print("stopped (SIGKILL)")


def cmd_stop(args: argparse.Namespace) -> int:
    target = str(args.target).strip()
    json_mode: bool = args.json

    pid: int | None = None
    client_id: str | None = None

    if target.isdigit():
        pid = int(target)
    else:
        client_id = target

    # Resolve pid/client_id via bridge metadata when possible.
    client_id, pid = _resolve_from_bridge_list(client_id, pid)

    # Fallback: parse pid from conventional client_id strings.
    if client_id is not None and pid is None:
        pid = _extract_pid_from_client_id(client_id)

    # Prefer graceful quit via bridge if we have a client_id.
    quit_ok = False
    if client_id is not None:
        try:
            quit_ok = asyncio.run(bridge.bridge_quit(client_id))
        except Exception:
            quit_ok = False

    if quit_ok and pid is not None:
        if not json_mode:
            print(f"requested graceful quit: {client_id}; waiting for exit...", flush=True)
        if proc.wait_for_exit(pid):
            _stop_result("quit", json_mode=json_mode)
            return 0
        if not json_mode:
            print("process still alive after graceful quit; escalating")
        # Fall through to terminate_pid.
    elif quit_ok:
        # No pid to wait on; best-effort.
        _stop_result("quit", json_mode=json_mode)
        return 0

    if pid is None:
        print(f"could not quit {client_id} via bridge; pid required for OS kill", file=sys.stderr)
        return 2

    method = proc.terminate_pid(pid)
    _stop_result(method, json_mode=json_mode)
    return 0


# ---------------------------------------------------------------------------
# save
# ---------------------------------------------------------------------------


def cmd_save(args: argparse.Namespace) -> int:
    """Save the IDB for a connected instance."""
    target = str(args.target).strip()
    json_mode: bool = args.json

    try:
        saved = asyncio.run(bridge.bridge_save(target, session_id=args.session_id, persist=args.stateful))
    except Exception as exc:
        print(f"save failed: {exc}", file=sys.stderr)
        return 2

    _output({"saved": saved}, json_mode=json_mode)
    return 0
