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
    """Return a sanitized environment for launching IDA via LaunchServices.

    Removes venv/python variables that could cause IDA's Python to resolve a
    different interpreter than intended, and scrubs the venv bin directory
    from PATH.
    """
    result = dict(os.environ)

    venv = result.pop("VIRTUAL_ENV", None)
    result.pop("__PYVENV_LAUNCHER__", None)
    result.pop("PYTHONHOME", None)
    result.pop("PYTHONPATH", None)

    if venv:
        venv_bin = Path(venv, "bin")
        path = result.get("PATH")
        if path:
            parts = [p for p in path.split(":") if p and Path(p).resolve() != venv_bin.resolve()]
            result["PATH"] = ":".join(parts)

    return result


def cmd_start_ui(args: argparse.Namespace) -> int:
    if sys.platform != "darwin" and not os.name == "nt":
        print("start-ui currently supports macOS and Windows only.", file=sys.stderr)
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

    # Resolve the IDA app bundle (macOS) or executable (Windows).
    if args.ida:
        app = Path(args.ida).expanduser().resolve()
        if os.name == "nt":
            if not app.is_file():
                raise SystemExit(f"--ida must point to the IDA executable (ida.exe/ida64.exe): {app}")
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

    if os.name == "nt":
        # Launch the GUI exe directly. CREATE_NEW_PROCESS_GROUP detaches the app
        # from the current console (so it never dies with it) without popping a
        # new console window. Popen gives us the child PID.
        child = subprocess.Popen([str(app), *args_list], creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        print("running:", " ".join([str(app), *args_list]), file=sys.stderr, flush=True)
    else:
        # Launch via LaunchServices
        cmd = ["open", "-n", "-a", str(app), "--args", *args_list]
        print("running:", " ".join(cmd), file=sys.stderr, flush=True)
        res = subprocess.run(cmd, env=_clean_env(), check=False)
        if res.returncode != 0:
            return int(res.returncode)

    want: str | None = None if os.name == "nt" else (idb_path or input_path or "").split("/")[-1]

    def _match_ui(c: protocol.ClientInfo) -> bool:
        meta = c.meta or {}
        if os.name == "nt":
            return meta.get("pid") == child.pid
        got = (meta.get("idb_path") or "").split("/")[-1]
        if want and got and want not in got and got not in want:
            return False
        return True

    matched = asyncio.run(bridge.poll_for_new_client(existing, _match_ui, timeout_s=float(args.wait_s), interval_s=0.5))

    if matched is None:
        prefix = "launched IDA via open, but" if not os.name == "nt" else "launched IDA, but"
        print(
            f"{prefix} could not observe a new client via the bridge.\n"
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


def _idalib_runner_path() -> Path:
    # idalib_runner.py lives alongside the supervisor package's parent.
    return Path(__file__).resolve().parent.parent / "idalib_runner.py"


def _idalib_venv_python() -> Path:
    """Default idalib venv python, mirroring the macOS layout under Windows."""
    if os.name == "nt":
        return Path.home() / ".idapro" / "venv" / "Scripts" / "python.exe"
    return Path.home() / ".idapro" / "venv" / "bin" / "python3"


IDALIB_VENV_PYTHON = _idalib_venv_python()


def _resolve_python(python: str | None) -> str:
    """Resolve the python interpreter for idalib. Raises StartError on failure."""
    if python is None:
        if IDALIB_VENV_PYTHON.exists() and os.access(IDALIB_VENV_PYTHON, os.X_OK):
            return str(IDALIB_VENV_PYTHON)
        raise StartError(
            f"idalib venv python not found: {IDALIB_VENV_PYTHON}\n\n"
            "Either:\n"
            f"  - Set up the headless venv (see README 'Windows setup' / 'Manual setup')\n"
            "  - Or pass --python /path/to/python explicitly"
        )
    resolved = str(Path(python).expanduser())
    if os.path.isfile(resolved) and os.access(resolved, os.X_OK):
        return resolved
    which = shutil.which(python)
    if which:
        return which
    raise StartError(f"python not found or not executable: {python}")


def _same_path(left: str, right: str) -> bool:
    """Compare absolute paths using the current platform's case semantics."""
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


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
    skip_auto_wait: bool = False,
) -> IdalibStartResult:
    """Start an idalib worker and poll until it connects to the bridge.

    Returns an IdalibStartResult. If ``client_id`` is None, the process
    started but did not connect within ``wait_s`` (may still be analyzing).

    Raises StartError on validation/startup failures.
    """
    python_path = _resolve_python(python)

    runner = _idalib_runner_path()
    if not runner.exists():
        raise StartError(f"idalib runner not found: {runner}")

    # Validate and resolve paths.
    idb_path: str | None = None
    input_path: str | None = None
    resolved_out_idb: str | None = None

    if idb:
        if dyld_module is not None:
            raise StartError("--dyld-module is only valid with --input")
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

    existing = asyncio.run(bridge.snapshot_existing())

    # Build runner args.
    runner_args: list[str] = [python_path, str(runner)]
    if idb_path is not None:
        runner_args.extend(["--idb", idb_path])
    else:
        assert input_path is not None and resolved_out_idb is not None
        runner_args.extend(["--input", input_path, "--out-idb", resolved_out_idb])
        if force:
            runner_args.append("--force")
        if arch:
            runner_args.extend(["--arch", arch])
        if dyld_module:
            runner_args.extend(["--dyld-module", dyld_module])
    if skip_auto_wait:
        runner_args.append("--skip-auto-wait")

    # Start with a placeholder log, then bind it to the pid once the process exists.
    tmp_log = _starting_log_path("idalib")
    log_fh = open(tmp_log, "w")
    if os.name == "nt":
        popen_kwargs: dict = {"creationflags": subprocess.CREATE_NO_WINDOW}
    else:
        popen_kwargs = {"start_new_session": True}
    child = subprocess.Popen(runner_args, stdout=log_fh, stderr=subprocess.STDOUT, **popen_kwargs)

    log_path = _bind_log_to_pid(tmp_log, "idalib", child.pid)

    expected_idb_path = idb_path or resolved_out_idb
    assert expected_idb_path is not None

    def _match_idalib(c: protocol.ClientInfo) -> bool:
        meta = c.meta or {}
        if meta.get("runtime") != "idalib":
            return False
        if not os.name == "nt":
            return meta.get("pid") == child.pid

        got_idb_path = meta.get("idb_path")
        return isinstance(got_idb_path, str) and _same_path(got_idb_path, expected_idb_path)

    matched = asyncio.run(
        bridge.poll_for_new_client(existing, _match_idalib, timeout_s=wait_s, abort=lambda: child.poll() is not None)
    )
    log_fh.close()

    if matched is None:
        if os.name == "nt":
            log_path = _bind_log_to_pid(Path(log_path), "idalib", child.pid)
        if proc.is_pid_alive(child.pid):
            return IdalibStartResult(pid=child.pid, client_id=None, log_path=log_path)
        raise StartError(f"idalib runner exited early with code {child.returncode}\nlog: {log_path}")

    matched_meta = matched.meta or {}
    connected_pid = matched_meta.get("pid")
    if not isinstance(connected_pid, int):
        connected_pid = child.pid
    if os.name == "nt" and connected_pid != child.pid:
        log_path = _bind_log_to_pid(Path(log_path), "idalib", connected_pid)

    connected_idb_path = matched_meta.get("idb_path")
    return IdalibStartResult(
        pid=connected_pid,
        client_id=matched.client_id,
        log_path=log_path,
        idb_path=connected_idb_path,
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
            skip_auto_wait=args.skip_auto_wait,
        )
    except StartError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if result.client_id is None:
        print(
            f"idalib runner started (pid={result.pid}) but did not connect to the bridge within {args.wait_s}s.\n"
            "This is expected for large binaries (auto-analysis must complete first).",
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
