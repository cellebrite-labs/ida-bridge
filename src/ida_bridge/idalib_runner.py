#!/usr/bin/env python3
# IMPORTANT: idalib requires `import idapro` to be the first import.
import argparse
import logging
import os
from pathlib import Path
import signal
import sys
from typing import Any, NoReturn

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl
    fcntl = None  # type: ignore[assignment]

import idapro

from ida_bridge import logs

log = logging.getLogger(__name__)


def _configure_logging() -> None:
    """Configure idalib runner logging to stdout (supervisor captures it)."""
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logs.make_formatter())
    root.addHandler(handler)

    # Suppress noisy websocket-client retry output.
    logging.getLogger("websocket").setLevel(logging.CRITICAL)


def _die(msg: str, *, code: int = 2) -> NoReturn:
    """Fatal exit before logging is configured."""
    print(msg, file=sys.stderr)
    raise SystemExit(code)


# Companion files IDA unpacks a database into while a session has it open (and
# repacks back into the single .i64/.idb on save/close). IDA holds an OS advisory
# lock (flock) on these while live, but not on the packed .i64/.idb itself.
_IDB_COMPANION_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til")


def _is_locked(path: Path) -> bool:
    """True if *path* is currently held under an exclusive OS lock.

    POSIX: ``fcntl.flock`` -- only ``BlockingIOError`` (lock unavailable) counts
    as "locked"; any other failure while probing propagates rather than silently
    treating an unrelated error (e.g. a filesystem that doesn't support flock)
    as "not locked" and letting a caller proceed to delete something it couldn't
    actually verify was safe to delete.

    Windows: IDA opens its database companions (``.id0/.id1/.id2/.nam/.til``)
    with share mode 0 (deny all), so an open attempt on a file another process
    holds fails with a sharing violation (``PermissionError``). Only that case
    counts as "locked"; other open errors fall through as "not locked".
    """
    if not path.exists():
        return False
    if os.name == "nt":
        try:
            fd = os.open(str(path), os.O_RDONLY)
        except PermissionError:
            return True  # sharing violation: held by another process (IDA)
        except OSError:
            return False
        os.close(fd)
        return False
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def _locked_companion(path: Path) -> Path | None:
    """Return the first file (companion, or *path* itself) found currently locked."""
    for candidate in (path, *(path.with_suffix(s) for s in _IDB_COMPANION_SUFFIXES)):
        if _is_locked(candidate):
            return candidate
    return None


def _idb_exists(path: Path) -> bool:
    """True if a packed IDB or any of its unpacked companions exist at *path*.

    A build killed before its pack-on-close step leaves companions with no
    packed file at all, so checking *path* alone would miss it.
    """
    return path.exists() or any(path.with_suffix(s).exists() for s in _IDB_COMPANION_SUFFIXES)


def _in_use_hint(locked: Path) -> str:
    """Diagnostic hint for a companion file already found to be currently locked."""
    return (
        f"\nHint: {locked.name} is currently lock-held by another process, meaning another "
        "idalib/IDA session has this database open right now. Close it first (see `ida-bridge list`)."
    )


def _remove_idb(path: Path) -> None:
    """Delete an IDB and any leftover companion files.

    IDA's ``-o``/``-c`` do not check whether the destination is currently open
    elsewhere: they unlink its companions unconditionally, with no error,
    silently orphaning the other session's live data (confirmed empirically --
    the other session keeps running against the now-unlinked inodes and
    permanently loses its data the moment it next saves). So refuse ourselves
    when a live lock is detected, instead of deleting.
    """
    locked = _locked_companion(path)
    if locked is not None:
        _die(f"refusing to overwrite {path}: it looks currently open elsewhere.{_in_use_hint(locked)}")
    path.unlink(missing_ok=True)
    for suffix in _IDB_COMPANION_SUFFIXES:
        path.with_suffix(suffix).unlink(missing_ok=True)


# Third-party deps expected to be installed into the python used to run this
# runner (same as the UI plugin requirements).
try:
    from pydantic import ValidationError  # noqa: F401
except Exception as exc:  # pragma: no cover
    _die(
        "missing python deps for idalib runner: pydantic, websocket-client\n"
        "Fix: use the ida-setup skill to install them into the python you pass to start-idalib.\n"
        f"Import error: {exc}"
    )

from ida_bridge import protocol  # noqa: E402
from ida_bridge.bridge_conn import BridgeConn  # noqa: E402
from ida_bridge.ida_runtime import RequestHandler, collect_meta, run_user_code  # noqa: E402
from ida_bridge.input_formats import dyld_cache_arch, fat_macho_arches, fat_macho_ida_filetype_arg  # noqa: E402

# IDA modules (available after importing idapro).
try:
    import ida_auto
except Exception as exc:  # pragma: no cover
    _die(f"failed to import IDA modules after idapro import: {exc}")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="idalib-runner", description="ida-bridge idalib runner")

    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--idb", help="Path to an existing IDB (.i64/.idb)")
    g.add_argument("--input", help="Path to an input binary/executable")

    parser.add_argument("--out-idb", default=None, help="Output IDB path when using --input")
    parser.add_argument("--force", action="store_true", help="Allow overwriting --out-idb if it exists")
    parser.add_argument(
        "--arch",
        default=None,
        help="Architecture slice to load from a fat (universal) Mach-O (e.g. arm64, x86_64)",
    )
    parser.add_argument(
        "--dyld-module",
        default=None,
        help="Initial dyld_shared_cache module to select for IDA's single-module loader",
    )

    parser.add_argument(
        "--connect-timeout-s",
        default=10.0,
        type=float,
        help="Fail if the bridge handshake does not complete within this timeout",
    )
    parser.add_argument(
        "--skip-auto-wait",
        action="store_true",
        help="Connect without draining IDA's auto-analysis queue (for poisoned or intentionally incomplete IDBs)",
    )

    ns = parser.parse_args(argv)

    # Normalize paths so the rest of the runner can treat them as already-validated strings.
    ns.idb = str(Path(ns.idb).expanduser().resolve()) if ns.idb else None
    ns.input = str(Path(ns.input).expanduser().resolve()) if ns.input else None

    if ns.input is not None:
        if not ns.out_idb:
            _die("--out-idb is required with --input")
        ns.out_idb = str(Path(ns.out_idb).expanduser().resolve())
        if ns.arch is not None and ns.dyld_module is not None:
            _die("--arch cannot be combined with --dyld-module")
    else:
        ns.out_idb = None
        if ns.arch is not None:
            _die("--arch is only valid with --input")
        if ns.dyld_module is not None:
            _die("--dyld-module is only valid with --input")

    # Validate filesystem inputs early.
    if ns.idb is not None and not os.path.exists(ns.idb):
        _die(f"IDB not found: {ns.idb}")

    if ns.input is not None and not os.path.exists(ns.input):
        _die(f"Input file not found: {ns.input}")

    if ns.out_idb is not None:
        out_parent = str(Path(ns.out_idb).parent)
        if not os.path.isdir(out_parent):
            _die(f"out-idb parent directory does not exist: {out_parent}")

        if _idb_exists(Path(ns.out_idb)):
            if not ns.force:
                _die(f"refusing to overwrite existing out-idb (use --force): {ns.out_idb}")
            # IDA's -o will not overwrite an existing database; clear it first.
            _remove_idb(Path(ns.out_idb))

    if ns.connect_timeout_s <= 0:
        _die("--connect-timeout-s must be > 0")

    return ns


def _open_database(args: argparse.Namespace) -> str:
    """Open an IDA database. Returns the IDB path."""
    if args.idb is not None:
        rc = idapro.open_database(args.idb, False)
        if rc != 0:
            locked = _locked_companion(Path(args.idb))
            hint = _in_use_hint(locked) if locked is not None else ""
            _die(f"open_database failed for IDB: {args.idb} (rc={rc}){hint}")
        return args.idb

    assert args.input is not None and args.out_idb is not None

    input_path = Path(args.input)

    if args.dyld_module is not None:
        arch = dyld_cache_arch(input_path)
        if arch is None:
            _die("--dyld-module requires a dyld_shared_cache input")
        os.environ["IDA_DYLD_CACHE_MODULE"] = args.dyld_module
        ida_args = f'-P+ -o{args.out_idb} -T"Apple DYLD cache for {arch} (single module)"'
    else:
        arches = fat_macho_arches(input_path)

        if arches is not None and args.arch is None:
            available = ", ".join(arches)
            _die(f"fat Mach-O with slices: {available}. Use --arch to select one.")

        ida_args = f"-P+ -o{args.out_idb}"

        if arches is not None and args.arch is not None:
            try:
                filetype = fat_macho_ida_filetype_arg(input_path, args.arch)
            except ValueError as exc:
                _die(str(exc))
            ida_args = f'-T"{filetype}" {ida_args}'
        elif arches is None and args.arch is not None:
            log.warning("--arch %s ignored: %s is not a fat Mach-O", args.arch, args.input)

    rc = idapro.open_database(args.input, False, args=ida_args)
    if rc != 0:
        _die(f"open_database failed for input: {args.input} (rc={rc})")
    return args.out_idb


def _run_code_direct(
    code: str,
    exec_env: dict[str, Any],
) -> tuple[Any, str, str, Exception | None]:
    """Execute user code directly (idalib owns the thread)."""
    return run_user_code(code=code, exec_env=exec_env)


def run_worker(args: argparse.Namespace) -> int:
    _configure_logging()

    client_id = f"idalib-{os.getpid()}"

    # Signal-initiated shutdown (SIGTERM/SIGINT).
    signal_shutdown = False

    def _on_signal(_signum: int, _frame: Any) -> None:
        nonlocal signal_shutdown
        signal_shutdown = True

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    idb_path = _open_database(args)
    conn: BridgeConn | None = None
    handler: RequestHandler | None = None

    try:
        # Wait for analysis before advertising ourselves to the bridge unless
        # explicitly bypassed for a poisoned/non-terminating analysis queue.
        if args.skip_auto_wait:
            log.warning("skipping auto-analysis wait: %s", idb_path)
        else:
            log.info("waiting for auto-analysis: %s", idb_path)
            ida_auto.auto_wait()

        if signal_shutdown:
            return 0

        meta = collect_meta(client_id=client_id, runtime="idalib")
        conn = BridgeConn(client_id=client_id, meta=meta)

        conn.start()
        if not conn.wait_ready(timeout_s=args.connect_timeout_s):
            conn.stop()
            log.critical(
                "failed to connect to ida-bridge at %s\n"
                "Hint: start the bridge server and/or check your python has websocket-client + pydantic installed.",
                protocol.bridge_url(),
            )
            return 2

        handler = RequestHandler(client_id=client_id, run_code=_run_code_direct, send=conn.send)

        log.info("ready: client_id=%s", client_id)

        while not signal_shutdown and not handler.quit_requested:
            msg = conn.recv(timeout_s=0.25)
            if msg is None:
                continue
            handler.handle(msg)

        return 0

    finally:
        # Never auto-save on shutdown.  Agent-initiated quit: the agent is
        # responsible for saving explicitly before requesting shutdown.
        # Signal-initiated quit: database state is uncertain, saving risks
        # persisting corruption.
        log.info("shutting down")

        try:
            idapro.close_database(save=False)
        except Exception:
            log.exception("close_database failed")

        if conn is not None:
            conn.stop()


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return run_worker(args)


if __name__ == "__main__":
    raise SystemExit(main())
