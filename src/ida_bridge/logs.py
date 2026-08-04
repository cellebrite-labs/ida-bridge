"""Shared logging primitives.

Import-safe so the IDA side (``idalib_runner``) can import it after
``import idapro``: only stdlib plus ``ida_bridge.proc`` (itself stdlib-only).
"""

import logging
import os
from pathlib import Path

from ida_bridge import proc

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Per-prefix retention for dead instance logs, and how often the server sweeps.
LOG_KEEP = int(os.getenv("IDA_BRIDGE_LOG_KEEP", "30"))
LOG_PRUNE_INTERVAL_S = float(os.getenv("IDA_BRIDGE_LOG_PRUNE_INTERVAL_S", "3600"))

_log = logging.getLogger("ida-bridge")


def log_dir() -> Path:
    """Base directory for bridge logs (server log + per-instance launch logs).

    Overridable via ``IDA_BRIDGE_LOG_DIR``. The server log can be relocated
    independently via ``IDA_BRIDGE_LOG_FILE``.

    Default is platform-aware: ``~/Library/Logs/ida-bridge`` on macOS/Unix,
    ``%LOCALAPPDATA%\\ida-bridge\\logs`` on Windows.
    """
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        default = Path(base) / "ida-bridge" / "logs"
    else:
        default = Path.home() / "Library" / "Logs" / "ida-bridge"
    return Path(os.getenv("IDA_BRIDGE_LOG_DIR", str(default))).expanduser()


def make_formatter() -> logging.Formatter:
    return logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT)


def _log_mtime(p: Path) -> float:
    """Return mtime for sorting; 0.0 if the file was concurrently deleted."""
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def prune_instance_logs() -> None:
    """Bound the instance-log directory: keep every live instance's log plus the
    ``LOG_KEEP`` most-recent dead logs per prefix, delete the rest.

    Owned by the bridge server (single writer). Best-effort -- never raises, so a
    cleanup hiccup cannot disrupt the server.
    """
    base = log_dir()
    try:
        for prefix in ("idaui", "idalib"):
            entries = sorted(base.glob(f"{prefix}-*.log"), key=_log_mtime, reverse=True)
            dead = []
            for p in entries:
                token = p.stem.rsplit("-", 1)[-1]  # idaui-<pid>.log / idalib-<pid>.log
                if not (token.isdigit() and proc.is_pid_alive(int(token))):
                    dead.append(p)
            for stale in dead[LOG_KEEP:]:
                stale.unlink(missing_ok=True)
    except OSError as exc:
        _log.warning("instance-log cleanup skipped: %s", exc)
