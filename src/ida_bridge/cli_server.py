"""IDA Bridge server management."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

from ida_bridge import logs, proc, protocol

SERVER_MODULE = "ida_bridge.server"

LOG_FILE = Path(os.getenv("IDA_BRIDGE_LOG_FILE", str(logs.log_dir() / "server.log"))).expanduser()
# Raw stdout/stderr capture for the server process: crash tracebacks and any output that
# bypasses logging. Kept separate from LOG_FILE so the server's RotatingFileHandler is the
# sole writer of LOG_FILE (a second writer would keep writing a rotated-out inode).
OUT_FILE = LOG_FILE.with_suffix(".out")

PORT = protocol.bridge_port()


def _server_cmd() -> list[str]:
    return [sys.executable, "-m", SERVER_MODULE]


def _parse_netstat_listening_pid(stdout: str) -> int | None:
    """Return the listener PID for ``PORT`` from Windows ``netstat -ano`` output."""
    wanted_port = str(PORT)
    for line in stdout.splitlines():
        tokens = line.split()
        if len(tokens) < 4 or "LISTENING" not in (token.upper() for token in tokens):
            continue

        # The local endpoint is the second column. rpartition handles both
        # 127.0.0.1:8765 and [::]:8765 without matching nearby ports such as
        # 87650.
        local_endpoint = tokens[1]
        _, separator, port = local_endpoint.rpartition(":")
        if not separator or port != wanted_port:
            continue
        try:
            return int(tokens[-1])
        except ValueError:
            continue
    return None


def _get_server_pid_windows() -> int | None:
    """Find the PID listening on our port on Windows via netstat (+ psutil if available)."""
    try:
        import psutil
    except ImportError:
        pass
    else:
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == "LISTEN" and conn.laddr.port == PORT:
                    return conn.pid
        except OSError:
            pass
    try:
        result = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True)
    except (subprocess.SubprocessError, OSError):
        return None
    return _parse_netstat_listening_pid(result.stdout)


def get_server_pid() -> int | None:
    """Get PID of process listening on our port."""
    if os.name == "nt":
        return _get_server_pid_windows()
    try:
        result = subprocess.run(
            ["lsof", "-ti", f":{PORT}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip().split()[0])
    except (subprocess.SubprocessError, ValueError):
        pass
    return None


def cmd_status(args: argparse.Namespace) -> int:
    pid = get_server_pid()
    if pid:
        print(f"Server running (PID: {pid})")
        return 0
    print("Server not running")
    return 1


def cmd_start(args: argparse.Namespace) -> int:
    if get_server_pid():
        print("Server already running")
        return 0

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["IDA_BRIDGE_LOG_FILE"] = str(LOG_FILE)

    print(f"Starting server... (logging to {LOG_FILE})")
    # Truncate per boot: this holds only the current run's raw output (mostly empty).
    with open(OUT_FILE, "w") as out:
        if os.name == "nt":
            # CREATE_NO_WINDOW keeps the server from popping a console.
            # (start_new_session is invalid on Windows.)
            popen_kwargs: dict = {"creationflags": subprocess.CREATE_NO_WINDOW}
        else:
            popen_kwargs = {"start_new_session": True}
        subprocess.Popen(
            _server_cmd(),
            stdout=out,
            stderr=subprocess.STDOUT,
            env=env,
            **popen_kwargs,
        )

    time.sleep(0.5)
    listener_pid = get_server_pid()
    if listener_pid:
        # A Windows venv python.exe is a redirector that remains as the parent
        # of the base interpreter. Popen sees the redirector PID, while the base
        # interpreter owns the socket. Always report the authoritative listener.
        print(f"Server started (PID: {listener_pid})")
        return 0

    print(f"Failed to start. Check logs: {LOG_FILE} and {OUT_FILE}")
    return 1


def cmd_stop(args: argparse.Namespace) -> int:
    pid = get_server_pid()
    if not pid:
        print("Server not running")
        return 0

    print(f"Stopping server (PID: {pid})...")
    # Cross-platform terminate: SIGTERM → wait → SIGKILL on POSIX; hard
    # TerminateProcess on Windows (graceful stop there would be the bridge quit RPC).
    proc.terminate_pid(pid)

    for _ in range(20):
        if not get_server_pid():
            print("Server stopped")
            return 0
        time.sleep(0.1)

    print("Server did not stop")
    return 1


def cmd_log(args: argparse.Namespace) -> int:
    if not LOG_FILE.exists():
        print(f"No log file: {LOG_FILE}")
        return 1
    try:
        if os.name == "nt":
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"Get-Content -Wait -Tail 20 '{LOG_FILE}'"]
            )
        else:
            subprocess.run(["tail", "-f", str(LOG_FILE)])
    except KeyboardInterrupt:
        pass
    return 0


def cmd_log_clear(args: argparse.Namespace) -> int:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if LOG_FILE.exists():
        LOG_FILE.write_text("")
        print(f"Log cleared: {LOG_FILE}")
    else:
        print(f"No log file to clear: {LOG_FILE}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IDA Bridge server management")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("status", help="Check if server is running")
    sub.add_parser("start", help="Start server in background")
    sub.add_parser("stop", help="Stop the server")
    sub.add_parser("log", help="Tail the server log")
    sub.add_parser("log-clear", help="Clear the server log")

    args = parser.parse_args(argv)
    commands = {
        "status": cmd_status,
        "start": cmd_start,
        "stop": cmd_stop,
        "log": cmd_log,
        "log-clear": cmd_log_clear,
    }

    if args.cmd in commands:
        return commands[args.cmd](args)
    parser.print_help()
    return 1
