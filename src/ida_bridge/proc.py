"""Process lifecycle primitives. Stdlib-only and import-safe (no ida_bridge imports)."""

import ctypes
from ctypes import wintypes
import os
import signal
import time

if os.name == "nt":  # pragma: no branch - definitions are platform-specific
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateProcess.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL


def _is_pid_alive_posix(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # Process entry exists but may be a zombie child -- try to reap.
    try:
        wpid, _ = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            return False
    except ChildProcessError:
        pass  # not our child
    return True


def _is_pid_alive_windows(pid: int) -> bool:
    """Windows liveness via OpenProcess + GetExitCodeProcess (STILL_ACTIVE).

    Cannot use ``os.kill(pid, 0)``: on Windows it *terminates* the process
    (TerminateProcess with exit code 0) instead of probing liveness.
    """
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259

    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        if not _kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == STILL_ACTIVE
    finally:
        _kernel32.CloseHandle(handle)


def is_pid_alive(pid: int) -> bool:
    if os.name == "nt":
        return _is_pid_alive_windows(pid)
    return _is_pid_alive_posix(pid)


def wait_for_exit(pid: int, timeout_s: float = 20.0) -> bool:
    """Poll until pid exits. Returns True if it exited within the timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not is_pid_alive(pid):
            return True
        time.sleep(0.1)
    return False


def _terminate_pid_posix(pid: int, *, timeout_s: float) -> str:
    """POSIX: best-effort SIGTERM then SIGKILL. Returns method string."""
    if not is_pid_alive(pid):
        return "already_dead"
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return "already_dead"
    if wait_for_exit(pid, timeout_s):
        return "sigterm"
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return "sigterm"
    return "sigkill"


def _terminate_pid_windows(pid: int, *, timeout_s: float) -> str:
    """Windows: hard TerminateProcess (no graceful OS signal exists).

    Graceful shutdown on Windows is handled earlier by the bridge ``quit`` RPC
    (``bridge_quit``) in both ``cmd_stop`` and ``exec-idb``; this OS kill is the
    escalation path only. ``TerminateProcess`` never runs the child's signal
    handlers, so we return ``sigkill`` (or ``already_dead``); callers tolerate
    any method string.
    """
    if not is_pid_alive(pid):
        return "already_dead"

    handle = _kernel32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
    if not handle:
        # No permission to open it; treat as already gone (best-effort).
        return "already_dead"
    try:
        _kernel32.TerminateProcess(handle, 1)
    finally:
        _kernel32.CloseHandle(handle)
    if wait_for_exit(pid, timeout_s):
        return "sigkill"
    return "sigkill"


def terminate_pid(pid: int, *, timeout_s: float = 10.0) -> str:
    """Best-effort terminate. Returns method: 'already_dead', 'sigterm', 'sigkill'.

    On POSIX this is SIGTERM then SIGKILL. On Windows there is no graceful OS
    signal (``TerminateProcess`` is unconditional); the graceful stop path is the
    bridge ``quit`` RPC, and this is the hard-kill escalation.
    """
    if os.name == "nt":
        return _terminate_pid_windows(pid, timeout_s=timeout_s)
    return _terminate_pid_posix(pid, timeout_s=timeout_s)
