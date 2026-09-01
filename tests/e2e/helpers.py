"""Shared helpers for e2e tests: bridge, idalib process management, SqlRunner."""

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import time

import pytest
import websockets

from ida_bridge import proc, protocol
from ida_bridge.agent_client import AgentClient, open_agent_client
from ida_bridge.server import BridgeServer
from ida_bridge.supervisor.commands import default_idalib_python

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

IDALIB_VENV_PYTHON = default_idalib_python()
IDALIB_RUNNER = Path(__file__).resolve().parent.parent.parent / "src" / "ida_bridge" / "idalib_runner.py"


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------


@dataclass
class BridgeInfo:
    server: BridgeServer
    url: str
    host: str
    port: int


async def start_bridge(*, timeout_s: int = 60) -> AsyncIterator[BridgeInfo]:
    """Shared async generator: start a bridge, yield it, then tear down."""
    server = BridgeServer(default_timeout_s=timeout_s, timeout_tick_s=1.0)
    server.start_background_tasks()
    try:
        async with websockets.serve(
            server.handler,
            "127.0.0.1",
            0,
            max_size=protocol.ws_max_size(),
        ) as ws_server:
            port = ws_server.sockets[0].getsockname()[1]
            url = f"ws://127.0.0.1:{port}"
            yield BridgeInfo(server=server, url=url, host="127.0.0.1", port=port)
    finally:
        await server.stop_background_tasks()


# ---------------------------------------------------------------------------
# idalib process management
# ---------------------------------------------------------------------------


def spawn_idalib(
    bridge: BridgeInfo,
    work_dir: Path,
    *,
    binary_path: Path | None = None,
    idb_path: Path | None = None,
    arch: str | None = None,
    skip_initial_auto_analysis: bool = False,
) -> tuple[subprocess.Popen[bytes], Path]:
    """Spawn an idalib runner subprocess. Returns (process, idb_path).

    Exactly one of *binary_path* (``--input``) or *idb_path* (``--idb``) must
    be provided.  *arch* is passed as ``--arch`` when set, and
    *skip_initial_auto_analysis* as ``--skip-initial-auto-analysis``.
    """
    if (binary_path is None) == (idb_path is None):
        raise ValueError("exactly one of binary_path or idb_path must be set")

    env = os.environ.copy()
    env["IDA_BRIDGE_HOST"] = bridge.host
    env["IDA_BRIDGE_PORT"] = str(bridge.port)

    if binary_path is not None:
        out_idb = work_dir / (binary_path.stem + ".i64")
        cmd = [
            str(IDALIB_VENV_PYTHON),
            str(IDALIB_RUNNER),
            "--input",
            str(binary_path),
            "--out-idb",
            str(out_idb),
            "--force",
        ]
        if arch is not None:
            cmd.extend(["--arch", arch])
    else:
        assert idb_path is not None
        out_idb = idb_path
        cmd = [
            str(IDALIB_VENV_PYTHON),
            str(IDALIB_RUNNER),
            "--idb",
            str(idb_path),
        ]
    if skip_initial_auto_analysis:
        cmd.append("--skip-initial-auto-analysis")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        **proc.detached_popen_kwargs(),
    )
    return process, out_idb


@dataclass
class IdalibReady:
    client_id: str
    pid: int


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


async def wait_for_idalib(
    bridge: BridgeInfo,
    process: subprocess.Popen[bytes],
    *,
    idb_path: Path | None = None,
) -> IdalibReady:
    """Poll bridge until the runner appears. Fails the test on timeout."""
    # Snapshot first so a leftover client with the same IDB path cannot match.
    existing_ids: set[str] = set()
    try:
        async with open_agent_client(client_id=f"e2e-snapshot-{os.getpid()}", url=bridge.url) as client:
            resp = await client.list(kind=protocol.LIST_KIND_IDA)
            if resp.ok and resp.clients:
                existing_ids = {c.client_id for c in resp.clients}
    except Exception:
        existing_ids = set()

    ready = await _poll_for_idalib(
        bridge.url,
        process.pid,
        timeout_s=120,
        idb_path=str(idb_path) if idb_path is not None else None,
        existing_ids=existing_ids,
    )
    if ready is None:
        dump_process_output(process)
        pytest.fail(f"idalib runner (pid={process.pid}) did not connect within timeout")
    return ready


def terminate_idalib(process: subprocess.Popen[bytes]) -> None:
    """Best-effort terminate + kill an idalib process (including venv children)."""
    if process.poll() is not None:
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        return
    proc.terminate_pid(process.pid, timeout_s=10.0)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


async def shutdown_and_save(bridge: BridgeInfo, client_id: str, proc: subprocess.Popen[bytes]) -> None:
    """Send idb.save() + idb.quit() and wait for process exit.

    Use this to produce a real, cleanly-closed packed .i64: the runner never
    saves on its own (SIGTERM/quit-without-save discards state), so this is the
    only way to get a packed file on disk via the runner itself.
    """
    async with open_agent_client(client_id="e2e-idb-setup", url=bridge.url) as agent:
        resp = await agent.exec(client_id, "_result_ = idb.save()", session_id="e2e-idb-setup", persist=True)
        if not resp.ok:
            dump_process_output(proc)
            pytest.fail(f"idb.save() failed: {resp.code} {resp.message}")
        resp = await agent.exec(client_id, "_result_ = idb.quit()", session_id="e2e-idb-setup", persist=True)
        if not resp.ok:
            dump_process_output(proc)
            pytest.fail(f"idb.quit() failed: {resp.code} {resp.message}")
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        terminate_idalib(proc)
        pytest.fail("idalib did not exit after shutdown(save=True)")


def run_idalib_runner_to_exit(
    bridge: BridgeInfo,
    *,
    idb: Path | None = None,
    input_file: Path | None = None,
    out_idb: Path | None = None,
    force: bool = False,
    timeout: float = 60,
) -> subprocess.CompletedProcess[str]:
    """Run idalib_runner.py directly as a subprocess and wait for it to exit on its own.

    For inputs expected to fail fast via a validation ``_die()`` (e.g. refusing to
    overwrite an existing/locked target). A *successful* open never returns on
    its own -- the runner falls into its request loop -- so this is not for
    success paths; use ``spawn_idalib`` + ``wait_for_idalib`` for those instead.
    If the expected failure does not happen, the open succeeds and this blocks
    until *timeout*, then raises ``subprocess.TimeoutExpired`` (a loud test
    failure) rather than passing silently.

    Exactly one of *idb* or (*input_file* and *out_idb*) must be provided.
    """
    if (idb is None) == (input_file is None):
        raise ValueError("exactly one of idb or (input_file and out_idb) must be set")

    env = os.environ.copy()
    env["IDA_BRIDGE_HOST"] = bridge.host
    env["IDA_BRIDGE_PORT"] = str(bridge.port)

    if idb is not None:
        cmd = [str(IDALIB_VENV_PYTHON), str(IDALIB_RUNNER), "--idb", str(idb)]
    else:
        assert input_file is not None and out_idb is not None
        cmd = [
            str(IDALIB_VENV_PYTHON),
            str(IDALIB_RUNNER),
            "--input",
            str(input_file),
            "--out-idb",
            str(out_idb),
        ]
        if force:
            cmd.append("--force")

    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)


async def _poll_for_idalib(
    url: str,
    pid: int,
    *,
    timeout_s: float,
    idb_path: str | None = None,
    existing_ids: set[str] | None = None,
) -> IdalibReady | None:
    """Poll the bridge for a *new* idalib client matching pid/tree or IDB path."""
    known = existing_ids if existing_ids is not None else set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            async with open_agent_client(client_id=f"e2e-poller-{os.getpid()}", url=url) as client:
                resp = await client.list(kind=protocol.LIST_KIND_IDA)
                if resp.ok and resp.clients:
                    for c in resp.clients:
                        if c.client_id in known:
                            continue
                        meta = c.meta or {}
                        if meta.get("runtime") != "idalib":
                            continue
                        got_pid = meta.get("pid")
                        got_idb = meta.get("idb_path")
                        pid_match = isinstance(got_pid, int) and proc.is_pid_in_tree(pid, got_pid)
                        path_match = idb_path is not None and isinstance(got_idb, str) and _same_path(got_idb, idb_path)
                        if pid_match or path_match:
                            real_pid = got_pid if isinstance(got_pid, int) else pid
                            return IdalibReady(client_id=c.client_id, pid=real_pid)
        except Exception:
            pass
        await asyncio.sleep(1.0)
    return None


def dump_process_output(proc: subprocess.Popen[bytes]) -> None:
    """Best-effort dump of runner stdout for debugging test failures."""
    if proc.stdout:
        try:
            out = proc.stdout.read()
            if out:
                print(f"--- idalib runner output (pid={proc.pid}) ---")
                print(out.decode(errors="replace"))
                print("--- end ---")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SqlRunner
# ---------------------------------------------------------------------------


class SqlRunner:
    """Execute SQL and IDAPython over a persistent agent connection."""

    def __init__(self, agent: AgentClient, client_id: str, *, session_id: str) -> None:
        self._agent = agent
        self._client_id = client_id
        self._session_id = session_id

    async def sql(self, query: str) -> dict:
        code = f"_result_ = idb.sql({query!r})"
        resp = await self._agent.exec(self._client_id, code, session_id=self._session_id, persist=True)
        assert resp.ok, f"SQL failed: {resp.message}\n{resp.traceback}"
        return resp.result

    async def sql_err(self, query: str) -> str:
        code = f"_result_ = idb.sql({query!r})"
        resp = await self._agent.exec(self._client_id, code, session_id=self._session_id, persist=True)
        assert not resp.ok, f"expected error but got: {resp.result}"
        return resp.message or ""

    async def exec(self, code: str):
        resp = await self._agent.exec(self._client_id, code, session_id=self._session_id, persist=True)
        assert resp.ok, f"exec failed: {resp.message}\n{resp.traceback}"
        return resp.result


async def make_runner(
    bridge_info: BridgeInfo, tmp_dir: Path, idb_path: Path, agent_id: str
) -> AsyncIterator[SqlRunner]:
    """Spawn idalib, open one agent connection, yield a SqlRunner."""
    process, out_idb = spawn_idalib(bridge_info, tmp_dir, idb_path=idb_path)
    try:
        ready = await wait_for_idalib(bridge_info, process, idb_path=out_idb)
        async with open_agent_client(client_id=agent_id, url=bridge_info.url) as agent:
            yield SqlRunner(agent, ready.client_id, session_id=agent_id)
    finally:
        terminate_idalib(process)
