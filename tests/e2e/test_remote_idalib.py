"""E2E test for CLI-managed idalib on the bridge host."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ida_bridge import proc
from tests.e2e.helpers import BridgeInfo


def _run_remote(bridge: BridgeInfo, *args: str, timeout: float = 180) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["IDA_BRIDGE_HOST"] = bridge.host
    env["IDA_BRIDGE_PORT"] = str(bridge.port)
    return subprocess.run(
        [sys.executable, "-m", "ida_bridge.cli", "remote", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


class TestRemoteIdalib:
    @pytest.mark.asyncio(loop_scope="function")
    async def test_cli_starts_and_stops_bridge_host_idalib(
        self,
        live_bridge: BridgeInfo,
        small_macho_arm64: Path,
        tmp_path: Path,
    ) -> None:
        out_idb = tmp_path / "remote.i64"
        pid: int | None = None
        stopped = False
        try:
            started = await asyncio.to_thread(
                _run_remote,
                live_bridge,
                "start-idalib",
                "--input",
                str(small_macho_arm64),
                "--out-idb",
                str(out_idb),
                "--force",
                "--wait-s",
                "120",
                "--json",
            )
            assert started.returncode == 0, f"start failed:\nstdout: {started.stdout}\nstderr: {started.stderr}"
            result = json.loads(started.stdout)
            assert result["status"] == "connected"
            assert result["client_id"].startswith("idalib-")
            assert result["idb_path"] == str(out_idb.resolve())
            pid = result["pid"]
            assert isinstance(pid, int) and pid > 0

            stopped_result = await asyncio.to_thread(
                _run_remote,
                live_bridge,
                "stop",
                result["client_id"],
                "--json",
                timeout=45,
            )
            assert stopped_result.returncode == 0, (
                f"stop failed:\nstdout: {stopped_result.stdout}\nstderr: {stopped_result.stderr}"
            )
            stop_payload = json.loads(stopped_result.stdout)
            assert stop_payload["ok"] is True
            assert stop_payload["pid"] == pid
            assert stop_payload["method"] in ("quit", "already_dead", "sigterm", "sigkill")
            stopped = True
        finally:
            if pid is not None and not stopped:
                await asyncio.to_thread(proc.terminate_pid, pid, timeout_s=5.0)
