"""E2E test: exec-idb one-shot command.

Uses a real bridge + idalib to test the full round-trip via subprocess.
"""

import asyncio
import json
import os
import subprocess
import sys

import pytest

from tests.e2e.helpers import BridgeInfo


def _run_exec_idb(
    *,
    bridge: BridgeInfo,
    idb: str | None = None,
    input_file: str | None = None,
    out_idb: str | None = None,
    code: str | None = None,
    file: str | None = None,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``ida-bridge exec-idb`` as a subprocess."""
    env = os.environ.copy()
    env["IDA_BRIDGE_CONNECT_HOST"] = bridge.host
    env["IDA_BRIDGE_PORT"] = str(bridge.port)

    cmd = [sys.executable, "-m", "ida_bridge.cli", "exec-idb"]
    if idb:
        cmd.extend(["--idb", idb])
    if input_file:
        cmd.extend(["--input", input_file])
    if out_idb:
        cmd.extend(["--out-idb", out_idb])
    if code:
        cmd.extend(["-c", code])
    if file:
        cmd.extend(["-f", file])
    if extra_args:
        cmd.extend(extra_args)

    return subprocess.run(cmd, capture_output=True, encoding="utf-8", timeout=180, env=env)


class TestExecIdb:
    @pytest.mark.asyncio(loop_scope="function")
    async def test_exec_idb_with_input(self, live_bridge: BridgeInfo, small_macho_arm64, tmp_path):
        """Full round-trip: analyze binary, exec script, stop."""
        out_idb = str(tmp_path / "out.i64")
        result = await asyncio.to_thread(
            _run_exec_idb,
            bridge=live_bridge,
            input_file=str(small_macho_arm64),
            out_idb=out_idb,
            code="import idautils; _result_ = len(list(idautils.Functions()))",
            extra_args=["--json", "--force"],
        )

        assert result.returncode == 0, f"exec-idb failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        data = json.loads(result.stdout)
        assert data["ok"] is True
        assert isinstance(data["result"], int)
        assert data["result"] > 0

    @pytest.mark.asyncio(loop_scope="function")
    async def test_exec_idb_combines_file_and_code(self, live_bridge: BridgeInfo, small_macho_arm64, tmp_path):
        """--file should run before --code in one exec request."""
        out_idb = str(tmp_path / "out.i64")
        snippet = tmp_path / "snippet.py"
        snippet.write_text("x = 40\n", encoding="utf-8")

        result = await asyncio.to_thread(
            _run_exec_idb,
            bridge=live_bridge,
            input_file=str(small_macho_arm64),
            out_idb=out_idb,
            file=str(snippet),
            code="_result_ = x + 2",
            extra_args=["--json", "--force"],
        )

        assert result.returncode == 0, f"exec-idb failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["ok"] is True
        assert data["result"] == 42

    @pytest.mark.asyncio(loop_scope="function")
    async def test_exec_idb_json_clean_stderr(self, live_bridge: BridgeInfo, small_macho_arm64, tmp_path):
        """--json mode should not emit lifecycle messages to stderr."""
        out_idb = str(tmp_path / "out.i64")
        result = await asyncio.to_thread(
            _run_exec_idb,
            bridge=live_bridge,
            input_file=str(small_macho_arm64),
            out_idb=out_idb,
            code="_result_ = True",
            extra_args=["--json", "--force"],
        )

        assert result.returncode == 0
        # Lifecycle messages suppressed in --json mode.
        assert "started:" not in result.stderr
        assert "stopped" not in result.stderr
