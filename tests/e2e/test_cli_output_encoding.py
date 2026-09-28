"""The CLI's output reaches a pipe as UTF-8 on every platform.

Windows encodes a piped stdout/stderr in the ANSI code page (cp1252), where these tests fail.
"""

import asyncio
import os
import subprocess
import sys

import pytest

from tests.e2e.conftest import IdalibInstance
from tests.e2e.helpers import BridgeInfo

# One character cp1252 can encode and one it cannot.
TEXT = "\u00e9\u4e2d"


def _bridge_env(bridge: BridgeInfo) -> dict[str, str]:
    return {**os.environ, "IDA_BRIDGE_HOST": bridge.host, "IDA_BRIDGE_PORT": str(bridge.port)}


def _run_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    cmd = [sys.executable, "-m", "ida_bridge.cli", *args]
    return subprocess.run(cmd, capture_output=True, timeout=120, env=env)


@pytest.mark.asyncio(loop_scope="module")
async def test_exec_human_output_reaches_a_pipe_as_utf8(shared_idalib: IdalibInstance) -> None:
    args = ["exec", shared_idalib.client_id, "-c", f"print({TEXT!r})"]
    result = await asyncio.to_thread(_run_cli, args, _bridge_env(shared_idalib.bridge))

    assert result.returncode == 0, result.stderr.decode("utf-8", "backslashreplace")
    assert TEXT in result.stdout.decode("utf-8")


def test_error_on_stderr_reaches_a_pipe_as_utf8(tmp_path) -> None:
    missing_idb = tmp_path / f"{TEXT}.i64"
    result = _run_cli(["exec-idb", "--idb", str(missing_idb), "-c", "1"], dict(os.environ))

    assert result.returncode == 2
    assert str(missing_idb) in result.stderr.decode("utf-8")
