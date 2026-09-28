"""E2E tests: supervisor stop command.

Each test gets a fresh idalib instance (function-scoped) and exercises
``ida-bridge supervisor stop`` as a subprocess, matching real usage.
"""

import asyncio
import os
import subprocess
import sys
import time

import pytest

from tests.e2e.conftest import IdalibInstance

pytestmark = [pytest.mark.asyncio(loop_scope="module")]


def _run_supervisor_stop(
    target: str,
    *,
    bridge_host: str,
    bridge_port: int,
) -> subprocess.CompletedProcess[str]:
    """Run ``ida-bridge supervisor stop <target>`` as a subprocess."""
    env = os.environ.copy()
    env["IDA_BRIDGE_HOST"] = bridge_host
    env["IDA_BRIDGE_PORT"] = str(bridge_port)

    return subprocess.run(
        [sys.executable, "-m", "ida_bridge.cli", "supervisor", "stop", target],
        capture_output=True,
        encoding="utf-8",
        timeout=30,
        env=env,
    )


class TestSupervisorStop:
    @pytest.mark.asyncio(loop_scope="function")
    async def test_stop_by_client_id(self, idalib_instance: IdalibInstance) -> None:
        """Stop via client_id: resolves pid from bridge list, graceful quit, process exits."""
        proc = idalib_instance.process
        bridge = idalib_instance.bridge

        # Reap the child concurrently so it doesn't linger as a zombie.
        # cmd_stop uses os.kill(pid, 0) which succeeds on zombies.
        reap_task = asyncio.create_task(asyncio.to_thread(proc.wait))

        t0 = time.monotonic()
        result = await asyncio.to_thread(
            _run_supervisor_stop,
            idalib_instance.client_id,
            bridge_host=bridge.host,
            bridge_port=bridge.port,
        )
        elapsed = time.monotonic() - t0

        assert result.returncode == 0, f"stop failed: {result.stderr}\nstdout: {result.stdout}"
        assert "stopped" in result.stdout, f"unexpected output: {result.stdout}"
        assert elapsed < 8.0, f"stop took {elapsed:.1f}s; expected < 8s"

        rc = await asyncio.wait_for(reap_task, timeout=5)
        assert rc == 0

    @pytest.mark.asyncio(loop_scope="function")
    async def test_stop_by_pid(self, idalib_instance: IdalibInstance) -> None:
        """Stop via pid: resolves client_id from bridge list, graceful quit, process exits."""
        proc = idalib_instance.process
        bridge = idalib_instance.bridge

        reap_task = asyncio.create_task(asyncio.to_thread(proc.wait))

        t0 = time.monotonic()
        result = await asyncio.to_thread(
            _run_supervisor_stop,
            str(idalib_instance.pid),
            bridge_host=bridge.host,
            bridge_port=bridge.port,
        )
        elapsed = time.monotonic() - t0

        assert result.returncode == 0, f"stop failed: {result.stderr}\nstdout: {result.stdout}"
        assert "stopped" in result.stdout, f"unexpected output: {result.stdout}"
        assert elapsed < 8.0, f"stop took {elapsed:.1f}s; expected < 8s"

        rc = await asyncio.wait_for(reap_task, timeout=5)
        assert rc == 0
