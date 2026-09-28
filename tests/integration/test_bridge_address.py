import asyncio
import os
import subprocess
import sys

from ida_bridge.server import BridgeServer


async def test_a_client_with_the_servers_env_connects_to_a_wildcard_listener() -> None:
    # Windows cannot connect to 0.0.0.0, so a client must not reuse the listen host.
    async with BridgeServer().serve("0.0.0.0", 0) as ws_server:
        port = ws_server.sockets[0].getsockname()[1]
        env = {**os.environ, "IDA_BRIDGE_LISTEN_HOST": "0.0.0.0", "IDA_BRIDGE_PORT": str(port)}
        cmd = [sys.executable, "-m", "ida_bridge.cli", "list"]
        result = await asyncio.to_thread(
            subprocess.run, cmd, capture_output=True, encoding="utf-8", timeout=60, env=env
        )

    assert result.returncode == 0, result.stderr
