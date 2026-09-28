"""The CLI reports a bridge it cannot reach in one line, not a traceback."""

import asyncio
import http.server
import os
import socket
import subprocess
import sys
import threading

import websockets


def _list(host: str, port: int) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "IDA_BRIDGE_CONNECT_HOST": host, "IDA_BRIDGE_PORT": str(port)}
    cmd = [sys.executable, "-m", "ida_bridge.cli", "list"]
    return subprocess.run(cmd, capture_output=True, encoding="utf-8", timeout=60, env=env)


def _assert_reported(result: subprocess.CompletedProcess[str], message: str) -> None:
    assert result.returncode == 1, result.stderr
    assert message in result.stderr, result.stderr
    assert "Traceback" not in result.stderr, result.stderr


async def test_nothing_listening_is_reported() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    result = await asyncio.to_thread(_list, "127.0.0.1", port)
    _assert_reported(result, f"cannot connect to bridge at ws://127.0.0.1:{port}")


async def test_an_unresolvable_host_is_reported() -> None:
    # .invalid is reserved and never resolves.
    result = await asyncio.to_thread(_list, "no-such-host.invalid", 8765)
    _assert_reported(result, "cannot connect to bridge at ws://no-such-host.invalid:8765")


async def test_a_non_websocket_server_on_the_port_is_reported() -> None:
    httpd = http.server.HTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        port = httpd.server_address[1]
        result = await asyncio.to_thread(_list, "127.0.0.1", port)
    finally:
        httpd.shutdown()
        httpd.server_close()
    _assert_reported(result, f"cannot connect to bridge at ws://127.0.0.1:{port}")


async def test_a_server_that_closes_before_the_handshake_ack_is_reported() -> None:
    async def close_at_once(ws) -> None:
        await ws.close()

    async with websockets.serve(close_at_once, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        result = await asyncio.to_thread(_list, "127.0.0.1", port)
    _assert_reported(result, "bridge disconnected")
