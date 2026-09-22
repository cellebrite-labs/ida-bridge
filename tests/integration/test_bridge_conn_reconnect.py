import asyncio
from contextlib import asynccontextmanager
import time

import pytest
import websockets

from ida_bridge import protocol
from ida_bridge.bridge_conn import BridgeConn


async def _wait_until(pred, *, timeout_s: float, interval_s: float = 0.01) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if pred():
            return
        await asyncio.sleep(interval_s)
    raise AssertionError("condition not met before timeout")


@asynccontextmanager
async def _serve_handshake(*, port: int, close_after_ack: bool) -> None:
    async def handler(ws: websockets.ServerConnection) -> None:
        raw = await ws.recv()
        assert isinstance(raw, str)
        msg = protocol.parse_message_json(raw)
        assert isinstance(msg, protocol.Hello)

        ack = protocol.HelloAck(
            client_id=msg.client_id,
            bridge_id="bridge",
            max_size=protocol.ws_max_size(),
            meta={"server": "test"},
        )
        await ws.send(protocol.dump_message_json(ack))

        if close_after_ack:
            await ws.close(code=1001, reason="test close")
            return

        # Keep connection open until the connection is closed.
        await ws.wait_closed()

    async with websockets.serve(handler, "127.0.0.1", port) as ws_server:
        yield ws_server


@pytest.mark.asyncio(loop_scope="function")
async def test_bridge_conn_reconnects_after_server_restart() -> None:
    # Pick an ephemeral port by starting a server on port=0, then restart on the same port.
    # Keep the same BridgeConn instance running across the restart to exercise reconnect.
    ida: BridgeConn | None = None
    url: str | None = None
    port: int | None = None

    try:
        async with _serve_handshake(port=0, close_after_ack=True) as ws_server:
            port = ws_server.sockets[0].getsockname()[1]
            url = f"ws://127.0.0.1:{port}"

            ida = BridgeConn(client_id="ida-reconnect", url=url, meta={}, queue_max=10)
            # Speed up retries for the test.
            ida._FAST_RETRY_S = 0.05
            ida._FAST_WINDOW_S = 0.2
            ida._SLOW_RETRY_S = 0.05

            ida.start()

            # Should connect at least once.
            assert await asyncio.to_thread(ida.wait_ready, timeout_s=2.0)

            # Server closes immediately after hello_ack; connection should drop.
            await _wait_until(lambda: not ida.is_connected(), timeout_s=2.0)

        assert ida is not None and url is not None and port is not None

        # Restart server on the same port, keeping the connection open this time.
        async with _serve_handshake(port=port, close_after_ack=False):
            assert await asyncio.to_thread(ida.wait_ready, timeout_s=2.0)
            assert ida.is_connected() is True

    finally:
        if ida is not None:
            ida.stop()


@pytest.mark.asyncio(loop_scope="function")
async def test_bridge_conn_stop_terminates_ws_thread_quickly() -> None:
    async with _serve_handshake(port=0, close_after_ack=False) as ws_server:
        port = ws_server.sockets[0].getsockname()[1]
        url = f"ws://127.0.0.1:{port}"

        ida = BridgeConn(client_id="ida-stop", url=url, meta={}, queue_max=10)
        ida.start()
        assert await asyncio.to_thread(ida.wait_ready, timeout_s=2.0)

        t = ida._ws_thread
        assert t is not None

        ida.stop()
        await asyncio.to_thread(t.join, 1.0)
        assert t.is_alive() is False
