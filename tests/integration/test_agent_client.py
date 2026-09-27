"""Tests for ida_bridge.agent_client (AgentClient state management and error paths)."""

import asyncio

import pytest

from ida_bridge import protocol
from ida_bridge.agent_client import AgentClient, BridgeDisconnected, open_agent_client
from tests.harness import ServeBridge, connect_client, recv_msg, respond_exec_ok, send_msg

SESSION_ID = "sess-1"


# ---------------------------------------------------------------------------
# Constructor / properties
# ---------------------------------------------------------------------------


class TestAgentClientInit:
    def test_empty_client_id_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            AgentClient(client_id="")

    async def test_bridge_id_before_connect_raises(self) -> None:
        client = AgentClient(client_id="a")
        with pytest.raises(RuntimeError, match="not connected"):
            _ = client.bridge_id

    async def test_not_connected_initially(self) -> None:
        client = AgentClient(client_id="a")
        assert client.is_connected() is False


# ---------------------------------------------------------------------------
# Connect / close lifecycle
# ---------------------------------------------------------------------------


class TestAgentClientLifecycle:
    async def test_connect_sets_bridge_id(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge(bridge_client_id="test-bridge") as (_, url):
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                assert client.is_connected()
                assert client.bridge_id == "test-bridge"
            finally:
                await client.close()

    async def test_agent_stores_advertised_max_message_bytes(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (server, url):
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                assert client._conn is not None
                assert client._conn.max_message_bytes == server.max_message_bytes
            finally:
                await client.close()

    async def test_agent_receives_responses_over_the_websockets_default_limit(self, serve_bridge: ServeBridge) -> None:
        # websockets caps inbound messages at 1 MiB unless told otherwise; the server bounds what we receive.
        result = "z" * (2 * 1024 * 1024)
        async with serve_bridge() as (_, url):
            ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                exec_task = asyncio.create_task(client.exec("ida-1", "big"))
                fwd = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
                assert isinstance(fwd, protocol.ExecRequest)
                await respond_exec_ok(ida, fwd, result=result)

                resp = await asyncio.wait_for(exec_task, timeout=5.0)
                assert resp.ok is True
                assert resp.result == result
            finally:
                await ida.close()
                await client.close()

    async def test_double_connect_raises(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                with pytest.raises(RuntimeError, match="already connected"):
                    await client.connect()
            finally:
                await client.close()

    async def test_close_when_not_connected_is_safe(self) -> None:
        client = AgentClient(client_id="a")
        await client.close()  # should not raise

    async def test_close_clears_state(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            await client.close()
            assert client.is_connected() is False
            with pytest.raises(RuntimeError, match="not connected"):
                _ = client.bridge_id

    async def test_request_after_close_raises(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            await client.close()
            with pytest.raises(RuntimeError, match="not connected"):
                await client.list()


# ---------------------------------------------------------------------------
# Close fails pending requests
# ---------------------------------------------------------------------------


class TestClosePendingRequests:
    async def test_close_fails_in_flight_request(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                exec_task = asyncio.create_task(client.exec("ida-1", "1+1"))
                _ = await asyncio.wait_for(recv_msg(ida), timeout=1.0)

                await client.close()

                with pytest.raises(BridgeDisconnected, match="bridge disconnected"):
                    await exec_task
            finally:
                await ida.close()


# ---------------------------------------------------------------------------
# Bridge disconnect mid-request
# ---------------------------------------------------------------------------


class TestBridgeDisconnect:
    async def test_bridge_drop_mid_request_disconnects_the_client(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (server, url):
            ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                exec_task = asyncio.create_task(client.exec("ida-1", "1+1"))
                _ = await asyncio.wait_for(recv_msg(ida), timeout=1.0)

                await server._clients["agent-1"].ws.close()

                with pytest.raises(BridgeDisconnected, match="bridge disconnected"):
                    await exec_task

                assert client.is_connected() is False

                with pytest.raises(RuntimeError, match="not connected"):
                    await client.list()
            finally:
                await ida.close()
                await client.close()


# ---------------------------------------------------------------------------
# Cancelled requests
# ---------------------------------------------------------------------------


class TestCancelledRequest:
    async def test_cancelled_request_disconnects_the_client(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(client.exec("ida-1", "1+1"), timeout=0.05)

                assert client.is_connected() is False
            finally:
                await ida.close()
                await client.close()


# ---------------------------------------------------------------------------
# exec / reset error responses
# ---------------------------------------------------------------------------


class TestErrorResponses:
    async def test_exec_error_response_returned(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                exec_task = asyncio.create_task(client.exec("ida-1", "bad"))
                fwd = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
                assert isinstance(fwd, protocol.ExecRequest)

                await send_msg(
                    ida,
                    protocol.ExecResponse(
                        id=fwd.id,
                        src="ida-1",
                        dst="agent-1",
                        ok=False,
                        code="EXEC_ERROR",
                        message="syntax error",
                        traceback="Traceback...\n",
                    ),
                )

                resp = await asyncio.wait_for(exec_task, timeout=1.0)
                assert isinstance(resp, protocol.ExecResponse)
                assert resp.ok is False
                assert resp.code == "EXEC_ERROR"
            finally:
                await ida.close()
                await client.close()

    async def test_reset_ok_response(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                reset_task = asyncio.create_task(client.reset("ida-1", session_id=SESSION_ID))
                fwd = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
                assert isinstance(fwd, protocol.ResetRequest)

                await send_msg(
                    ida,
                    protocol.ResetResponse(id=fwd.id, src="ida-1", dst="agent-1", ok=True),
                )

                resp = await asyncio.wait_for(reset_task, timeout=1.0)
                assert isinstance(resp, protocol.ResetResponse)
                assert resp.ok is True
            finally:
                await ida.close()
                await client.close()

    async def test_quit_ok_response(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                quit_task = asyncio.create_task(client.quit("ida-1"))
                fwd = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
                assert isinstance(fwd, protocol.QuitRequest)

                await send_msg(
                    ida,
                    protocol.QuitResponse(id=fwd.id, src="ida-1", dst="agent-1", ok=True),
                )

                resp = await asyncio.wait_for(quit_task, timeout=1.0)
                assert isinstance(resp, protocol.QuitResponse)
                assert resp.ok is True
            finally:
                await ida.close()
                await client.close()

    async def test_target_not_found(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                resp = await asyncio.wait_for(client.exec("no-such-ida", "1"), timeout=1.0)
                assert isinstance(resp, protocol.ExecResponse)
                assert resp.ok is False
                assert resp.code == protocol.ERR_TARGET_NOT_FOUND
            finally:
                await client.close()


# ---------------------------------------------------------------------------
# open_agent_client context manager
# ---------------------------------------------------------------------------


class TestOpenAgentClient:
    async def test_context_manager_connects_and_closes(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            async with open_agent_client(client_id="agent-1", url=url) as client:
                assert client.is_connected()
                resp = await asyncio.wait_for(client.list(), timeout=1.0)
                assert resp.ok

            assert client.is_connected() is False
