"""Tests for ida_bridge.agent_client (AgentClient state management and error paths)."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from ida_bridge import protocol
from ida_bridge.agent_client import AgentClient, BridgeDisconnected, open_agent_client
from tests.harness import ServeBridge, connect_client, recv_msg, send_msg

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

    async def test_bridge_meta_before_connect_raises(self) -> None:
        client = AgentClient(client_id="a")
        with pytest.raises(RuntimeError, match="not connected"):
            _ = client.bridge_meta

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
                assert isinstance(client.bridge_meta, dict)
            finally:
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

                with pytest.raises(BridgeDisconnected, match="client closed"):
                    await exec_task
            finally:
                await ida.close()


# ---------------------------------------------------------------------------
# Bridge disconnect mid-request
# ---------------------------------------------------------------------------


class TestBridgeDisconnect:
    async def test_hard_disconnect_fails_pending(self, serve_bridge: ServeBridge) -> None:
        """Simulates the listener detecting a broken connection."""
        async with serve_bridge() as (_, url):
            ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                exec_task = asyncio.create_task(client.exec("ida-1", "1+1"))
                _ = await asyncio.wait_for(recv_msg(ida), timeout=1.0)

                await client._hard_disconnect(BridgeDisconnected("test disconnect"))

                with pytest.raises(BridgeDisconnected, match="test disconnect"):
                    await exec_task

                assert client.is_connected() is False

                with pytest.raises(RuntimeError, match="not connected"):
                    await client.list()
            finally:
                await ida.close()
                await client.close()


# ---------------------------------------------------------------------------
# Cancelled / abandoned requests
# ---------------------------------------------------------------------------


class TestAbandonedRequests:
    async def test_cancelled_request_allows_late_response(self, serve_bridge: ServeBridge) -> None:
        """A cancelled request should not kill the connection; the late response is silently dropped."""
        async with serve_bridge() as (_, url):
            ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(client.exec("ida-1", "1+1"), timeout=0.05)

                fwd = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
                assert isinstance(fwd, protocol.ExecRequest)

                await send_msg(
                    ida,
                    protocol.ExecResponse(id=fwd.id, src="ida-1", dst="agent-1", ok=True, result=2),
                )

                await asyncio.sleep(0.05)
                assert client.is_connected()

                list_resp = await asyncio.wait_for(client.list(), timeout=1.0)
                assert list_resp.ok
            finally:
                await ida.close()
                await client.close()

    async def test_too_many_abandoned_requests_disconnects(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge() as (_, url):
            ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
            client = AgentClient(client_id="agent-1", url=url)
            await client.connect()
            try:
                for _ in range(AgentClient._MAX_ABANDONED_IDS + 1):
                    with pytest.raises((asyncio.TimeoutError, BridgeDisconnected)):
                        await asyncio.wait_for(client.exec("ida-1", "1"), timeout=0.01)

                    try:
                        await asyncio.wait_for(recv_msg(ida), timeout=0.05)
                    except TimeoutError:
                        pass

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


class TestRemoteIdalibLifecycleRequests:
    async def test_start_idalib_addresses_bridge_and_maps_input_name(self) -> None:
        client = AgentClient(client_id="agent-1")
        client._bridge_id = "bridge-1"
        response = protocol.StartIdalibResponse(
            id=protocol.new_req_id(),
            src="bridge-1",
            dst="agent-1",
            ok=True,
            status="waiting",
            pid=42,
            idb_path="/srv/idbs/sample.i64",
            log="/srv/logs/idalib-42.log",
        )
        request = AsyncMock(return_value=response)
        client._request = request

        result = await client.start_idalib(
            input_file="/srv/bins/sample",
            out_idb="/srv/idbs/sample.i64",
            force=True,
            arch="arm64",
            python="/srv/venv/bin/python",
            wait_s=12.5,
        )

        assert result is response
        sent = request.await_args.args[0]
        assert isinstance(sent, protocol.StartIdalibRequest)
        assert sent.src == "agent-1"
        assert sent.dst == "bridge-1"
        assert sent.input == "/srv/bins/sample"
        assert sent.out_idb == "/srv/idbs/sample.i64"
        assert sent.force is True
        assert sent.arch == "arm64"
        assert sent.python == "/srv/venv/bin/python"
        assert sent.wait_s == 12.5

    async def test_stop_idalib_addresses_bridge(self) -> None:
        client = AgentClient(client_id="agent-1")
        client._bridge_id = "bridge-1"
        response = protocol.StopIdalibResponse(
            id=protocol.new_req_id(),
            src="bridge-1",
            dst="agent-1",
            ok=True,
            method="quit",
            client_id="idalib-42",
            pid=42,
        )
        request = AsyncMock(return_value=response)
        client._request = request

        result = await client.stop_idalib("idalib-42")

        assert result is response
        sent = request.await_args.args[0]
        assert isinstance(sent, protocol.StopIdalibRequest)
        assert sent.src == "agent-1"
        assert sent.dst == "bridge-1"
        assert sent.target == "idalib-42"


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
