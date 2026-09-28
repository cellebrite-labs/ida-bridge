import asyncio
import logging

import pytest

from ida_bridge import protocol
from tests.harness import ServeBridge, connect_client, connected_client, recv_msg, send_msg

# ---------------------------------------------------------------------------
# list (bridge-handled)
# ---------------------------------------------------------------------------


async def test_list_all(serve_bridge: ServeBridge) -> None:
    async with serve_bridge(instance_id="test-instance") as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1", meta={"idb_path": "/tmp/test.i64"}),
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            req_id = protocol.new_req_id()
            await send_msg(
                agent,
                protocol.ListRequest(
                    id=req_id,
                    src="agent-1",
                    dst=server.bridge_id,
                    kind=protocol.LIST_KIND_ALL,
                ),
            )
            resp = await recv_msg(agent)
            assert isinstance(resp, protocol.ListResponse)
            assert resp.ok is True
            assert resp.id == req_id
            assert resp.src == server.bridge_id
            assert resp.dst == "agent-1"
            assert resp.kind == protocol.LIST_KIND_ALL

            assert resp.clients is not None
            assert [c.client_id for c in resp.clients] == ["agent-1", "ida-1"]
            ida_info = next(c for c in resp.clients if c.client_id == "ida-1")
            assert ida_info.role == protocol.ROLE_IDA
            assert ida_info.meta["idb_path"] == "/tmp/test.i64"
            assert ida_info.session_id is None


async def test_list_is_logged_with_its_result(serve_bridge: ServeBridge, caplog: pytest.LogCaptureFixture) -> None:
    async with serve_bridge() as (server, url):
        async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent:
            with caplog.at_level(logging.INFO, logger="ida-bridge"):
                req = protocol.ListRequest(
                    id=protocol.new_req_id(), src="agent-1", dst=server.bridge_id, kind=protocol.LIST_KIND_IDA
                )
                await send_msg(agent, req)
                await recv_msg(agent)

    assert any(r.getMessage().endswith("agent-1 kind=ida -> 0 clients") for r in caplog.records)


async def test_list_shows_session_id_after_ownership_claimed(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1", meta={"idb_path": "/tmp/test.i64"}) as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            # Claim ownership via exec.
            req_id = protocol.new_req_id()
            await send_msg(
                agent,
                protocol.ExecRequest(
                    id=req_id,
                    src="agent-1",
                    dst="ida-1",
                    persist=True,
                    session_id="sess-abc",
                    code="1",
                ),
            )
            await recv_msg(ida)
            await send_msg(
                ida,
                protocol.ExecResponse(id=req_id, src="ida-1", dst="agent-1", ok=True, result=1),
            )
            _ = await recv_msg(agent)

            # List should now show session_id on the IDA client.
            list_id = protocol.new_req_id()
            await send_msg(
                agent,
                protocol.ListRequest(
                    id=list_id,
                    src="agent-1",
                    dst=server.bridge_id,
                    kind=protocol.LIST_KIND_IDA,
                ),
            )
            resp = await recv_msg(agent)
            assert isinstance(resp, protocol.ListResponse)
            assert resp.ok is True
            ida_info = resp.clients[0]
            assert ida_info.client_id == "ida-1"
            assert ida_info.session_id == "sess-abc"


# ---------------------------------------------------------------------------
# target not found
# ---------------------------------------------------------------------------


async def test_target_not_found_produces_error_response(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent:
            req_id = protocol.new_req_id()
            await send_msg(
                agent,
                protocol.ResetRequest(
                    id=req_id,
                    src="agent-1",
                    dst="ida-missing",
                    session_id="sess-1",
                ),
            )
            resp = await recv_msg(agent)
            assert isinstance(resp, protocol.ResetResponse)
            assert resp.ok is False
            assert resp.id == req_id
            assert resp.src == server.bridge_id
            assert resp.dst == "agent-1"
            assert resp.code == protocol.ERR_TARGET_NOT_FOUND


def _make_request(
    req_type: str,
    *,
    req_id: str,
    src: str = "agent-1",
    dst: str = "ida-1",
    session_id: str = "sess-1",
    takeover: bool = False,
    timeout_s: int | None = None,
    reset_env: bool = True,
) -> protocol.RequestBase:
    if req_type == protocol.MSG_EXEC:
        return protocol.ExecRequest(
            id=req_id,
            src=src,
            dst=dst,
            persist=True,
            session_id=session_id,
            reset_env=reset_env,
            code="1 + 1",
            timeout_s=timeout_s,
        )
    if req_type == protocol.MSG_RESET:
        return protocol.ResetRequest(
            id=req_id,
            src=src,
            dst=dst,
            session_id=session_id,
            takeover=takeover,
            timeout_s=timeout_s,
        )

    raise AssertionError(f"unexpected req_type: {req_type}")


def _make_ok_response(
    req_type: str,
    *,
    req_id: str,
    src: str = "ida-1",
    dst: str = "agent-1",
) -> protocol.ResponseBase:
    if req_type == protocol.MSG_EXEC:
        return protocol.ExecResponse(id=req_id, src=src, dst=dst, ok=True, result=2)
    if req_type == protocol.MSG_RESET:
        return protocol.ResetResponse(id=req_id, src=src, dst=dst, ok=True)

    raise AssertionError(f"unexpected req_type: {req_type}")


def _expect_response_type(req_type: str) -> type[protocol.ResponseBase]:
    if req_type == protocol.MSG_EXEC:
        return protocol.ExecResponse
    if req_type == protocol.MSG_RESET:
        return protocol.ResetResponse

    raise AssertionError(f"unexpected req_type: {req_type}")


@pytest.mark.parametrize("req_type", [protocol.MSG_EXEC, protocol.MSG_RESET])
async def test_request_types_success_golden_route(serve_bridge: ServeBridge, req_type: str) -> None:
    async with serve_bridge() as (_, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            req_id = protocol.new_req_id()
            req = _make_request(req_type, req_id=req_id)

            await send_msg(agent, req)
            forwarded = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded == req

            resp = _make_ok_response(req_type, req_id=req_id)
            await send_msg(ida, resp)

            got = await asyncio.wait_for(recv_msg(agent), timeout=1.0)
            assert got == resp


@pytest.mark.parametrize("req_type", [protocol.MSG_EXEC, protocol.MSG_RESET])
async def test_request_types_timeout(serve_bridge: ServeBridge, req_type: str) -> None:
    async with serve_bridge(default_timeout_s=0.05, timeout_tick_s=0.01) as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            req_id = protocol.new_req_id()
            req = _make_request(req_type, req_id=req_id)

            await send_msg(agent, req)
            _ = await asyncio.wait_for(recv_msg(ida), timeout=1.0)  # forwarded

            resp = await asyncio.wait_for(recv_msg(agent), timeout=1.0)
            expected_cls = _expect_response_type(req_type)
            assert isinstance(resp, expected_cls)
            assert resp.id == req_id
            assert resp.src == server.bridge_id
            assert resp.dst == "agent-1"
            assert resp.ok is False
            assert resp.code == protocol.ERR_TIMEOUT

            # Late IDA response for a timed out id must be dropped without penalizing IDA.
            late = _make_ok_response(req_type, req_id=req_id)
            await send_msg(ida, late)

            # Bridge should not close IDA connection.
            pong = await ida.ping()
            await asyncio.wait_for(pong, timeout=1.0)

            # Bridge should not send anything to agent or IDA for the late response.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(recv_msg(agent), timeout=0.1)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(recv_msg(ida), timeout=0.1)


@pytest.mark.parametrize("req_type", [protocol.MSG_EXEC, protocol.MSG_RESET])
async def test_request_types_timeout_override_longer_than_default(serve_bridge: ServeBridge, req_type: str) -> None:
    async with serve_bridge(default_timeout_s=0.05, timeout_tick_s=0.01) as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            req_id = protocol.new_req_id()
            req = _make_request(req_type, req_id=req_id, timeout_s=1)

            await send_msg(agent, req)
            forwarded = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded == req

            # Should not time out at the bridge default (0.05s).
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(recv_msg(agent), timeout=0.2)

            resp = await asyncio.wait_for(recv_msg(agent), timeout=2.0)
            expected_cls = _expect_response_type(req_type)
            assert isinstance(resp, expected_cls)
            assert resp.ok is False
            assert resp.code == protocol.ERR_TIMEOUT
            assert resp.src == server.bridge_id
            assert resp.dst == "agent-1"
            assert resp.id == req_id
            assert resp.trace and resp.trace.get("timeout_s") == 1


@pytest.mark.parametrize("req_type", [protocol.MSG_EXEC, protocol.MSG_RESET])
async def test_request_types_timeout_override_shorter_than_default(serve_bridge: ServeBridge, req_type: str) -> None:
    async with serve_bridge(default_timeout_s=2.0, timeout_tick_s=0.01) as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent,
        ):
            req_id = protocol.new_req_id()
            req = _make_request(req_type, req_id=req_id, timeout_s=1)

            await send_msg(agent, req)
            forwarded = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded == req

            # Should time out before the bridge default (2.0s).
            resp = await asyncio.wait_for(recv_msg(agent), timeout=1.5)
            expected_cls = _expect_response_type(req_type)
            assert isinstance(resp, expected_cls)
            assert resp.ok is False
            assert resp.code == protocol.ERR_TIMEOUT
            assert resp.src == server.bridge_id
            assert resp.dst == "agent-1"
            assert resp.id == req_id
            assert resp.trace and resp.trace.get("timeout_s") == 1


@pytest.mark.parametrize("req_type", [protocol.MSG_EXEC, protocol.MSG_RESET])
async def test_request_types_ida_disconnect_mid_flight(serve_bridge: ServeBridge, req_type: str) -> None:
    async with serve_bridge(default_timeout_s=1, timeout_tick_s=0.01) as (server, url):
        ida = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
        async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent:
            req_id = protocol.new_req_id()
            req = _make_request(req_type, req_id=req_id)

            await send_msg(agent, req)
            _ = await asyncio.wait_for(recv_msg(ida), timeout=1.0)  # forwarded

            await ida.close()

            resp = await asyncio.wait_for(recv_msg(agent), timeout=1.0)
            expected_cls = _expect_response_type(req_type)
            assert isinstance(resp, expected_cls)
            assert resp.id == req_id
            assert resp.src == server.bridge_id
            assert resp.dst == "agent-1"
            assert resp.ok is False
            assert resp.code == protocol.ERR_TARGET_DISCONNECTED


@pytest.mark.parametrize("req_type", [protocol.MSG_EXEC, protocol.MSG_RESET])
async def test_session_conflict_rejects_request_and_does_not_forward(
    serve_bridge: ServeBridge,
    req_type: str,
) -> None:
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            req1 = _make_request(req_type, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, req1)
            forwarded = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded == req1

            req2 = _make_request(
                req_type,
                req_id=protocol.new_req_id(),
                src="agent-2",
                session_id="sess-2",
            )
            await send_msg(agent2, req2)

            resp = await asyncio.wait_for(recv_msg(agent2), timeout=1.0)
            expected_cls = _expect_response_type(req_type)
            assert isinstance(resp, expected_cls)
            assert resp.id == req2.id
            assert resp.src == server.bridge_id
            assert resp.dst == "agent-2"
            assert resp.ok is False
            assert resp.code == protocol.ERR_SESSION_CONFLICT
            assert resp.trace == {
                "target_client_id": "ida-1",
                "current_session_id": "sess-1",
                "requested_session_id": "sess-2",
            }

            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(recv_msg(ida), timeout=0.1)


async def test_takeover_reset_locks_target_while_pending_and_transfers_ownership(
    serve_bridge: ServeBridge,
) -> None:
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            claim = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, claim)
            forwarded_claim = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded_claim == claim
            await send_msg(ida, _make_ok_response(protocol.MSG_EXEC, req_id=claim.id, dst="agent-1"))
            _ = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)

            takeover = _make_request(
                protocol.MSG_RESET,
                req_id=protocol.new_req_id(),
                src="agent-2",
                session_id="sess-2",
                takeover=True,
            )
            await send_msg(agent2, takeover)
            forwarded_takeover = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded_takeover == takeover

            blocked = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, blocked)
            blocked_resp = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)
            assert isinstance(blocked_resp, protocol.ExecResponse)
            assert blocked_resp.id == blocked.id
            assert blocked_resp.src == server.bridge_id
            assert blocked_resp.dst == "agent-1"
            assert blocked_resp.ok is False
            assert blocked_resp.code == protocol.ERR_TAKEOVER_PENDING
            assert blocked_resp.trace == {
                "target_client_id": "ida-1",
                "requested_session_id": "sess-1",
            }

            await send_msg(ida, _make_ok_response(protocol.MSG_RESET, req_id=takeover.id, dst="agent-2"))
            takeover_resp = await asyncio.wait_for(recv_msg(agent2), timeout=1.0)
            assert isinstance(takeover_resp, protocol.ResetResponse)
            assert takeover_resp.ok is True

            new_req = _make_request(
                protocol.MSG_EXEC,
                req_id=protocol.new_req_id(),
                src="agent-2",
                session_id="sess-2",
                reset_env=False,
            )
            await send_msg(agent2, new_req)
            forwarded_new = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded_new == new_req
            await send_msg(ida, _make_ok_response(protocol.MSG_EXEC, req_id=new_req.id, dst="agent-2"))
            _ = await asyncio.wait_for(recv_msg(agent2), timeout=1.0)

            old_req = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, old_req)
            old_resp = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)
            assert isinstance(old_resp, protocol.ExecResponse)
            assert old_resp.id == old_req.id
            assert old_resp.src == server.bridge_id
            assert old_resp.dst == "agent-1"
            assert old_resp.ok is False
            assert old_resp.code == protocol.ERR_SESSION_CONFLICT
            assert old_resp.trace == {
                "target_client_id": "ida-1",
                "current_session_id": "sess-2",
                "requested_session_id": "sess-1",
            }


async def test_takeover_timeout_locks_target_until_reconnect(serve_bridge: ServeBridge) -> None:
    async with serve_bridge(default_timeout_s=0.05, timeout_tick_s=0.01) as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            claim = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, claim)
            forwarded_claim = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded_claim == claim
            await send_msg(ida, _make_ok_response(protocol.MSG_EXEC, req_id=claim.id, dst="agent-1"))
            _ = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)

            takeover = _make_request(
                protocol.MSG_RESET,
                req_id=protocol.new_req_id(),
                src="agent-2",
                session_id="sess-2",
                takeover=True,
            )
            await send_msg(agent2, takeover)
            forwarded_takeover = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded_takeover == takeover

            timeout_resp = await asyncio.wait_for(recv_msg(agent2), timeout=1.0)
            assert isinstance(timeout_resp, protocol.ResetResponse)
            assert timeout_resp.id == takeover.id
            assert timeout_resp.src == server.bridge_id
            assert timeout_resp.dst == "agent-2"
            assert timeout_resp.ok is False
            assert timeout_resp.code == protocol.ERR_TIMEOUT

            pong = await ida.ping()
            await asyncio.wait_for(pong, timeout=1.0)

            blocked_old = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, blocked_old)
            blocked_old_resp = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)
            assert isinstance(blocked_old_resp, protocol.ExecResponse)
            assert blocked_old_resp.code == protocol.ERR_SESSION_LOCKED
            assert blocked_old_resp.trace == {
                "target_client_id": "ida-1",
                "requested_session_id": "sess-1",
            }

            blocked_new = _make_request(
                protocol.MSG_EXEC,
                req_id=protocol.new_req_id(),
                src="agent-2",
                session_id="sess-2",
            )
            await send_msg(agent2, blocked_new)
            blocked_new_resp = await asyncio.wait_for(recv_msg(agent2), timeout=1.0)
            assert isinstance(blocked_new_resp, protocol.ExecResponse)
            assert blocked_new_resp.code == protocol.ERR_SESSION_LOCKED
            assert blocked_new_resp.trace == {
                "target_client_id": "ida-1",
                "requested_session_id": "sess-2",
            }


async def test_takeover_error_response_locks_target(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            claim = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, claim)
            forwarded_claim = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded_claim == claim
            await send_msg(ida, _make_ok_response(protocol.MSG_EXEC, req_id=claim.id, dst="agent-1"))
            _ = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)

            takeover = _make_request(
                protocol.MSG_RESET,
                req_id=protocol.new_req_id(),
                src="agent-2",
                session_id="sess-2",
                takeover=True,
            )
            await send_msg(agent2, takeover)
            forwarded_takeover = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded_takeover == takeover

            await send_msg(
                ida,
                protocol.ResetResponse(
                    id=takeover.id,
                    src="ida-1",
                    dst="agent-2",
                    ok=False,
                    code="RESET_FAILED",
                    message="reset failed",
                ),
            )
            failure_resp = await asyncio.wait_for(recv_msg(agent2), timeout=1.0)
            assert isinstance(failure_resp, protocol.ResetResponse)
            assert failure_resp.id == takeover.id
            assert failure_resp.ok is False
            assert failure_resp.code == "RESET_FAILED"

            blocked_old = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, blocked_old)
            blocked_old_resp = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)
            assert isinstance(blocked_old_resp, protocol.ExecResponse)
            assert blocked_old_resp.src == server.bridge_id
            assert blocked_old_resp.code == protocol.ERR_SESSION_LOCKED
            assert blocked_old_resp.trace == {
                "target_client_id": "ida-1",
                "requested_session_id": "sess-1",
            }

            blocked_new = _make_request(
                protocol.MSG_EXEC,
                req_id=protocol.new_req_id(),
                src="agent-2",
                session_id="sess-2",
            )
            await send_msg(agent2, blocked_new)
            blocked_new_resp = await asyncio.wait_for(recv_msg(agent2), timeout=1.0)
            assert isinstance(blocked_new_resp, protocol.ExecResponse)
            assert blocked_new_resp.src == server.bridge_id
            assert blocked_new_resp.code == protocol.ERR_SESSION_LOCKED
            assert blocked_new_resp.trace == {
                "target_client_id": "ida-1",
                "requested_session_id": "sess-2",
            }


async def test_takeover_survives_requesting_agent_disconnect_until_response(
    serve_bridge: ServeBridge,
) -> None:
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
        ):
            claim = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, claim)
            forwarded_claim = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded_claim == claim
            await send_msg(ida, _make_ok_response(protocol.MSG_EXEC, req_id=claim.id, dst="agent-1"))
            _ = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)

            agent2 = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-2")
            try:
                takeover = _make_request(
                    protocol.MSG_RESET,
                    req_id=protocol.new_req_id(),
                    src="agent-2",
                    session_id="sess-2",
                    takeover=True,
                )
                await send_msg(agent2, takeover)
                forwarded_takeover = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
                assert forwarded_takeover == takeover
            finally:
                await agent2.close()

            blocked = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, blocked)
            blocked_resp = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)
            assert isinstance(blocked_resp, protocol.ExecResponse)
            assert blocked_resp.id == blocked.id
            assert blocked_resp.src == server.bridge_id
            assert blocked_resp.dst == "agent-1"
            assert blocked_resp.ok is False
            assert blocked_resp.code == protocol.ERR_TAKEOVER_PENDING
            assert blocked_resp.trace == {
                "target_client_id": "ida-1",
                "requested_session_id": "sess-1",
            }

            await send_msg(ida, _make_ok_response(protocol.MSG_RESET, req_id=takeover.id, dst="agent-2"))

            agent3 = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-3")
            try:
                new_req = _make_request(
                    protocol.MSG_EXEC,
                    req_id=protocol.new_req_id(),
                    src="agent-3",
                    session_id="sess-2",
                    reset_env=False,
                )
                await send_msg(agent3, new_req)
                forwarded_new = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
                assert forwarded_new == new_req
                await send_msg(ida, _make_ok_response(protocol.MSG_EXEC, req_id=new_req.id, dst="agent-3"))
                _ = await asyncio.wait_for(recv_msg(agent3), timeout=1.0)
            finally:
                await agent3.close()


async def test_quit_bypasses_session_ownership(serve_bridge: ServeBridge) -> None:
    """Quit should work even when the target is owned by another session."""
    async with serve_bridge() as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
        ):
            # agent-1 claims ownership
            claim = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, claim)
            forwarded_claim = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert forwarded_claim == claim
            await send_msg(ida, _make_ok_response(protocol.MSG_EXEC, req_id=claim.id, dst="agent-1"))
            _ = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)

            # agent-2 (different session) sends quit -- should bypass ownership
            quit_req = protocol.QuitRequest(
                id=protocol.new_req_id(),
                src="agent-2",
                dst="ida-1",
            )
            await send_msg(agent2, quit_req)
            forwarded_quit = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert isinstance(forwarded_quit, protocol.QuitRequest)
            assert forwarded_quit.id == quit_req.id

            await send_msg(
                ida,
                protocol.QuitResponse(
                    id=quit_req.id,
                    src="ida-1",
                    dst="agent-2",
                    ok=True,
                ),
            )
            quit_resp = await asyncio.wait_for(recv_msg(agent2), timeout=1.0)
            assert isinstance(quit_resp, protocol.QuitResponse)
            assert quit_resp.ok is True


async def test_quit_works_on_locked_target(serve_bridge: ServeBridge) -> None:
    """Quit should work even when the target ownership is locked."""
    async with serve_bridge(default_timeout_s=0.05, timeout_tick_s=0.01) as (server, url):
        async with (
            connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2,
            connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-3") as agent3,
        ):
            # Claim, then trigger a takeover timeout to get locked_unknown
            claim = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), session_id="sess-1")
            await send_msg(agent1, claim)
            _ = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            await send_msg(ida, _make_ok_response(protocol.MSG_EXEC, req_id=claim.id, dst="agent-1"))
            _ = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)

            takeover = _make_request(
                protocol.MSG_RESET,
                req_id=protocol.new_req_id(),
                src="agent-2",
                session_id="sess-2",
                takeover=True,
            )
            await send_msg(agent2, takeover)
            _ = await asyncio.wait_for(recv_msg(ida), timeout=1.0)

            # Wait for timeout -> locked_unknown
            timeout_resp = await asyncio.wait_for(recv_msg(agent2), timeout=1.0)
            assert timeout_resp.code == protocol.ERR_TIMEOUT

            # Verify target is locked
            blocked = _make_request(protocol.MSG_EXEC, req_id=protocol.new_req_id(), src="agent-3", session_id="sess-3")
            await send_msg(agent3, blocked)
            blocked_resp = await asyncio.wait_for(recv_msg(agent3), timeout=1.0)
            assert blocked_resp.code == protocol.ERR_SESSION_LOCKED

            # Quit should still work
            quit_req = protocol.QuitRequest(
                id=protocol.new_req_id(),
                src="agent-3",
                dst="ida-1",
            )
            await send_msg(agent3, quit_req)
            forwarded_quit = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
            assert isinstance(forwarded_quit, protocol.QuitRequest)

            await send_msg(
                ida,
                protocol.QuitResponse(
                    id=quit_req.id,
                    src="ida-1",
                    dst="agent-3",
                    ok=True,
                ),
            )
            quit_resp = await asyncio.wait_for(recv_msg(agent3), timeout=1.0)
            assert isinstance(quit_resp, protocol.QuitResponse)
            assert quit_resp.ok is True


async def test_quit_target_not_found(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent:
            quit_req = protocol.QuitRequest(
                id=protocol.new_req_id(),
                src="agent-1",
                dst="no-such-ida",
            )
            await send_msg(agent, quit_req)
            resp = await asyncio.wait_for(recv_msg(agent), timeout=1.0)
            assert isinstance(resp, protocol.QuitResponse)
            assert resp.ok is False
            assert resp.code == protocol.ERR_TARGET_NOT_FOUND


@pytest.mark.parametrize("req_type", [protocol.MSG_EXEC, protocol.MSG_RESET])
async def test_same_session_may_continue_across_agent_reconnect(
    serve_bridge: ServeBridge,
    req_type: str,
) -> None:
    async with serve_bridge() as (_, url):
        async with connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida:
            agent1 = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            try:
                req1 = _make_request(req_type, req_id=protocol.new_req_id(), session_id="sess-1")
                await send_msg(agent1, req1)
                forwarded1 = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
                assert forwarded1 == req1
                await send_msg(ida, _make_ok_response(req_type, req_id=req1.id, dst="agent-1"))
                _ = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)
            finally:
                await agent1.close()

            agent2 = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-2")
            try:
                req2 = _make_request(
                    req_type,
                    req_id=protocol.new_req_id(),
                    src="agent-2",
                    session_id="sess-1",
                    reset_env=False,
                )
                await send_msg(agent2, req2)
                forwarded2 = await asyncio.wait_for(recv_msg(ida), timeout=1.0)
                assert forwarded2 == req2
            finally:
                await agent2.close()


@pytest.mark.parametrize("req_type", [protocol.MSG_EXEC, protocol.MSG_RESET])
async def test_session_owner_clears_on_ida_disconnect(serve_bridge: ServeBridge, req_type: str) -> None:
    async with serve_bridge() as (_, url):
        ida1 = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
        try:
            async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1:
                req1 = _make_request(req_type, req_id=protocol.new_req_id(), session_id="sess-1")
                await send_msg(agent1, req1)
                forwarded1 = await asyncio.wait_for(recv_msg(ida1), timeout=1.0)
                assert forwarded1 == req1
                await send_msg(ida1, _make_ok_response(req_type, req_id=req1.id, dst="agent-1"))
                _ = await asyncio.wait_for(recv_msg(agent1), timeout=1.0)
        finally:
            await ida1.close()

        ida2 = await connect_client(url, role=protocol.ROLE_IDA, client_id="ida-1")
        try:
            async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-2") as agent2:
                req2 = _make_request(
                    req_type,
                    req_id=protocol.new_req_id(),
                    src="agent-2",
                    session_id="sess-2",
                )
                await send_msg(agent2, req2)
                forwarded2 = await asyncio.wait_for(recv_msg(ida2), timeout=1.0)
                assert forwarded2 == req2
        finally:
            await ida2.close()
