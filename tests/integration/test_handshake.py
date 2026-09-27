import asyncio

import websockets
from websockets.frames import CloseCode

from ida_bridge import protocol
from tests.harness import (
    ServeBridge,
    connect_client,
    connected_client,
    expect_protocol_error_and_close,
    recv_msg,
    recv_typed,
    send_msg,
)


async def test_handshake_happy_path(serve_bridge: ServeBridge) -> None:
    async with serve_bridge(bridge_client_id="bridge", instance_id="test-instance") as (server, url):
        ida = await websockets.connect(url)
        agent = await websockets.connect(url)
        try:
            await send_msg(
                ida,
                protocol.Hello(
                    role=protocol.ROLE_IDA,
                    client_id="ida-1",
                    meta={"idb_path": "/tmp/x.i64"},
                ),
            )
            ida_ack = await recv_msg(ida)
            assert isinstance(ida_ack, protocol.HelloAck)
            assert ida_ack.v == protocol.PROTO_VERSION
            assert ida_ack.client_id == "ida-1"
            assert ida_ack.bridge_id == server.bridge_id
            assert ida_ack.meta["server"] == "ida-bridge"
            assert ida_ack.meta["instance_id"] == "test-instance"
            assert ida_ack.max_message_bytes == server.max_message_bytes

            await send_msg(agent, protocol.Hello(role=protocol.ROLE_AGENT, client_id="agent-1", meta={}))
            agent_ack = await recv_msg(agent)
            assert isinstance(agent_ack, protocol.HelloAck)
            assert agent_ack.client_id == "agent-1"
            assert agent_ack.bridge_id == server.bridge_id
        finally:
            await ida.close()
            await agent.close()


def _exec_json_of_size(size: int) -> str:
    req_id = protocol.new_req_id()
    empty = protocol.ExecRequest(id=req_id, src="agent-1", dst="ida-missing", code="")
    padding = size - len(protocol.dump_message_json(empty))
    data = protocol.dump_message_json(
        protocol.ExecRequest(id=req_id, src="agent-1", dst="ida-missing", code="z" * padding)
    )
    assert len(data) == size
    return data


async def test_server_enforces_the_limit_it_advertises(serve_bridge: ServeBridge) -> None:
    async with serve_bridge(max_message_bytes=protocol.MIN_MESSAGE_BYTES * 2) as (_, url):
        agent = await websockets.connect(url)
        try:
            await send_msg(agent, protocol.Hello(role=protocol.ROLE_AGENT, client_id="agent-1", meta={}))
            ack = await recv_msg(agent)
            assert isinstance(ack, protocol.HelloAck)
            limit = ack.max_message_bytes

            await agent.send(_exec_json_of_size(limit))
            resp = await recv_typed(agent, protocol.ExecResponse)
            assert resp.code == protocol.ERR_TARGET_NOT_FOUND

            await agent.send("z" * (limit + 1))
            await asyncio.wait_for(agent.wait_closed(), timeout=1.0)
            assert agent.close_code == CloseCode.MESSAGE_TOO_BIG
        finally:
            await agent.close()


async def test_handshake_required_first_message_must_be_hello(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        ws = await websockets.connect(url)
        try:
            await send_msg(
                ws,
                protocol.ListRequest(
                    id=protocol.new_req_id(),
                    src="agent-1",
                    dst=server.bridge_id,
                    kind=protocol.LIST_KIND_ALL,
                ),
            )
            await expect_protocol_error_and_close(
                ws,
                code=protocol.ERR_HANDSHAKE_REQUIRED,
                close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
            )
        finally:
            await ws.close()


async def test_handshake_duplicate_hello_is_rejected(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        ws = await websockets.connect(url)
        try:
            await send_msg(ws, protocol.Hello(role=protocol.ROLE_AGENT, client_id="agent-1", meta={}))
            ack = await recv_msg(ws)
            assert isinstance(ack, protocol.HelloAck)

            # Send hello again.
            await send_msg(ws, protocol.Hello(role=protocol.ROLE_AGENT, client_id="agent-1", meta={}))

            await expect_protocol_error_and_close(
                ws,
                code=protocol.ERR_DUPLICATE_HELLO,
                close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
            )
        finally:
            await ws.close()


async def test_handshake_reserved_client_id_is_rejected(serve_bridge: ServeBridge) -> None:
    async with serve_bridge(bridge_client_id="bridge") as (_, url):
        ws = await websockets.connect(url)
        try:
            await send_msg(ws, protocol.Hello(role=protocol.ROLE_AGENT, client_id="bridge", meta={}))
            await expect_protocol_error_and_close(
                ws,
                code=protocol.ERR_INVALID_CLIENT_ID,
                close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
            )
        finally:
            await ws.close()


async def test_handshake_duplicate_client_id_is_rejected(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent1:
            agent2 = await websockets.connect(url)
            try:
                await send_msg(agent2, protocol.Hello(role=protocol.ROLE_AGENT, client_id="agent-1", meta={}))
                await expect_protocol_error_and_close(
                    agent2,
                    code=protocol.ERR_DUPLICATE_CLIENT_ID,
                    close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
                )

                # Original connection should still be usable.
                await send_msg(
                    agent1,
                    protocol.ListRequest(
                        id=protocol.new_req_id(),
                        src="agent-1",
                        dst=server.bridge_id,
                        kind=protocol.LIST_KIND_ALL,
                    ),
                )
                resp = await recv_msg(agent1)
                assert isinstance(resp, protocol.ListResponse)
                assert resp.ok is True
            finally:
                await agent2.close()


async def test_post_handshake_protocol_error_message_is_rejected(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
        await send_msg(agent, protocol.ProtocolError(code="X", message="Y"))
        await expect_protocol_error_and_close(
            agent,
            code=protocol.ERR_UNSUPPORTED_MESSAGE,
            close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
        )


async def test_post_handshake_src_mismatch_is_rejected(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
        await send_msg(
            agent,
            protocol.ListRequest(
                id=protocol.new_req_id(),
                src="spoofed-agent",
                dst=server.bridge_id,
                kind=protocol.LIST_KIND_ALL,
            ),
        )
        await expect_protocol_error_and_close(
            agent,
            code=protocol.ERR_SRC_MISMATCH,
            close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
        )
