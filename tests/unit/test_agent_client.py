import asyncio

import pytest

from ida_bridge import protocol
from ida_bridge.agent_client import AgentClient, BridgeDisconnected, _ConnState


async def test_agent_send_uses_advertised_limit_not_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_BRIDGE_WS_MAX_SIZE", str(protocol.MIN_WS_MAX_SIZE))
    client = AgentClient(client_id="agent-1")
    advertised = protocol.MIN_WS_MAX_SIZE * 8
    client._frame_limit_bytes = advertised
    client._bridge_id = "bridge"
    sent: list[str] = []

    class _WS:
        async def send(self, data: str) -> None:
            sent.append(data)
            req_id = protocol.parse_message_json(data).id
            fut = client._pending[req_id]
            if not fut.done():
                fut.set_result(protocol.ExecResponse(id=req_id, src="ida-1", dst="agent-1", ok=True, result=1))

    listener = asyncio.create_task(asyncio.sleep(30))
    client._conn = _ConnState(ws=_WS(), listener=listener)
    try:
        req = protocol.ExecRequest(
            id=protocol.new_req_id(),
            src="agent-1",
            dst="ida-1",
            code="z" * (protocol.MIN_WS_MAX_SIZE + 64),
        )
        original = protocol.dump_message_json(req)
        assert len(original) > protocol.MIN_WS_MAX_SIZE
        assert len(original) <= advertised
        resp = await client._request(req)
        assert sent == [original]
        assert isinstance(resp, protocol.ExecResponse)
        assert resp.ok is True
    finally:
        listener.cancel()


async def test_agent_send_rejects_over_advertised_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_BRIDGE_WS_MAX_SIZE", str(protocol.DEFAULT_WS_MAX_SIZE))
    client = AgentClient(client_id="agent-1")
    client._frame_limit_bytes = protocol.MIN_WS_MAX_SIZE
    client._bridge_id = "bridge"
    client._conn = _ConnState(ws=object(), listener=asyncio.create_task(asyncio.sleep(30)))
    try:
        req = protocol.ExecRequest(
            id=protocol.new_req_id(),
            src="agent-1",
            dst="ida-1",
            code="z" * (protocol.MIN_WS_MAX_SIZE + 64),
        )
        with pytest.raises(BridgeDisconnected, match=str(protocol.MIN_WS_MAX_SIZE)):
            await client._request(req)
    finally:
        client._conn.listener.cancel()
