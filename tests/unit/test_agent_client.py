import asyncio

import pytest

from ida_bridge import protocol
from ida_bridge.agent_client import AgentClient, BridgeDisconnected, _ConnState

LIMIT = protocol.MIN_MESSAGE_BYTES * 2


class _ReachedSocket(Exception):
    pass


class _RecordingWS:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, data: str) -> None:
        self.sent.append(data)
        raise _ReachedSocket


@pytest.mark.parametrize(
    ("code_size", "raised"),
    [(protocol.MIN_MESSAGE_BYTES + 64, _ReachedSocket), (LIMIT + 64, BridgeDisconnected)],
    ids=["under-limit", "over-limit"],
)
async def test_request_size_is_checked_against_the_advertised_limit(code_size: int, raised: type[Exception]) -> None:
    client = AgentClient(client_id="agent-1")
    ws = _RecordingWS()
    listener = asyncio.create_task(asyncio.sleep(30))
    client._conn = _ConnState(ws=ws, listener=listener, max_message_bytes=LIMIT)
    req = protocol.ExecRequest(id=protocol.new_req_id(), src="agent-1", dst="ida-1", code="z" * code_size)
    try:
        with pytest.raises(raised):
            await client._request(req)
    finally:
        listener.cancel()

    reached_socket = raised is _ReachedSocket
    assert ws.sent == ([protocol.dump_message_json(req)] if reached_socket else [])
