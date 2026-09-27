import pytest

from ida_bridge import protocol
from ida_bridge.agent_client import AgentClient, BridgeDisconnected, RequestTooLarge, _ConnState

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
    [(protocol.MIN_MESSAGE_BYTES + 64, _ReachedSocket), (LIMIT + 64, RequestTooLarge)],
    ids=["under-limit", "over-limit"],
)
async def test_request_size_is_checked_against_the_advertised_limit(code_size: int, raised: type[Exception]) -> None:
    client = AgentClient(client_id="agent-1")
    ws = _RecordingWS()
    client._conn = _ConnState(ws=ws, max_message_bytes=LIMIT)
    req = protocol.ExecRequest(id=protocol.new_req_id(), src="agent-1", dst="ida-1", code="z" * code_size)
    with pytest.raises(raised):
        await client._request(req)

    reached_socket = raised is _ReachedSocket
    assert ws.sent == ([protocol.dump_message_json(req)] if reached_socket else [])


class _ReplyingWS:
    def __init__(self, reply: str | bytes) -> None:
        self._reply = reply
        self.close_code: int | None = None

    async def send(self, data: str) -> None:
        pass

    async def recv(self) -> str | bytes:
        return self._reply

    async def close(self, code: int = 1000) -> None:
        self.close_code = code


_REQ_ID = protocol.new_req_id()


def _exec_response(**overrides: str) -> str:
    fields = {"id": _REQ_ID, "src": "ida-1", "dst": "agent-1", **overrides}
    return protocol.dump_message_json(protocol.ExecResponse(ok=True, result=1, **fields))


@pytest.mark.parametrize(
    ("reply", "detail"),
    [
        (b"binary", "non-text websocket frame"),
        ("{not json", "invalid message"),
        (
            protocol.dump_message_json(
                protocol.ListRequest(id=protocol.new_req_id(), src="bridge", dst="agent-1", kind="ida")
            ),
            "expected ExecResponse, got: list",
        ),
        (_exec_response(dst="agent-2"), "dst mismatch"),
        (_exec_response(id=protocol.new_req_id()), "unexpected response id"),
    ],
    ids=["binary", "invalid", "wrong-type", "wrong-dst", "wrong-id"],
)
async def test_a_bad_reply_is_a_protocol_violation_that_disconnects(reply: str | bytes, detail: str) -> None:
    client = AgentClient(client_id="agent-1")
    ws = _ReplyingWS(reply)
    client._conn = _ConnState(ws=ws, max_message_bytes=LIMIT)
    req = protocol.ExecRequest(id=_REQ_ID, src="agent-1", dst="ida-1", code="1")

    with pytest.raises(BridgeDisconnected, match=detail):
        await client._request(req)

    assert client.is_connected() is False
    assert ws.close_code == protocol.WS_CLOSE_PROTOCOL_ERROR
