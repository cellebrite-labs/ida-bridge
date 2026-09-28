"""Tests for BridgeConn.send failure handling."""

import logging

import pytest

from ida_bridge import protocol
from ida_bridge.bridge_conn import BridgeConn
from ida_bridge.ida_runtime import RequestHandler, run_user_code


def _direct_run_code(
    code: str,
    exec_env: dict,
) -> tuple[object, str, str, Exception | None]:
    return run_user_code(code=code, exec_env=exec_env)


class _FakeWS:
    def __init__(self, *, max_message_bytes: int) -> None:
        self.sent: list[str] = []
        self.max_message_bytes = max_message_bytes
        self.closed = False

    def send(self, data: str) -> None:
        if len(data) > self.max_message_bytes:
            self.closed = True
            raise OSError("message too big")
        self.sent.append(data)


def _conn_with_fake_ws(*, max_message_bytes: int = protocol.MIN_MESSAGE_BYTES) -> tuple[BridgeConn, _FakeWS]:
    """A connection whose fake server enforces max_message_bytes and has advertised it."""
    conn = BridgeConn(client_id="ida-1", url="ws://127.0.0.1:9", meta={})
    ws = _FakeWS(max_message_bytes=max_message_bytes)
    conn._ws = ws  # type: ignore[assignment]
    conn._max_message_bytes = max_message_bytes
    return conn, ws


def _surrogate_text() -> str:
    return b"PRE_abc\xff_POST".decode("utf-8", "surrogateescape")


def test_send_unserializable_response_replies_error(caplog: pytest.LogCaptureFixture) -> None:
    conn, ws = _conn_with_fake_ws()
    req_id = protocol.new_req_id()
    bad = protocol.ExecResponse(
        id=req_id,
        src="ida-1",
        dst="agent-1",
        ok=True,
        stdout=_surrogate_text(),
    )

    with caplog.at_level(logging.ERROR, logger="ida_bridge.bridge_conn"):
        conn.send(bad)

    assert len(ws.sent) == 1
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.ok is False
    assert parsed.id == req_id
    assert parsed.src == "ida-1"
    assert parsed.dst == "agent-1"
    assert parsed.code == protocol.ERR_RESPONSE_NOT_SERIALIZABLE
    assert parsed.message is not None
    assert "stdout" in parsed.message
    parsed.message.encode("utf-8")
    ws.sent[0].encode("utf-8")

    error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(error_records) == 1
    assert error_records[0].exc_info is not None


def test_send_unserializable_result_names_field() -> None:
    conn, ws = _conn_with_fake_ws()
    bad = protocol.ExecResponse(
        id=protocol.new_req_id(),
        src="ida-1",
        dst="agent-1",
        ok=True,
        result=_surrogate_text(),
    )
    conn.send(bad)
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.code == protocol.ERR_RESPONSE_NOT_SERIALIZABLE
    assert parsed.message is not None
    assert "result" in parsed.message


def test_send_serializable_response_unchanged() -> None:
    conn, ws = _conn_with_fake_ws()
    ok = protocol.ExecResponse(
        id=protocol.new_req_id(),
        src="ida-1",
        dst="agent-1",
        ok=True,
        result=1,
        stdout="hello",
    )
    conn.send(ok)
    assert len(ws.sent) == 1
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.ok is True
    assert parsed.id == ok.id
    assert parsed.result == 1
    assert parsed.stdout == "hello"


def test_send_non_ascii_serialize_error_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    conn, ws = _conn_with_fake_ws()
    ok = protocol.ExecResponse(
        id=protocol.new_req_id(),
        src="ida-1",
        dst="agent-1",
        ok=True,
        result=1,
    )
    orig = protocol.dump_message_json
    calls = {"n": 0}

    def dump(msg: protocol.Message) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("café")
        return orig(msg)

    monkeypatch.setattr("ida_bridge.bridge_conn.protocol.dump_message_json", dump)
    conn.send(ok)
    assert len(ws.sent) == 1
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.ok is False
    assert parsed.id == ok.id
    assert parsed.code == protocol.ERR_RESPONSE_NOT_SERIALIZABLE
    assert parsed.message is not None
    parsed.message.encode("ascii")
    ws.sent[0].encode("utf-8")


def test_exec_surrogate_stdout_does_not_raise() -> None:
    conn, ws = _conn_with_fake_ws()
    handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=conn.send)
    req = protocol.ExecRequest(
        id=protocol.new_req_id(),
        src="agent-1",
        dst="ida-1",
        code="print(b'PRE_abc\\xff_POST'.decode('utf-8', 'surrogateescape'))",
    )
    handler.handle(req)
    assert len(ws.sent) == 1
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.ok is False
    assert parsed.id == req.id
    assert parsed.code == protocol.ERR_RESPONSE_NOT_SERIALIZABLE
    assert parsed.message is not None
    assert "stdout" in parsed.message


def test_send_names_every_unserializable_field() -> None:
    """One reply should let the caller fix everything, not one field per retry."""
    conn, ws = _conn_with_fake_ws()
    bad = protocol.ExecResponse(
        id=protocol.new_req_id(),
        src="ida-1",
        dst="agent-1",
        ok=True,
        stdout=_surrogate_text(),
        stderr=_surrogate_text(),
        result={"k": [_surrogate_text()]},
    )

    conn.send(bad)

    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.message is not None
    for field in ("stdout", "stderr", "result"):
        assert field in parsed.message


def test_send_does_not_blame_a_field_pydantic_can_serialize() -> None:
    """A set has no JSON form but pydantic handles it; the surrogate is the culprit."""
    conn, ws = _conn_with_fake_ws()
    bad = protocol.ExecResponse(
        id=protocol.new_req_id(),
        src="ida-1",
        dst="agent-1",
        ok=True,
        result={"k": {1, 2}},
        stdout=_surrogate_text(),
    )

    conn.send(bad)

    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.message is not None
    assert "stdout" in parsed.message
    assert "result" not in parsed.message


def test_send_replaces_an_error_response_that_is_itself_unserializable(caplog: pytest.LogCaptureFixture) -> None:
    """An error reply that cannot be sent is rebuilt, not dropped: the caller still hears back."""
    conn, ws = _conn_with_fake_ws()
    req_id = protocol.new_req_id()
    bad = protocol.ExecResponse(
        id=req_id,
        src="ida-1",
        dst="agent-1",
        ok=False,
        code=protocol.ERR_RESPONSE_NOT_SERIALIZABLE,
        message="already failed",
        traceback=_surrogate_text(),
    )

    with caplog.at_level(logging.ERROR, logger="ida_bridge.bridge_conn"):
        conn.send(bad)

    assert len(ws.sent) == 1
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.id == req_id
    assert parsed.code == protocol.ERR_RESPONSE_NOT_SERIALIZABLE
    assert parsed.message is not None
    assert "traceback" in parsed.message
    assert parsed.traceback is None
    assert [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_send_oversized_response_replies_error() -> None:
    limit = protocol.MIN_MESSAGE_BYTES
    conn, ws = _conn_with_fake_ws(max_message_bytes=limit)
    conn._ready.set()
    req_id = protocol.new_req_id()
    huge = protocol.ExecResponse(
        id=req_id,
        src="ida-1",
        dst="agent-1",
        ok=True,
        result="z" * (protocol.MIN_MESSAGE_BYTES * 2),
    )
    original = protocol.dump_message_json(huge)
    assert len(original) > limit

    conn.send(huge)

    assert ws.closed is False
    assert conn._ready.is_set()
    assert len(ws.sent) == 1
    assert ws.sent[0] != original
    assert original not in ws.sent
    assert len(ws.sent[0]) <= limit
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.ok is False
    assert parsed.id == req_id
    assert parsed.src == "ida-1"
    assert parsed.dst == "agent-1"
    assert parsed.code == protocol.ERR_RESPONSE_TOO_LARGE
    assert parsed.message is not None
    assert str(limit) in parsed.message
    assert str(len(original)) in parsed.message
    parsed.message.encode("ascii")
    ws.sent[0].encode("ascii")


def test_send_oversized_covers_stdout_stderr_result_together() -> None:
    limit = protocol.MIN_MESSAGE_BYTES
    conn, ws = _conn_with_fake_ws(max_message_bytes=limit)
    conn._ready.set()
    chunk = "z" * (protocol.MIN_MESSAGE_BYTES // 2)
    combined = protocol.ExecResponse(
        id=protocol.new_req_id(),
        src="ida-1",
        dst="agent-1",
        ok=True,
        result=chunk,
        stdout=chunk,
        stderr=chunk,
    )
    original = protocol.dump_message_json(combined)
    assert len(original) > limit
    for kwargs in ({"result": chunk}, {"stdout": chunk}, {"stderr": chunk}):
        alone = protocol.ExecResponse(id=combined.id, src="ida-1", dst="agent-1", ok=True, **kwargs)
        assert len(protocol.dump_message_json(alone)) <= limit

    conn.send(combined)

    assert ws.closed is False
    assert len(ws.sent) == 1
    assert original not in ws.sent
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.code == protocol.ERR_RESPONSE_TOO_LARGE
    assert parsed.message is not None
    assert str(limit) in parsed.message
    assert str(len(original)) in parsed.message


def test_oversized_response_keeps_handler_serving() -> None:
    limit = protocol.MIN_MESSAGE_BYTES
    conn, ws = _conn_with_fake_ws(max_message_bytes=limit)
    conn._ready.set()
    handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=conn.send)

    huge_req = protocol.ExecRequest(
        id=protocol.new_req_id(),
        src="agent-1",
        dst="ida-1",
        code=f"_result_ = 'z' * {protocol.MIN_MESSAGE_BYTES * 2}",
    )
    handler.handle(huge_req)

    assert ws.closed is False
    assert conn._ready.is_set()
    assert conn._ws is ws
    assert len(ws.sent) == 1
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.ExecResponse)
    assert parsed.ok is False
    assert parsed.id == huge_req.id
    assert parsed.code == protocol.ERR_RESPONSE_TOO_LARGE
    assert parsed.message is not None
    assert str(limit) in parsed.message
    assert all(len(frame) <= limit for frame in ws.sent)

    ok_req = protocol.ExecRequest(
        id=protocol.new_req_id(),
        src="agent-1",
        dst="ida-1",
        code="_result_ = 1",
    )
    handler.handle(ok_req)

    assert ws.closed is False
    assert conn._ready.is_set()
    assert conn._ws is ws
    assert len(ws.sent) == 2
    parsed_ok = protocol.parse_message_json(ws.sent[1])
    assert isinstance(parsed_ok, protocol.ExecResponse)
    assert parsed_ok.ok is True
    assert parsed_ok.id == ok_req.id
    assert parsed_ok.result == 1


def test_hello_ack_sets_the_limit_and_disconnect_resets_it() -> None:
    conn, ws = _conn_with_fake_ws()
    advertised = protocol.MIN_MESSAGE_BYTES * 8
    ack = protocol.HelloAck(client_id="ida-1", bridge_id="bridge", max_message_bytes=advertised)

    conn._on_message(ws, protocol.dump_message_json(ack))
    assert conn._ready.is_set()
    assert conn._max_message_bytes == advertised

    conn._mark_disconnected()
    assert conn._max_message_bytes == protocol.MIN_MESSAGE_BYTES


def test_send_drops_an_unserializable_handshake(caplog: pytest.LogCaptureFixture) -> None:
    """A hello has no error form -- an IDB path with undecodable bytes can produce one."""
    conn, ws = _conn_with_fake_ws()
    hello = protocol.Hello(
        client_id="ida-1",
        role="ida",
        meta={"idb_path": b"idb_\xff.i64".decode("utf-8", "surrogateescape")},
    )

    with caplog.at_level(logging.ERROR, logger="ida_bridge.bridge_conn"):
        conn.send(hello)

    assert ws.sent == []
    assert [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_send_without_a_connection_logs_the_drop(caplog: pytest.LogCaptureFixture) -> None:
    conn, _ = _conn_with_fake_ws()
    conn._ws = None  # type: ignore[assignment]
    resp = protocol.ExecResponse(
        id=protocol.new_req_id(),
        src="ida-1",
        dst="agent-1",
        ok=True,
        result=1,
    )

    with caplog.at_level(logging.WARNING, logger="ida_bridge.bridge_conn"):
        conn.send(resp)

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert "not connected" in warnings[0].getMessage()
