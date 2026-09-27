import json
from uuid import uuid4

from pydantic import ValidationError
import pytest

from ida_bridge import protocol

UUID_V4 = "f47ac10b-58cc-4372-a567-0e02b2c3d479"  # canonical UUIDv4
UUID_V1 = "f47ac10b-58cc-1372-a567-0e02b2c3d479"  # third group starts with 1 => v1
UUID_V5 = "f47ac10b-58cc-5372-a567-0e02b2c3d479"  # third group starts with 5 => v5


def test_protocol_version_is_5() -> None:
    assert protocol.PROTO_VERSION == 5


def test_parse_requires_version_on_wire() -> None:
    raw = json.dumps({"type": protocol.MSG_HELLO, "role": protocol.ROLE_AGENT, "client_id": "agent-1", "meta": {}})
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(raw)

    errors = excinfo.value.errors()
    assert any(e.get("type") == "missing_version" for e in errors)


def test_parse_rejects_unsupported_version_on_wire() -> None:
    raw = json.dumps(
        {"v": 999, "type": protocol.MSG_HELLO, "role": protocol.ROLE_AGENT, "client_id": "agent-1", "meta": {}}
    )
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(raw)

    errors = excinfo.value.errors()
    assert any(e.get("type") == "unsupported_version" for e in errors)


def test_parse_rejects_invalid_json() -> None:
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json("{not json")

    errors = excinfo.value.errors()
    assert any(e.get("type") == "json_invalid" for e in errors)


def test_parse_rejects_unknown_message_type() -> None:
    raw = json.dumps({"v": protocol.PROTO_VERSION, "type": "nope"})
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(raw)

    errors = excinfo.value.errors()
    assert any(e.get("type") == "union_tag_invalid" for e in errors)


@pytest.mark.parametrize(
    "bad_id",
    [
        123,
        "not-a-uuid",
        UUID_V1,
        UUID_V5,
        UUID_V4.upper(),
        UUID_V4.replace("-", ""),
        "{" + UUID_V4 + "}",
    ],
)
def test_request_id_validator_rejects_noncanonical_uuidv4(bad_id) -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_LIST,
        "id": bad_id,
        "src": "agent-1",
        "dst": "bridge",
        "kind": protocol.LIST_KIND_ALL,
    }
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(json.dumps(msg))

    errors = excinfo.value.errors()
    assert any(e.get("type") == "invalid_request_id" for e in errors)


def test_request_id_accepts_uuidv4() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_LIST,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "bridge",
        "kind": protocol.LIST_KIND_ALL,
    }
    parsed = protocol.parse_message_json(json.dumps(msg))
    assert isinstance(parsed, protocol.ListRequest)
    assert parsed.id == UUID_V4


def test_models_are_strict_extra_forbidden() -> None:
    raw = json.dumps(
        {
            "v": protocol.PROTO_VERSION,
            "type": protocol.MSG_HELLO,
            "role": protocol.ROLE_AGENT,
            "client_id": "agent-1",
            "meta": {},
            "extra": "nope",
        }
    )
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(raw)

    errors = excinfo.value.errors()
    assert any(e.get("type") == "extra_forbidden" for e in errors)


def test_exec_request_defaults_to_stateless() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_EXEC,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
        "code": "1 + 1",
    }
    parsed = protocol.parse_message_json(json.dumps(msg))
    assert isinstance(parsed, protocol.ExecRequest)
    assert parsed.persist is False
    assert parsed.session_id is None
    assert parsed.reset_env is True


def test_stateful_exec_request_accepts_session_id() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_EXEC,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
        "session_id": "sess-1",
        "persist": True,
        "code": "1 + 1",
    }
    parsed = protocol.parse_message_json(json.dumps(msg))
    assert isinstance(parsed, protocol.ExecRequest)
    assert parsed.persist is True
    assert parsed.session_id == "sess-1"


def test_stateful_exec_request_requires_session_id() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_EXEC,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
        "persist": True,
        "code": "1 + 1",
    }
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(json.dumps(msg))

    errors = excinfo.value.errors()
    assert any("session_id is required" in e.get("msg", "") for e in errors)


def test_stateless_exec_request_rejects_session_id() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_EXEC,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
        "session_id": "sess-1",
        "code": "1 + 1",
    }
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(json.dumps(msg))

    errors = excinfo.value.errors()
    assert any("only valid when persist=true" in e.get("msg", "") for e in errors)


def test_reset_request_requires_session_id() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_RESET,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
    }
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(json.dumps(msg))

    errors = excinfo.value.errors()
    assert any(e.get("type") == "missing" and e.get("loc", ())[-1] == "session_id" for e in errors)


def test_reset_request_accepts_takeover() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_RESET,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
        "session_id": "sess-1",
        "takeover": True,
    }
    parsed = protocol.parse_message_json(json.dumps(msg))
    assert isinstance(parsed, protocol.ResetRequest)
    assert parsed.takeover is True


def test_reset_request_accepts_release() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_RESET,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
        "session_id": "sess-1",
        "release": True,
    }
    parsed = protocol.parse_message_json(json.dumps(msg))
    assert isinstance(parsed, protocol.ResetRequest)
    assert parsed.release is True


def test_reset_request_rejects_takeover_with_release() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_RESET,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
        "session_id": "sess-1",
        "takeover": True,
        "release": True,
    }
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(json.dumps(msg))

    errors = excinfo.value.errors()
    assert any("mutually exclusive" in e.get("msg", "") for e in errors)


def test_exec_request_rejects_takeover_field() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_EXEC,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
        "session_id": "sess-1",
        "persist": True,
        "code": "1 + 1",
        "takeover": True,
    }
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(json.dumps(msg))

    errors = excinfo.value.errors()
    assert any(e.get("type") == "extra_forbidden" and e.get("loc", ())[-1] == "takeover" for e in errors)


def test_quit_request_has_no_session_id() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_QUIT,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
    }
    parsed = protocol.parse_message_json(json.dumps(msg))
    assert isinstance(parsed, protocol.QuitRequest)
    assert not hasattr(parsed, "session_id")


def test_quit_request_rejects_session_id() -> None:
    msg = {
        "v": protocol.PROTO_VERSION,
        "type": protocol.MSG_QUIT,
        "id": UUID_V4,
        "src": "agent-1",
        "dst": "ida-1",
        "session_id": "sess-1",
    }
    with pytest.raises(ValidationError) as excinfo:
        protocol.parse_message_json(json.dumps(msg))
    errors = excinfo.value.errors()
    assert any(e.get("type") == "extra_forbidden" and e.get("loc", ())[-1] == "session_id" for e in errors)


def test_response_ok_true_forbids_error_fields() -> None:
    req_id = str(uuid4())
    with pytest.raises(ValidationError):
        protocol.ExecResponse(
            id=req_id,
            src="ida-1",
            dst="agent-1",
            ok=True,
            code="SHOULD_NOT_BE_HERE",
        )

    with pytest.raises(ValidationError):
        protocol.ExecResponse(
            id=req_id,
            src="ida-1",
            dst="agent-1",
            ok=True,
            message="nope",
        )

    with pytest.raises(ValidationError):
        protocol.ExecResponse(
            id=req_id,
            src="ida-1",
            dst="agent-1",
            ok=True,
            trace={"x": 1},
        )


def test_response_ok_false_requires_code() -> None:
    req_id = str(uuid4())
    with pytest.raises(ValidationError):
        protocol.ResetResponse(id=req_id, src="ida-1", dst="agent-1", ok=False)


def test_list_response_ok_true_requires_clients() -> None:
    req_id = str(uuid4())
    with pytest.raises(ValidationError):
        protocol.ListResponse(
            id=req_id,
            src="bridge",
            dst="agent-1",
            ok=True,
            kind=protocol.LIST_KIND_ALL,
        )


def test_list_response_ok_false_forbids_clients_and_requires_code() -> None:
    req_id = str(uuid4())

    with pytest.raises(ValidationError):
        protocol.ListResponse(
            id=req_id,
            src="bridge",
            dst="agent-1",
            ok=False,
            kind=protocol.LIST_KIND_ALL,
        )

    with pytest.raises(ValidationError):
        protocol.ListResponse(
            id=req_id,
            src="bridge",
            dst="agent-1",
            ok=False,
            code="ERR",
            kind=protocol.LIST_KIND_ALL,
            clients=[],
        )
