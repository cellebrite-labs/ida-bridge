import asyncio
import subprocess
import sys

import pytest

from ida_bridge import protocol, remote
from ida_bridge.agent_client import AgentClient, BridgeDisconnected, _ConnState
from ida_bridge.cli_remote import apply_response, main as remote_main
from ida_bridge.server import BridgeServer


def test_protocol_version_is_5() -> None:
    assert protocol.PROTO_VERSION == 5


@pytest.mark.parametrize(
    "argv",
    [
        ["remote"],
        ["remote", "--", "list"],
        ["server", "stop"],
        ["server", "stop", "extra"],
        ["server", "--", "stop"],
        ["server", "--", "stop", "extra"],
    ],
)
def test_denied_commands(argv: list[str]) -> None:
    reason = remote.denied_reason(argv)
    assert reason
    assert "remote" in reason or "server stop" in reason


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--help"],
        ["list"],
        ["server", "status"],
        ["server", "--", "status"],
        ["server", "start"],
        ["server", "log"],
        ["supervisor", "stop", "ida-1"],
        ["supervisor", "start-idalib", "--input", "/host/path"],
    ],
)
def test_allowed_commands(argv: list[str]) -> None:
    assert remote.denied_reason(argv) is None


def test_error_for_request_covers_remote() -> None:
    req = protocol.RemoteRequest(id=protocol.new_req_id(), src="agent-1", dst="bridge", argv=["remote"])
    resp = protocol.error_for_request(req, code=protocol.ERR_REMOTE_DENIED, message="no")
    assert isinstance(resp, protocol.RemoteResponse)
    assert resp.ok is False
    assert resp.code == protocol.ERR_REMOTE_DENIED
    assert resp.exit_code is None
    assert resp.stdout is None
    assert resp.stderr is None


class _FakeWS:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, data: str) -> None:
        self.sent.append(data)


async def test_handle_remote_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    server = BridgeServer()
    seen: dict[str, list[str]] = {}

    async def fake_run(argv: list[str]) -> tuple[int, str, str]:
        seen["argv"] = argv
        return 4, "from-host\n", "host-err\n"

    monkeypatch.setattr("ida_bridge.server.remote.run_argv", fake_run)
    ws = _FakeWS()
    req = protocol.RemoteRequest(
        id=protocol.new_req_id(),
        src="agent-1",
        dst=server.bridge_id,
        argv=["supervisor", "start-idalib", "--input", "/host/bin"],
    )
    await server._handle_remote(ws, "agent-1", req)

    assert seen["argv"] == ["supervisor", "start-idalib", "--input", "/host/bin"]
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.RemoteResponse)
    assert parsed.ok is True
    assert parsed.exit_code == 4
    assert parsed.stdout == "from-host\n"
    assert parsed.stderr == "host-err\n"
    assert parsed.src == server.bridge_id
    assert parsed.dst == "agent-1"
    assert parsed.id == req.id


@pytest.mark.parametrize("argv", [["server", "stop"], ["server", "--", "stop"]])
async def test_handle_remote_filter_does_not_spawn(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> None:
    server = BridgeServer()

    async def fail(argv: list[str]) -> tuple[int, str, str]:
        raise AssertionError(f"spawned {argv}")

    monkeypatch.setattr("ida_bridge.server.remote.run_argv", fail)
    ws = _FakeWS()
    req = protocol.RemoteRequest(id=protocol.new_req_id(), src="agent-1", dst=server.bridge_id, argv=argv)
    await server._handle_remote(ws, "agent-1", req)

    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.RemoteResponse)
    assert parsed.ok is False
    assert parsed.code == protocol.ERR_REMOTE_DENIED
    assert parsed.message is not None
    assert "server stop" in parsed.message


async def test_handle_remote_yields_to_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    server = BridgeServer()
    started = asyncio.Event()
    release = asyncio.Event()
    other_ran = False

    async def fake_run(argv: list[str]) -> tuple[int, str, str]:
        started.set()
        await release.wait()
        return 0, "", ""

    monkeypatch.setattr("ida_bridge.server.remote.run_argv", fake_run)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("subprocess.run")))

    async def other() -> None:
        nonlocal other_ran
        await started.wait()
        other_ran = True
        release.set()

    other_task = asyncio.create_task(other())
    await server._handle_remote(
        _FakeWS(),
        "agent-1",
        protocol.RemoteRequest(id=protocol.new_req_id(), src="agent-1", dst=server.bridge_id, argv=["list"]),
    )
    await other_task
    assert other_ran


async def test_handle_remote_bounds_the_response(monkeypatch: pytest.MonkeyPatch) -> None:
    limit = protocol.MIN_WS_MAX_SIZE
    server = BridgeServer(max_size=limit)

    async def fake_run(argv: list[str]) -> tuple[int, str, str]:
        return 0, "z" * (limit * 2), ""

    monkeypatch.setattr("ida_bridge.server.remote.run_argv", fake_run)
    ws = _FakeWS()
    req = protocol.RemoteRequest(id=protocol.new_req_id(), src="agent-1", dst=server.bridge_id, argv=["list"])
    await server._handle_remote(ws, "agent-1", req)

    assert len(ws.sent) == 1
    assert "z" * 64 not in ws.sent[0]
    assert len(ws.sent[0]) <= limit
    parsed = protocol.parse_message_json(ws.sent[0])
    assert isinstance(parsed, protocol.RemoteResponse)
    assert parsed.code == protocol.ERR_RESPONSE_TOO_LARGE
    assert parsed.message is not None
    assert str(limit) in parsed.message


async def test_run_argv_uses_async_subprocess_of_our_install(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("subprocess.run")))
    started = asyncio.Event()
    release = asyncio.Event()
    seen: dict[str, object] = {}

    class _Proc:
        returncode = 3
        pid = 42

        async def communicate(self) -> tuple[bytes, bytes]:
            started.set()
            await release.wait()
            return b"stdout-text", b"stderr-text"

    async def fake_exec(*args: object, **kwargs: object) -> _Proc:
        seen["args"] = args
        seen["kwargs"] = kwargs
        return _Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    async def other() -> None:
        await started.wait()
        release.set()

    other_task = asyncio.create_task(other())
    code, out, err = await remote.run_argv(["supervisor", "start-idalib", "--input", "/host/path"])
    await other_task

    assert code == 3
    assert out == "stdout-text"
    assert err == "stderr-text"
    args = seen["args"]
    assert isinstance(args, tuple)
    assert args[0] == sys.executable
    assert args[1:3] == ("-m", "ida_bridge")
    assert args[3:] == ("supervisor", "start-idalib", "--input", "/host/path")
    kwargs = seen["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["stdout"] is asyncio.subprocess.PIPE
    assert kwargs["stderr"] is asyncio.subprocess.PIPE


def test_cli_prints_child_streams_and_exits_with_child_code(capsys: pytest.CaptureFixture[str]) -> None:
    resp = protocol.RemoteResponse(
        id=protocol.new_req_id(),
        src="bridge",
        dst="agent-1",
        ok=True,
        exit_code=4,
        stdout="OUT",
        stderr="ERR",
    )
    assert apply_response(resp) == 4
    captured = capsys.readouterr()
    assert captured.out == "OUT"
    assert captured.err == "ERR"


def test_cli_forwards_argv_after_double_dash(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, list[str]] = {}

    def fake(argv: list[str]) -> int:
        seen["argv"] = argv
        return 9

    monkeypatch.setattr("ida_bridge.cli_remote._run_sync", fake)
    assert remote_main(["--", "supervisor", "start-idalib", "--input", "/host/a.i64"]) == 9
    assert seen["argv"] == ["supervisor", "start-idalib", "--input", "/host/a.i64"]


def test_cli_requires_double_dash(capsys: pytest.CaptureFixture[str]) -> None:
    assert remote_main(["list"]) == 1
    assert "requires --" in capsys.readouterr().err


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
