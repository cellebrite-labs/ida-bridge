"""Tests for ida_bridge CLI layers (cli_agent, cli_server)."""

import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from ida_bridge import protocol
from ida_bridge.agent_client import BridgeDisconnected, BridgeProtocolError, RequestTooLarge
from ida_bridge.cli_agent import (
    _print_available_ida_instances_human,
    _run,
    main as agent_main,
)
from ida_bridge.cli_common import format_client_list_human, print_exec_human, print_reset_human
from ida_bridge.cli_server import (
    _server_cmd,
    main as server_main,
)
from ida_bridge.protocol import ExecResponse, ResetResponse, new_req_id


def _exec_response(**kw) -> ExecResponse:
    defaults = {
        "type": "exec_response",
        "src": "ida-1",
        "dst": "agent-1",
        "id": new_req_id(),
        "ok": True,
    }
    defaults.update(kw)
    return ExecResponse(**defaults)


def _reset_response(**kw) -> ResetResponse:
    defaults = {
        "type": "reset_response",
        "src": "ida-1",
        "dst": "agent-1",
        "id": new_req_id(),
        "ok": True,
    }
    defaults.update(kw)
    return ResetResponse(**defaults)


# ---------------------------------------------------------------------------
# cli_common: format_client_list_human
# ---------------------------------------------------------------------------


class TestFormatClientListHuman:
    def test_empty(self) -> None:
        assert format_client_list_human([]) == "(no clients)\n"

    def test_formats_table(self) -> None:
        out = format_client_list_human(
            [
                protocol.ClientInfo(
                    client_id="ida-1",
                    role=protocol.ROLE_IDA,
                    session_id="sess-1",
                    meta={"pid": 123, "idb_path": "/tmp/test.i64"},
                )
            ]
        )
        assert out == "client_id\trole\tpid\tsession\tidb_path\nida-1\tida\t123\tsess-1\t/tmp/test.i64\n"


# ---------------------------------------------------------------------------
# cli_common: print_exec_human
# ---------------------------------------------------------------------------


class TestPrintExecHuman:
    def test_ok_no_result_no_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_exec_human(_exec_response())
        assert capsys.readouterr().out == "exec: ok\n"

    def test_ok_sections_are_ordered_and_on_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_exec_human(_exec_response(result=42, stdout="debug\n", stderr="warning\n"))
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out.startswith("exec: ok\n\n")
        assert captured.out.index("--- result ---") < captured.out.index("--- stdout ---")
        assert captured.out.index("--- stdout ---") < captured.out.index("--- stderr ---")

    def test_error_metadata_hint_and_traceback(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_exec_human(
            _exec_response(
                ok=False,
                code=protocol.ERR_TARGET_NOT_FOUND,
                message="ida-1",
                traceback="Traceback (most recent call last):\n  ...\n",
            )
        )
        out = capsys.readouterr().out
        assert "exec: error" in out
        assert "error code: TARGET_NOT_FOUND" in out
        assert "error message: ida-1" in out
        assert "hint: run `ida-bridge list`" in out
        assert "--- traceback ---" in out

    def test_error_bridge_trace_precedes_exec_traceback(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_exec_human(
            _exec_response(
                ok=False,
                code="EXEC_ERROR",
                message="boom",
                trace={"detail": "bridge"},
                traceback="tb\n",
            )
        )
        out = capsys.readouterr().out
        assert out.index("--- bridge trace ---") < out.index("--- traceback ---")
        assert '"detail": "bridge"' in out


# ---------------------------------------------------------------------------
# cli_common: print_reset_human
# ---------------------------------------------------------------------------


class TestPrintResetHuman:
    def test_ok(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_reset_human(_reset_response())
        assert capsys.readouterr().out == "reset: ok\n"

    def test_error_with_bridge_trace(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_reset_human(_reset_response(ok=False, code="SESSION_CONFLICT", message="owned", trace={"detail": "x"}))
        out = capsys.readouterr().out
        assert "reset: error" in out
        assert "error code: SESSION_CONFLICT" in out
        assert "error message: owned" in out
        assert "--- bridge trace ---" in out
        assert '"detail": "x"' in out


# ---------------------------------------------------------------------------
# cli_agent: _print_available_ida_instances_human
# ---------------------------------------------------------------------------


class TestPrintAvailableIdaInstancesHuman:
    async def test_prints_list_section(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = AsyncMock()
        client.list.return_value = SimpleNamespace(
            clients=[
                protocol.ClientInfo(
                    client_id="ida-1",
                    role=protocol.ROLE_IDA,
                    meta={"pid": 123, "idb_path": "/tmp/test.i64"},
                ),
            ]
        )
        await _print_available_ida_instances_human(client)
        captured = capsys.readouterr()
        assert captured.err == ""
        assert "--- available ida instances ---" in captured.out
        assert "client_id\trole\tpid\tsession\tidb_path" in captured.out
        assert "ida-1" in captured.out
        assert "123" in captured.out

    async def test_swallows_list_exception(self) -> None:
        client = AsyncMock()
        client.list.side_effect = RuntimeError("boom")
        # Should not raise.
        await _print_available_ida_instances_human(client)


# ---------------------------------------------------------------------------
# cli_agent: _run
# ---------------------------------------------------------------------------


class TestRun:
    def test_returns_coro_result(self) -> None:
        async def ok():
            return 42

        assert _run(ok()) == 42

    def test_connection_refused(self, capsys: pytest.CaptureFixture[str]) -> None:
        async def fail():
            raise ConnectionRefusedError()

        assert _run(fail()) == 1
        assert "cannot connect" in capsys.readouterr().err

    def test_bridge_protocol_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        async def fail():
            raise BridgeProtocolError(protocol.ProtocolError(code="BAD", message="nope"))

        assert _run(fail()) == 1
        assert "BAD" in capsys.readouterr().err

    def test_bridge_disconnected(self, capsys: pytest.CaptureFixture[str]) -> None:
        async def fail():
            raise BridgeDisconnected("gone")

        assert _run(fail()) == 1
        assert "gone" in capsys.readouterr().err

    def test_request_too_large(self, capsys: pytest.CaptureFixture[str]) -> None:
        async def fail():
            raise RequestTooLarge("request is 9 bytes")

        assert _run(fail()) == 1
        err = capsys.readouterr().err
        assert "request is 9 bytes" in err
        assert "shrink --sql/--code/--file" in err


# ---------------------------------------------------------------------------
# cli_agent: main (arg parsing)
# ---------------------------------------------------------------------------


class _AgentClientCm:
    def __init__(self, client) -> None:
        self._client = client

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _FakeAgentClient:
    def __init__(self, resp) -> None:
        self._resp = resp
        self.exec_calls: list[tuple[str, str, str | None, bool, int | None]] = []
        self.reset_calls: list[tuple[str, str, bool, bool, int | None]] = []

    async def exec(
        self,
        target: str,
        code: str,
        *,
        session_id: str | None = None,
        persist: bool = False,
        timeout_s: int | None = None,
    ):
        self.exec_calls.append((target, code, session_id, persist, timeout_s))
        return self._resp

    async def reset(
        self,
        target: str,
        *,
        session_id: str,
        takeover: bool = False,
        release: bool = False,
        timeout_s: int | None = None,
    ):
        self.reset_calls.append((target, session_id, takeover, release, timeout_s))
        return self._resp

    async def list(self, kind: str = "ida"):
        return SimpleNamespace(ok=True, clients=[])


class TestAgentMain:
    def test_exec_requires_code_or_file(self) -> None:
        with pytest.raises(SystemExit):
            agent_main(["exec", "ida-1"])

    def test_exec_rejects_session_id_without_stateful(self) -> None:
        with pytest.raises(SystemExit):
            agent_main(["exec", "ida-1", "--session-id", "sess-1", "-c", "_result_ = 1"])

    def test_exec_rejects_stateful_without_session_id(self) -> None:
        with pytest.raises(SystemExit):
            agent_main(["exec", "ida-1", "--stateful", "-c", "_result_ = 1"])

    def test_reset_requires_session_id(self) -> None:
        with pytest.raises(SystemExit):
            agent_main(["reset", "ida-1"])

    def test_exec_combines_file_and_code(self, tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
        snippet = tmp_path / "snippet.py"
        snippet.write_text("x = 40\n", encoding="utf-8")

        client = _FakeAgentClient(_exec_response(result=42))

        with patch("ida_bridge.cli_agent.open_agent_client", return_value=_AgentClientCm(client)):
            rc = agent_main(["exec", "ida-1", "-f", str(snippet), "-c", "_result_ = x + 2"])

        assert rc == 0
        out = capsys.readouterr().out
        assert "exec: ok" in out
        assert "--- result ---" in out
        assert "42" in out
        assert len(client.exec_calls) == 1

        target, code, session_id, persist, timeout_s = client.exec_calls[0]
        assert target == "ida-1"
        assert session_id is None
        assert persist is False
        assert timeout_s is None

        env = {"__builtins__": __builtins__}
        exec(code, env, env)
        assert env["_result_"] == 42

    def test_exec_stateful_passes_session_and_persist(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = _FakeAgentClient(_exec_response(result=1))

        with patch("ida_bridge.cli_agent.open_agent_client", return_value=_AgentClientCm(client)):
            rc = agent_main(["exec", "ida-1", "--stateful", "--session-id", "sess-1", "-c", "_result_ = 1"])

        assert rc == 0
        assert "exec: ok" in capsys.readouterr().out
        assert client.exec_calls[0][2:] == ("sess-1", True, None)

    def test_reset_passes_takeover(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = _FakeAgentClient(_reset_response())

        with patch("ida_bridge.cli_agent.open_agent_client", return_value=_AgentClientCm(client)):
            rc = agent_main(["reset", "ida-1", "--session-id", "sess-2", "--takeover"])

        assert rc == 0
        assert "reset: ok" in capsys.readouterr().out
        assert client.reset_calls == [("ida-1", "sess-2", True, False, None)]

    def test_reset_error_human(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = _FakeAgentClient(_reset_response(ok=False, code=protocol.ERR_SESSION_CONFLICT, message="owned"))

        with patch("ida_bridge.cli_agent.open_agent_client", return_value=_AgentClientCm(client)):
            rc = agent_main(["reset", "ida-1", "--session-id", "sess-2"])

        assert rc == 1
        out = capsys.readouterr().out
        assert "reset: error" in out
        assert "error code: SESSION_CONFLICT" in out
        assert "error message: owned" in out

    def test_unknown_subcommand(self) -> None:
        with pytest.raises(SystemExit):
            agent_main(["bogus"])


# ---------------------------------------------------------------------------
# cli_server: _server_cmd
# ---------------------------------------------------------------------------


class TestServerCmd:
    def test_returns_list(self) -> None:
        cmd = _server_cmd()
        assert isinstance(cmd, list)
        assert cmd[0] == sys.executable
        assert "ida_bridge.server" in cmd[1:]


# ---------------------------------------------------------------------------
# cli_server: main (arg dispatch)
# ---------------------------------------------------------------------------


class TestServerMain:
    def test_no_subcommand_prints_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = server_main([])
        assert rc == 1

    def test_status_delegates(self) -> None:
        with patch("ida_bridge.cli_server.get_server_pid", return_value=None):
            rc = server_main(["status"])
        assert rc == 1  # not running

    def test_status_running(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("ida_bridge.cli_server.get_server_pid", return_value=1234):
            rc = server_main(["status"])
        assert rc == 0
        assert "1234" in capsys.readouterr().out
