"""Unit tests for bridge-host idalib lifecycle CLI commands."""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from ida_bridge import protocol
from ida_bridge.cli import main as cli_main
from ida_bridge.cli_remote import main as remote_main


class _AgentClientCm:
    def __init__(self, client) -> None:
        self._client = client

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


def _start_response(**updates) -> protocol.StartIdalibResponse:
    fields = {
        "id": protocol.new_req_id(),
        "src": "bridge-1",
        "dst": "agent-1",
        "ok": True,
        "status": "connected",
        "client_id": "idalib-42",
        "pid": 42,
        "idb_path": "/srv/idbs/sample.i64",
        "log": "/srv/logs/idalib-42.log",
    }
    fields.update(updates)
    return protocol.StartIdalibResponse(**fields)


def _stop_response(**updates) -> protocol.StopIdalibResponse:
    fields = {
        "id": protocol.new_req_id(),
        "src": "bridge-1",
        "dst": "agent-1",
        "ok": True,
        "method": "quit",
        "client_id": "idalib-42",
        "pid": 42,
    }
    fields.update(updates)
    return protocol.StopIdalibResponse(**fields)


class TestRemoteStartIdalib:
    def test_forwards_remote_paths_without_local_validation(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = AsyncMock()
        client.start_idalib.return_value = _start_response()

        with patch("ida_bridge.cli_remote.open_agent_client", return_value=_AgentClientCm(client)):
            rc = remote_main(
                [
                    "start-idalib",
                    "--input",
                    "/remote/does/not/exist/sample",
                    "--out-idb",
                    "/remote/does/not/exist/sample.i64",
                    "--python",
                    "/remote/venv/bin/python",
                    "--force",
                    "--arch",
                    "arm64",
                    "--wait-s",
                    "12.5",
                ]
            )

        assert rc == 0
        client.start_idalib.assert_awaited_once_with(
            idb=None,
            input_file="/remote/does/not/exist/sample",
            out_idb="/remote/does/not/exist/sample.i64",
            force=True,
            arch="arm64",
            dyld_module=None,
            python="/remote/venv/bin/python",
            wait_s=12.5,
        )
        captured = capsys.readouterr()
        assert captured.err == ""
        assert "status: connected" in captured.out
        assert "client_id: idalib-42" in captured.out
        assert "pid: 42" in captured.out

    def test_waiting_is_success_and_json_is_cli_result_only(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = AsyncMock()
        client.start_idalib.return_value = _start_response(status="waiting", client_id=None)

        with patch("ida_bridge.cli_remote.open_agent_client", return_value=_AgentClientCm(client)):
            rc = remote_main(["--json", "start-idalib", "--idb", "/srv/idbs/sample.i64"])

        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload == {
            "status": "waiting",
            "client_id": None,
            "pid": 42,
            "idb_path": "/srv/idbs/sample.i64",
            "log": "/srv/logs/idalib-42.log",
        }

    def test_start_failure_is_exit_two(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = AsyncMock()
        client.start_idalib.return_value = _start_response(
            ok=False,
            code=protocol.ERR_START_FAILED,
            message="IDB not found: /bad.i64",
            status=None,
            client_id=None,
            pid=None,
            idb_path=None,
            log=None,
        )

        with patch("ida_bridge.cli_remote.open_agent_client", return_value=_AgentClientCm(client)):
            rc = remote_main(["start-idalib", "--idb", "/bad.i64"])

        assert rc == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "START_FAILED" in captured.err
        assert "IDB not found" in captured.err

    @pytest.mark.parametrize(
        "argv",
        [
            ["start-idalib", "--input", "/a"],
            ["start-idalib", "--idb", "/a.i64", "--out-idb", "/b.i64"],
            ["start-idalib", "--idb", "/a.i64", "--force"],
            ["start-idalib", "--input", "/a", "--out-idb", "/a.i64", "--arch", "x86_64", "--dyld-module", "x"],
        ],
    )
    def test_rejects_invalid_option_combinations_before_connect(self, argv: list[str]) -> None:
        with (
            patch("ida_bridge.cli_remote.open_agent_client") as open_client,
            pytest.raises(SystemExit),
        ):
            remote_main(argv)
        open_client.assert_not_called()


class TestRemoteStopIdalib:
    def test_stop_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = AsyncMock()
        client.stop_idalib.return_value = _stop_response(method="sigterm")

        with patch("ida_bridge.cli_remote.open_agent_client", return_value=_AgentClientCm(client)):
            rc = remote_main(["stop", "idalib-42", "--json"])

        assert rc == 0
        client.stop_idalib.assert_awaited_once_with("idalib-42")
        assert json.loads(capsys.readouterr().out) == {
            "ok": True,
            "method": "sigterm",
            "client_id": "idalib-42",
            "pid": 42,
        }

    def test_stop_failure_is_exit_two(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = AsyncMock()
        client.stop_idalib.return_value = _stop_response(
            ok=False,
            code=protocol.ERR_TARGET_NOT_FOUND,
            message="no such idalib instance",
            method=None,
            client_id=None,
            pid=None,
        )

        with patch("ida_bridge.cli_remote.open_agent_client", return_value=_AgentClientCm(client)):
            rc = remote_main(["stop", "12345"])

        assert rc == 2
        assert "TARGET_NOT_FOUND" in capsys.readouterr().err


def test_top_level_cli_dispatches_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    remote = Mock(return_value=17)
    monkeypatch.setattr("ida_bridge.cli_remote.main", remote)

    assert cli_main(["remote", "stop", "42"]) == 17
    remote.assert_called_once_with(["stop", "42"])
