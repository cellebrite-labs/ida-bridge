from argparse import Namespace
from pathlib import Path
from unittest.mock import Mock, patch

from ida_bridge import cli_server


def test_parse_netstat_listening_pid_matches_exact_port(monkeypatch) -> None:
    monkeypatch.setattr(cli_server, "PORT", 8765)
    stdout = """
      TCP    127.0.0.1:87650       0.0.0.0:0       LISTENING       111
      TCP    127.0.0.1:8765        0.0.0.0:0       LISTENING       222
      TCP    [::]:8765             [::]:0          LISTENING       333
    """

    assert cli_server._parse_netstat_listening_pid(stdout) == 222


def test_cmd_start_reports_socket_owner_pid(tmp_path: Path, capsys, monkeypatch) -> None:
    log_file = tmp_path / "server.log"
    out_file = tmp_path / "server.out"
    process = Mock(pid=1234)

    monkeypatch.setattr(cli_server, "LOG_FILE", log_file)
    monkeypatch.setattr(cli_server, "OUT_FILE", out_file)
    with (
        patch.object(cli_server, "get_server_pid", side_effect=[None, 5678]),
        patch.object(cli_server.subprocess, "Popen", return_value=process),
        patch.object(cli_server.time, "sleep"),
    ):
        assert cli_server.cmd_start(Namespace()) == 0

    output = capsys.readouterr().out
    assert "Server started (PID: 5678)" in output
    assert "PID: 1234" not in output
