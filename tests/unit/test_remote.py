from pydantic import ValidationError
import pytest

from ida_bridge import cli_remote, protocol, remote

_REQ_ID = protocol.new_req_id()


@pytest.mark.parametrize(
    "argv",
    [
        ["remote", "--", "list"],
        ["server"],
        ["server", "status"],
        ["server", "stop"],
        ["server", "log"],
    ],
)
def test_remote_and_server_commands_are_denied(argv: list[str]) -> None:
    assert remote.denied_reason(argv) is not None


@pytest.mark.parametrize("argv", [[], ["list"], ["exec", "ida-1", "-c", "1"], ["supervisor", "stop", "ida-1"]])
def test_other_commands_are_allowed(argv: list[str]) -> None:
    assert remote.denied_reason(argv) is None


@pytest.mark.parametrize("missing", ["exit_code", "stdout", "stderr"])
def test_a_response_that_ran_needs_all_its_output(missing: str) -> None:
    fields = {"exit_code": 0, "stdout": "", "stderr": ""}
    del fields[missing]
    with pytest.raises(ValidationError, match=missing):
        protocol.RemoteResponse(id=_REQ_ID, src="bridge", dst="agent-1", ok=True, **fields)


@pytest.mark.parametrize(("field", "value"), [("exit_code", 0), ("stdout", ""), ("stderr", "")])
def test_an_error_response_carries_no_output(field: str, value: object) -> None:
    with pytest.raises(ValidationError, match=field):
        protocol.RemoteResponse(
            id=_REQ_ID,
            src="bridge",
            dst="agent-1",
            ok=False,
            code=protocol.ERR_REMOTE_FAILED,
            message="x",
            **{field: value},
        )


@pytest.mark.parametrize("argv", [[], ["list"], ["--"]], ids=["nothing", "no-separator", "no-command"])
def test_the_cli_needs_a_separator_and_a_command(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    # Exit 2, not the 1 of an unreachable bridge: nothing tried to connect.
    assert cli_remote.main(argv) == 2
    assert "expected -- followed by an ida-bridge command" in capsys.readouterr().err


@pytest.mark.parametrize(("exit_code", "reported"), [(0, 0), (3, 3), (-9, 137)])
def test_the_cli_writes_the_output_and_reports_the_exit_code_like_a_shell(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], exit_code: int, reported: int
) -> None:
    async def ran(argv: list[str]) -> protocol.RemoteResponse:
        return protocol.RemoteResponse(
            id=_REQ_ID, src="bridge", dst="agent-1", ok=True, exit_code=exit_code, stdout="out\n", stderr="err\n"
        )

    monkeypatch.setattr(cli_remote, "_remote", ran)
    assert cli_remote.main(["--", "list"]) == reported
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("out\n", "err\n")


def test_the_cli_reports_a_refusal_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def refused(argv: list[str]) -> protocol.RemoteResponse:
        return protocol.RemoteResponse(
            id=_REQ_ID, src="bridge", dst="agent-1", ok=False, code=protocol.ERR_REMOTE_DENIED, message="refused"
        )

    monkeypatch.setattr(cli_remote, "_remote", refused)
    assert cli_remote.main(["--", "server", "status"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert protocol.ERR_REMOTE_DENIED in captured.err
    assert "hint: run the command on the bridge host directly." in captured.err
