"""Unit tests for cli_exec_idb: orchestration logic with mocked idalib/bridge."""

from unittest.mock import AsyncMock, patch

import pytest

from ida_bridge.agent_client import BridgeDisconnected, RequestTooLarge
from ida_bridge.cli_exec_idb import main
from ida_bridge.protocol import ExecResponse, new_req_id
from ida_bridge.supervisor.commands import IdalibStartResult, StartError


def _ok_response(*, result=None, stdout=None, stderr=None) -> ExecResponse:
    return ExecResponse(
        type="exec_response",
        src="test",
        dst="test",
        id=new_req_id(),
        ok=True,
        result=result,
        stdout=stdout,
        stderr=stderr,
    )


def _err_response(*, code="exec_error", message="boom", traceback=None) -> ExecResponse:
    return ExecResponse(
        type="exec_response",
        src="test",
        dst="test",
        id=new_req_id(),
        ok=False,
        code=code,
        message=message,
        traceback=traceback,
    )


def _start_result(client_id: str = "idalib-123") -> IdalibStartResult:
    return IdalibStartResult(pid=123, client_id=client_id, log_path="/tmp/test.log")


def _start_result_waiting() -> IdalibStartResult:
    return IdalibStartResult(pid=123, client_id=None, log_path="/tmp/test.log")


# Patch targets — all within cli_exec_idb's namespace.
_P = "ida_bridge.cli_exec_idb"


def _patches(*, exec_rv=None, exec_err=None, start_rv=None, start_err=None, save_rv=True):
    """Build a dict of patches for the common mocks."""
    p = {}
    if start_err:
        p["start"] = patch(f"{_P}.start_idalib", side_effect=start_err)
    else:
        p["start"] = patch(f"{_P}.start_idalib", return_value=start_rv or _start_result())
    if exec_err:
        p["exec"] = patch(f"{_P}._exec", new=AsyncMock(side_effect=exec_err))
    else:
        p["exec"] = patch(f"{_P}._exec", new=AsyncMock(return_value=exec_rv or _ok_response()))
    p["save"] = patch(f"{_P}.bridge_save", new=AsyncMock(return_value=save_rv))
    p["quit"] = patch(f"{_P}.bridge_quit", new=AsyncMock(return_value=True))
    p["term"] = patch(f"{_P}.terminate_pid", return_value="already_dead")
    return p


def _run_with(patches: dict, argv: list[str]):
    """Enter all patch contexts and run main."""
    cms = [p for p in patches.values()]
    mocks = {}
    entered = []
    try:
        for key, cm in zip(patches.keys(), cms, strict=True):
            mocks[key] = cm.__enter__()
            entered.append(cm)
        rc = main(argv)
    finally:
        for cm in reversed(entered):
            cm.__exit__(None, None, None)
    return rc, mocks


_IDB_ARGS = ["--idb", "/tmp/test.i64", "-c", "x"]


class TestHappyPath:
    def test_exec_ok_human(self, capsys):
        rc, _ = _run_with(_patches(exec_rv=_ok_response(result=42)), _IDB_ARGS)
        assert rc == 0
        out = capsys.readouterr().out
        assert "exec: ok" in out
        assert "--- result ---" in out
        assert "42" in out

    def test_exec_ok_json(self, capsys):
        rc, _ = _run_with(_patches(exec_rv=_ok_response(result=42)), [*_IDB_ARGS, "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        assert '"ok": true' in out
        assert '"result": 42' in out

    def test_script_stdout_passthrough(self, capsys):
        rc, _ = _run_with(_patches(exec_rv=_ok_response(stdout="hello\n")), _IDB_ARGS)
        assert rc == 0
        out = capsys.readouterr().out
        assert "exec: ok" in out
        assert "--- stdout ---" in out
        assert "hello\n" in out

    def test_combines_file_and_code(self, tmp_path):
        snippet = tmp_path / "snippet.py"
        snippet.write_text("x = 40\n", encoding="utf-8")

        rc, mocks = _run_with(
            _patches(exec_rv=_ok_response(result=42)),
            ["--idb", "/tmp/test.i64", "-f", str(snippet), "-c", "_result_ = x + 2"],
        )

        assert rc == 0
        mocks["exec"].assert_awaited_once()

        _, code = mocks["exec"].await_args.args
        assert "session_id" not in mocks["exec"].await_args.kwargs
        env = {"__builtins__": __builtins__}
        exec(code, env, env)
        assert env["_result_"] == 42

    def test_exec_sql_only(self) -> None:
        rc, mocks = _run_with(
            _patches(exec_rv=_ok_response(result=1)),
            ["--idb", "/tmp/test.i64", "--sql", "SELECT 1 AS v"],
        )

        assert rc == 0
        mocks["start"].assert_called_once()
        mocks["exec"].assert_awaited_once()

        target, code = mocks["exec"].await_args.args
        assert target == "idalib-123"
        assert "session_id" not in mocks["exec"].await_args.kwargs
        assert "_result_ = idb.sql(" in code
        assert "SELECT 1 AS v" in code
        assert '"columns"' not in code


class TestCleanup:
    def test_exec_error_still_stops(self, capsys):
        rc, mocks = _run_with(_patches(exec_rv=_err_response()), _IDB_ARGS)
        assert rc == 1
        out = capsys.readouterr().out
        assert "exec: error" in out
        assert "error code: exec_error" in out
        mocks["term"].assert_called_once_with(123)

    def test_exec_exception_still_stops(self, capsys):
        rc, mocks = _run_with(_patches(exec_err=RuntimeError("kaboom")), _IDB_ARGS)
        assert rc == 2
        mocks["term"].assert_called_once_with(123)
        assert "kaboom" in capsys.readouterr().err


class TestStartFailure:
    def test_start_error_no_cleanup(self):
        p = _patches(start_err=StartError("no python"))
        rc, mocks = _run_with(p, _IDB_ARGS)
        assert rc == 2
        mocks["term"].assert_not_called()

    def test_start_waiting_kills_and_exits(self):
        p = _patches(start_rv=_start_result_waiting())
        rc, mocks = _run_with(p, _IDB_ARGS)
        assert rc == 2
        mocks["term"].assert_called_once_with(123)


class TestSave:
    def test_save_on_success(self):
        rc, mocks = _run_with(_patches(), [*_IDB_ARGS, "--save"])
        assert rc == 0
        mocks["save"].assert_awaited_once()

    def test_no_save_on_exec_error(self):
        rc, mocks = _run_with(_patches(exec_rv=_err_response()), [*_IDB_ARGS, "--save"])
        assert rc == 1
        mocks["save"].assert_not_awaited()

    def test_no_save_without_flag(self):
        rc, mocks = _run_with(_patches(), _IDB_ARGS)
        assert rc == 0
        mocks["save"].assert_not_awaited()


class TestJsonSuppression:
    def test_json_suppresses_lifecycle_stderr(self, capsys):
        rc, _ = _run_with(_patches(exec_rv=_ok_response(result=1)), [*_IDB_ARGS, "--json"])
        assert rc == 0
        err = capsys.readouterr().err
        assert "started:" not in err
        assert "stopped" not in err

    def test_human_shows_lifecycle_stderr(self, capsys):
        rc, _ = _run_with(_patches(exec_rv=_ok_response(result=1)), _IDB_ARGS)
        assert rc == 0
        err = capsys.readouterr().err
        assert "started:" in err
        assert "stopped" in err


class TestConnectionErrors:
    def test_connection_refused(self, capsys):
        rc, _ = _run_with(_patches(exec_err=ConnectionRefusedError()), _IDB_ARGS)
        assert rc == 2
        assert "cannot connect to bridge" in capsys.readouterr().err

    def test_bridge_disconnected(self, capsys):
        rc, _ = _run_with(_patches(exec_err=BridgeDisconnected("gone")), _IDB_ARGS)
        assert rc == 2
        err = capsys.readouterr().err
        assert "bridge disconnected: gone" in err
        assert "server log" in err

    def test_request_too_large(self, capsys):
        rc, _ = _run_with(_patches(exec_err=RequestTooLarge("request is 9 bytes")), _IDB_ARGS)
        assert rc == 2
        err = capsys.readouterr().err
        assert "request is 9 bytes" in err
        assert "shrink --sql/--code/--file" in err
        assert "disconnected" not in err


class TestArgValidation:
    def test_requires_code_or_file(self) -> None:
        with pytest.raises(SystemExit):
            main(["--idb", "/tmp/test.i64"])

    def test_rejects_session_id(self) -> None:
        with pytest.raises(SystemExit):
            main(["--idb", "/tmp/test.i64", "--session-id", "sess-1", "-c", "x"])

    def test_rejects_stateful(self) -> None:
        with pytest.raises(SystemExit):
            main(["--idb", "/tmp/test.i64", "--stateful", "-c", "x"])

    def test_passes_dyld_module_to_start_idalib(self) -> None:
        _, mocks = _run_with(
            _patches(exec_rv=_ok_response(result=1)),
            [
                "--input",
                "/tmp/dyld_shared_cache_arm64e",
                "--out-idb",
                "/tmp/out.i64",
                "--dyld-module",
                "/usr/lib/system/libcompiler_rt.dylib",
                "-c",
                "_result_ = 1",
            ],
        )

        mocks["start"].assert_called_once()
        assert mocks["start"].call_args.kwargs["dyld_module"] == "/usr/lib/system/libcompiler_rt.dylib"

    def test_passes_skip_initial_auto_analysis(self) -> None:
        _, mocks = _run_with(_patches(exec_rv=_ok_response(result=1)), [*_IDB_ARGS, "--skip-initial-auto-analysis"])
        assert mocks["start"].call_args.kwargs["skip_initial_auto_analysis"] is True

    def test_default_does_not_skip_initial_auto_analysis(self) -> None:
        _, mocks = _run_with(_patches(exec_rv=_ok_response(result=1)), _IDB_ARGS)
        assert mocks["start"].call_args.kwargs["skip_initial_auto_analysis"] is False
