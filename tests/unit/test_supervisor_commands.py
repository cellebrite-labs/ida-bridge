"""Unit tests for supervisor command validation."""

from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from ida_bridge import protocol
from ida_bridge.supervisor import commands
from ida_bridge.supervisor.commands import (
    SpawnedIdalib,
    StartError,
    default_idalib_python,
    matches_spawned_idalib,
    spawn_idalib,
    start_idalib,
)


class TestDefaultIdalibPython:
    def test_uses_venv_layout_for_platform(self) -> None:
        path = default_idalib_python()
        assert path.parent.parent.name == "venv"
        if sys.platform == "win32":
            assert path.parts[-2:] == ("Scripts", "python.exe")
        else:
            assert path.parts[-2:] == ("bin", "python3")


def _thin_macho() -> bytes:
    return bytes.fromhex("cffaedfe") + b"\x00" * 28


class TestStartIdalibDyldValidation:
    def test_rejects_macho_input_with_dyld_module(self, tmp_path: Path) -> None:
        macho = tmp_path / "thin_macho"
        macho.write_bytes(_thin_macho())
        out_idb = tmp_path / "out.i64"
        runner = tmp_path / "idalib_runner.py"
        runner.write_text("# test\n", encoding="utf-8")

        with (
            patch("ida_bridge.supervisor.commands._resolve_python", return_value="/usr/bin/python3"),
            patch("ida_bridge.supervisor.commands._idalib_runner_path", return_value=runner),
        ):
            with pytest.raises(StartError, match="requires a dyld_shared_cache input"):
                start_idalib(
                    input_file=str(macho),
                    out_idb=str(out_idb),
                    dyld_module="/usr/lib/system/libcompiler_rt.dylib",
                )

    def test_rejects_non_cache_non_macho_input_with_dyld_module(self, tmp_path: Path) -> None:
        blob = tmp_path / "blob.bin"
        blob.write_bytes(b"not macho")
        out_idb = tmp_path / "out.i64"
        runner = tmp_path / "idalib_runner.py"
        runner.write_text("# test\n", encoding="utf-8")

        with (
            patch("ida_bridge.supervisor.commands._resolve_python", return_value="/usr/bin/python3"),
            patch("ida_bridge.supervisor.commands._idalib_runner_path", return_value=runner),
        ):
            with pytest.raises(StartError, match=r"requires a dyld_shared_cache input"):
                start_idalib(
                    input_file=str(blob),
                    out_idb=str(out_idb),
                    dyld_module="/usr/lib/system/libcompiler_rt.dylib",
                )


class TestCleanEnv:
    """UI IDA must land on the same venv the headless runner uses."""

    def test_points_ida_at_the_venv(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        venv_python = tmp_path / "python3"
        venv_python.write_text("")
        monkeypatch.setattr(commands, "IDALIB_VENV_PYTHON", venv_python)
        monkeypatch.delenv("IDAPYTHON_VENV_EXECUTABLE", raising=False)

        assert commands._clean_env()["IDAPYTHON_VENV_EXECUTABLE"] == str(venv_python)

    def test_keeps_an_explicit_choice(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        venv_python = tmp_path / "python3"
        venv_python.write_text("")
        monkeypatch.setattr(commands, "IDALIB_VENV_PYTHON", venv_python)
        monkeypatch.setenv("IDAPYTHON_VENV_EXECUTABLE", "/somewhere/else/python3")

        assert commands._clean_env()["IDAPYTHON_VENV_EXECUTABLE"] == "/somewhere/else/python3"

    def test_stays_silent_without_a_venv(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """No venv means IDA keeps whatever interpreter it would have used."""
        monkeypatch.setattr(commands, "IDALIB_VENV_PYTHON", tmp_path / "missing" / "python3")
        monkeypatch.delenv("IDAPYTHON_VENV_EXECUTABLE", raising=False)

        assert "IDAPYTHON_VENV_EXECUTABLE" not in commands._clean_env()


class TestSpawnIdalib:
    def test_uses_bridge_host_paths_and_connection_endpoint(self, tmp_path: Path) -> None:
        idb = tmp_path / "sample.i64"
        idb.write_bytes(b"idb")
        runner = tmp_path / "idalib_runner.py"
        runner.write_text("# test\n", encoding="utf-8")
        tmp_log = tmp_path / "starting.log"
        process = SimpleNamespace(pid=4242)
        popen = MagicMock(return_value=process)

        with (
            patch("ida_bridge.supervisor.commands._resolve_python", return_value="/srv/venv/bin/python"),
            patch("ida_bridge.supervisor.commands._idalib_runner_path", return_value=runner),
            patch("ida_bridge.supervisor.commands._starting_log_path", return_value=tmp_log),
            patch("ida_bridge.supervisor.commands._bind_log_to_pid", return_value=str(tmp_path / "idalib-4242.log")),
            patch("ida_bridge.supervisor.commands.subprocess.Popen", popen),
        ):
            spawned = spawn_idalib(
                idb=str(idb),
                python="/srv/venv/bin/python",
                bridge_host="10.0.0.5",
                bridge_port=9911,
            )

        assert spawned.process is process
        assert spawned.pid == 4242
        assert spawned.expected_idb_path == str(idb.resolve())
        assert spawned.log_path == str(tmp_path / "idalib-4242.log")
        call = popen.call_args
        assert call.args[0] == ["/srv/venv/bin/python", str(runner), "--idb", str(idb.resolve())]
        assert call.kwargs["env"]["IDA_BRIDGE_HOST"] == "10.0.0.5"
        assert call.kwargs["env"]["IDA_BRIDGE_PORT"] == "9911"
        assert call.kwargs["stdout"].closed is True

    def test_rejects_partial_bridge_endpoint(self, tmp_path: Path) -> None:
        idb = tmp_path / "sample.i64"
        idb.write_bytes(b"idb")
        with pytest.raises(ValueError, match="bridge_host and bridge_port"):
            spawn_idalib(idb=str(idb), bridge_host="127.0.0.1")


class TestMatchesSpawnedIdalib:
    def test_matches_idalib_runtime_by_pid(self) -> None:
        spawned = SpawnedIdalib(
            process=SimpleNamespace(pid=4242),
            expected_idb_path="/srv/idbs/sample.i64",
            log_path="/srv/logs/idalib-4242.log",
        )

        assert matches_spawned_idalib(
            protocol.ClientInfo(
                client_id="idalib-4242",
                role=protocol.ROLE_IDA,
                meta={"runtime": "idalib", "pid": 4242, "idb_path": "/srv/idbs/sample.i64"},
            ),
            spawned,
        )
        assert not matches_spawned_idalib(
            protocol.ClientInfo(
                client_id="idaui-4242",
                role=protocol.ROLE_IDA,
                meta={"runtime": "ui", "pid": 4242, "idb_path": "/srv/idbs/sample.i64"},
            ),
            spawned,
        )
