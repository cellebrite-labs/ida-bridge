"""Unit tests for supervisor command validation."""

from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from ida_bridge import protocol
from ida_bridge.supervisor import commands
from ida_bridge.supervisor.commands import StartError, _same_path, start_idalib


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


def test_same_path_normalizes_absolute_components(tmp_path: Path) -> None:
    path = tmp_path / "subdir" / ".." / "sample.i64"
    expected = tmp_path / "sample.i64"

    assert _same_path(str(path), str(expected))


def test_start_idalib_windows_matches_worker_by_idb_path(tmp_path: Path, monkeypatch) -> None:
    input_file = tmp_path / "sample.exe"
    input_file.write_bytes(b"plain test executable")
    out_idb = tmp_path / "sample.i64"
    runner = tmp_path / "idalib_runner.py"
    runner.write_text("# test\n", encoding="utf-8")
    starting_log = tmp_path / "idalib-starting.log"

    launcher = Mock(pid=1111)
    launcher.poll.return_value = None
    connected = protocol.ClientInfo(
        client_id="idalib-2222",
        role=protocol.ROLE_IDA,
        meta={"runtime": "idalib", "pid": 2222, "idb_path": str(out_idb.resolve())},
    )

    async def poll_for_worker(existing, match, **kwargs):
        assert existing == set()
        assert match(connected)
        return connected

    monkeypatch.setattr(commands, "_IS_WIN", True)
    monkeypatch.setattr(commands.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    with (
        patch.object(commands, "_resolve_python", return_value="python.exe"),
        patch.object(commands, "_idalib_runner_path", return_value=runner),
        patch.object(commands, "_starting_log_path", return_value=starting_log),
        patch.object(commands, "_bind_log_to_pid", side_effect=lambda path, prefix, pid: str(path)) as bind_log,
        patch.object(commands.bridge, "snapshot_existing", AsyncMock(return_value=set())),
        patch.object(commands.bridge, "poll_for_new_client", side_effect=poll_for_worker),
        patch.object(commands.subprocess, "Popen", return_value=launcher),
    ):
        result = start_idalib(input_file=str(input_file), out_idb=str(out_idb), wait_s=1)

    assert result.client_id == "idalib-2222"
    assert result.pid == 2222
    assert result.idb_path == str(out_idb.resolve())
    assert bind_log.call_args_list[-1].args[2] == 2222
