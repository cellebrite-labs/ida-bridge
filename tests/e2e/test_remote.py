"""ida-bridge remote driving real idalib instances on the bridge host."""

import asyncio
import json
from pathlib import Path

import pytest

from ida_bridge import proc
from ida_bridge.agent_client import AgentClient, open_agent_client
from tests.e2e.helpers import BridgeInfo


@pytest.fixture
def remote_bridge(live_bridge: BridgeInfo, monkeypatch: pytest.MonkeyPatch) -> BridgeInfo:
    # The remote child inherits the server's environment, and the server runs in this process.
    monkeypatch.setenv("IDA_BRIDGE_CONNECT_HOST", live_bridge.host)
    monkeypatch.setenv("IDA_BRIDGE_PORT", str(live_bridge.port))
    return live_bridge


async def _remote_json(client: AgentClient, argv: list[str]) -> dict:
    resp = await client.remote([*argv, "--json"])
    assert resp.ok, resp
    assert resp.exit_code == 0, resp.stderr
    return json.loads(resp.stdout)


async def test_remote_starts_uses_saves_and_stops_an_instance(
    remote_bridge: BridgeInfo, small_macho_arm64: Path, tmp_path: Path
) -> None:
    out_idb = tmp_path / "remote.i64"
    async with open_agent_client(url=remote_bridge.url) as client:
        argv = ["supervisor", "start-idalib", "--input", str(small_macho_arm64), "--out-idb", str(out_idb)]
        started = await _remote_json(client, argv)
        pid = started["pid"]
        try:
            target = started["client_id"]
            queried = await client.exec(target, "_result_ = idb.sql('SELECT COUNT(*) AS count FROM funcs')")
            assert queried.ok, queried
            count = queried.result["rows"][0]["count"]
            assert count > 0

            # A host path with a space: the file is read on the bridge host.
            script = tmp_path / "host script.py"
            script.write_text("_result_ = idb.sql('SELECT COUNT(*) AS count FROM funcs')", encoding="utf-8")
            from_file = await _remote_json(client, ["exec", target, "-f", str(script)])
            assert from_file["result"]["rows"][0]["count"] == count

            saved = await _remote_json(client, ["supervisor", "save", target])
            assert isinstance(saved["saved"], bool)
            stopped = await _remote_json(client, ["supervisor", "stop", target])
            assert stopped["ok"]
            assert not proc.is_pid_alive(pid)

            reopened = await _remote_json(
                client, ["exec-idb", "--idb", str(out_idb), "--sql", "SELECT COUNT(*) AS count FROM funcs"]
            )
            assert reopened["result"]["rows"][0]["count"] == count
            assert (await client.list()).clients == []
        finally:
            if proc.is_pid_alive(pid):
                await asyncio.to_thread(proc.terminate_pid, pid)


@pytest.mark.parametrize(("code", "exit_code"), [("_result_ = 42", 0), ("raise ValueError('intentional failure')", 1)])
async def test_remote_one_shot_reports_the_script_outcome_and_cleans_up(
    remote_bridge: BridgeInfo, small_macho_arm64: Path, tmp_path: Path, code: str, exit_code: int
) -> None:
    out_idb = tmp_path / "one-shot.i64"
    async with open_agent_client(url=remote_bridge.url) as client:
        try:
            argv = ["exec-idb", "--input", str(small_macho_arm64), "--out-idb", str(out_idb), "-c", code, "--json"]
            resp = await client.remote(argv)
            assert resp.ok, resp
            assert resp.exit_code == exit_code, resp.stderr
            result = json.loads(resp.stdout)
            if exit_code == 0:
                assert result["result"] == 42
            else:
                assert "intentional failure" in result["traceback"]
            assert (await client.list()).clients == []
        finally:
            for instance in (await client.list()).clients:
                await asyncio.to_thread(proc.terminate_pid, instance.meta["pid"])
