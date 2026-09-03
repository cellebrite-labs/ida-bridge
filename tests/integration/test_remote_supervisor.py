"""Integration tests for bridge-host idalib lifecycle requests."""

import asyncio
from dataclasses import dataclass
import threading
from unittest.mock import patch

from ida_bridge import protocol
from ida_bridge.supervisor.commands import SpawnedIdalib
from tests.harness import ServeBridge, connect_client, recv_typed, send_msg


@dataclass
class _FakeProcess:
    pid: int
    returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode


async def _wait_until_called(mock, *, timeout_s: float = 1.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_s
    while not mock.called:
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError("mock was not called")
        await asyncio.sleep(0.01)


class TestRemoteStartIdalib:
    async def test_spawns_on_bridge_thread_and_waits_for_matching_client(self, serve_bridge: ServeBridge) -> None:
        spawned = SpawnedIdalib(
            process=_FakeProcess(pid=4242),
            expected_idb_path="/srv/idbs/sample.i64",
            log_path="/srv/logs/idalib-4242.log",
        )
        caller_threads: list[int] = []

        def fake_spawn(**kwargs):
            caller_threads.append(threading.get_ident())
            return spawned

        async with serve_bridge(bridge_client_id="bridge-1") as (_, url):
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            main_thread = threading.get_ident()
            try:
                with patch("ida_bridge.server.spawn_idalib", side_effect=fake_spawn) as spawn:
                    req = protocol.StartIdalibRequest(
                        id=protocol.new_req_id(),
                        src="agent-1",
                        dst="bridge-1",
                        input="/srv/bins/sample",
                        out_idb="/srv/idbs/sample.i64",
                        force=True,
                        arch="arm64",
                        python="/srv/venv/bin/python",
                        wait_s=1,
                    )
                    await send_msg(agent, req)
                    await _wait_until_called(spawn)

                    ida = await connect_client(
                        url,
                        role=protocol.ROLE_IDA,
                        client_id="idalib-4242",
                        meta={"runtime": "idalib", "pid": 4242, "idb_path": "/srv/idbs/sample.i64"},
                    )
                    try:
                        resp = await recv_typed(agent, protocol.StartIdalibResponse)
                    finally:
                        await ida.close()

                assert resp.ok is True
                assert resp.status == "connected"
                assert resp.client_id == "idalib-4242"
                assert resp.pid == 4242
                assert resp.idb_path == "/srv/idbs/sample.i64"
                assert resp.log == "/srv/logs/idalib-4242.log"
                assert caller_threads == [caller_threads[0]]
                assert caller_threads[0] != main_thread
                _, port = url.rsplit(":", 1)
                spawn.assert_called_once_with(
                    idb=None,
                    input_file="/srv/bins/sample",
                    out_idb="/srv/idbs/sample.i64",
                    force=True,
                    arch="arm64",
                    dyld_module=None,
                    python="/srv/venv/bin/python",
                    bridge_host="127.0.0.1",
                    bridge_port=int(port),
                )
            finally:
                await agent.close()


class TestRemoteStopIdalib:
    async def test_connected_idalib_gets_bridge_originated_quit(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge(bridge_client_id="bridge-1") as (_, url):
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            ida = await connect_client(
                url,
                role=protocol.ROLE_IDA,
                client_id="idalib-4242",
                meta={"runtime": "idalib", "pid": 4242, "idb_path": "/srv/idbs/sample.i64"},
            )
            try:
                with patch("ida_bridge.server.proc.wait_for_exit", return_value=True) as wait_for_exit:
                    req = protocol.StopIdalibRequest(
                        id=protocol.new_req_id(),
                        src="agent-1",
                        dst="bridge-1",
                        target="idalib-4242",
                    )
                    await send_msg(agent, req)
                    quit_req = await recv_typed(ida, protocol.QuitRequest)
                    assert quit_req.src == "bridge-1"
                    assert quit_req.dst == "idalib-4242"
                    await send_msg(
                        ida,
                        protocol.QuitResponse(
                            id=quit_req.id,
                            src="idalib-4242",
                            dst="bridge-1",
                            ok=True,
                        ),
                    )
                    resp = await recv_typed(agent, protocol.StopIdalibResponse)

                assert resp.ok is True
                assert resp.method == "quit"
                assert resp.client_id == "idalib-4242"
                assert resp.pid == 4242
                wait_for_exit.assert_called_once_with(4242, timeout_s=20.0)
            finally:
                await ida.close()
                await agent.close()

    async def test_rejects_ui_target_without_closing_agent(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge(bridge_client_id="bridge-1") as (_, url):
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            ui = await connect_client(
                url,
                role=protocol.ROLE_IDA,
                client_id="idaui-4242",
                meta={"runtime": "ui", "pid": 4242, "idb_path": "/srv/idbs/sample.i64"},
            )
            try:
                await send_msg(
                    agent,
                    protocol.StopIdalibRequest(
                        id=protocol.new_req_id(), src="agent-1", dst="bridge-1", target="idaui-4242"
                    ),
                )
                resp = await recv_typed(agent, protocol.StopIdalibResponse)
                assert resp.ok is False
                assert resp.code == protocol.ERR_INVALID_TARGET_ROLE

                await send_msg(
                    agent,
                    protocol.ListRequest(
                        id=protocol.new_req_id(), src="agent-1", dst="bridge-1", kind=protocol.LIST_KIND_IDA
                    ),
                )
                assert (await recv_typed(agent, protocol.ListResponse)).ok is True
            finally:
                await ui.close()
                await agent.close()

    async def test_numeric_target_must_be_connected_or_bridge_managed(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge(bridge_client_id="bridge-1") as (_, url):
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            try:
                with patch("ida_bridge.server.proc.terminate_pid") as terminate:
                    await send_msg(
                        agent,
                        protocol.StopIdalibRequest(
                            id=protocol.new_req_id(), src="agent-1", dst="bridge-1", target="4242"
                        ),
                    )
                    resp = await recv_typed(agent, protocol.StopIdalibResponse)
                assert resp.ok is False
                assert resp.code == protocol.ERR_TARGET_NOT_FOUND
                terminate.assert_not_called()
            finally:
                await agent.close()

    async def test_quit_timeout_escalates_on_bridge_host(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge(
            bridge_client_id="bridge-1",
            lifecycle_quit_timeout_s=0.02,
            lifecycle_exit_timeout_s=0.01,
        ) as (_, url):
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            ida = await connect_client(
                url,
                role=protocol.ROLE_IDA,
                client_id="idalib-4242",
                meta={"runtime": "idalib", "pid": 4242, "idb_path": "/srv/idbs/sample.i64"},
            )
            try:
                with patch("ida_bridge.server.proc.terminate_pid", return_value="sigkill") as terminate:
                    await send_msg(
                        agent,
                        protocol.StopIdalibRequest(
                            id=protocol.new_req_id(), src="agent-1", dst="bridge-1", target="idalib-4242"
                        ),
                    )
                    await recv_typed(ida, protocol.QuitRequest)
                    resp = await recv_typed(agent, protocol.StopIdalibResponse)

                assert resp.ok is True
                assert resp.method == "sigkill"
                terminate.assert_called_once_with(4242)
            finally:
                await ida.close()
                await agent.close()

    async def test_stops_waiting_bridge_managed_child_by_pid(self, serve_bridge: ServeBridge) -> None:
        spawned = SpawnedIdalib(
            process=_FakeProcess(pid=4242),
            expected_idb_path="/srv/idbs/sample.i64",
            log_path="/srv/logs/idalib-4242.log",
        )
        async with serve_bridge(bridge_client_id="bridge-1") as (_, url):
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            try:
                with (
                    patch("ida_bridge.server.spawn_idalib", return_value=spawned),
                    patch("ida_bridge.server.proc.terminate_pid", return_value="sigterm") as terminate,
                ):
                    await send_msg(
                        agent,
                        protocol.StartIdalibRequest(
                            id=protocol.new_req_id(),
                            src="agent-1",
                            dst="bridge-1",
                            idb="/srv/idbs/sample.i64",
                            wait_s=0,
                        ),
                    )
                    assert (await recv_typed(agent, protocol.StartIdalibResponse)).status == "waiting"

                    await send_msg(
                        agent,
                        protocol.StopIdalibRequest(
                            id=protocol.new_req_id(), src="agent-1", dst="bridge-1", target="4242"
                        ),
                    )
                    resp = await recv_typed(agent, protocol.StopIdalibResponse)

                assert resp.ok is True
                assert resp.method == "sigterm"
                assert resp.client_id is None
                assert resp.pid == 4242
                terminate.assert_called_once_with(4242)
            finally:
                await agent.close()


class TestRemoteStartIdalibResults:
    async def test_returns_waiting_and_keeps_live_child_tracked(self, serve_bridge: ServeBridge) -> None:
        spawned = SpawnedIdalib(
            process=_FakeProcess(pid=4242),
            expected_idb_path="/srv/idbs/sample.i64",
            log_path="/srv/logs/idalib-4242.log",
        )
        async with serve_bridge(bridge_client_id="bridge-1") as (server, url):
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            try:
                with patch("ida_bridge.server.spawn_idalib", return_value=spawned):
                    await send_msg(
                        agent,
                        protocol.StartIdalibRequest(
                            id=protocol.new_req_id(),
                            src="agent-1",
                            dst="bridge-1",
                            idb="/srv/idbs/sample.i64",
                            wait_s=0,
                        ),
                    )
                    resp = await recv_typed(agent, protocol.StartIdalibResponse)

                assert resp.ok is True
                assert resp.status == "waiting"
                assert resp.client_id is None
                assert resp.pid == 4242
                assert resp.idb_path == "/srv/idbs/sample.i64"
                assert 4242 in server._managed_idalib
            finally:
                await agent.close()

    async def test_early_child_exit_is_request_error(self, serve_bridge: ServeBridge) -> None:
        spawned = SpawnedIdalib(
            process=_FakeProcess(pid=4242, returncode=7),
            expected_idb_path="/srv/idbs/sample.i64",
            log_path="/srv/logs/idalib-4242.log",
        )
        async with serve_bridge(bridge_client_id="bridge-1") as (_, url):
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            try:
                with patch("ida_bridge.server.spawn_idalib", return_value=spawned):
                    await send_msg(
                        agent,
                        protocol.StartIdalibRequest(
                            id=protocol.new_req_id(),
                            src="agent-1",
                            dst="bridge-1",
                            idb="/srv/idbs/sample.i64",
                            wait_s=1,
                        ),
                    )
                    resp = await recv_typed(agent, protocol.StartIdalibResponse)

                assert resp.ok is False
                assert resp.code == protocol.ERR_START_FAILED
                assert "exited early with code 7" in (resp.message or "")
                assert resp.trace == {"log": "/srv/logs/idalib-4242.log"}
            finally:
                await agent.close()

    async def test_validation_failure_is_request_error(self, serve_bridge: ServeBridge) -> None:
        async with serve_bridge(bridge_client_id="bridge-1") as (_, url):
            agent = await connect_client(url, role=protocol.ROLE_AGENT, client_id="agent-1")
            try:
                with patch("ida_bridge.server.spawn_idalib", side_effect=RuntimeError("IDB not found")):
                    await send_msg(
                        agent,
                        protocol.StartIdalibRequest(
                            id=protocol.new_req_id(),
                            src="agent-1",
                            dst="bridge-1",
                            idb="/srv/idbs/missing.i64",
                            wait_s=0,
                        ),
                    )
                    resp = await recv_typed(agent, protocol.StartIdalibResponse)

                assert resp.ok is False
                assert resp.code == protocol.ERR_START_FAILED
                assert resp.message == "IDB not found"
            finally:
                await agent.close()
