"""ida-bridge remote against an in-process bridge, with real host CLI child processes."""

import asyncio
import logging
import signal
import subprocess
import sys

import pytest

from ida_bridge import protocol
from ida_bridge.agent_client import open_agent_client
from tests.harness import ServeBridge, connected_client, recv_typed, send_msg

_CLI = [sys.executable, "-m", "ida_bridge.cli"]


@pytest.fixture
def point_at(monkeypatch: pytest.MonkeyPatch):
    """Point this process's environment at a bridge, as `server start` does for the server.

    The remote child inherits the server's environment, and here the server is this process.
    """

    def point(url: str) -> None:
        monkeypatch.setenv("IDA_BRIDGE_CONNECT_HOST", "127.0.0.1")
        monkeypatch.setenv("IDA_BRIDGE_PORT", url.rsplit(":", 1)[1])

    return point


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([*_CLI, *args], capture_output=True, encoding="utf-8", timeout=60)


async def _forwarded_exec(ida) -> protocol.ExecRequest:
    return await recv_typed(ida, protocol.ExecRequest, timeout_s=30)


async def _answer(ida, forwarded: protocol.ExecRequest, **fields) -> None:
    await send_msg(ida, protocol.ExecResponse(id=forwarded.id, src=forwarded.dst, dst=forwarded.src, ok=True, **fields))


async def test_remote_list_matches_a_direct_list(serve_bridge: ServeBridge, point_at) -> None:
    async with serve_bridge() as (_, url):
        point_at(url)
        meta = {"idb_path": "/tmp/calc.i64", "pid": 4242}
        async with connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1", meta=meta):
            remote = await asyncio.to_thread(_cli, "remote", "--", "list")
            direct = await asyncio.to_thread(_cli, "list")

    assert (remote.returncode, remote.stderr) == (0, "")
    assert remote.stdout == direct.stdout
    assert "ida-1" in remote.stdout


async def test_the_childs_streams_and_exit_code_come_through(serve_bridge: ServeBridge, point_at) -> None:
    async with serve_bridge() as (_, url):
        point_at(url)
        result = await asyncio.to_thread(_cli, "remote", "--", "nosuchcmd")
        merged = await asyncio.to_thread(
            subprocess.run,
            [*_CLI, "remote", "--", "nosuchcmd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            timeout=60,
        )

    assert result.returncode == 1
    assert "usage: ida-bridge" in result.stdout
    assert "unknown command: nosuchcmd" in result.stderr
    # The child's stdout comes first, as it would locally.
    assert merged.stdout.index("usage: ida-bridge") < merged.stdout.index("unknown command: nosuchcmd")


async def test_non_ascii_output_arrives_unchanged(serve_bridge: ServeBridge, point_at) -> None:
    async with serve_bridge() as (_, url):
        point_at(url)
        async with connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida:
            command = asyncio.create_task(asyncio.to_thread(_cli, "remote", "--", "exec", "ida-1", "-c", "print(1)"))
            await _answer(ida, await _forwarded_exec(ida), stdout="\u00e9\u4e2d\n")
            result = await command

    assert result.returncode == 0, result.stderr
    assert "\u00e9\u4e2d" in result.stdout


async def test_a_denied_command_leaves_the_connection_usable(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with open_agent_client(url=url) as client:
            denied = await client.remote(["server", "status"])
            listed = await client.list()

    assert (denied.ok, denied.code) == (False, protocol.ERR_REMOTE_DENIED)
    assert listed.ok


async def test_a_command_that_cannot_start_is_reported(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (_, url):
        async with open_agent_client(url=url) as client:
            # The OS cannot pass a NUL in an argument, so the child never starts.
            resp = await client.remote(["list", "a\x00b"])

    assert (resp.ok, resp.code) == (False, protocol.ERR_REMOTE_FAILED)
    assert "ValueError" in resp.message


async def test_a_requester_that_leaves_does_not_stop_the_command(
    serve_bridge: ServeBridge, point_at, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="ida-bridge")
    async with serve_bridge() as (_, url):
        point_at(url)
        async with connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida:
            async with open_agent_client(url=url) as client:
                waiting = asyncio.create_task(client.remote(["exec", "ida-1", "-c", "print(1)"]))
                forwarded = await _forwarded_exec(ida)
                waiting.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiting

            # The child is still waiting for IDA; answering lets it finish after the requester left.
            await _answer(ida, forwarded, result=1)
            for _ in range(300):
                if any("result dropped" in r.getMessage() for r in caplog.records):
                    break
                await asyncio.sleep(0.1)
            else:
                pytest.fail("the bridge never finished the command of a requester that left")

            async with open_agent_client(url=url) as client:
                assert (await client.list()).ok


async def test_the_caller_warns_when_the_bridge_drops_it_mid_command(serve_bridge: ServeBridge, point_at) -> None:
    async with serve_bridge() as (server, url):
        point_at(url)
        async with connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida:
            caller = await asyncio.create_subprocess_exec(
                *_CLI, "remote", "--", "exec", "ida-1", "-c", "print(1)", stderr=asyncio.subprocess.PIPE
            )
            forwarded = await _forwarded_exec(ida)
            [remote_caller] = [c for c in server._clients.values() if c.meta.get("tool") == "remote"]
            await remote_caller.ws.close()
            _, stderr = await asyncio.wait_for(caller.communicate(), timeout=30)
            await _answer(ida, forwarded, result=1)

    assert caller.returncode == 1
    assert "may still be running" in stderr.decode("utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="no portable way to send Ctrl-C to a child on Windows")
async def test_ctrl_c_while_waiting_warns_that_the_command_may_still_run(serve_bridge: ServeBridge, point_at) -> None:
    async with serve_bridge() as (_, url):
        point_at(url)
        async with connected_client(url, role=protocol.ROLE_IDA, client_id="ida-1") as ida:
            caller = await asyncio.create_subprocess_exec(
                *_CLI, "remote", "--", "exec", "ida-1", "-c", "print(1)", stderr=asyncio.subprocess.PIPE
            )
            forwarded = await _forwarded_exec(ida)
            caller.send_signal(signal.SIGINT)
            _, stderr = await asyncio.wait_for(caller.communicate(), timeout=30)
            await _answer(ida, forwarded, result=1)

    assert caller.returncode == 130
    assert "may still be running" in stderr.decode("utf-8")
