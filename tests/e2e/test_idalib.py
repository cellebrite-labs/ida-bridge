"""E2E tests: idalib runner with a real binary through the bridge.

Non-destructive tests share a single module-scoped idalib instance
(``shared_idalib``) to avoid paying the startup cost per test.

Destructive tests (e.g. shutdown) use the function-scoped ``idalib_instance``
fixture so they get a fresh process they can kill.
"""

import asyncio
import os

import pytest

from ida_bridge import protocol
from ida_bridge.ida_runtime import EXEC_OUTPUT_LIMIT_BYTES, OUTPUT_TRUNCATION_MARKER
from tests.e2e.conftest import IdalibInstance

pytestmark = [pytest.mark.asyncio(loop_scope="module")]

SESSION_ID = "e2e-idalib"


def _read_process_output_until_marker(instance: IdalibInstance) -> bytes:
    assert instance.process.stdout is not None
    marker = OUTPUT_TRUNCATION_MARKER.encode("utf-8")
    output = bytearray()
    while marker not in output:
        chunk = os.read(instance.process.stdout.fileno(), 4096)
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


# ---- non-destructive tests (shared instance) --------------------------------


class TestIdalibConnects:
    async def test_appears_in_list(self, shared_idalib: IdalibInstance) -> None:
        """Runner connects and appears in bridge client list with correct metadata."""
        from ida_bridge import protocol

        async with shared_idalib.agent_client() as agent:
            resp = await agent.list(kind=protocol.LIST_KIND_IDA)
            assert resp.ok
            assert resp.clients

            match = [c for c in resp.clients if c.client_id == shared_idalib.client_id]
            assert len(match) == 1

            meta = match[0].meta or {}
            assert meta["runtime"] == "idalib"
            assert meta["pid"] == shared_idalib.pid
            assert meta["bits"] == 64
            assert meta.get("processor")
            assert meta.get("idb_path")


class TestExecBasic:
    async def test_exec_arithmetic(self, shared_idalib: IdalibInstance) -> None:
        async with shared_idalib.agent_client() as agent:
            resp = await agent.exec(shared_idalib.client_id, "_result_ = 1 + 1", session_id=SESSION_ID, persist=True)
            assert resp.ok
            assert resp.result == 2

    async def test_exec_string(self, shared_idalib: IdalibInstance) -> None:
        async with shared_idalib.agent_client() as agent:
            resp = await agent.exec(shared_idalib.client_id, "_result_ = 'hello'", session_id=SESSION_ID, persist=True)
            assert resp.ok
            assert resp.result == "hello"


class TestExecFunctions:
    async def test_function_count(self, shared_idalib: IdalibInstance) -> None:
        """IDA should find at least the 5 named functions in the test binary."""
        code = "import idautils; _result_ = len(list(idautils.Functions()))"
        async with shared_idalib.agent_client() as agent:
            resp = await agent.exec(shared_idalib.client_id, code, session_id=SESSION_ID, persist=True)
            assert resp.ok
            assert isinstance(resp.result, int)
            assert resp.result >= 5

    async def test_function_names(self, shared_idalib: IdalibInstance) -> None:
        """IDA should recover our known function names."""
        code = """\
import idautils, idc
_result_ = [idc.get_func_name(ea) for ea in idautils.Functions()]
"""
        async with shared_idalib.agent_client() as agent:
            resp = await agent.exec(shared_idalib.client_id, code, session_id=SESSION_ID, persist=True)
            assert resp.ok
            names = resp.result
            assert isinstance(names, list)
            for expected in ("_add", "_multiply", "_get_greeting", "_compute", "_main"):
                assert expected in names, f"{expected} not found in {names}"


class TestExecStrings:
    async def test_find_greeting(self, shared_idalib: IdalibInstance) -> None:
        code = """\
import idautils
_result_ = [str(s) for s in idautils.Strings() if "hello" in str(s)]
"""
        async with shared_idalib.agent_client() as agent:
            resp = await agent.exec(shared_idalib.client_id, code, session_id=SESSION_ID, persist=True)
            assert resp.ok
            assert isinstance(resp.result, list)
            assert any("hello from ida-bridge test binary" in s for s in resp.result)


class TestExecEntryPoint:
    async def test_entry_point_nonzero(self, shared_idalib: IdalibInstance) -> None:
        code = "import idc; _result_ = idc.get_inf_attr(idc.INF_START_IP)"
        async with shared_idalib.agent_client() as agent:
            resp = await agent.exec(shared_idalib.client_id, code, session_id=SESSION_ID, persist=True)
            assert resp.ok
            assert isinstance(resp.result, int)
            assert resp.result > 0


class TestExecStdout:
    async def test_stdout_capture(self, shared_idalib: IdalibInstance) -> None:
        async with shared_idalib.agent_client() as agent:
            resp = await agent.exec(
                shared_idalib.client_id, "print('bridge_test_output')", session_id=SESSION_ID, persist=True
            )
            assert resp.ok
            assert resp.stdout and "bridge_test_output" in resp.stdout

    async def test_large_stdout_bounds_capture_and_mirror(self, shared_idalib: IdalibInstance) -> None:
        prefix = "ida_bridge_output_limit_start:"
        drain_task = asyncio.create_task(
            asyncio.to_thread(_read_process_output_until_marker, shared_idalib)
        )
        async with shared_idalib.agent_client() as agent:
            resp = await agent.exec(
                shared_idalib.client_id,
                f"print({prefix!r} + 'x' * {EXEC_OUTPUT_LIMIT_BYTES * 2}, end='')",
                session_id=SESSION_ID,
                persist=True,
            )

        mirrored = await asyncio.wait_for(drain_task, timeout=30)
        marker = OUTPUT_TRUNCATION_MARKER.encode("utf-8")
        mirrored_start = mirrored.index(prefix.encode("utf-8"))
        mirrored_end = mirrored.index(marker, mirrored_start) + len(marker)
        mirrored_request = mirrored[mirrored_start:mirrored_end]

        assert resp.ok
        assert resp.stdout is not None
        assert resp.stdout.endswith(OUTPUT_TRUNCATION_MARKER)
        assert len(resp.stdout.encode("utf-8")) <= EXEC_OUTPUT_LIMIT_BYTES
        assert mirrored_request.endswith(marker)
        assert len(mirrored_request) <= EXEC_OUTPUT_LIMIT_BYTES


class TestExecError:
    async def test_exec_error(self, shared_idalib: IdalibInstance) -> None:
        async with shared_idalib.agent_client() as agent:
            resp = await agent.exec(
                shared_idalib.client_id, "raise ValueError('boom')", session_id=SESSION_ID, persist=True
            )
            assert not resp.ok
            assert resp.code == "EXEC_ERROR"
            assert resp.traceback and "ValueError" in resp.traceback
            assert resp.traceback and "boom" in resp.traceback


class TestReset:
    async def test_reset_clears_env(self, shared_idalib: IdalibInstance) -> None:
        async with shared_idalib.agent_client() as agent:
            resp = await agent.exec(shared_idalib.client_id, "x = 42", session_id=SESSION_ID, persist=True)
            assert resp.ok

            resp = await agent.exec(shared_idalib.client_id, "_result_ = x", session_id=SESSION_ID, persist=True)
            assert resp.ok
            assert resp.result == 42

            reset_resp = await agent.reset(shared_idalib.client_id, session_id=SESSION_ID)
            assert reset_resp.ok

            resp = await agent.exec(shared_idalib.client_id, "_result_ = x", session_id=SESSION_ID, persist=True)
            assert not resp.ok
            assert resp.code == "EXEC_ERROR"
            assert resp.traceback and "NameError" in resp.traceback


# ---- fresh instance smoke tests ---------------------------------------------


class TestMultiAgentState:
    @pytest.mark.asyncio(loop_scope="function")
    async def test_stateless_default_and_stateful_owner_with_two_agents(self, idalib_instance: IdalibInstance) -> None:
        target = idalib_instance.client_id
        session_id = "e2e-multi-agent"

        async with (
            idalib_instance.agent_client(client_id="e2e-stateless-a") as agent_a,
            idalib_instance.agent_client(client_id="e2e-stateless-b") as agent_b,
        ):
            resp = await agent_a.exec(target, "shared_value = 123\n_result_ = shared_value")
            assert resp.ok
            assert resp.result == 123

            resp = await agent_b.exec(target, "_result_ = globals().get('shared_value', 'missing')")
            assert resp.ok
            assert resp.result == "missing"

            list_resp = await agent_a.list()
            assert list_resp.ok
            assert list_resp.clients
            target_info = next(c for c in list_resp.clients if c.client_id == target)
            assert target_info.session_id is None

            resp = await agent_a.exec(
                target,
                "shared_value = 456\n_result_ = shared_value",
                session_id=session_id,
                persist=True,
            )
            assert resp.ok
            assert resp.result == 456

            resp = await agent_b.exec(target, "_result_ = 1")
            assert not resp.ok
            assert resp.code == protocol.ERR_SESSION_CONFLICT

            reset_resp = await agent_a.reset(target, session_id=session_id, release=True)
            assert reset_resp.ok

            resp = await agent_b.exec(target, "_result_ = globals().get('shared_value', 'missing')")
            assert resp.ok
            assert resp.result == "missing"

            list_resp = await agent_b.list()
            assert list_resp.ok
            assert list_resp.clients
            target_info = next(c for c in list_resp.clients if c.client_id == target)
            assert target_info.session_id is None


# ---- destructive tests (own instance) ---------------------------------------


class TestShutdown:
    @pytest.mark.asyncio(loop_scope="function")
    async def test_shutdown_via_idb_quit(self, idalib_instance: IdalibInstance) -> None:
        """idb.quit() should cause the runner to exit cleanly."""
        async with idalib_instance.agent_client() as agent:
            resp = await agent.exec(
                idalib_instance.client_id,
                "_result_ = idb.quit()",
                session_id=SESSION_ID,
                persist=True,
            )
            assert resp.ok
            result = resp.result
            assert isinstance(result, dict)
            assert result.get("ok") is True

        import time

        proc = idalib_instance.process
        t0 = time.monotonic()
        try:
            proc.wait(timeout=15)
        except Exception:
            pytest.fail(f"idalib runner (pid={idalib_instance.pid}) did not exit after shutdown")
        elapsed = time.monotonic() - t0

        assert proc.returncode == 0
        assert elapsed < 3.0, (
            f"shutdown took {elapsed:.1f}s; expected < 3 s. Likely regression in websocket teardown (see _abort_ws)."
        )
