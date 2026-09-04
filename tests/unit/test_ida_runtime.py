"""Tests for ida_bridge.ida_runtime (serialize_result, Tee, run_user_code)."""

import io
import queue

import pytest

from ida_bridge.ida_runtime import (
    OUTPUT_TRUNCATION_MARKER,
    QUEUE_SENTINEL,
    BoundedTextWriter,
    RequestHandler,
    Tee,
    build_exec_error,
    build_exec_response,
    make_exec_env,
    run_user_code,
    serialize_result,
    shutdown_queue,
)
from ida_bridge.protocol import ExecRequest, ExecResponse, QuitRequest, QuitResponse, ResetRequest, new_req_id

# ---------------------------------------------------------------------------
# serialize_result
# ---------------------------------------------------------------------------


class TestSerializePrimitives:
    @pytest.mark.parametrize("val", [None, True, False, 0, 1, -1, 3.14, "", "hello"])
    def test_primitives_pass_through(self, val: object) -> None:
        assert serialize_result(val) is val

    def test_bool_is_not_coerced_to_int(self) -> None:
        # bool is a subclass of int; ensure we don't accidentally match int first.
        assert serialize_result(True) is True
        assert serialize_result(False) is False


class TestSerializeBytes:
    def test_short_bytes(self) -> None:
        b = b"\xde\xad"
        result = serialize_result(b)
        assert result == {"_bytes_hex": "dead", "_len": 2}

    def test_exactly_1024_bytes_not_truncated(self) -> None:
        b = b"\x00" * 1024
        result = serialize_result(b)
        assert "_truncated" not in result
        assert result["_len"] == 1024
        assert len(result["_bytes_hex"]) == 2048  # 1024 bytes * 2 hex chars

    def test_long_bytes_truncated(self) -> None:
        b = b"\xff" * 2000
        result = serialize_result(b)
        assert result["_truncated"] is True
        assert result["_len"] == 2000
        assert len(result["_bytes_hex"]) == 2048  # 1024 * 2


class TestSerializeContainers:
    def test_list(self) -> None:
        assert serialize_result([1, "a", None]) == [1, "a", None]

    def test_tuple_becomes_list(self) -> None:
        assert serialize_result((1, 2)) == [1, 2]

    def test_set_becomes_list(self) -> None:
        result = serialize_result({42})
        assert result == [42]

    def test_dict_keys_become_strings(self) -> None:
        assert serialize_result({1: "a", 2: "b"}) == {"1": "a", "2": "b"}

    def test_nested(self) -> None:
        obj = {"items": [1, {"nested": True}]}
        result = serialize_result(obj)
        assert result == {"items": [1, {"nested": True}]}


class TestSerializeDepthLimit:
    def test_depth_limit_returns_truncation_marker(self) -> None:
        # Build a nested list deeper than max_depth.
        # serialize_result uses `depth > max_depth`, so with max_depth=4
        # it recurses at depths 0..4 and truncates at depth 5.
        obj: object = "leaf"
        for _ in range(6):
            obj = [obj]

        result = serialize_result(obj, max_depth=4)
        # Walk down 5 levels (depths 0..4 all recurse normally).
        cur = result
        for _ in range(5):
            assert isinstance(cur, list)
            cur = cur[0]
        # At depth 5 (> max_depth), we get a truncation marker dict.
        assert isinstance(cur, dict)
        assert cur["_truncated_at_depth"] == 5
        assert cur["_type"] == "list"
        assert "_repr" in cur

    def test_custom_max_depth(self) -> None:
        result = serialize_result([[[1]]], max_depth=1)
        # depth 0 -> list, depth 1 -> list, depth 2 (> 1) -> truncation marker
        marker = result[0][0]
        assert isinstance(marker, dict)
        assert marker["_truncated_at_depth"] == 2


class TestSerializeObjects:
    def test_object_with_dict(self) -> None:
        class Foo:
            def __init__(self) -> None:
                self.x = 1
                self._private = 2

        result = serialize_result(Foo())
        assert result["_type"] == "Foo"
        assert result["x"] == 1
        assert "_private" not in result

    def test_unknown_type_fallback(self) -> None:
        # An object without __dict__ that isn't a known type.
        result = serialize_result(range(3))
        assert result["_type"] == "range"
        assert "_repr" in result


class TestSerializeQueryResult:
    def test_address_columns_hex_formatted(self) -> None:
        from ida_bridge.sql.models import QueryResult

        qr = QueryResult(
            columns=["address", "name", "size"],
            rows=[{"address": 0x77150, "name": "start", "size": 44}],
            hex_columns=frozenset({"address", "size"}),
        )
        result = serialize_result(qr)
        assert result["rows"][0]["address"] == "0x77150"
        assert result["rows"][0]["name"] == "start"
        assert result["rows"][0]["size"] == "0x2c"

    def test_ea_suffix_hex_formatted(self) -> None:
        from ida_bridge.sql.models import QueryResult

        qr = QueryResult(
            columns=["from_ea", "to_ea", "func_ea", "type"],
            rows=[{"from_ea": 0x1000, "to_ea": 0x2000, "func_ea": 0x3000, "type": 16}],
            hex_columns=frozenset({"from_ea", "to_ea", "func_ea"}),
        )
        result = serialize_result(qr)
        row = result["rows"][0]
        assert row["from_ea"] == "0x1000"
        assert row["to_ea"] == "0x2000"
        assert row["func_ea"] == "0x3000"
        assert row["type"] == 16

    def test_addr_suffix_hex_formatted(self) -> None:
        from ida_bridge.sql.models import QueryResult

        qr = QueryResult(
            columns=["func_addr", "caller_addr", "arg_count"],
            rows=[{"func_addr": 0xABCD, "caller_addr": 0x1234, "arg_count": 10}],
            hex_columns=frozenset({"func_addr", "caller_addr"}),
        )
        result = serialize_result(qr)
        row = result["rows"][0]
        assert row["func_addr"] == "0xabcd"
        assert row["caller_addr"] == "0x1234"
        assert row["arg_count"] == 10

    def test_no_hex_columns_unchanged(self) -> None:
        from ida_bridge.sql.models import QueryResult

        qr = QueryResult(
            columns=["name", "arg_count", "type_source"],
            rows=[{"name": "f", "arg_count": 3, "type_source": "hexrays"}],
        )
        result = serialize_result(qr)
        row = result["rows"][0]
        assert row["arg_count"] == 3
        assert row["type_source"] == "hexrays"

    def test_null_address_stays_null(self) -> None:
        from ida_bridge.sql.models import QueryResult

        qr = QueryResult(
            columns=["address", "name"],
            rows=[{"address": None, "name": "f"}],
            hex_columns=frozenset({"address"}),
        )
        result = serialize_result(qr)
        assert result["rows"][0]["address"] is None


# ---------------------------------------------------------------------------
# BoundedTextWriter
# ---------------------------------------------------------------------------


class TestBoundedTextWriter:
    def test_accepts_payload_up_to_reserved_marker_boundary(self) -> None:
        target = io.StringIO()
        limit = len(OUTPUT_TRUNCATION_MARKER.encode("utf-8")) + 4
        writer = BoundedTextWriter(target, max_bytes=limit)

        assert writer.write("abcd") == 4
        assert target.getvalue() == "abcd"
        assert writer.truncated is False

    def test_overflow_appends_one_marker_within_limit(self) -> None:
        target = io.StringIO()
        limit = len(OUTPUT_TRUNCATION_MARKER.encode("utf-8")) + 4
        writer = BoundedTextWriter(target, max_bytes=limit)

        assert writer.write("abcdef") == 6
        value = target.getvalue()
        assert value == f"abcd{OUTPUT_TRUNCATION_MARKER}"
        assert len(value.encode("utf-8")) == limit
        assert writer.truncated is True

    def test_later_writes_do_not_grow_target(self) -> None:
        target = io.StringIO()
        limit = len(OUTPUT_TRUNCATION_MARKER.encode("utf-8")) + 1
        writer = BoundedTextWriter(target, max_bytes=limit)
        writer.write("too much")
        before = target.getvalue()

        assert writer.write("still too much") == len("still too much")
        assert target.getvalue() == before
        assert before.count(OUTPUT_TRUNCATION_MARKER) == 1

    def test_utf8_prefix_is_valid_and_within_byte_limit(self) -> None:
        target = io.StringIO()
        limit = len(OUTPUT_TRUNCATION_MARKER.encode("utf-8")) + 5
        writer = BoundedTextWriter(target, max_bytes=limit)

        assert writer.write("ééé") == 3
        value = target.getvalue()
        assert value == f"éé{OUTPUT_TRUNCATION_MARKER}"
        assert len(value.encode("utf-8")) <= limit

    def test_flush_delegates_to_target(self) -> None:
        flushed = False

        class FakeStream:
            def write(self, s: str) -> int:
                return len(s)

            def flush(self) -> None:
                nonlocal flushed
                flushed = True

        writer = BoundedTextWriter(
            FakeStream(),
            max_bytes=len(OUTPUT_TRUNCATION_MARKER.encode("utf-8")) + 1,
        )
        writer.flush()
        assert flushed is True


# ---------------------------------------------------------------------------
# Tee
# ---------------------------------------------------------------------------


class TestTee:
    def test_writes_to_all_streams(self) -> None:
        a, b = io.StringIO(), io.StringIO()
        tee = Tee(a, b)
        tee.write("hello")
        assert a.getvalue() == "hello"
        assert b.getvalue() == "hello"

    def test_flush_flushes_all(self) -> None:
        flushed: list[str] = []

        class FakeStream:
            def write(self, s: str) -> int:
                return len(s)

            def flush(self) -> None:
                flushed.append("yes")

        tee = Tee(FakeStream(), FakeStream())
        tee.flush()
        assert len(flushed) == 2

    def test_tolerates_broken_stream(self) -> None:
        good = io.StringIO()

        class BrokenStream:
            def write(self, s: str) -> int:
                raise OSError("broken")

            def flush(self) -> None:
                raise OSError("broken")

        tee = Tee(BrokenStream(), good)
        tee.write("ok")
        tee.flush()
        assert good.getvalue() == "ok"

    def test_returns_max_write_count(self) -> None:
        a, b = io.StringIO(), io.StringIO()
        tee = Tee(a, b)
        n = tee.write("abc")
        assert n == 3


# ---------------------------------------------------------------------------
# run_user_code
# ---------------------------------------------------------------------------


class TestRunUserCode:
    def test_exec_no_output(self) -> None:
        env: dict = {"__name__": "__test__", "__builtins__": __builtins__}
        value, stdout, stderr, err = run_user_code(code="x = 1", exec_env=env)
        assert value is None
        assert stdout == ""
        assert stderr == ""
        assert err is None
        assert env["x"] == 1

    def test_exec_captures_stdout(self) -> None:
        env: dict = {"__name__": "__test__", "__builtins__": __builtins__}
        value, stdout, stderr, err = run_user_code(code="print('hello')", exec_env=env)
        assert stdout == "hello\n"
        assert err is None

    def test_exec_captures_stderr(self) -> None:
        env: dict = {"__name__": "__test__", "__builtins__": __builtins__}
        code = "import sys; sys.stderr.write('warn\\n')"
        value, stdout, stderr, err = run_user_code(code=code, exec_env=env)
        assert stderr == "warn\n"
        assert err is None

    def test_exec_bounds_stdout_and_stderr_independently(self) -> None:
        env: dict = {"__name__": "__test__", "__builtins__": __builtins__}
        limit = len(OUTPUT_TRUNCATION_MARKER.encode("utf-8")) + 4
        code = "import sys; print('abcdef', end=''); sys.stderr.write('uvwxyz')"

        value, stdout, stderr, err = run_user_code(code=code, exec_env=env, output_limit_bytes=limit)

        assert value is None
        assert stdout == f"abcd{OUTPUT_TRUNCATION_MARKER}"
        assert stderr == f"uvwx{OUTPUT_TRUNCATION_MARKER}"
        assert len(stdout.encode("utf-8")) <= limit
        assert len(stderr.encode("utf-8")) <= limit
        assert err is None

    def test_exec_result_convention(self) -> None:
        env: dict = {"__name__": "__test__", "__builtins__": __builtins__}
        value, stdout, stderr, err = run_user_code(code="_result_ = 42", exec_env=env)
        assert value == 42
        assert "_result_" not in env  # popped after extraction
        assert err is None

    def test_exec_error_is_captured(self) -> None:
        env: dict = {"__name__": "__test__", "__builtins__": __builtins__}
        value, stdout, stderr, err = run_user_code(code="raise ValueError('boom')", exec_env=env)
        assert value is None
        assert isinstance(err, ValueError)
        assert str(err) == "boom"

    def test_exec_division_error_is_captured(self) -> None:
        env: dict = {"__name__": "__test__", "__builtins__": __builtins__}
        value, stdout, stderr, err = run_user_code(code="1/0", exec_env=env)
        assert value is None
        assert isinstance(err, ZeroDivisionError)

    def test_stdout_restored_after_error(self) -> None:
        import sys

        orig = sys.stdout
        env: dict = {"__name__": "__test__", "__builtins__": __builtins__}
        run_user_code(code="raise RuntimeError()", exec_env=env)
        assert sys.stdout is orig

    def test_persistent_env_across_calls(self) -> None:
        env: dict = {"__name__": "__test__", "__builtins__": __builtins__}
        run_user_code(code="counter = 1", exec_env=env)
        run_user_code(code="counter += 1", exec_env=env)
        assert env["counter"] == 2


# ---------------------------------------------------------------------------
# make_exec_env
# ---------------------------------------------------------------------------


class TestMakeExecEnv:
    def test_has_name_and_builtins(self) -> None:
        env = make_exec_env()
        assert env["__name__"] == "__ida_bridge__"
        assert env["__builtins__"] is __builtins__

    def test_returns_fresh_dict_each_call(self) -> None:
        a = make_exec_env()
        b = make_exec_env()
        assert a is not b

    def test_injects_idb_namespace(self) -> None:
        env = make_exec_env()
        assert "idb" in env
        idb = env["idb"]
        assert hasattr(idb, "sql")
        assert hasattr(idb, "save")
        assert hasattr(idb, "quit")
        assert idb.quit_requested is False

    def test_idb_quit_sets_flag(self) -> None:
        env = make_exec_env()
        idb = env["idb"]
        idb.quit()
        assert idb.quit_requested is True

    def test_fresh_idb_per_env(self) -> None:
        a = make_exec_env()
        b = make_exec_env()
        assert a["idb"] is not b["idb"]


# ---------------------------------------------------------------------------
# build_exec_response / build_exec_error
# ---------------------------------------------------------------------------


class TestBuildExecResponse:
    def test_ok_response(self) -> None:
        req_id = new_req_id()
        resp = build_exec_response(
            req_id=req_id,
            client_id="ida-1",
            dst="agent-1",
            value=42,
            stdout="out",
            stderr="",
            error=None,
        )
        assert isinstance(resp, ExecResponse)
        assert resp.ok is True
        assert resp.result == 42
        assert resp.stdout == "out"
        assert resp.stderr is None  # empty string -> None
        assert resp.id == req_id

    def test_ok_response_none_value(self) -> None:
        resp = build_exec_response(
            req_id=new_req_id(),
            client_id="ida-1",
            dst="agent-1",
            value=None,
            stdout="",
            stderr="",
            error=None,
        )
        assert resp.ok is True
        assert resp.result is None

    def test_error_response(self) -> None:
        exc = ValueError("boom")
        resp = build_exec_response(
            req_id=new_req_id(),
            client_id="ida-1",
            dst="agent-1",
            value=None,
            stdout="",
            stderr="",
            error=exc,
        )
        assert resp.ok is False
        assert resp.code == "EXEC_ERROR"
        assert "boom" in (resp.message or "")

    def test_serialization_failure_becomes_error(self) -> None:
        # An object that serialize_result can handle, but we force failure
        # by passing a value whose serialization raises.
        class BadRepr:
            def __repr__(self) -> str:
                raise RuntimeError("repr failed")

            @property
            def __dict__(self):
                raise RuntimeError("dict failed")

        resp = build_exec_response(
            req_id=new_req_id(),
            client_id="ida-1",
            dst="agent-1",
            value=BadRepr(),
            stdout="",
            stderr="",
            error=None,
        )
        assert resp.ok is False
        assert resp.code == "EXEC_ERROR"


class TestBuildExecError:
    def test_basic(self) -> None:
        exc = RuntimeError("test error")
        resp = build_exec_error(
            req_id=new_req_id(),
            client_id="ida-1",
            dst="agent-1",
            exc=exc,
        )
        assert resp.ok is False
        assert resp.code == "EXEC_ERROR"
        assert resp.message == "test error"
        assert resp.traceback is not None
        assert "RuntimeError" in resp.traceback

    def test_empty_message_fallback(self) -> None:
        exc = RuntimeError()
        resp = build_exec_error(
            req_id=new_req_id(),
            client_id="ida-1",
            dst="agent-1",
            exc=exc,
        )
        assert resp.message == "execution failed"


# ---------------------------------------------------------------------------
# shutdown_queue / QUEUE_SENTINEL
# ---------------------------------------------------------------------------


class TestShutdownQueue:
    def test_sentinel_wakes_consumer(self) -> None:
        q: queue.Queue[object] = queue.Queue()
        shutdown_queue(q, immediate=False)
        item = q.get_nowait()
        assert item is QUEUE_SENTINEL

    def test_immediate_drains_then_sentinel(self) -> None:
        q: queue.Queue[object] = queue.Queue(maxsize=3)
        q.put("a")
        q.put("b")
        shutdown_queue(q, immediate=True)
        # Only the sentinel should remain.
        item = q.get_nowait()
        assert item is QUEUE_SENTINEL
        assert q.empty()

    def test_full_queue_drops_one_and_enqueues_sentinel(self) -> None:
        q: queue.Queue[object] = queue.Queue(maxsize=1)
        q.put("block")
        shutdown_queue(q, immediate=False)
        item = q.get_nowait()
        assert item is QUEUE_SENTINEL


# ---------------------------------------------------------------------------
# RequestHandler
# ---------------------------------------------------------------------------


def _direct_run_code(
    code: str,
    exec_env: dict,
) -> tuple[object, str, str, Exception | None]:
    return run_user_code(code=code, exec_env=exec_env)


class TestRequestHandler:
    def test_exec_ok(self) -> None:
        sent: list[object] = []
        handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=sent.append)

        req = ExecRequest(id=new_req_id(), src="agent-1", dst="ida-1", code="_result_ = 42")
        handler.handle(req)

        assert len(sent) == 1
        resp = sent[0]
        assert isinstance(resp, ExecResponse)
        assert resp.ok is True
        assert resp.result == 42

    def test_exec_error(self) -> None:
        sent: list[object] = []
        handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=sent.append)

        req = ExecRequest(id=new_req_id(), src="agent-1", dst="ida-1", code="raise ValueError('boom')")
        handler.handle(req)

        assert len(sent) == 1
        resp = sent[0]
        assert isinstance(resp, ExecResponse)
        assert resp.ok is False
        assert resp.code == "EXEC_ERROR"

    def test_default_exec_resets_env(self) -> None:
        sent: list[object] = []
        handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=sent.append)

        handler.handle(ExecRequest(id=new_req_id(), src="agent-1", dst="ida-1", code="x = 99"))
        handler.handle(ExecRequest(id=new_req_id(), src="agent-1", dst="ida-1", code="_result_ = 'x' in dir()"))

        resp = sent[-1]
        assert isinstance(resp, ExecResponse)
        assert resp.ok is True
        assert resp.result is False

    def test_reset_clears_env(self) -> None:
        sent: list[object] = []
        handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=sent.append)

        # Set a variable.
        exec_req = ExecRequest(
            id=new_req_id(), src="agent-1", dst="ida-1", session_id="sess-1", persist=True, code="x = 99"
        )
        handler.handle(exec_req)

        # Reset.
        reset_req = ResetRequest(id=new_req_id(), src="agent-1", dst="ida-1", session_id="sess-1")
        handler.handle(reset_req)

        # Variable should be gone.
        check_req = ExecRequest(
            id=new_req_id(),
            src="agent-1",
            dst="ida-1",
            session_id="sess-1",
            persist=True,
            code="_result_ = 'x' in dir()",
        )
        handler.handle(check_req)

        resp = sent[-1]
        assert isinstance(resp, ExecResponse)
        assert resp.ok is True
        assert resp.result is False

    def test_persistent_env_across_exec(self) -> None:
        sent: list[object] = []
        handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=sent.append)

        handler.handle(
            ExecRequest(
                id=new_req_id(), src="agent-1", dst="ida-1", session_id="sess-1", persist=True, code="counter = 1"
            )
        )
        handler.handle(
            ExecRequest(
                id=new_req_id(),
                src="agent-1",
                dst="ida-1",
                session_id="sess-1",
                persist=True,
                reset_env=False,
                code="counter += 1",
            )
        )
        handler.handle(
            ExecRequest(
                id=new_req_id(),
                src="agent-1",
                dst="ida-1",
                session_id="sess-1",
                persist=True,
                reset_env=False,
                code="_result_ = counter",
            )
        )

        resp = sent[-1]
        assert isinstance(resp, ExecResponse)
        assert resp.result == 2

    def test_quit_not_requested_by_default(self) -> None:
        handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=lambda _: None)
        assert handler.quit_requested is False

    def test_shutdown_via_idb_quit(self) -> None:
        sent: list[object] = []
        handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=sent.append)

        req = ExecRequest(
            id=new_req_id(),
            src="agent-1",
            dst="ida-1",
            code="_result_ = idb.quit()",
        )
        handler.handle(req)

        assert handler.quit_requested is True

    def test_quit_request_sets_flag_and_sends_response(self) -> None:
        sent: list[object] = []
        handler = RequestHandler(client_id="ida-1", run_code=_direct_run_code, send=sent.append)

        req = QuitRequest(id=new_req_id(), src="agent-1", dst="ida-1")
        handler.handle(req)

        assert handler.quit_requested is True
        assert len(sent) == 1
        resp = sent[0]
        assert isinstance(resp, QuitResponse)
        assert resp.id == req.id
        assert resp.src == "ida-1"
        assert resp.dst == "agent-1"
        assert resp.ok is True
