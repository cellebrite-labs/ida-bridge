"""Shared CLI helpers for formatting and printing protocol responses, and building execution payloads."""

import json
from pathlib import Path
import sys

from ida_bridge import protocol
from ida_bridge.agent_client import BridgeDisconnected, BridgeProtocolError, BridgeUnreachable, RequestTooLarge

_INLINE_FILENAME = "<ida-bridge -c>"

BRIDGE_ERRORS = (BridgeUnreachable, BridgeDisconnected, BridgeProtocolError, RequestTooLarge)


def bridge_error_text(exc: Exception) -> str:
    match exc:
        case BridgeUnreachable():
            return (
                f"error: {exc}\n"
                "Hint: is the bridge running (`ida-bridge server start`), "
                "and are IDA_BRIDGE_CONNECT_HOST/IDA_BRIDGE_PORT correct?"
            )
        case BridgeProtocolError():
            return (
                f"error: bridge protocol error: {exc.err.code}: {exc.err.message}\n"
                "Hint: check client/server versions and the server log."
            )
        case BridgeDisconnected():
            return f"error: bridge disconnected: {exc}\nHint: check `ida-bridge server log`."
        case RequestTooLarge():
            return (
                f"error: {exc}\n"
                "Hint: shrink --sql/--code/--file, or write the data to a file on the IDA host and read it from the script."
            )
    raise TypeError(f"not a bridge error: {exc!r}")


def stateful_arg_error(*, stateful: bool, session_id: str | None) -> str | None:
    """Return a CLI error for invalid stateful/session flag combinations."""
    if stateful and session_id is None:
        return "--stateful requires --session-id"
    if (not stateful) and session_id is not None:
        return "--session-id is only valid with --stateful; remove it for stateless mode"
    return None


def build_exec_code(*, code: str | None, files: list[str] | None, sql: str | None = None) -> str:
    """Build one exec payload from SQL query, file(s), and/or inline code.

    Execution order: sql -> files -> code. All share the same globals().
    """
    if not code and not files and not sql:
        msg = "sql, code, or file required"
        raise ValueError(msg)

    parts: list[str] = []

    if sql:
        stmt = f"_result_ = idb.sql({sql!r})"
        if code or files:
            # Convert QueryResult to plain dict so -c/-f code can
            # subscript it (e.g. _result_["rows"]).  Keep raw values
            # (ints, not hex strings) -- hex formatting is transport-only.
            stmt += '\n_result_ = {"columns": list(_result_.columns), "rows": list(_result_.rows)}'
        parts.append(stmt)

    for f in files or []:
        source = Path(f).read_text(encoding="utf-8")
        parts.append(_compiled_exec(source=source, filename=f))

    if code:
        parts.append(_compiled_exec(source=code, filename=_INLINE_FILENAME))

    return "\n".join(parts)


def _compiled_exec(*, source: str, filename: str) -> str:
    return f"exec(compile({source!r}, {filename!r}, 'exec'), globals(), globals())"


# ---------------------------------------------------------------------------
# Error hints (human mode)
# ---------------------------------------------------------------------------

_ERROR_HINTS: dict[str, str] = {
    protocol.ERR_TARGET_NOT_FOUND: "run `ida-bridge list` to see available IDA client ids.",
    protocol.ERR_TARGET_DISCONNECTED: "restart IDA (or wait for it to reconnect) and retry.",
    protocol.ERR_TARGET_PING_TIMEOUT: (
        "IDA's WebSocket thread may be starved (GIL contention during heavy analysis).\n"
        "The exec may still complete. Probe with: "
        "ida-bridge exec <id> --timeout-s 30 -c '_result_=1'"
    ),
    protocol.ERR_TIMEOUT: "retry with a higher --timeout-s (or 0 to disable timeout).",
    protocol.ERR_INVALID_TARGET_ROLE: "the target must be an IDA client id (role=ida). See `ida-bridge list`.",
    protocol.ERR_QUEUE_FULL: "retry later or reduce concurrent requests.",
    protocol.ERR_RESPONSE_NOT_SERIALIZABLE: (
        "the named field holds text JSON cannot encode (e.g. surrogate-escaped bytes). The target is still running."
    ),
    protocol.ERR_RESPONSE_TOO_LARGE: (
        "shrink the result or stdout so the serialized response fits. The target is still running."
    ),
    protocol.ERR_TARGET_INTERNAL_ERROR: (
        "the IDA side failed outside your script -- our code, IDA, or another plugin. "
        "The target is still running, but internal IDA state is unknown; see the traceback."
    ),
    protocol.ERR_TAKEOVER_PENDING: "a takeover reset is in flight. Wait and retry.",
    protocol.ERR_SESSION_LOCKED: "reconnect the target to clear the lock.",
    protocol.ERR_SESSION_CONFLICT: (
        "use `--stateful --session-id <sid>` with the owning session, or run "
        "`ida-bridge reset <target> --session-id <sid> --takeover` to steal ownership."
    ),
}


def format_human_section(name: str, content: str) -> str:
    """Format a named human-output section with header."""
    trailer = content if content.endswith("\n") else content + "\n"
    return f"--- {name} ---\n{trailer}"


def format_client_list_human(clients) -> str:
    """Format connected client rows for human output."""
    clients = list(clients)
    if not clients:
        return "(no clients)\n"

    parts = ["client_id\trole\tpid\tsession\tidb_path\n"]
    for client in clients:
        meta = client.meta or {}
        pid = meta.get("pid")
        pid_s = str(pid) if pid is not None else "unknown"
        session_s = client.session_id or ""
        if client.role == protocol.ROLE_IDA:
            idb_path = meta.get("idb_path") or "unknown"
        else:
            idb_path = ""
        parts.append(f"{client.client_id}\t{client.role}\t{pid_s}\t{session_s}\t{idb_path}\n")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Human-mode exec output
# ---------------------------------------------------------------------------


def _format_status_block(cmd: str, resp: protocol.ResponseBase) -> str:
    """Format the command status line and error metadata."""
    parts: list[str] = [f"{cmd}: {'ok' if resp.ok else 'error'}\n"]
    if resp.ok:
        return "".join(parts)

    if resp.code:
        parts.append(f"error code: {resp.code}\n")
    if resp.message:
        parts.append(f"error message: {resp.message}\n")
    hint = _ERROR_HINTS.get(resp.code or "")
    if hint:
        for line in hint.splitlines():
            parts.append(f"hint: {line}\n")
    return "".join(parts)


def _bridge_trace_section(trace: dict) -> str:
    """Format the shared bridge error trace section."""
    try:
        trace_s = json.dumps(trace, indent=2, ensure_ascii=True)
    except TypeError:
        trace_s = str(trace)
    return format_human_section("bridge trace", trace_s)


def _print_human(status: str, sections: list[str]) -> None:
    """Print status plus optional named sections."""
    if sections:
        sys.stdout.write(status + "\n" + "".join(sections))
    else:
        sys.stdout.write(status)


def print_exec_human(resp: protocol.ExecResponse) -> None:
    """Print an ExecResponse in structured human-readable format to stdout.

    Layout:
      exec: ok|error
      [error code: ...]
      [error message: ...]
      [hint: ...]

      [--- bridge trace ---]
      [--- traceback ---]
      [--- result ---]
      [--- stdout ---]
      [--- stderr ---]

    Sections are only emitted when their content is present.
    """
    sections: list[str] = []

    if resp.trace is not None:
        sections.append(_bridge_trace_section(resp.trace))

    # Traceback (exec-specific: user code failure)
    if resp.traceback:
        sections.append(format_human_section("traceback", resp.traceback))

    # Result (success only)
    if resp.ok and resp.result is not None:
        try:
            result_s = json.dumps(resp.result, indent=2, ensure_ascii=True)
        except TypeError:
            result_s = str(resp.result)
        sections.append(format_human_section("result", result_s))

    # Stdout
    if resp.stdout:
        sections.append(format_human_section("stdout", resp.stdout))

    # Stderr
    if resp.stderr:
        sections.append(format_human_section("stderr", resp.stderr))

    _print_human(_format_status_block("exec", resp), sections)


def print_reset_human(resp: protocol.ResetResponse) -> None:
    """Print a ResetResponse in structured human-readable format to stdout."""
    sections = []
    if resp.trace is not None:
        sections.append(_bridge_trace_section(resp.trace))
    _print_human(_format_status_block("reset", resp), sections)
