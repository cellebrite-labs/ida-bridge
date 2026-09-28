import argparse
import asyncio
import json
import os
import sys

from ida_bridge import protocol
from ida_bridge.agent_client import open_agent_client
from ida_bridge.cli_common import (
    BRIDGE_ERRORS,
    bridge_error_text,
    build_exec_code,
    format_client_list_human,
    format_human_section,
    print_exec_human,
    print_reset_human,
    stateful_arg_error,
)


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=True))


def _connect_meta() -> dict:
    return {"tool": "cli", "pid": os.getpid()}


async def _print_available_ida_instances_human(client) -> None:
    try:
        list_resp = await client.list(kind="ida")
    except Exception:
        return

    sys.stdout.write("\n")
    sys.stdout.write(format_human_section("available ida instances", format_client_list_human(list_resp.clients or [])))


async def cmd_list(args) -> int:
    async with open_agent_client(client_id=args._client_id, meta=_connect_meta()) as client:
        resp = await client.list(kind=args.kind)

        if args.json:
            _print_json(resp.model_dump(exclude_none=True))
            return 0

        sys.stdout.write(format_client_list_human(resp.clients or []))
        return 0


async def cmd_exec(args) -> int:
    async with open_agent_client(client_id=args._client_id, meta=_connect_meta()) as client:
        code = build_exec_code(sql=args.sql, code=args.code, files=args.file)

        resp = await client.exec(
            args.target, code, session_id=args.session_id, persist=args.stateful, timeout_s=args.timeout_s
        )

        if args.json:
            _print_json(resp.model_dump(exclude_none=True))
        else:
            print_exec_human(resp)
            if not resp.ok and resp.code == protocol.ERR_TARGET_NOT_FOUND:
                await _print_available_ida_instances_human(client)

        return 0 if resp.ok else 1


async def cmd_reset(args) -> int:
    async with open_agent_client(client_id=args._client_id, meta=_connect_meta()) as client:
        resp = await client.reset(
            args.target,
            session_id=args.session_id,
            takeover=args.takeover,
            release=args.release,
            timeout_s=args.timeout_s,
        )

        if args.json:
            _print_json(resp.model_dump(exclude_none=True))
        else:
            print_reset_human(resp)
            if not resp.ok and resp.code == protocol.ERR_TARGET_NOT_FOUND:
                await _print_available_ida_instances_human(client)

        return 0 if resp.ok else 1


def _run(coro) -> int:
    try:
        return asyncio.run(coro)
    except BRIDGE_ERRORS as exc:
        print(bridge_error_text(exc), file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json",
        action="store_true",
        # Allow `cli --json list` AND `cli list --json` without the subparser
        # default clobbering the global value.
        default=argparse.SUPPRESS,
        help="Print machine-readable JSON responses (otherwise human-friendly output)",
    )

    parser = argparse.ArgumentParser(description="IDA Bridge agent client CLI", parents=[common])

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", parents=[common], help="List connected clients")
    p_list.add_argument(
        "--kind",
        choices=["ida", "all"],
        default="ida",
        help="What to list (default: ida)",
    )

    p_exec = sub.add_parser("exec", parents=[common], help="Execute Python code in IDA")
    p_exec.add_argument("target", help="Target IDA client id")
    p_exec.add_argument("--stateful", action="store_true", help="Preserve the Python exec environment across calls")
    p_exec.add_argument("--session-id", help="Logical session id for stateful exec ownership")
    p_exec.add_argument("--sql", help="SQL SELECT query (runs before --file and --code, result in _result_)")
    p_exec.add_argument("--code", "-c", help="Python code to execute (runs after --file, if provided)")
    p_exec.add_argument("--file", "-f", action="append", help="Python file(s) to execute, in order (before --code)")
    p_exec.add_argument("--timeout-s", type=int, default=None, help="Bridge timeout in seconds (0=none)")

    p_reset = sub.add_parser("reset", parents=[common], help="Reset execution environment")
    p_reset.add_argument("target", help="Target IDA client id")
    p_reset.add_argument("--session-id", required=True, help="Logical session id for exec environment ownership")
    p_reset.add_argument("--takeover", action="store_true", help="Transfer exec ownership from another session")
    p_reset.add_argument(
        "--release", action="store_true", help="Reset the stateful exec environment and clear ownership"
    )
    p_reset.add_argument("--timeout-s", type=int, default=None, help="Bridge timeout in seconds (0=none)")

    args = parser.parse_args(argv)
    if not hasattr(args, "json"):
        args.json = False

    # Auto-generated per-process client id to avoid collisions when running multiple CLIs.
    args._client_id = f"agent-cli-{os.getpid()}"

    if args.cmd == "list":
        return _run(cmd_list(args))
    elif args.cmd == "exec":
        if not args.code and not args.file and not args.sql:
            parser.error("--sql, --code, or --file required")
        if err := stateful_arg_error(stateful=args.stateful, session_id=args.session_id):
            parser.error(err)
        return _run(cmd_exec(args))
    elif args.cmd == "reset":
        if args.takeover and args.release:
            parser.error("--takeover and --release are mutually exclusive")
        return _run(cmd_reset(args))
    return 0
