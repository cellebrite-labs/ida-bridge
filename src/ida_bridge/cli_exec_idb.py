"""CLI for exec-idb: one-shot idalib execution."""

import argparse
import asyncio
import json
import os
import sys

from ida_bridge.agent_client import BridgeDisconnected, BridgeProtocolError, open_agent_client
from ida_bridge.cli_common import build_exec_code, print_exec_human
from ida_bridge.supervisor import StartError, start_idalib, terminate_pid
from ida_bridge.supervisor.bridge import bridge_quit, bridge_save

_CLIENT_ID = f"exec-idb-{os.getpid()}"


async def _exec(target: str, code: str, *, timeout_s: int | None):
    """Execute code against a connected IDA client."""
    async with open_agent_client(client_id=_CLIENT_ID) as client:
        return await client.exec(target, code, timeout_s=timeout_s)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ida-bridge exec-idb", description="One-shot: start idalib, exec, stop")

    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--idb", help="Path to an existing IDB (.i64/.idb)")
    g.add_argument("--input", help="Path to an input binary/executable")

    parser.add_argument("--out-idb", default=None, help="Output IDB path when using --input")
    parser.add_argument("--force", action="store_true", help="Allow overwriting --out-idb if it exists")
    parser.add_argument("--arch", default=None, help="Architecture slice for fat Mach-O (e.g. arm64)")
    parser.add_argument(
        "--dyld-module",
        default=None,
        help="Initial dyld_shared_cache module to select for IDA's single-module loader",
    )
    parser.add_argument("--python", default=None, help="Path to python with idapro installed")
    parser.add_argument(
        "--wait-s", default=300.0, type=float, help="Max seconds to wait for analysis + bridge connect (default: 300s)"
    )
    parser.add_argument(
        "--skip-auto-wait",
        action="store_true",
        help="Connect without waiting for auto-analysis (for poisoned or intentionally incomplete IDBs)",
    )

    parser.add_argument("--sql", help="SQL query (runs before --file and --code, result in _result_)")
    parser.add_argument("--code", "-c", help="Python code to execute (runs after --file, if provided)")
    parser.add_argument("--file", "-f", action="append", help="Python file(s) to execute, in order (before --code)")

    parser.add_argument("--timeout-s", type=int, default=None, help="Exec timeout in seconds")
    parser.add_argument("--save", action="store_true", help="Save the IDB before stopping")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Print machine-readable JSON output")

    args = parser.parse_args(argv)
    has_code = args.sql or args.code or args.file
    if not has_code and not args.save:
        parser.error("--sql, --code, or --file required (or --save for create-only)")

    code = build_exec_code(sql=args.sql, code=args.code, files=args.file) if has_code else None

    # Start.
    try:
        result = start_idalib(
            idb=args.idb,
            input_file=args.input,
            out_idb=args.out_idb,
            force=args.force,
            arch=args.arch,
            dyld_module=args.dyld_module,
            python=args.python,
            wait_s=args.wait_s,
            skip_auto_wait=args.skip_auto_wait,
        )
    except StartError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if result.client_id is None:
        print(
            f"idalib started (pid={result.pid}) but did not connect within {args.wait_s}s\nlog: {result.log_path}",
            file=sys.stderr,
        )
        terminate_pid(result.pid)
        return 2

    client_id = result.client_id
    pid = result.pid
    json_mode = args.json_output
    if not json_mode:
        print(f"started: {client_id} (pid={pid})", file=sys.stderr)

    # Exec + cleanup.
    exit_code = 0
    try:
        if has_code:
            resp = asyncio.run(_exec(client_id, code, timeout_s=args.timeout_s))

            if json_mode:
                print(json.dumps(resp.model_dump(exclude_none=True), indent=2, ensure_ascii=True))
            else:
                print_exec_human(resp)

            exit_code = 0 if resp.ok else 1

    except ConnectionRefusedError:
        print("error: bridge connection lost\nHint: check `ida-bridge server status`.", file=sys.stderr)
        exit_code = 2
    except BridgeDisconnected as exc:
        print(f"error: bridge disconnected: {exc}\nHint: the IDA instance may have crashed.", file=sys.stderr)
        exit_code = 2
    except BridgeProtocolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        exit_code = 2
    except Exception as exc:
        print(f"exec failed: {exc}", file=sys.stderr)
        exit_code = 2

    finally:
        if args.save and exit_code == 0:
            try:
                saved = asyncio.run(bridge_save(client_id))
                if not json_mode:
                    print("saved" if saved else "save: no changes to write", file=sys.stderr)
            except Exception as exc:
                print(f"save failed: {exc}", file=sys.stderr)

        try:
            asyncio.run(bridge_quit(client_id))
        except Exception:
            pass
        terminate_pid(pid)
        if not json_mode:
            print("stopped", file=sys.stderr)

    return exit_code
