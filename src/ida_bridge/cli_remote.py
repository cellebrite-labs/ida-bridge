"""CLI for idalib lifecycle operations executed by a remote bridge host."""

import argparse
import asyncio
import json
import os
import sys

from ida_bridge import protocol
from ida_bridge.agent_client import BridgeDisconnected, BridgeProtocolError, open_agent_client


def _connect_meta() -> dict:
    return {"tool": "remote-cli", "pid": os.getpid()}


def _print_json(data: dict) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=True))


def _error_payload(resp: protocol.ResponseBase) -> dict:
    result = {"ok": False, "code": resp.code, "message": resp.message}
    if resp.trace is not None:
        result["trace"] = resp.trace
    return result


def _print_response_error(command: str, resp: protocol.ResponseBase, *, json_mode: bool) -> None:
    if json_mode:
        _print_json(_error_payload(resp))
        return
    print(f"{command}: error", file=sys.stderr)
    print(f"error code: {resp.code}", file=sys.stderr)
    if resp.message:
        print(f"error message: {resp.message}", file=sys.stderr)


async def cmd_start_idalib(args: argparse.Namespace) -> int:
    async with open_agent_client(client_id=args._client_id, meta=_connect_meta()) as client:
        resp = await client.start_idalib(
            idb=args.idb,
            input_file=args.input,
            out_idb=args.out_idb,
            force=args.force,
            arch=args.arch,
            dyld_module=args.dyld_module,
            python=args.python,
            wait_s=args.wait_s,
        )

    if not resp.ok:
        _print_response_error("start-idalib", resp, json_mode=args.json)
        return 2

    result = {
        "status": resp.status,
        "client_id": resp.client_id,
        "pid": resp.pid,
        "idb_path": resp.idb_path,
        "log": resp.log,
    }
    if args.json:
        _print_json(result)
    else:
        for key, value in result.items():
            if value is not None:
                print(f"{key}: {value}")
    return 0


async def cmd_stop_idalib(args: argparse.Namespace) -> int:
    async with open_agent_client(client_id=args._client_id, meta=_connect_meta()) as client:
        resp = await client.stop_idalib(args.target)

    if not resp.ok:
        _print_response_error("stop", resp, json_mode=args.json)
        return 2

    result = {
        "ok": True,
        "method": resp.method,
        "client_id": resp.client_id,
        "pid": resp.pid,
    }
    if args.json:
        _print_json(result)
    else:
        for key, value in result.items():
            if value is not None:
                print(f"{key}: {value}")
    return 0


def _run(coro) -> int:
    try:
        return asyncio.run(coro)
    except ConnectionRefusedError:
        print(
            f"error: cannot connect to bridge at {protocol.bridge_url()}\n"
            "Hint: verify IDA_BRIDGE_HOST/IDA_BRIDGE_PORT or the TCP tunnel.",
            file=sys.stderr,
        )
        return 1
    except BridgeProtocolError as exc:
        print(
            f"error: bridge protocol error: {exc.err.code}: {exc.err.message}\n"
            "Hint: check client/server versions and the server log.",
            file=sys.stderr,
        )
        return 1
    except BridgeDisconnected as exc:
        print(f"error: bridge disconnected: {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print machine-readable JSON output",
    )
    parser = argparse.ArgumentParser(
        prog="ida-bridge remote",
        description="Manage headless idalib instances on the bridge host",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    start = sub.add_parser(
        "start-idalib",
        parents=[common],
        help="Start headless idalib on the bridge host",
    )
    source = start.add_mutually_exclusive_group(required=True)
    source.add_argument("--idb", help="Existing IDB path on the bridge host")
    source.add_argument("--input", help="Input binary path on the bridge host")
    start.add_argument("--out-idb", help="Output IDB path on the bridge host when using --input")
    start.add_argument("--force", action="store_true", help="Allow overwriting --out-idb")
    loader = start.add_mutually_exclusive_group()
    loader.add_argument("--arch", help="Architecture slice for a fat Mach-O")
    loader.add_argument("--dyld-module", help="Initial dyld_shared_cache module")
    start.add_argument("--python", help="Python interpreter path on the bridge host")
    start.add_argument(
        "--wait-s",
        type=float,
        default=300.0,
        help="Seconds to wait for analysis and bridge connection (default: 300)",
    )

    stop = sub.add_parser("stop", parents=[common], help="Stop a headless idalib instance on the bridge host")
    stop.add_argument("target", help="Connected client_id or bridge-host pid")

    args = parser.parse_args(argv)
    if not hasattr(args, "json"):
        args.json = False
    args._client_id = f"agent-remote-cli-{os.getpid()}"

    if args.cmd == "start-idalib":
        if args.input is not None and args.out_idb is None:
            parser.error("--input requires --out-idb")
        if args.idb is not None and (args.out_idb is not None or args.force or args.arch or args.dyld_module):
            parser.error("--out-idb, --force, --arch, and --dyld-module are only valid with --input")
        if args.wait_s < 0:
            parser.error("--wait-s must be >= 0")
        return _run(cmd_start_idalib(args))
    return _run(cmd_stop_idalib(args))


if __name__ == "__main__":
    raise SystemExit(main())
