import asyncio
import os
import sys

from ida_bridge import protocol
from ida_bridge.agent_client import BridgeDisconnected, BridgeProtocolError, open_agent_client


def _print_usage() -> None:
    print(
        "usage: ida-bridge remote -- <command> [args]\n"
        "\n"
        "Run an ida-bridge command on the host where the bridge server is running.\n"
        "Paths in <command> are host paths.\n"
        "\n"
        "example:\n"
        "  ida-bridge remote -- supervisor start-idalib --input /path/on/host ...\n"
    )


def apply_response(resp: protocol.RemoteResponse) -> int:
    """Print a remote response through and return the process exit code."""
    if not resp.ok:
        detail = resp.message or "remote command failed"
        if resp.code:
            print(f"error: {resp.code}: {detail}", file=sys.stderr)
        else:
            print(f"error: {detail}", file=sys.stderr)
        return 1
    sys.stdout.write(resp.stdout or "")
    sys.stderr.write(resp.stderr or "")
    if resp.exit_code is None:
        print("error: remote response missing exit code", file=sys.stderr)
        return 1
    return resp.exit_code


async def _run(argv: list[str]) -> int:
    async with open_agent_client(
        client_id=f"remote-cli-{os.getpid()}", meta={"tool": "remote", "pid": os.getpid()}
    ) as client:
        resp = await client.remote(argv)
    return apply_response(resp)


def _run_sync(argv: list[str]) -> int:
    try:
        return asyncio.run(_run(argv))
    except ConnectionRefusedError:
        print(
            f"error: cannot connect to bridge at {protocol.bridge_url()}\nHint: start it with `ida-bridge server start`.",
            file=sys.stderr,
        )
        return 1
    except BridgeProtocolError as exc:
        err = exc.err
        print(
            f"error: bridge protocol error: {err.code}: {err.message}\nHint: check client/server versions and the server log.",
            file=sys.stderr,
        )
        return 1
    except BridgeDisconnected as exc:
        print(
            f"error: bridge disconnected: {exc}\nHint: check `ida-bridge server log`.",
            file=sys.stderr,
        )
        return 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args in (["-h"], ["--help"]):
        _print_usage()
        return 0
    if not args or args[0] != "--":
        print("error: remote requires -- before the host command", file=sys.stderr)
        _print_usage()
        return 1
    return _run_sync(args[1:])
