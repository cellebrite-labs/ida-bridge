"""CLI for remote: run an ida-bridge command on the bridge host."""

import asyncio
import sys

from ida_bridge import protocol
from ida_bridge.agent_client import BridgeDisconnected, open_agent_client
from ida_bridge.cli_common import BRIDGE_ERRORS, bridge_error_text, format_status_block

_USAGE = (
    "usage: ida-bridge remote -- <command> [args]\n"
    "\n"
    "Run an ida-bridge command on the bridge host. Paths in <command> are host paths.\n"
)
_STILL_RUNNING = "The host command may still be running; check before retrying."


async def _remote(argv: list[str]) -> protocol.RemoteResponse:
    async with open_agent_client(meta={"tool": "remote"}) as client:
        return await client.remote(argv)


def main(argv: list[str]) -> int:
    if argv in (["-h"], ["--help"]):
        print(_USAGE, end="")
        return 0
    if argv[:1] != ["--"] or len(argv) < 2:
        print(f"{_USAGE}\nerror: expected -- followed by an ida-bridge command", file=sys.stderr)
        return 2

    try:
        resp = asyncio.run(_remote(argv[1:]))
    except BridgeDisconnected as exc:
        print(f"{bridge_error_text(exc)}\n{_STILL_RUNNING}", file=sys.stderr)
        return 1
    except BRIDGE_ERRORS as exc:
        print(bridge_error_text(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"aborted. {_STILL_RUNNING}", file=sys.stderr)
        return 130

    if not resp.ok:
        sys.stderr.write(format_status_block("remote", resp))
        return 1

    sys.stdout.write(resp.stdout)
    sys.stdout.flush()
    sys.stderr.write(resp.stderr)
    # A negative code is a signal on a POSIX host; report it the way a shell does.
    return 128 - resp.exit_code if resp.exit_code < 0 else resp.exit_code
