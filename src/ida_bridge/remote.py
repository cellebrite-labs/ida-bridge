import asyncio
import sys


def denied_reason(argv: list[str]) -> str | None:
    """Why this argv must not run on the host, or None if it may."""
    if not argv:
        return None
    if argv[0] == "remote":
        return (
            "remote cannot invoke remote; that recurses through this server. Pass the host command directly after --."
        )
    if argv[0] == "server" and _server_subcommand(argv) == "stop":
        return (
            "remote cannot run server stop; that would stop the bridge this connection is using. "
            "Stop the server on the host, not through remote."
        )
    return None


def _server_subcommand(argv: list[str]) -> str | None:
    """Subcommand argparse would select. A leading -- is end-of-options, not the command."""
    rest = argv[1:]
    if rest[:1] == ["--"]:
        rest = rest[1:]
    if not rest or rest[0].startswith("-"):
        return None
    return rest[0]


def _text(data: bytes | None) -> str:
    if not data:
        return ""
    return data.decode("utf-8", errors="replace")


async def run_argv(argv: list[str]) -> tuple[int, str, str]:
    """Run this install's CLI and wait. Does not kill the child if the waiter is cancelled."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "ida_bridge",
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()
    if proc.returncode is None:
        raise RuntimeError("host CLI exited without a return code")
    return proc.returncode, _text(stdout_b), _text(stderr_b)
