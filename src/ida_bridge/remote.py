"""Run an ida-bridge CLI command on the bridge host, for `ida-bridge remote`."""

import asyncio
import os
import sys


def denied_reason(argv: list[str]) -> str | None:
    """Why the bridge host refuses to run argv, or None."""
    command = argv[0] if argv else None
    if command == "remote":
        return "remote cannot run remote: the command would call this bridge again. Pass the host command after --."
    if command == "server":
        return (
            "remote cannot run server commands: they manage the bridge serving this request, "
            "and `server log` never exits. Run them on the bridge host."
        )
    return None


async def run(argv: list[str]) -> tuple[int, str, str]:
    """Run this install's CLI with argv; return its exit code, stdout, and stderr."""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "ida_bridge",
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    return process.returncode, _decode_and_normalize(stdout), _decode_and_normalize(stderr)


def _decode_and_normalize(data: bytes) -> str:
    # The CLI writes UTF-8 (cli.main_cli), so only bytes it did not write can be invalid.
    # Undoing text-mode newline translation lets the caller's stdout apply its own.
    return data.decode("utf-8", errors="replace").replace(os.linesep, "\n")
