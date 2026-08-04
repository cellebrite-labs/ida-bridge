"""Supervisor CLI — argument parsing and dispatch."""

import argparse

from ida_bridge.cli_common import stateful_arg_error

from .commands import cmd_save, cmd_start_idalib, cmd_start_ui, cmd_stop


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print machine-readable JSON output",
    )

    parser = argparse.ArgumentParser(
        prog="ida-supervisor",
        description="IDA Bridge supervisor",
        parents=[common],
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_start = sub.add_parser(
        "start-ui", parents=[common], help="Start UI IDA; waits for bridge connect, prints client_id"
    )
    g = p_start.add_mutually_exclusive_group(required=True)
    g.add_argument("--idb", help="Path to an existing IDB (.i64/.idb)")
    g.add_argument("--input", help="Path to an input binary/executable")
    p_start.add_argument(
        "--out-idb",
        default=None,
        help="Output IDB path when using --input (passed as -o...; implies -c)",
    )
    p_start.add_argument(
        "--ida",
        default=None,
        help="Path to an IDA .app bundle (macOS) or ida.exe (Windows); default: auto-detect",
    )
    p_start.add_argument(
        "--wait-s",
        default=30.0,
        type=float,
        help="Max seconds to wait for the new client to connect (default: 30s)",
    )
    p_start.set_defaults(func=cmd_start_ui)

    p_idalib = sub.add_parser(
        "start-idalib",
        parents=[common],
        help="Start headless idalib; waits for analysis + bridge connect, prints client_id",
    )
    p_idalib.add_argument(
        "--python",
        default=None,
        help="Path to a python with idapro + deps installed (default: ~/.idapro/venv/bin/python3 on macOS, ~/.idapro/venv/Scripts/python.exe on Windows)",
    )
    g2 = p_idalib.add_mutually_exclusive_group(required=True)
    g2.add_argument("--idb", help="Path to an existing IDB (.i64/.idb)")
    g2.add_argument("--input", help="Path to an input binary/executable")
    p_idalib.add_argument("--out-idb", default=None, help="Output IDB path when using --input")
    p_idalib.add_argument("--force", action="store_true", help="Allow overwriting --out-idb if it exists")
    p_idalib.add_argument(
        "--arch",
        default=None,
        help="Architecture slice to load from a fat (universal) Mach-O (e.g. arm64, x86_64)",
    )
    p_idalib.add_argument(
        "--dyld-module",
        default=None,
        help="Initial dyld_shared_cache module to select for IDA's single-module loader",
    )
    p_idalib.add_argument(
        "--wait-s",
        default=300.0,
        type=float,
        help="Max seconds to wait for analysis + bridge connect (default: 300s)",
    )
    p_idalib.add_argument(
        "--skip-auto-wait",
        action="store_true",
        help="Connect without waiting for auto-analysis (for poisoned or intentionally incomplete IDBs)",
    )
    p_idalib.set_defaults(func=cmd_start_idalib)

    p_stop = sub.add_parser("stop", parents=[common], help="Stop an instance (graceful quit, then SIGTERM/SIGKILL)")
    p_stop.add_argument("target", help="client_id or pid")
    p_stop.set_defaults(func=cmd_stop)

    p_save = sub.add_parser("save", parents=[common], help="Save the IDB for a connected instance")
    p_save.add_argument("target", help="client_id")
    p_save.add_argument("--stateful", action="store_true", help="Save through an existing stateful exec session")
    p_save.add_argument("--session-id", help="Logical session id for stateful exec ownership")
    p_save.set_defaults(func=cmd_save)

    args = parser.parse_args(argv)
    if not hasattr(args, "json"):
        args.json = False

    if args.cmd == "save":
        if err := stateful_arg_error(stateful=args.stateful, session_id=args.session_id):
            parser.error(err)

    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
