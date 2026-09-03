import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if not args:
        _print_usage()
        return 1

    cmd = args[0]

    if cmd in ("--help", "-h"):
        _print_usage()
        return 0

    cmd = args[0]

    if cmd in ("server",):
        from ida_bridge.cli_server import main as server_main

        return server_main(args[1:])

    if cmd in ("supervisor", "sup"):
        from ida_bridge.supervisor import main as supervisor_main

        return supervisor_main(args[1:])

    # Agent commands (list, exec, reset) are handled directly.
    if cmd in ("list", "exec", "reset"):
        from ida_bridge.cli_agent import main as agent_main

        return agent_main(args)

    if cmd == "exec-idb":
        from ida_bridge.cli_exec_idb import main as exec_idb_main

        return exec_idb_main(args[1:])

    if cmd == "remote":
        from ida_bridge.cli_remote import main as remote_main

        return remote_main(args[1:])

    _print_usage()
    print(f"\nerror: unknown command: {cmd}", file=sys.stderr)
    return 1


def _print_usage() -> None:
    print(
        "usage: ida-bridge <command> [args]\n"
        "\n"
        "commands:\n"
        "  server <cmd>             Server management (start, stop, status, ...)\n"
        "  list [--kind]            List connected IDA clients\n"
        "  exec <target> [--stateful --session-id SID] [--sql QUERY] [-f FILE ...] [-c CODE]  Execute in IDA\n"
        "  exec-idb --idb ... [--sql QUERY] [-f FILE ...] [-c CODE]  One-shot: start idalib, exec, stop\n"
        "  remote <cmd>             Manage headless idalib on the bridge host (start-idalib, stop)\n"
        "  reset <target> --session-id SID [--takeover|--release]  Reset stateful execution environment\n"
        "  supervisor <cmd>         Process lifecycle (start-ui, start-idalib, stop, save)\n"
    )


def main_cli() -> int:
    """Entry point for console_scripts and `python -m ida_bridge`."""
    try:
        return main()
    except KeyboardInterrupt:
        print("aborted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main_cli())
