# Remote CLI

`ida-bridge remote -- <ida-bridge arguments>` runs the command on the bridge host. Use it when the command needs the host's files or IDA installation. In the sandbox, set `IDA_BRIDGE_CONNECT_HOST` and `IDA_BRIDGE_PORT` to reach the bridge.

```bash
ida-bridge remote -- supervisor start-idalib --idb /host/target.i64 --json
ida-bridge exec <client_id> --sql "SELECT COUNT(*) FROM funcs"
ida-bridge remote -- supervisor save <client_id>
ida-bridge remote -- supervisor stop <client_id>
```

## Paths and execution context

- The command runs with the bridge's interpreter, environment, and working directory, and connects back to the same bridge.
- Use absolute host paths for binaries, IDBs, and scripts. No files or sandbox environment variables are transferred.
- Arguments pass without a shell. The sandbox shell expands `~` and `$HOME` before forwarding, to sandbox values; do not use them for host paths.
- Direct `exec -f` reads a sandbox file and sends its contents to IDA. Remote `exec -f` reads the file on the host.
- `remote` and all `server` commands are refused (`REMOTE_DENIED`). Manage the bridge on its host.
- There is no stdin and no interactive terminal.

## Output and uncertain outcomes

- Output arrives when the command exits: its stdout, then its stderr, with its exit code. A signal exit on a POSIX host maps to `128 + signal`. Put `--json` after the command for its JSON output.
- There is no bridge timeout. The command's own `--wait-s` and `--timeout-s` apply.
- A disconnect or Ctrl-C stops the wait, not the command. Its output is then lost; reconnecting does not recover it.
- Do not retry automatically after an uncertain outcome. After an uncertain start, check `ida-bridge list` before starting another instance. After an uncertain write, inspect the IDB before repeating it.
- `REMOTE_FAILED`: the command did not start; the server log on the host has the reason.
