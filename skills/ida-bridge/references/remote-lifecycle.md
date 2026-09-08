# Remote headless lifecycle

Use this flow when the CLI talks through a TCP socket or tunnel to an ida-bridge server on another host, and the target IDBs, input binaries, and idapro installation are available on that bridge host.

## Start

Existing IDB:

```bash
ida-bridge remote start-idalib --idb /bridge/path/sample.i64
```

Create an IDB from a bridge-host input:

```bash
ida-bridge remote start-idalib \
  --input /bridge/path/sample \
  --out-idb /bridge/path/sample.i64 \
  --force
```

Options:
- `--python` is an executable on the bridge host; omit it to use that host's default `~/.idapro/venv` interpreter.
- `--arch` selects a fat Mach-O slice.
- `--dyld-module` selects one image from a dyld shared cache.
- Do not combine `--arch` and `--dyld-module`.
- `--out-idb`, `--force`, `--arch`, and `--dyld-module` apply only to `--input`.
- `--wait-s` defaults to 300 seconds.

Do not preflight these paths on the CLI host. The bridge validates and resolves them where idalib will run.

Success has one of two states:
- `status: connected`: use the returned `client_id` immediately.
- `status: waiting`: the PID is alive but analysis did not finish before `--wait-s`; do not launch a duplicate. Poll `ida-bridge list` for the new idalib client.

The returned log path is also on the bridge host.

## Save and stop

Remote stop never saves:

```bash
ida-bridge remote stop <client_id-or-pid>
```

Save first when changes must persist:

```bash
ida-bridge supervisor save <client_id>
ida-bridge remote stop <client_id>
```

The save command is an exec RPC and therefore works through the configured remote bridge socket. `remote stop` sends a graceful quit first and then, if necessary, terminates the validated idalib PID on the bridge host. It accepts only a connected headless idalib or a child PID managed by that bridge. It rejects UI clients and arbitrary numeric PIDs.

Never use `ida-bridge supervisor stop` with a remote PID. That command performs fallback process control on the CLI host.

## Trust boundary

The bridge has no authentication and supports code execution plus remote headless process lifecycle. Use it only through a trusted network or tunnel.
