# IDA Bridge architecture

This file keeps only the structural facts that are easy to forget. `README.md`, `docs/protocol.md`, and code are the source of truth for usage and behavior.

```text
+---------+    +--------------+          +--------+          +-[ UI IDA ]--------+
|  Agent  | -> | agent client |<-- WS -->| Bridge |<-- WS -->|   IDA plugin      | +
+---------+    +--------------+          |        |          +-------------------+ |
   (SKILL)           (CLI)               |        |            +-------------------+
                                         |        |
                                         |        |          +-[ idalib ]--------+
                                         |        |<-- WS -->|   idalib runner   | +
                                         |        |          +-------------------+ |
                                         +--------+            +-------------------+
```

## Components

- agent client -- CLI or agent-authored code sending requests
- bridge server -- authoritative websocket router, policy layer, and remote headless process supervisor
- UI IDA client -- plugin-hosted runtime inside desktop IDA
- idalib runner -- headless runtime process
- local supervisor -- lifecycle commands executed on the CLI host

## Ownership of concerns

Bridge:
- validates protocol
- routes messages
- enforces request and response correlation
- enforces exec-environment ownership policy
- tracks pending requests and timeouts
- starts, tracks, reaps, and stops headless idalib children for remote lifecycle requests
- never starts UI IDA

IDA runtime:
- owns `_exec_env`
- executes requests in the correct runtime thread model
- returns responses
- owns the quit flag
- does not enforce bridge routing or ownership policy

Supervisor:
- starts and stops runtimes on the CLI host
- provides local lifecycle commands, including UI IDA
- does not own protocol policy

## Thread model

UI IDA:
- IDA main thread
- websocket thread
- executor thread
- user code runs on the main thread via `ida_kernwin.execute_sync`

idalib:
- worker thread
- websocket thread
- user code runs on the worker thread

In both runtimes, the websocket thread must stay responsive. Requests are queued first, then executed serially by the executor.

## Lifecycle model

One live runtime serves one open target.

Use:
- `exec-idb` for one-shot work
- local `supervisor start-ui` or `supervisor start-idalib` plus `exec` for iterative work
- `remote start-idalib` when the bridge and target files are on another host

Ownership and lifecycle are separate:
- stateless `exec` resets the exec environment for one request and leaves no reusable session behind
- stateful `exec` and `reset` act on exec-environment ownership
- `save` persists work through an exec request; it can be stateless or use an existing stateful session
- `quit` is a lifecycle action and bypasses session ownership
- `remote stop` is bridge-host-only, does not save, and accepts only connected or bridge-managed idalib processes

## Runtime notes

- UI IDA may be started by the supervisor or by a human. The plugin behavior is the same either way.
- On Windows the venv launcher re-execs, so the process that connects is not the one the supervisor spawned; clients are matched by their self-reported pid.
- idalib connects to the bridge after `ida_auto.auto_wait()` completes initial auto-analysis. `--skip-initial-auto-analysis` is available when the auto-analysis hangs.
- Both UI IDA and idalib reconnect to the bridge after bridge restarts.

## Security model

Trusted use only, including when carried through a TCP tunnel.

- no authentication
- code execution inside IDA
- remote lifecycle can launch idalib and terminate validated idalib PIDs on the bridge host
- do not expose the bridge to untrusted networks
