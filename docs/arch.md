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
- bridge server -- authoritative websocket router and policy layer
- UI IDA client -- plugin-hosted runtime inside desktop IDA
- idalib runner -- headless runtime process
- supervisor -- lifecycle commands for start, save, and stop

## Ownership of concerns

Bridge:
- validates protocol
- routes messages
- enforces request and response correlation
- enforces exec-environment ownership policy
- tracks pending requests and timeouts
- does not spawn or execute IDA

IDA runtime:
- owns `_exec_env`
- executes requests in the correct runtime thread model
- bounds each request's captured and mirrored stdout/stderr stream to 1 MiB
- returns responses
- owns the quit flag
- does not enforce bridge routing or ownership policy

Supervisor:
- starts and stops runtimes
- provides lifecycle commands
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
- `supervisor start-ui` or `supervisor start-idalib` plus `exec` for iterative work

Ownership and lifecycle are separate:
- stateless `exec` resets the exec environment for one request and leaves no reusable session behind
- stateful `exec` and `reset` act on exec-environment ownership
- `save` persists work through an exec request; it can be stateless or use an existing stateful session
- `quit` is a lifecycle action and bypasses session ownership

## Runtime notes

- UI IDA may be started by the supervisor or by a human. The plugin behavior is the same either way.
- On Windows the venv launcher re-execs, so the process that connects is not the one the supervisor spawned; clients are matched by their self-reported pid.
- idalib connects to the bridge after `ida_auto.auto_wait()` completes initial auto-analysis. `--skip-initial-auto-analysis` is available when the auto-analysis hangs.
- Both UI IDA and idalib reconnect to the bridge after bridge restarts.

## Security model

Local and trusted use only.

- no authentication
- code execution inside IDA
- do not expose the bridge to untrusted networks
