# IDA Bridge Protocol

Defines the websocket protocol between `agent`, `bridge`, and `ida`.

## Scope

- WebSocket, JSON over text frames
- default URL: `ws://127.0.0.1:8765`
- protocol version: `5`
- trusted deployments only; the socket may be remote or tunneled
- no compatibility guarantees for third-party clients

## Core rules

- Messages are strict: unknown fields are rejected.
- `type` is the single message discriminator.
- The bridge is authoritative:
  - only the bridge emits `ProtocolError` (`type: "error"`)
  - clients should close the websocket on protocol violations rather than trying to send bridge-style errors
- Protocol violations are connection-level faults.
- Honest failures such as disconnects, timeouts, queue pressure, and ownership conflicts are normal `ok: false` responses.
- Response correlation is strict: `id`, route, and response type must match the pending request.

## Transport

- non-text frames are rejected with `ProtocolError`, then close `1002`
- oversized messages may be rejected by the websocket server with `1009`
- server max incoming message size defaults to `67108864` bytes and is configured by `IDA_BRIDGE_WS_MAX_SIZE`

## Roles and client IDs

Roles:
- `agent`
- `ida`
- `bridge`

Clients choose `client_id` during handshake.
`bridge` is reserved and cannot be claimed by clients.

## Message model

All messages include:
- `v`: protocol version integer (`5`)
- `type`: message type string

All requests and responses include:
- `id`: canonical UUIDv4 string
- `src`: sender `client_id`
- `dst`: destination `client_id`

Requests may include:
- `timeout_s`
  - omitted or `null`: bridge default timeout
  - `0`: no timeout
  - `> 0`: explicit bridge-side timeout

Responses include:
- `ok`: boolean

Response rules:
- if `ok = true`, the response must not include `code`, `message`, or `trace`
- if `ok = false`, the response must include `code`
- `message` and `trace` are optional on failures

## Handshake

The first message from a client must be `hello`.

### `hello`

```json
{
  "v": 5,
  "type": "hello",
  "role": "agent",
  "client_id": "agent-1",
  "meta": {}
}
```

Fields:
- `role`: `agent` or `ida`
- `client_id`: non-empty string, unique among connected clients
- `meta`: free-form JSON object

### `hello_ack`

```json
{
  "v": 5,
  "type": "hello_ack",
  "client_id": "agent-1",
  "bridge_id": "bridge",
  "meta": {
    "server": "ida-bridge",
    "instance_id": "bridge-12345"
  }
}
```

## Allowed routing

- agent -> bridge: `list`, `start_idalib`, `stop_idalib`
- agent -> ida: `exec`, `reset`, `quit`
- ida -> agent: `exec_response`, `reset_response`, `quit_response`
- bridge -> ida: `quit` while handling `stop_idalib`
- ida -> bridge: the correlated `quit_response`
- bridge -> agent: `list_response`, `start_idalib_response`, `stop_idalib_response`
- bridge -> agent: bridge-originated request failures as `exec_response`, `reset_response`, or `quit_response`

## Operations

### `list`

Request:

```json
{
  "v": 5,
  "type": "list",
  "id": "<uuid-v4>",
  "src": "agent-1",
  "dst": "bridge",
  "kind": "all"
}
```

Fields:
- `kind`: `ida` or `all`

Response:

```json
{
  "v": 5,
  "type": "list_response",
  "id": "<uuid-v4>",
  "src": "bridge",
  "dst": "agent-1",
  "ok": true,
  "kind": "all",
  "clients": [
    {"client_id": "ida-1", "role": "ida", "meta": {}},
    {"client_id": "agent-1", "role": "agent", "meta": {}}
  ]
}
```

`clients` is sorted deterministically by `client_id`.

### `exec`

Runs IDAPython in the target runtime.

Stateless request:

```json
{
  "v": 5,
  "type": "exec",
  "id": "<uuid-v4>",
  "src": "agent-1",
  "dst": "ida-1",
  "code": "print('hi')",
  "timeout_s": 60
}
```

Stateful request:

```json
{
  "v": 5,
  "type": "exec",
  "id": "<uuid-v4>",
  "src": "agent-1",
  "dst": "ida-1",
  "persist": true,
  "session_id": "sess-1",
  "code": "print('hi')",
  "timeout_s": 60
}
```

Fields:
- `code`: IDAPython source string
- `persist` (optional, default `false`): claim or reuse stateful ownership
- `session_id`: required when `persist=true`; invalid when `persist=false`
- `reset_env`: bridge-derived on forwarded requests; agents should not use it for ownership policy

Success response:

```json
{
  "v": 5,
  "type": "exec_response",
  "id": "<uuid-v4>",
  "src": "ida-1",
  "dst": "agent-1",
  "ok": true,
  "result": null,
  "stdout": "...",
  "stderr": "..."
}
```

On failure, `exec_response` follows the common `ok: false` response rules and may include `traceback`.

### `reset`

Resets the target exec environment.

Request:

```json
{
  "v": 5,
  "type": "reset",
  "id": "<uuid-v4>",
  "src": "agent-1",
  "dst": "ida-1",
  "session_id": "sess-1",
  "takeover": true
}
```

Fields:
- `session_id`: logical owner of the target exec environment
- `takeover` (optional, default `false`): request ownership transfer from another session
- `release` (optional, default `false`): clear ownership after a successful reset

Takeover rules:
- ownership transfers only after `reset_response(ok=true)`
- if a forwarded takeover fails or times out, ownership becomes unknown and the target is locked until reconnect

Release rules:
- ownership clears only after `reset_response(ok=true)`
- while release is in flight, exec/reset requests get `RELEASE_PENDING`
- if release fails, the previous owner is restored
- if release outcome is unknown, the target is locked until reconnect

Success response:

```json
{
  "v": 5,
  "type": "reset_response",
  "id": "<uuid-v4>",
  "src": "ida-1",
  "dst": "agent-1",
  "ok": true
}
```

### `quit`

Requests graceful shutdown of the target runtime. `quit` bypasses exec-environment ownership.

Request:

```json
{
  "v": 5,
  "type": "quit",
  "id": "<uuid-v4>",
  "src": "agent-1",
  "dst": "ida-1"
}
```

Success response:

```json
{
  "v": 5,
  "type": "quit_response",
  "id": "<uuid-v4>",
  "src": "ida-1",
  "dst": "agent-1",
  "ok": true
}
```

### `start_idalib`

Starts a headless idalib process on the bridge host. Paths and `python` are resolved on that host, not on the agent host. The bridge passes the accepted socket's local TCP endpoint to the child so it reconnects to the same bridge.

Existing IDB request:

```json
{
  "v": 5,
  "type": "start_idalib",
  "id": "<uuid-v4>",
  "src": "agent-1",
  "dst": "bridge",
  "idb": "/srv/idbs/sample.i64",
  "python": "/srv/ida-venv/bin/python",
  "wait_s": 300
}
```

Input request:

```json
{
  "v": 5,
  "type": "start_idalib",
  "id": "<uuid-v4>",
  "src": "agent-1",
  "dst": "bridge",
  "input": "/srv/binaries/sample",
  "out_idb": "/srv/idbs/sample.i64",
  "force": true,
  "arch": "arm64",
  "wait_s": 300
}
```

Fields:
- exactly one of `idb` or `input` is required
- `out_idb` is required with `input`
- `force`, `arch`, and `dyld_module` are valid only with `input`
- `arch` and `dyld_module` are mutually exclusive
- `python` selects an interpreter on the bridge host; omission uses the bridge host's default idalib venv
- `wait_s` is the maximum readiness wait and defaults to 300 seconds

Connected response:

```json
{
  "v": 5,
  "type": "start_idalib_response",
  "id": "<uuid-v4>",
  "src": "bridge",
  "dst": "agent-1",
  "ok": true,
  "status": "connected",
  "client_id": "idalib-4242",
  "pid": 4242,
  "idb_path": "/srv/idbs/sample.i64",
  "log": "/srv/logs/idalib-4242.log"
}
```

If the child is still running when `wait_s` expires, the same success response has `status = "waiting"` and no `client_id`. The bridge continues to manage the child. A validation or early-exit failure returns `ok = false` with `code = "START_FAILED"`.

### `stop_idalib`

Stops a headless idalib on the bridge host without saving. The target is a connected idalib `client_id`, a connected idalib PID, or the PID of a child previously started by this bridge. Numeric targets do not authorize arbitrary process termination.

```json
{
  "v": 5,
  "type": "stop_idalib",
  "id": "<uuid-v4>",
  "src": "agent-1",
  "dst": "bridge",
  "target": "idalib-4242"
}
```

The bridge first sends its own correlated `quit` request to a connected idalib. If graceful shutdown fails or times out, it terminates that PID on the bridge host. UI IDA clients are rejected.

```json
{
  "v": 5,
  "type": "stop_idalib_response",
  "id": "<uuid-v4>",
  "src": "bridge",
  "dst": "agent-1",
  "ok": true,
  "method": "quit",
  "client_id": "idalib-4242",
  "pid": 4242
}
```

`method` is one of `quit`, `already_dead`, `sigterm`, or `sigkill`. Failures use `TARGET_NOT_FOUND`, `INVALID_TARGET_ROLE`, or `STOP_FAILED`.

## Ownership and lifecycle semantics

`exec` and `reset` participate in exec-environment ownership.

Rules:
- stateless `exec` (`persist=false`) does not create stateful ownership and is forwarded with `reset_env=true` when no stateful owner exists
- stateful `exec` (`persist=true`) claims an unowned target for its `session_id`
- the same `session_id` continues and refreshes the ownership TTL
- a different `session_id` gets `SESSION_CONFLICT`
- stateless `exec` gets `SESSION_CONFLICT` while a stateful owner exists
- normal `reset` keeps ownership
- `reset --release` clears ownership after a successful reset response
- while release is in flight, requests get `RELEASE_PENDING`
- `reset --takeover` transfers ownership to a new session
- while takeover is in flight, requests get `TAKEOVER_PENDING`
- if takeover or release outcome is unknown, the target is locked with `SESSION_LOCKED` until reconnect
- agent disconnect does not clear ownership
- IDA disconnect clears ownership

Lifecycle:
- `save` uses an exec request and may run stateless or through an existing stateful session
- `quit` bypasses ownership because it is a lifecycle action, not exec-environment access
- remote `start_idalib` and `stop_idalib` are bridge-host process operations and do not participate in exec ownership
- `stop_idalib` does not save the database

Ownership policy lives in the bridge, not in the IDA runtime.

## Bridge-originated request failures

When the bridge cannot deliver or complete an agent -> ida request without an IDA response, it replies directly to the agent with the matching `*_response` message:
- same `id`
- `src = bridge`
- `dst = agent`
- `ok = false`

Codes:
- `TARGET_NOT_FOUND`: target was not connected at routing time
- `TARGET_DISCONNECTED`: target disconnected before responding
- `TARGET_PING_TIMEOUT`: target connection died due to keepalive timeout
- `TIMEOUT`: bridge-side request timeout
- `QUEUE_FULL`: IDA runtime rejected the request because its request queue is full
- `SESSION_CONFLICT`: target exec environment is owned by another session
- `TAKEOVER_PENDING`: ownership transfer in progress
- `RELEASE_PENDING`: ownership release in progress
- `SESSION_LOCKED`: ownership unknown after failed or timed-out takeover/release
- `START_FAILED`: the bridge host rejected or failed an idalib launch
- `STOP_FAILED`: the bridge host could not stop a resolved idalib process

Remote lifecycle validation and process failures likewise use the matching `start_idalib_response` or `stop_idalib_response` with `src = bridge`, `ok = false`, and do not close the agent connection.

## Protocol errors

`ProtocolError` is bridge-only, fatal, and immediately followed by connection close.

Example:

```json
{
  "v": 5,
  "type": "error",
  "code": "INVALID_MESSAGE",
  "message": "invalid message",
  "trace": {"...": "..."}
}
```

Close codes:
- `1002` (`WS_CLOSE_PROTOCOL_ERROR`): parse or format errors
- `1008` (`WS_CLOSE_POLICY_VIOLATION`): policy, routing, or state violations

Connection-level error codes:
- `INVALID_JSON`
- `UNSUPPORTED_FRAME`
- `MISSING_VERSION`
- `UNSUPPORTED_VERSION`
- `HANDSHAKE_REQUIRED`
- `DUPLICATE_HELLO`
- `INVALID_ROLE`
- `INVALID_CLIENT_ID`
- `DUPLICATE_CLIENT_ID`
- `SRC_MISMATCH`
- `UNSUPPORTED_MESSAGE`
- `DUPLICATE_REQUEST_ID`
- `RESPONSE_MISMATCH`
- `INVALID_STATE`
- `INVALID_MESSAGE`
- `INVALID_REQUEST_ID`
- `INVALID_TARGET_ROLE`

`INVALID_TARGET_ROLE` is also a normal `stop_idalib_response` code when a remote stop names a connected non-idalib client.

## Correlation, ordering, and concurrency

- multiple requests may be in flight concurrently
- responses may arrive out of order
- clients must correlate by `id`
- the bridge enforces strict response correlation by `(id, route, response type)`
- late responses for timed-out or dropped requests are discarded

The bridge runs on one asyncio event loop. Connection handlers can still interleave at `await` points.

A failure on one connection must not close unrelated connections.

If the source disconnects, the bridge usually drops that source's pending requests. Forwarded takeover and release resets are retained until they resolve because they affect ownership state.

## Timeouts

The bridge enforces request timeouts for agent -> ida routed requests.

- default timeout comes from `IDA_BRIDGE_DEFAULT_TIMEOUT_S` and defaults to `60`
- requests may override it with `timeout_s`
- on timeout, the bridge replies with `ok = false` and `code = "TIMEOUT"`
- if IDA later responds for that `id`, the bridge drops the response

## Security

- no authentication or authorization
- messages can request code execution inside IDA
- remote lifecycle messages can launch idalib and terminate validated idalib PIDs on the bridge host
- do not expose the bridge to untrusted networks
