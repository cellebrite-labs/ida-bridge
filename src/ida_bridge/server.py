import asyncio
import contextlib
from dataclasses import dataclass
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
from typing import Any

import websockets
from websockets.asyncio.server import ServerConnection
from websockets.exceptions import ConnectionClosed

from ida_bridge import logs, protocol

DEFAULT_MAX_MESSAGE_BYTES = 64 * 1024 * 1024

_DEFAULT_SERVER_LOG_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_SERVER_LOG_BACKUP_COUNT = 3

_configure_logging_done = False


def _configure_logging() -> None:
    """Configure the bridge server's root logger. Idempotent."""
    global _configure_logging_done
    if _configure_logging_done:
        return
    _configure_logging_done = True

    level = getattr(logging, os.getenv("IDA_BRIDGE_LOG_LEVEL", "INFO").upper(), logging.INFO)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    log_file = os.getenv("IDA_BRIDGE_LOG_FILE")
    if log_file:
        path = Path(log_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)

        max_bytes = int(os.getenv("IDA_BRIDGE_LOG_MAX_BYTES", str(_DEFAULT_SERVER_LOG_MAX_BYTES)))
        backup_count = int(os.getenv("IDA_BRIDGE_LOG_BACKUP_COUNT", str(_DEFAULT_SERVER_LOG_BACKUP_COUNT)))

        handler = RotatingFileHandler(
            path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
    else:
        handler = logging.StreamHandler(stream=sys.stdout)

    handler.setFormatter(logs.make_formatter())
    root.addHandler(handler)

    logging.getLogger("websockets").setLevel(logging.WARNING)


log = logging.getLogger("ida-bridge")


class _AbortConnection(Exception):
    pass


@dataclass
class _Client:
    ws: ServerConnection
    role: protocol.ClientRole
    meta: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _Owned:
    session_id: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class _TakeoverPending:
    from_session_id: str
    to_session_id: str
    req_id: str


@dataclass(frozen=True, slots=True)
class _ReleasePending:
    session_id: str
    req_id: str


@dataclass(frozen=True, slots=True)
class _LockedUnknown:
    pass


_LOCKED_UNKNOWN = _LockedUnknown()

type _OwnershipState = _Owned | _TakeoverPending | _ReleasePending | _LockedUnknown


@dataclass(frozen=True, slots=True)
class _Pending:
    agent_id: str
    ida_id: str
    req_type: str
    deadline: float | None
    timeout_s: int | None
    takeover: _TakeoverPending | None = None
    release: _ReleasePending | None = None


@dataclass(frozen=True, slots=True)
class _ForwardReject:
    code: str
    message: str
    trace: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class _ExecEnvPolicy:
    msg: protocol.ExecRequest | protocol.ResetRequest
    claimed_owner: bool = False
    takeover: _TakeoverPending | None = None
    release: _ReleasePending | None = None
    reject: _ForwardReject | None = None


class BridgeServer:
    @property
    def bridge_id(self) -> str:
        return self._bridge_id

    @property
    def max_message_bytes(self) -> int:
        return self._max_message_bytes

    def __init__(
        self,
        *,
        bridge_client_id: str | None = None,
        default_timeout_s: int | None = None,
        timeout_tick_s: float = 0.5,
        instance_id: str | None = None,
        stateful_ttl_s: float | None = None,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ):
        # Most defaults come from env (main() reads the message limit); tests override via ctor.
        bridge_id = bridge_client_id if bridge_client_id is not None else os.getenv("IDA_BRIDGE_CLIENT_ID", "bridge")
        if not bridge_id:
            raise ValueError("bridge_client_id must be a non-empty string")

        dt = (
            default_timeout_s if default_timeout_s is not None else int(os.getenv("IDA_BRIDGE_DEFAULT_TIMEOUT_S", "60"))
        )
        if dt < 0:
            raise ValueError("default_timeout_s must be >= 0")

        if timeout_tick_s <= 0:
            raise ValueError("timeout_tick_s must be > 0")

        ttl = stateful_ttl_s if stateful_ttl_s is not None else float(os.getenv("IDA_BRIDGE_STATEFUL_TTL_S", "3600"))
        if ttl <= 0:
            raise ValueError("stateful_ttl_s must be > 0")

        self._bridge_id = bridge_id
        self._default_timeout_s = dt
        self._timeout_tick_s = float(timeout_tick_s)
        self._stateful_ttl_s = float(ttl)
        self._instance_id = instance_id or f"bridge-{os.getpid()}"
        if max_message_bytes < protocol.MIN_MESSAGE_BYTES:
            raise ValueError(
                f"max_message_bytes must be >= {protocol.MIN_MESSAGE_BYTES} (IDA_BRIDGE_MAX_MESSAGE_BYTES)"
            )
        self._max_message_bytes = max_message_bytes

        self._timeout_task: asyncio.Task[None] | None = None
        self._log_prune_task: asyncio.Task[None] | None = None

        # client_id -> _Client
        self._clients: dict[str, _Client] = {}
        # ws -> client_id
        self._by_ws: dict[ServerConnection, str] = {}

        # req_id -> _Pending
        self._pending: dict[str, _Pending] = {}

        # ida client_id -> exec environment ownership state
        self._ownership_by_ida: dict[str, _OwnershipState] = {}

        # client_ids whose WebSocket closed due to keepalive ping timeout
        # (vs socket drop or clean close).  Consumed by _disconnect().
        self._ping_timeouts: set[str] = set()

    def _owned(self, session_id: str) -> _Owned:
        return _Owned(session_id=session_id, expires_at=asyncio.get_running_loop().time() + self._stateful_ttl_s)

    def _expire_ownerships(self, now: float | None = None) -> None:
        current_time = asyncio.get_running_loop().time() if now is None else now
        for ida_id, ownership in list(self._ownership_by_ida.items()):
            if isinstance(ownership, _Owned) and ownership.expires_at <= current_time:
                self._clear_ownership(ida_id)

    def _get_ownership(self, ida_id: str) -> _OwnershipState | None:
        self._expire_ownerships()
        return self._ownership_by_ida.get(ida_id)

    def _claim_owner(self, ida_id: str, session_id: str) -> None:
        self._ownership_by_ida[ida_id] = self._owned(session_id)

    def _refresh_owner(self, ida_id: str, session_id: str) -> None:
        self._ownership_by_ida[ida_id] = self._owned(session_id)

    def _enter_takeover(self, ida_id: str, takeover: _TakeoverPending) -> None:
        self._ownership_by_ida[ida_id] = takeover

    def _enter_release(self, ida_id: str, release: _ReleasePending) -> None:
        self._ownership_by_ida[ida_id] = release

    def _clear_ownership(self, ida_id: str) -> None:
        self._ownership_by_ida.pop(ida_id, None)

    def _lock_takeover_unknown(self, ida_id: str, takeover: _TakeoverPending) -> None:
        if self._ownership_by_ida.get(ida_id) == takeover:
            self._ownership_by_ida[ida_id] = _LOCKED_UNKNOWN

    def _lock_release_unknown(self, ida_id: str, release: _ReleasePending) -> None:
        if self._ownership_by_ida.get(ida_id) == release:
            self._ownership_by_ida[ida_id] = _LOCKED_UNKNOWN

    def _commit_takeover(self, ida_id: str, takeover: _TakeoverPending, *, ok: bool) -> None:
        if self._ownership_by_ida.get(ida_id) != takeover:
            return
        if ok:
            self._ownership_by_ida[ida_id] = self._owned(takeover.to_session_id)
        else:
            self._ownership_by_ida[ida_id] = _LOCKED_UNKNOWN

    def _commit_release(self, ida_id: str, release: _ReleasePending, *, ok: bool) -> None:
        if self._ownership_by_ida.get(ida_id) != release:
            return
        if ok:
            self._clear_ownership(ida_id)
        else:
            self._ownership_by_ida[ida_id] = self._owned(release.session_id)

    def _restore_owner(self, ida_id: str, takeover: _TakeoverPending) -> None:
        if self._ownership_by_ida.get(ida_id) == takeover:
            self._ownership_by_ida[ida_id] = self._owned(takeover.from_session_id)

    def _restore_release_owner(self, ida_id: str, release: _ReleasePending) -> None:
        if self._ownership_by_ida.get(ida_id) == release:
            self._ownership_by_ida[ida_id] = self._owned(release.session_id)

    def serve(self, host: str, port: int, **ws_kwargs: Any) -> websockets.asyncio.server.serve:
        return websockets.serve(self.handler, host, port, max_size=self._max_message_bytes, **ws_kwargs)

    def start_background_tasks(self) -> None:
        """Start long-running background tasks.

        Tests should call this explicitly to avoid copying task wiring.
        """

        if self._timeout_task and not self._timeout_task.done():
            return
        self._timeout_task = asyncio.create_task(self._timeout_loop(), name="ida-bridge-timeouts")
        self._log_prune_task = asyncio.create_task(self._log_prune_loop(), name="ida-bridge-log-prune")

    async def stop_background_tasks(self) -> None:
        tasks = [self._timeout_task, self._log_prune_task]
        self._timeout_task = None
        self._log_prune_task = None
        for task in tasks:
            if not task:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def _log_prune_loop(self) -> None:
        """Server-owned instance-log GC: prune at startup, then on a fixed cadence.

        Single owner means no multi-writer race over the log directory. Prune runs
        in a worker thread so its filesystem I/O never stalls the event loop.
        """
        while True:
            await asyncio.to_thread(logs.prune_instance_logs)
            await asyncio.sleep(logs.LOG_PRUNE_INTERVAL_S)

    async def _timeout_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(self._timeout_tick_s)
            now = loop.time()
            self._expire_ownerships(now)

            expired: list[tuple[str, _Pending]] = [
                (req_id, pending)
                for req_id, pending in list(self._pending.items())
                if pending.deadline is not None and pending.deadline <= now
            ]

            for req_id, pending in expired:
                # Only one loop iteration should handle each id.
                popped = self._pending.pop(req_id, None)
                if not popped:
                    continue

                if pending.takeover is not None:
                    self._lock_takeover_unknown(pending.ida_id, pending.takeover)
                elif pending.release is not None:
                    self._lock_release_unknown(pending.ida_id, pending.release)

                log.debug(
                    "Request timed out: id=%s agent=%s ida=%s",
                    req_id[:8],
                    pending.agent_id,
                    pending.ida_id,
                )

                agent = self._clients.get(pending.agent_id)
                if not agent:
                    continue

                payload = self._error_response(
                    pending.req_type,
                    req_id,
                    dst=pending.agent_id,
                    code=protocol.ERR_TIMEOUT,
                    message="request timed out",
                    trace={
                        "timeout_s": pending.timeout_s,
                        "ida_id": pending.ida_id,
                    },
                )
                await self._send_best_effort(agent.ws, payload, context="timeout")

    async def handler(self, ws: ServerConnection) -> None:
        client_role: protocol.ClientRole | None = None
        client_id: str | None = None

        try:
            async for message in ws:
                if not isinstance(message, str):
                    # Protocol is JSON-over-text-websocket only.
                    log.warning(
                        "Rejecting non-text websocket frame: type=%s len=%s",
                        type(message).__name__,
                        len(message),
                    )
                    await self._protocol_error(
                        ws,
                        code=protocol.ERR_UNSUPPORTED_FRAME,
                        message="binary websocket frames are not supported",
                        trace={"frame_type": type(message).__name__},
                        close_code=protocol.WS_CLOSE_PROTOCOL_ERROR,
                    )
                    return

                try:
                    parsed = protocol.parse_message_json(message)
                except protocol.ValidationError as exc:
                    code, err_msg, trace = protocol.classify_validation_error(exc)
                    await self._protocol_error(
                        ws,
                        code=code,
                        message=err_msg,
                        trace=trace,
                        close_code=protocol.WS_CLOSE_PROTOCOL_ERROR,
                    )
                    return

                # role comes from hello, and hello must be the first message
                if client_role is None and not isinstance(parsed, protocol.Hello):
                    await self._protocol_error(
                        ws,
                        code=protocol.ERR_HANDSHAKE_REQUIRED,
                        message="first message must be hello",
                        trace={"type": getattr(parsed, "type", None)},
                    )
                    return

                if isinstance(parsed, protocol.Hello):
                    if client_role is not None:
                        await self._protocol_error(
                            ws,
                            code=protocol.ERR_DUPLICATE_HELLO,
                            message="hello already received",
                        )
                        return

                    client_role, client_id = await self._handle_hello(ws, parsed)
                    continue

                if isinstance(parsed, protocol.ProtocolError):
                    await self._protocol_error(
                        ws,
                        code=protocol.ERR_UNSUPPORTED_MESSAGE,
                        message="protocol_error is bridge-only",
                    )
                    return

                # After handshake, clients may only send routed messages (must carry id/src/dst).
                if not isinstance(parsed, protocol.RoutedBase):
                    await self._protocol_error(
                        ws,
                        code=protocol.ERR_UNSUPPORTED_MESSAGE,
                        message="unsupported message type for state",
                        trace={"type": parsed.type},
                    )
                    return

                # Anti-spoofing: src must match the handshake client_id.
                if parsed.src != client_id:
                    await self._protocol_error(
                        ws,
                        code=protocol.ERR_SRC_MISMATCH,
                        message="src does not match authenticated client_id",
                        trace={"src": parsed.src, "client_id": client_id},
                    )
                    return

                if parsed.dst == self._bridge_id:
                    if not isinstance(parsed, protocol.RequestBase):
                        await self._protocol_error(
                            ws,
                            code=protocol.ERR_UNSUPPORTED_MESSAGE,
                            message="unsupported message to bridge",
                            trace={"type": parsed.type},
                        )
                        return
                    await self._handle_msg_to_bridge(ws, client_id, client_role, parsed)
                    continue

                if client_role == protocol.ROLE_AGENT:
                    if not isinstance(parsed, protocol.RequestBase):
                        await self._protocol_error(
                            ws,
                            code=protocol.ERR_UNSUPPORTED_MESSAGE,
                            message="agents may only send requests",
                            trace={"type": parsed.type},
                        )
                        return
                    await self._handle_agent_message(ws, client_id, parsed)
                elif client_role == protocol.ROLE_IDA:
                    if not isinstance(parsed, protocol.ResponseBase):
                        await self._protocol_error(
                            ws,
                            code=protocol.ERR_UNSUPPORTED_MESSAGE,
                            message="ida clients may only send responses",
                            trace={"type": parsed.type},
                        )
                        return
                    await self._handle_ida_message(ws, client_id, parsed)
                else:
                    await self._protocol_error(
                        ws,
                        code=protocol.ERR_INVALID_STATE,
                        message="invalid server state",
                        trace={"role": client_role},
                    )
                    return

        except _AbortConnection:
            pass
        except ConnectionClosed as exc:
            if client_id and exc.sent and "keepalive ping timeout" in (exc.sent.reason or ""):
                log.warning(
                    "IDA ping timeout: %s (pong not received within deadline)",
                    client_id,
                )
                self._mark_ping_timeout(client_id)
        except Exception:
            log.exception("Handler error")
            try:
                await ws.close(code=1011, reason="internal error")
            except Exception:
                pass
        finally:
            if client_id:
                await self._disconnect(client_id)

    def _mark_ping_timeout(self, client_id: str) -> None:
        """Flag a client whose connection was lost due to keepalive ping timeout."""
        self._ping_timeouts.add(client_id)

    async def _disconnect(self, client_id: str) -> None:
        client = self._clients.pop(client_id, None)
        if not client:
            return
        self._by_ws.pop(client.ws, None)
        ping_timeout = client_id in self._ping_timeouts
        self._ping_timeouts.discard(client_id)

        if client.role == protocol.ROLE_AGENT:
            log.info("Agent disconnected: %s", client_id)

            # Drop in-flight requests owned by this agent. Keep forwarded ownership
            # transition resets pending until they resolve because they affect target ownership.
            for req_id, pending in list(self._pending.items()):
                if pending.agent_id == client_id and pending.takeover is None and pending.release is None:
                    self._pending.pop(req_id, None)

        if client.role == protocol.ROLE_IDA:
            self._clear_ownership(client_id)

            idb = os.path.basename(client.meta.get("idb_path", "")) or "(no idb)"
            if ping_timeout:
                log.info("IDA ping timeout: %s [%s]", client_id, idb)
                err_code = protocol.ERR_TARGET_PING_TIMEOUT
                err_msg = "keepalive ping timeout"
            else:
                log.info("IDA disconnected: %s [%s]", client_id, idb)
                err_code = protocol.ERR_TARGET_DISCONNECTED
                err_msg = "IDA disconnected"

            # Fail pending requests for this IDA client.
            for req_id, pending in list(self._pending.items()):
                if pending.ida_id != client_id:
                    continue
                self._pending.pop(req_id, None)

                agent = self._clients.get(pending.agent_id)
                if not agent:
                    continue

                payload = self._error_response(
                    pending.req_type,
                    req_id,
                    dst=pending.agent_id,
                    code=err_code,
                    message=err_msg,
                    trace={"ida_id": client_id},
                )
                await self._send_best_effort(agent.ws, payload, context="disconnect_ida")

    async def _protocol_error(
        self,
        ws: ServerConnection,
        *,
        code: str,
        message: str,
        trace: dict[str, Any] | None = None,
        close_code: int = protocol.WS_CLOSE_POLICY_VIOLATION,
    ) -> None:
        payload = protocol.ProtocolError(code=code, message=message, trace=trace)

        try:
            await self._send(ws, payload)
        except Exception:
            pass

        try:
            await ws.close(code=close_code, reason=str(message)[:120])
        except Exception:
            pass

    async def _handle_hello(self, ws: ServerConnection, msg: protocol.Hello) -> tuple[protocol.ClientRole, str]:
        client_id = msg.client_id
        if not client_id:
            await self._protocol_error(
                ws,
                code=protocol.ERR_INVALID_CLIENT_ID,
                message="client_id must be a non-empty string",
            )
            raise _AbortConnection()

        if client_id == self._bridge_id:
            await self._protocol_error(
                ws,
                code=protocol.ERR_INVALID_CLIENT_ID,
                message="client_id is reserved",
                trace={"client_id": client_id},
            )
            raise _AbortConnection()

        if client_id in self._clients:
            await self._protocol_error(
                ws,
                code=protocol.ERR_DUPLICATE_CLIENT_ID,
                message="duplicate client_id",
                trace={"client_id": client_id},
            )
            raise _AbortConnection()

        self._clients[client_id] = _Client(ws=ws, role=msg.role, meta=msg.meta)
        self._by_ws[ws] = client_id

        if msg.role == protocol.ROLE_AGENT:
            log.info("Agent connected: %s tool=%s pid=%s", client_id, msg.meta.get("tool"), msg.meta.get("pid"))
        elif msg.role == protocol.ROLE_IDA:
            idb = os.path.basename(msg.meta.get("idb_path", "")) or "(no idb)"
            log.info("IDA connected: %s [%s]", client_id, idb)

        ack = protocol.HelloAck(
            client_id=client_id,
            bridge_id=self._bridge_id,
            max_message_bytes=self._max_message_bytes,
            meta={
                "server": "ida-bridge",
                "instance_id": self._instance_id,
            },
        )
        ok = await self._send_best_effort(ws, ack, context="hello_ack")
        if not ok:
            self._clients.pop(client_id, None)
            self._by_ws.pop(ws, None)
            with contextlib.suppress(Exception):
                await ws.close(code=1011, reason="failed to send hello_ack")
            raise _AbortConnection()

        return msg.role, client_id

    async def _handle_msg_to_bridge(
        self,
        ws: ServerConnection,
        client_id: str,
        client_role: protocol.ClientRole,
        msg: protocol.RequestBase,
    ) -> None:
        if client_role != protocol.ROLE_AGENT:
            await self._protocol_error(
                ws,
                code=protocol.ERR_UNSUPPORTED_MESSAGE,
                message="only agents may send messages to bridge",
                trace={"role": client_role, "type": msg.type},
            )
            return

        if isinstance(msg, protocol.ListRequest):
            await self._handle_list(ws, client_id, msg)
            return

        await self._protocol_error(
            ws,
            code=protocol.ERR_UNSUPPORTED_MESSAGE,
            message="unsupported message to bridge",
            trace={"type": msg.type},
        )

    async def _handle_agent_message(self, ws: ServerConnection, client_id: str, msg: protocol.RequestBase) -> None:
        if isinstance(msg, (protocol.ExecRequest, protocol.ResetRequest)):
            await self._forward_to_ida(client_id, msg)
            return

        if isinstance(msg, protocol.QuitRequest):
            await self._forward_quit_to_ida(client_id, msg)
            return

        await self._protocol_error(
            ws,
            code=protocol.ERR_UNSUPPORTED_MESSAGE,
            message="unsupported message type for role",
            trace={"role": protocol.ROLE_AGENT, "type": msg.type},
        )

    async def _handle_ida_message(self, ws: ServerConnection, client_id: str, msg: protocol.ResponseBase) -> None:
        if isinstance(msg, (protocol.ExecResponse, protocol.ResetResponse, protocol.QuitResponse)):
            await self._forward_to_agent(client_id, msg)
            return

        await self._protocol_error(
            ws,
            code=protocol.ERR_UNSUPPORTED_MESSAGE,
            message="unsupported message type for role",
            trace={"role": protocol.ROLE_IDA, "type": msg.type},
        )

    async def _handle_list(self, ws: ServerConnection, agent_id: str, msg: protocol.ListRequest) -> None:
        kind = msg.kind
        clients: list[protocol.ClientInfo] = []

        include_ida = kind in (protocol.LIST_KIND_IDA, protocol.LIST_KIND_ALL)
        include_agent = kind == protocol.LIST_KIND_ALL

        for cid, info in self._clients.items():
            if info.role == protocol.ROLE_IDA and include_ida:
                ownership = self._get_ownership(cid)
                sid = ownership.session_id if isinstance(ownership, _Owned) else None
                clients.append(
                    protocol.ClientInfo(client_id=cid, role=protocol.ROLE_IDA, meta=info.meta, session_id=sid)
                )
            elif info.role == protocol.ROLE_AGENT and include_agent:
                clients.append(protocol.ClientInfo(client_id=cid, role=protocol.ROLE_AGENT, meta=info.meta))

        # Deterministic ordering.
        clients.sort(key=lambda c: c.client_id)

        payload = protocol.ListResponse(
            id=msg.id,
            src=self._bridge_id,
            dst=agent_id,
            ok=True,
            kind=kind,
            clients=clients,
        )
        ok = await self._send_best_effort(ws, payload, context="list")
        if not ok:
            await self._disconnect(agent_id)

    def _apply_exec_env_policy(self, msg: protocol.ExecRequest | protocol.ResetRequest) -> _ExecEnvPolicy:
        ownership = self._get_ownership(msg.dst)

        def trace_with_session(*, current_session_id: str | None = None) -> dict[str, Any]:
            trace = {"target_client_id": msg.dst}
            if current_session_id is not None:
                trace["current_session_id"] = current_session_id
            if msg.session_id is not None:
                trace["requested_session_id"] = msg.session_id
            return trace

        # Pending/locked ownership blocks every exec/reset request.
        if isinstance(ownership, _TakeoverPending):
            return _ExecEnvPolicy(
                msg=msg,
                reject=_ForwardReject(
                    code=protocol.ERR_TAKEOVER_PENDING,
                    message="ownership transfer in progress",
                    trace=trace_with_session(),
                ),
            )

        if isinstance(ownership, _ReleasePending):
            return _ExecEnvPolicy(
                msg=msg,
                reject=_ForwardReject(
                    code=protocol.ERR_RELEASE_PENDING,
                    message="ownership release in progress",
                    trace=trace_with_session(current_session_id=ownership.session_id),
                ),
            )

        if isinstance(ownership, _LockedUnknown):
            return _ExecEnvPolicy(
                msg=msg,
                reject=_ForwardReject(
                    code=protocol.ERR_SESSION_LOCKED,
                    message="target exec environment ownership is locked",
                    trace=trace_with_session(),
                ),
            )

        # Stateless exec never claims ownership; it only runs when no stateful owner exists.
        if isinstance(msg, protocol.ExecRequest) and not msg.persist:
            # not owned - good + enforce env reset
            if ownership is None:
                return _ExecEnvPolicy(msg=msg.model_copy(update={"reset_env": True}))

            # owned - error
            if isinstance(ownership, _Owned):
                return _ExecEnvPolicy(
                    msg=msg,
                    reject=_ForwardReject(
                        code=protocol.ERR_SESSION_CONFLICT,
                        message="target exec environment is in stateful mode",
                        trace={
                            "target_client_id": msg.dst,
                            "current_session_id": ownership.session_id,
                        },
                    ),
                )
            msg_err = f"Unexpected ownership state for {msg.dst}: {ownership!r}"
            raise AssertionError(msg_err)

        session_id = msg.session_id
        if session_id is None:
            msg_err = f"stateful request missing session_id: {msg!r}"
            raise AssertionError(msg_err)

        release = isinstance(msg, protocol.ResetRequest) and msg.release

        # Stateful exec/reset claims an unowned target unless this is release-only reset.
        if ownership is None:
            if release:
                return _ExecEnvPolicy(msg=msg)

            self._claim_owner(msg.dst, session_id)
            if isinstance(msg, protocol.ExecRequest):
                msg = msg.model_copy(update={"reset_env": True})
            return _ExecEnvPolicy(msg=msg, claimed_owner=True)

        # Owned targets require the matching session, except explicit reset takeover.
        if isinstance(ownership, _Owned):
            if ownership.session_id != session_id:
                if isinstance(msg, protocol.ResetRequest) and msg.takeover:
                    takeover = _TakeoverPending(
                        from_session_id=ownership.session_id,
                        to_session_id=session_id,
                        req_id=msg.id,
                    )
                    self._enter_takeover(msg.dst, takeover)
                    return _ExecEnvPolicy(msg=msg, takeover=takeover)

                return _ExecEnvPolicy(
                    msg=msg,
                    reject=_ForwardReject(
                        code=protocol.ERR_SESSION_CONFLICT,
                        message="target exec environment is owned by another session",
                        trace={
                            "target_client_id": msg.dst,
                            "current_session_id": ownership.session_id,
                            "requested_session_id": session_id,
                        },
                    ),
                )
            if release:
                release_pending = _ReleasePending(session_id=session_id, req_id=msg.id)
                self._enter_release(msg.dst, release_pending)
                return _ExecEnvPolicy(msg=msg, release=release_pending)

            self._refresh_owner(msg.dst, session_id)
            if isinstance(msg, protocol.ExecRequest):
                msg = msg.model_copy(update={"reset_env": False})
            return _ExecEnvPolicy(msg=msg)

        msg_err = f"Unexpected ownership state for {msg.dst}: {ownership!r}"
        raise AssertionError(msg_err)

    async def _forward_to_ida(self, agent_id: str, msg: protocol.ExecRequest | protocol.ResetRequest) -> None:
        async def reject(
            request: protocol.ExecRequest | protocol.ResetRequest,
            rejection: _ForwardReject,
        ) -> None:
            agent = self._clients.get(agent_id)
            if not agent:
                return

            payload = self._error_response(
                request.type,
                request.id,
                dst=agent_id,
                code=rejection.code,
                message=rejection.message,
                trace=rejection.trace,
            )
            ok = await self._send_best_effort(agent.ws, payload, context=f"reject:{rejection.code}")
            if not ok:
                await self._disconnect(agent_id)

        dst_client = self._clients.get(msg.dst)
        if not dst_client:
            await reject(
                msg,
                _ForwardReject(code=protocol.ERR_TARGET_NOT_FOUND, message="target not found", trace={"dst": msg.dst}),
            )
            return

        if dst_client.role != protocol.ROLE_IDA:
            # This should be impossible when using our agent client API.
            # Treat it as a protocol-level fault to surface bugs early.
            log.error(
                "Agent sent %s to non-IDA destination: agent=%s dst=%s dst_role=%s",
                msg.type,
                agent_id,
                msg.dst,
                dst_client.role,
            )
            await self._protocol_error(
                self._clients[agent_id].ws,
                code=protocol.ERR_INVALID_TARGET_ROLE,
                message="destination must be an ida client",
                trace={"dst": msg.dst, "dst_role": dst_client.role},
            )
            return

        # Basic duplicate request protection. This is connection-level and deliberately strict.
        if msg.id in self._pending:
            await self._protocol_error(
                self._clients[agent_id].ws,
                code=protocol.ERR_DUPLICATE_REQUEST_ID,
                message="duplicate request id",
                trace={"id": msg.id},
            )
            return

        policy = self._apply_exec_env_policy(msg)
        if policy.reject is not None:
            await reject(msg, policy.reject)
            return

        msg = policy.msg

        timeout_s = self._default_timeout_s if msg.timeout_s is None else msg.timeout_s
        if timeout_s == 0:
            deadline = None
        else:
            deadline = asyncio.get_running_loop().time() + timeout_s

        log.info(
            "%s [%s] %s -> %s timeout_s=%s",
            msg.type,
            msg.id[:8],
            agent_id,
            msg.dst,
            timeout_s,
        )
        self._pending[msg.id] = _Pending(
            agent_id=agent_id,
            ida_id=msg.dst,
            req_type=msg.type,
            deadline=deadline,
            timeout_s=timeout_s,
            takeover=policy.takeover,
            release=policy.release,
        )

        ok = await self._send_best_effort(dst_client.ws, msg, context="forward_to_ida")
        if not ok:
            # Roll back the pending entry; the request never reached IDA.
            self._pending.pop(msg.id, None)
            if policy.takeover is not None:
                self._restore_owner(msg.dst, policy.takeover)
            elif policy.release is not None:
                self._restore_release_owner(msg.dst, policy.release)
            elif policy.claimed_owner:
                self._clear_ownership(msg.dst)

            payload = self._error_response(
                msg.type,
                msg.id,
                dst=agent_id,
                code=protocol.ERR_TARGET_DISCONNECTED,
                message="target disconnected",
                trace={"dst": msg.dst},
            )
            agent = self._clients.get(agent_id)
            if agent:
                ok2 = await self._send_best_effort(agent.ws, payload, context="forward_to_ida_fail")
                if not ok2:
                    await self._disconnect(agent_id)
            await self._disconnect(msg.dst)
            return

    async def _forward_quit_to_ida(self, agent_id: str, msg: protocol.QuitRequest) -> None:
        """Route a quit request to IDA, bypassing session ownership."""
        dst_client = self._clients.get(msg.dst)
        if not dst_client:
            payload = self._error_response(
                msg.type,
                msg.id,
                dst=agent_id,
                code=protocol.ERR_TARGET_NOT_FOUND,
                message="target not found",
                trace={"dst": msg.dst},
            )
            agent = self._clients.get(agent_id)
            if not agent:
                return
            ok = await self._send_best_effort(agent.ws, payload, context="target_not_found")
            if not ok:
                await self._disconnect(agent_id)
            return

        if dst_client.role != protocol.ROLE_IDA:
            log.error(
                "Agent sent quit to non-IDA destination: agent=%s dst=%s dst_role=%s",
                agent_id,
                msg.dst,
                dst_client.role,
            )
            await self._protocol_error(
                self._clients[agent_id].ws,
                code=protocol.ERR_INVALID_TARGET_ROLE,
                message="destination must be an ida client",
                trace={"dst": msg.dst, "dst_role": dst_client.role},
            )
            return

        if msg.id in self._pending:
            await self._protocol_error(
                self._clients[agent_id].ws,
                code=protocol.ERR_DUPLICATE_REQUEST_ID,
                message="duplicate request id",
                trace={"id": msg.id},
            )
            return

        timeout_s = self._default_timeout_s if msg.timeout_s is None else msg.timeout_s
        if timeout_s == 0:
            deadline = None
        else:
            deadline = asyncio.get_running_loop().time() + timeout_s

        log.info(
            "quit [%s] %s -> %s timeout_s=%s",
            msg.id[:8],
            agent_id,
            msg.dst,
            timeout_s,
        )
        self._pending[msg.id] = _Pending(
            agent_id=agent_id,
            ida_id=msg.dst,
            req_type=msg.type,
            deadline=deadline,
            timeout_s=timeout_s,
        )

        ok = await self._send_best_effort(dst_client.ws, msg, context="forward_quit_to_ida")
        if not ok:
            self._pending.pop(msg.id, None)

            payload = self._error_response(
                msg.type,
                msg.id,
                dst=agent_id,
                code=protocol.ERR_TARGET_DISCONNECTED,
                message="target disconnected",
                trace={"dst": msg.dst},
            )
            agent = self._clients.get(agent_id)
            if agent:
                ok2 = await self._send_best_effort(agent.ws, payload, context="forward_quit_fail")
                if not ok2:
                    await self._disconnect(agent_id)
            await self._disconnect(msg.dst)
            return

    async def _forward_to_agent(
        self,
        ida_id: str,
        msg: protocol.ExecResponse | protocol.ResetResponse | protocol.QuitResponse,
    ) -> None:
        pending = self._pending.pop(msg.id, None)
        if not pending:
            # This can happen if the agent disconnected or the request timed out.
            # Drop the response without penalizing IDA.
            log.warning(
                "Dropping response for unknown id: ida=%s dst=%s type=%s id=%s",
                ida_id,
                msg.dst,
                msg.type,
                msg.id[:8],
            )
            return

        # Strict correlation.
        expected_cls = protocol.response_type(pending.req_type)
        if pending.ida_id != ida_id or pending.agent_id != msg.dst or not isinstance(msg, expected_cls):
            if pending.takeover is not None:
                self._lock_takeover_unknown(pending.ida_id, pending.takeover)
            elif pending.release is not None:
                self._lock_release_unknown(pending.ida_id, pending.release)
            await self._protocol_error(
                self._clients[ida_id].ws,
                code=protocol.ERR_RESPONSE_MISMATCH,
                message="response does not match pending request",
                trace={
                    "id": msg.id,
                    "expected": {
                        "ida_id": pending.ida_id,
                        "agent_id": pending.agent_id,
                        "response_type": expected_cls.model_fields["type"].default,
                    },
                    "got": {
                        "ida_id": ida_id,
                        "agent_id": msg.dst,
                        "response_type": msg.type,
                    },
                },
            )
            return

        if pending.takeover is not None:
            self._commit_takeover(pending.ida_id, pending.takeover, ok=msg.ok)
        elif pending.release is not None:
            self._commit_release(pending.ida_id, pending.release, ok=msg.ok)

        dst_client = self._clients.get(msg.dst)
        if not dst_client:
            # Agent disconnected; drop the response after applying any ownership transition.
            log.warning("Dropping response for disconnected agent: %s -> %s", ida_id, msg.dst)
            return

        if dst_client.role != protocol.ROLE_AGENT:
            await self._protocol_error(
                self._clients[ida_id].ws,
                code=protocol.ERR_INVALID_MESSAGE,
                message="destination must be an agent client",
                trace={"dst": msg.dst, "dst_role": dst_client.role},
            )
            return

        log.info("%s [%s] ok=%s", msg.type, msg.id[:8], msg.ok)
        ok = await self._send_best_effort(dst_client.ws, msg, context="forward_to_agent")
        if not ok:
            await self._disconnect(msg.dst)

    def _error_response(
        self,
        req_type: str,
        req_id: str,
        *,
        dst: str,
        code: str,
        message: str | None = None,
        trace: dict[str, Any] | None = None,
    ) -> protocol.ResponseBase:
        response_cls = protocol.response_type(req_type)
        return response_cls(id=req_id, src=self._bridge_id, dst=dst, ok=False, code=code, message=message, trace=trace)

    async def _send_best_effort(
        self,
        ws: ServerConnection,
        msg: protocol.Message,
        *,
        context: str | None = None,
    ) -> bool:
        """Send a message, treating disconnects as a normal condition.

        Returns False if the message could not be delivered due to connection close or send error.
        """

        try:
            await self._send(ws, msg)
            return True
        except ConnectionClosed:
            peer = self._by_ws.get(ws, "<unknown>")
            log.debug(
                "Send failed (connection closed): context=%s peer=%s type=%s",
                context or "<none>",
                peer,
                getattr(msg, "type", type(msg).__name__),
            )
            return False
        except Exception:
            peer = self._by_ws.get(ws, "<unknown>")
            log.warning(
                "Send failed: context=%s peer=%s type=%s",
                context or "<none>",
                peer,
                getattr(msg, "type", type(msg).__name__),
                exc_info=True,
            )
            return False

    async def _send(self, ws: ServerConnection, msg: protocol.Message) -> None:
        await ws.send(protocol.dump_message_json(msg))


async def main() -> None:
    _configure_logging()

    host = protocol.listen_host()
    port = protocol.bridge_port()
    max_message_bytes = int(os.getenv("IDA_BRIDGE_MAX_MESSAGE_BYTES", DEFAULT_MAX_MESSAGE_BYTES))
    server = BridgeServer(max_message_bytes=max_message_bytes)
    server.start_background_tasks()

    log.info("Starting server on %s:%s", host, port)
    # IDA plugins run exec on IDA's main thread while a background thread
    # handles WebSocket I/O.  Under heavy load Python's GIL can starve the
    # WS thread long enough to miss the default 20s pong deadline.  60s
    # accommodates these bursts while still detecting genuinely dead
    # connections.
    async with server.serve(host, port, ping_timeout=60):
        try:
            await asyncio.Future()
        finally:
            await server.stop_background_tasks()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
