import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any, NoReturn

from pydantic import ValidationError
import websockets
from websockets.exceptions import ConnectionClosed

from . import protocol


class BridgeProtocolError(RuntimeError):
    def __init__(self, err: protocol.ProtocolError):
        super().__init__(f"bridge protocol error: {err.code}: {err.message}")
        self.err = err


class BridgeDisconnected(RuntimeError):
    pass


@dataclass(frozen=True)
class _ConnState:
    ws: Any
    listener: asyncio.Task[None]


class AgentClient:
    """Agent-side client for the ida-bridge protocol.

    Fail-fast design:
    - If the websocket closes, pending requests fail.
    - Invalid inbound messages are treated as protocol errors.

    """

    _MAX_ABANDONED_IDS = 32

    def __init__(self, *, client_id: str, url: str | None = None):
        if not client_id:
            raise ValueError("client_id must be a non-empty string")

        self._client_id = client_id
        self._url = url or protocol.bridge_url()
        self._meta: dict[str, Any] = {}

        self._bridge_id: str | None = None
        self._bridge_meta: dict[str, Any] | None = None
        self._conn: _ConnState | None = None

        self._pending: dict[str, asyncio.Future[protocol.Message]] = {}
        # Request IDs abandoned due to local cancellation/timeout. We ignore late
        # responses for these without treating them as protocol violations.
        self._abandoned: set[str] = set()
        self._lock = asyncio.Lock()

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def bridge_id(self) -> str:
        if self._bridge_id is None:
            raise RuntimeError("not connected")
        return self._bridge_id

    @property
    def bridge_meta(self) -> dict[str, Any]:
        if self._bridge_meta is None:
            raise RuntimeError("not connected")
        return self._bridge_meta

    async def connect(self, *, meta: dict[str, Any] | None = None) -> None:
        if self._conn is not None:
            raise RuntimeError("already connected")

        ws = await websockets.connect(self._url, max_size=protocol.ws_max_size())

        try:
            # Handshake: hello must be first, and we expect hello_ack next.
            self._meta = meta or {}
            hello = protocol.Hello(role=protocol.ROLE_AGENT, client_id=self._client_id, meta=self._meta)
            await ws.send(protocol.dump_message_json(hello))

            raw = await ws.recv()
            if not isinstance(raw, str):
                await ws.close(code=protocol.WS_CLOSE_PROTOCOL_ERROR)
                raise BridgeDisconnected("bridge sent non-text websocket frame")

            try:
                msg = protocol.parse_message_json(raw)
            except ValidationError as exc:
                await ws.close(code=protocol.WS_CLOSE_PROTOCOL_ERROR)
                raise BridgeDisconnected(f"invalid handshake message: {exc}") from exc

            if isinstance(msg, protocol.ProtocolError):
                await ws.close(code=protocol.WS_CLOSE_POLICY_VIOLATION)
                raise BridgeProtocolError(msg)

            if not isinstance(msg, protocol.HelloAck):
                await ws.close(code=protocol.WS_CLOSE_POLICY_VIOLATION)
                raise BridgeDisconnected(f"expected hello_ack, got: {msg.type}")

            if msg.client_id != self._client_id:
                await ws.close(code=protocol.WS_CLOSE_POLICY_VIOLATION)
                raise BridgeDisconnected(
                    f"handshake client_id mismatch: expected={self._client_id} got={msg.client_id}"
                )

            self._bridge_id = msg.bridge_id
            self._bridge_meta = msg.meta

            listener = asyncio.create_task(
                self._listen(ws),
                name=f"ida-bridge-agent-listen:{self._client_id}",
            )
            self._conn = _ConnState(ws=ws, listener=listener)
            return None

        except Exception:
            await ws.close()
            raise

    def is_connected(self) -> bool:
        return self._conn is not None

    async def close(self) -> None:
        conn = self._conn
        self._conn = None

        # Fail any in-flight requests deterministically.
        self._fail_all(BridgeDisconnected("client closed"))
        self._abandoned.clear()

        self._bridge_id = None
        self._bridge_meta = None

        if conn is None:
            return

        conn.listener.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await conn.listener

        await conn.ws.close()

    async def list(self, kind: protocol.ListKind = protocol.LIST_KIND_IDA) -> protocol.ListResponse:
        bridge_id = self.bridge_id
        req = protocol.ListRequest(id=protocol.new_req_id(), src=self._client_id, dst=bridge_id, kind=kind)
        resp = await self._request(req)

        # Fail loudly: these are protocol invariants.
        if not isinstance(resp, protocol.ListResponse):
            await self._protocol_violation(f"expected list_response, got: {getattr(resp, 'type', type(resp).__name__)}")

        if resp.src != bridge_id:
            await self._protocol_violation(f"list_response src mismatch: expected={bridge_id} got={resp.src}")

        if resp.kind != kind:
            await self._protocol_violation(f"list_response kind mismatch: expected={kind} got={resp.kind}")

        return resp

    async def exec(
        self,
        dst: str,
        code: str,
        *,
        session_id: str | None = None,
        persist: bool = False,
        timeout_s: int | None = None,
    ) -> protocol.ExecResponse:
        if persist and session_id is None:
            msg = "session_id is required when persist=True"
            raise ValueError(msg)
        if (not persist) and session_id is not None:
            msg = "session_id is only valid when persist=True"
            raise ValueError(msg)

        req = protocol.ExecRequest(
            id=protocol.new_req_id(),
            src=self._client_id,
            dst=dst,
            session_id=session_id,
            persist=persist,
            code=code,
            timeout_s=timeout_s,
        )
        resp = await self._request(req)

        # Fail loudly: these are protocol invariants.
        if not isinstance(resp, protocol.ExecResponse):
            await self._protocol_violation(f"expected exec_response, got: {getattr(resp, 'type', type(resp).__name__)}")

        return resp

    async def reset(
        self,
        dst: str,
        *,
        session_id: str,
        takeover: bool = False,
        release: bool = False,
        timeout_s: int | None = None,
    ) -> protocol.ResetResponse:
        if takeover and release:
            msg = "takeover and release are mutually exclusive"
            raise ValueError(msg)

        req = protocol.ResetRequest(
            id=protocol.new_req_id(),
            src=self._client_id,
            dst=dst,
            session_id=session_id,
            takeover=takeover,
            release=release,
            timeout_s=timeout_s,
        )
        resp = await self._request(req)

        # Fail loudly: these are protocol invariants.
        if not isinstance(resp, protocol.ResetResponse):
            await self._protocol_violation(
                f"expected reset_response, got: {getattr(resp, 'type', type(resp).__name__)}"
            )

        return resp

    async def quit(
        self,
        dst: str,
        *,
        timeout_s: int | None = None,
    ) -> protocol.QuitResponse:
        req = protocol.QuitRequest(
            id=protocol.new_req_id(),
            src=self._client_id,
            dst=dst,
            timeout_s=timeout_s,
        )
        resp = await self._request(req)

        if not isinstance(resp, protocol.QuitResponse):
            await self._protocol_violation(f"expected quit_response, got: {getattr(resp, 'type', type(resp).__name__)}")

        return resp

    async def start_idalib(
        self,
        *,
        idb: str | None = None,
        input_file: str | None = None,
        out_idb: str | None = None,
        force: bool = False,
        arch: str | None = None,
        dyld_module: str | None = None,
        python: str | None = None,
        wait_s: float = 300.0,
    ) -> protocol.StartIdalibResponse:
        bridge_id = self.bridge_id
        req = protocol.StartIdalibRequest(
            id=protocol.new_req_id(),
            src=self._client_id,
            dst=bridge_id,
            idb=idb,
            input=input_file,
            out_idb=out_idb,
            force=force,
            arch=arch,
            dyld_module=dyld_module,
            python=python,
            wait_s=wait_s,
        )
        resp = await self._request(req)

        if not isinstance(resp, protocol.StartIdalibResponse):
            await self._protocol_violation(
                f"expected start_idalib_response, got: {getattr(resp, 'type', type(resp).__name__)}"
            )
        if resp.src != bridge_id:
            await self._protocol_violation(f"start_idalib_response src mismatch: expected={bridge_id} got={resp.src}")
        return resp

    async def stop_idalib(self, target: str) -> protocol.StopIdalibResponse:
        bridge_id = self.bridge_id
        req = protocol.StopIdalibRequest(
            id=protocol.new_req_id(),
            src=self._client_id,
            dst=bridge_id,
            target=target,
        )
        resp = await self._request(req)

        if not isinstance(resp, protocol.StopIdalibResponse):
            await self._protocol_violation(
                f"expected stop_idalib_response, got: {getattr(resp, 'type', type(resp).__name__)}"
            )
        if resp.src != bridge_id:
            await self._protocol_violation(f"stop_idalib_response src mismatch: expected={bridge_id} got={resp.src}")
        return resp

    async def _protocol_violation(
        self,
        detail: str,
        *,
        close_code: int = protocol.WS_CLOSE_PROTOCOL_ERROR,
    ) -> NoReturn:
        exc = BridgeDisconnected(f"protocol violation: {detail}")
        await self._hard_disconnect(exc, close_code=close_code)
        raise exc

    async def _request(self, req: protocol.RequestBase) -> protocol.Message:
        conn = self._conn
        if conn is None:
            raise RuntimeError("not connected")

        fut: asyncio.Future[protocol.Message] = asyncio.get_running_loop().create_future()

        async with self._lock:
            if req.id in self._pending:
                raise RuntimeError(f"duplicate request id: {req.id}")

            self._pending[req.id] = fut
            try:
                await conn.ws.send(protocol.dump_message_json(req))
            except Exception as exc:
                self._pending.pop(req.id, None)
                fut.set_exception(exc)
                raise

        try:
            return await fut
        except asyncio.CancelledError:
            # Caller abandoned the request (e.g. wait_for timeout). Keep the
            # connection healthy and ignore the eventual late response.
            if self._pending.get(req.id) is fut:
                self._pending.pop(req.id, None)
                self._abandoned.add(req.id)
                fut.cancel()

                if len(self._abandoned) > self._MAX_ABANDONED_IDS:
                    exc = BridgeDisconnected(
                        f"too many abandoned requests ({len(self._abandoned)}); refusing to continue"
                    )
                    await self._hard_disconnect(exc, close_code=1011)
                    raise exc from None
            raise

    async def _listen(self, ws: Any) -> None:
        try:
            async for raw in ws:
                if not isinstance(raw, str):
                    await self._hard_disconnect(
                        BridgeDisconnected("received non-text websocket frame"),
                        ws=ws,
                        close_code=protocol.WS_CLOSE_PROTOCOL_ERROR,
                    )
                    return

                try:
                    msg = protocol.parse_message_json(raw)
                except ValidationError as exc:
                    await self._hard_disconnect(
                        BridgeDisconnected(f"invalid message: {exc}"),
                        ws=ws,
                        close_code=protocol.WS_CLOSE_PROTOCOL_ERROR,
                    )
                    return

                if isinstance(msg, protocol.ProtocolError):
                    await self._hard_disconnect(
                        BridgeProtocolError(msg),
                        ws=ws,
                        close_code=protocol.WS_CLOSE_POLICY_VIOLATION,
                    )
                    return

                if not isinstance(msg, protocol.ResponseBase):
                    await self._hard_disconnect(
                        BridgeDisconnected(f"unexpected message after handshake: {msg.type}"),
                        ws=ws,
                        close_code=protocol.WS_CLOSE_PROTOCOL_ERROR,
                    )
                    return

                req_id = msg.id

                if msg.dst != self._client_id:
                    await self._hard_disconnect(
                        BridgeDisconnected(f"dst mismatch on {msg.type}: expected={self._client_id} got={msg.dst}"),
                        ws=ws,
                        close_code=protocol.WS_CLOSE_PROTOCOL_ERROR,
                    )
                    return

                fut = self._pending.pop(req_id, None)
                if fut is None:
                    if req_id in self._abandoned:
                        self._abandoned.discard(req_id)
                        continue

                    await self._hard_disconnect(
                        BridgeDisconnected(f"unexpected response id: {req_id}"),
                        ws=ws,
                        close_code=protocol.WS_CLOSE_PROTOCOL_ERROR,
                    )
                    return

                if not fut.done():
                    fut.set_result(msg)

        except ConnectionClosed as exc:
            await self._hard_disconnect(BridgeDisconnected(f"bridge disconnected: {exc}"), ws=ws)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover
            await self._hard_disconnect(exc, ws=ws)

    async def _hard_disconnect(
        self,
        exc: Exception,
        *,
        ws: Any | None = None,
        close_code: int | None = None,
    ) -> None:
        # Idempotent best-effort transition to a disconnected state.
        conn = self._conn
        self._conn = None
        self._bridge_id = None
        self._bridge_meta = None

        self._fail_all(exc)
        self._abandoned.clear()

        if ws is None and conn is not None:
            ws = conn.ws

        if ws is None:
            return

        with contextlib.suppress(Exception):
            if close_code is None:
                await ws.close()
            else:
                await ws.close(code=close_code)

    def _fail_all(self, exc: Exception) -> None:
        pending = list(self._pending.values())
        self._pending.clear()
        for fut in pending:
            if not fut.done():
                fut.set_exception(exc)


@contextlib.asynccontextmanager
async def open_agent_client(
    *,
    client_id: str,
    url: str | None = None,
    meta: dict[str, Any] | None = None,
):
    """Open an AgentClient and ensure it is closed.

    This avoids exposing handshake details in call sites and is convenient for scripts.
    """

    client = AgentClient(client_id=client_id, url=url)
    await client.connect(meta=meta)
    try:
        yield client
    finally:
        await client.close()
