from collections.abc import Sequence
import contextlib
from dataclasses import dataclass
import os
from typing import Any, NoReturn
from uuid import uuid4

from pydantic import ValidationError
import websockets
from websockets.exceptions import ConnectionClosed, InvalidHandshake

from . import protocol


class BridgeProtocolError(RuntimeError):
    def __init__(self, err: protocol.ProtocolError):
        super().__init__(f"bridge protocol error: {err.code}: {err.message}")
        self.err = err


class BridgeDisconnected(RuntimeError):
    pass


class BridgeUnreachable(RuntimeError):
    """No websocket connection to the bridge could be opened; nothing was sent."""


class RequestTooLarge(ValueError):
    """The request exceeds the server's message limit; nothing was sent."""


@dataclass(frozen=True)
class _ConnState:
    ws: Any
    max_message_bytes: int


class AgentClient:
    """Agent side attachment to bridge server. One request in flight at a time."""

    def __init__(self, *, client_id: str | None = None, url: str | None = None):
        # A PID-based default would collide across PID namespaces (sandboxes).
        if client_id is None:
            client_id = f"agent-{uuid4().hex[:12]}"
        if not client_id:
            raise ValueError("client_id must be a non-empty string")

        self._client_id = client_id
        self._url = url or protocol.bridge_url()

        self._bridge_id: str | None = None
        self._conn: _ConnState | None = None

    @property
    def bridge_id(self) -> str:
        if self._bridge_id is None:
            raise RuntimeError("not connected")
        return self._bridge_id

    async def connect(self, *, meta: dict[str, Any] | None = None) -> None:
        if self._conn is not None:
            raise RuntimeError("already connected")

        try:
            ws = await websockets.connect(self._url, max_size=None)
        except (OSError, InvalidHandshake) as exc:
            raise BridgeUnreachable(f"cannot connect to bridge at {self._url}: {exc}") from exc

        try:
            # Handshake: hello must be first, and we expect hello_ack next.
            hello_meta = {"pid": os.getpid(), **(meta or {})}
            hello = protocol.Hello(role=protocol.ROLE_AGENT, client_id=self._client_id, meta=hello_meta)
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
            self._conn = _ConnState(ws=ws, max_message_bytes=msg.max_message_bytes)
            return None

        except ConnectionClosed as exc:
            raise BridgeDisconnected(f"bridge disconnected: {exc}") from exc
        except Exception:
            await ws.close()
            raise

    def is_connected(self) -> bool:
        return self._conn is not None

    async def close(self) -> None:
        await self._disconnect()

    async def list(self, kind: protocol.ListKind = protocol.LIST_KIND_IDA) -> protocol.ListResponse:
        bridge_id = self.bridge_id
        req = protocol.ListRequest(id=protocol.new_req_id(), src=self._client_id, dst=bridge_id, kind=kind)
        return await self._request(req)

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
        return await self._request(req)

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
        return await self._request(req)

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
        return await self._request(req)

    async def remote(self, argv: Sequence[str]) -> protocol.RemoteResponse:
        req = protocol.RemoteRequest(id=protocol.new_req_id(), src=self._client_id, dst=self.bridge_id, argv=list(argv))
        return await self._request(req)

    async def _protocol_violation(self, detail: str) -> NoReturn:
        await self._disconnect(close_code=protocol.WS_CLOSE_PROTOCOL_ERROR)
        raise BridgeDisconnected(f"protocol violation: {detail}")

    async def _request(self, req: protocol.RequestBase) -> protocol.ResponseBase:
        conn = self._conn
        if conn is None:
            raise RuntimeError("not connected")

        data = protocol.dump_message_json(req)
        if len(data) > conn.max_message_bytes:
            raise RequestTooLarge(
                f"request is {len(data)} bytes; server message limit is {conn.max_message_bytes} bytes"
            )

        try:
            await conn.ws.send(data)
            return await self._recv_response(conn.ws, req)
        except ConnectionClosed as exc:
            await self._disconnect()
            raise BridgeDisconnected(f"bridge disconnected: {exc}") from exc
        except BaseException:
            # A request that didn't complete leaves the connection's state unknown.
            await self._disconnect()
            raise

    async def _recv_response(self, ws: Any, req: protocol.RequestBase) -> protocol.ResponseBase:
        raw = await ws.recv()
        if not isinstance(raw, str):
            await self._protocol_violation("received non-text websocket frame")

        try:
            msg = protocol.parse_message_json(raw)
        except ValidationError as exc:
            await self._protocol_violation(f"invalid message: {exc}")

        if isinstance(msg, protocol.ProtocolError):
            await self._disconnect(close_code=protocol.WS_CLOSE_POLICY_VIOLATION)
            raise BridgeProtocolError(msg)

        expected = protocol.response_type(req.type)
        if not isinstance(msg, expected):
            await self._protocol_violation(f"expected {expected.__name__}, got: {msg.type}")

        if msg.dst != self._client_id:
            await self._protocol_violation(f"dst mismatch on {msg.type}: expected={self._client_id} got={msg.dst}")

        if msg.id != req.id:
            await self._protocol_violation(f"unexpected response id: {msg.id}")

        return msg

    async def _disconnect(self, *, close_code: int | None = None) -> None:
        # Idempotent: a failed request may disconnect before its caller's close().
        conn = self._conn
        self._conn = None
        self._bridge_id = None
        if conn is None:
            return
        with contextlib.suppress(Exception):
            if close_code is None:
                await conn.ws.close()
            else:
                await conn.ws.close(code=close_code)


@contextlib.asynccontextmanager
async def open_agent_client(
    *,
    client_id: str | None = None,
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
