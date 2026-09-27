"""Shared WebSocket connection to the bridge server.

Used by both UI IDA (plugin) and idalib (headless runner).
Handles handshake, message validation, request queueing, and reconnect with backoff.
"""

import logging
import queue
import threading
import time
from typing import Any

from pydantic import ValidationError
import websocket

from . import protocol
from .ida_runtime import QUEUE_SENTINEL, shutdown_queue

log = logging.getLogger(__name__)


def abort_ws(ws: websocket.WebSocketApp) -> None:
    """Immediately tear down a WebSocketApp from a non-WS thread.

    ``ws.close()`` performs the close handshake (send close frame, wait for
    reply) which blocks up to 3 s.  When called from a thread other than the
    one running ``run_forever()``, both threads race on ``recv_frame()`` and
    the caller almost always hits the full 3 s timeout.

    Instead we abort the underlying socket so ``run_forever()`` wakes up and
    exits its read loop on its own.
    """
    try:
        ws.keep_running = False
        if ws.sock:
            ws.sock.abort()
    except Exception:
        pass


def _not_serializable_message(msg: protocol.Message, exc: BaseException) -> str:
    details = protocol.ascii_escaped(f"{type(exc).__name__}: {exc}", fallback="response not serializable")
    fields = protocol.unserializable_fields(msg)
    return f"cannot serialize {', '.join(fields)}: {details}" if fields else details


class BridgeConn:
    """WebSocket connection to the bridge with automatic reconnect.

    - WS thread: handshake, receive, validate, enqueue requests.
    - Owner thread: dequeue via recv(), send responses via send().
    """

    _FAST_RETRY_S = 5.0
    _FAST_WINDOW_S = 120.0
    _SLOW_RETRY_S = 60.0

    def __init__(self, *, client_id: str, url: str | None = None, meta: dict[str, Any], queue_max: int = 100):
        if not client_id:
            raise ValueError("client_id must be a non-empty string")

        self._client_id = client_id
        self._url = url or protocol.bridge_url()
        self._meta = meta

        self._ws: websocket.WebSocketApp | None = None
        self._ws_thread: threading.Thread | None = None

        self._ready = threading.Event()
        self._stopped = threading.Event()
        self._send_lock = threading.Lock()
        self._conn_lock = threading.Lock()

        self._queue_max = queue_max
        self._inbox: queue.Queue[object] = queue.Queue(maxsize=queue_max)

        self._last_disconnect_at = time.monotonic()

        # Log throttling: announce retry/backoff once per disconnect cycle.
        self._retry_announced = False
        self._backoff_announced = False
        self._advertised_max_size: int | None = None

    def start(self) -> None:
        """Start the WS thread (non-blocking)."""
        if self._stopped.is_set():
            raise RuntimeError("cannot restart a stopped connection")

        if self._ws_thread and self._ws_thread.is_alive():
            return

        self._ws_thread = threading.Thread(target=self._run_ws, name=f"ida-bridge-ws:{self._client_id}", daemon=True)
        self._ws_thread.start()

    def wait_ready(self, *, timeout_s: float) -> bool:
        """Block until handshake completes. Returns True if ready."""
        return self._ready.wait(timeout=timeout_s)

    def stop(self) -> None:
        """Stop the connection and clean up."""
        if self._stopped.is_set():
            return

        self._stopped.set()
        shutdown_queue(self._inbox, immediate=True)

        with self._conn_lock:
            ws = self._ws

        if ws is not None:
            abort_ws(ws)

    def is_connected(self) -> bool:
        return self._ready.is_set() and not self._stopped.is_set()

    def is_stopped(self) -> bool:
        return self._stopped.is_set()

    def recv(self, *, timeout_s: float) -> protocol.ExecRequest | protocol.ResetRequest | protocol.QuitRequest | None:
        """Dequeue next request (blocking with timeout)."""
        try:
            item = self._inbox.get(timeout=timeout_s)
        except queue.Empty:
            return None

        if item is QUEUE_SENTINEL:
            return None

        if isinstance(item, (protocol.ExecRequest, protocol.ResetRequest, protocol.QuitRequest)):
            return item

        return None

    def _frame_limit(self) -> int:
        """Server-advertised cap, or the local setting until the handshake ack."""
        if self._advertised_max_size is not None:
            return self._advertised_max_size
        return protocol.ws_max_size()

    def send(self, msg: protocol.Message) -> None:
        """Send a message, or replace it with an error when it cannot be delivered.

        A request that got a response deserves an answer either way, so a response we
        cannot serialize or that exceeds the frame cap is replaced by an error on the same
        request. A handshake has no error form; it can only be logged and dropped.
        """
        handling_response = isinstance(msg, protocol.ResponseBase)

        try:
            data = protocol.dump_message_json(msg)
        except Exception as exc:
            log.error("message not serializable", exc_info=True)
            if not handling_response:
                return
            try:
                data = protocol.dump_message_json(
                    protocol.error_from_response(
                        msg,
                        code=protocol.ERR_RESPONSE_NOT_SERIALIZABLE,
                        message=_not_serializable_message(msg, exc),
                    )
                )
            except Exception:
                log.error("error response not serializable", exc_info=True)
                return

        limit = self._frame_limit()
        if len(data) > limit:
            log.error("message is %d bytes, over the %d byte frame limit", len(data), limit)
            if not handling_response:
                return
            data = protocol.dump_message_json(
                protocol.error_from_response(
                    msg,
                    code=protocol.ERR_RESPONSE_TOO_LARGE,
                    message=f"serialized response is {len(data)} bytes; limit is {limit} bytes.",
                )
            )

        with self._conn_lock:
            ws = self._ws
        if ws is None:
            log.warning("dropping %s: not connected", msg.type)
            return

        with self._send_lock:
            try:
                ws.send(data)
            except Exception as exc:
                log.warning("send failed; will reconnect: %s", exc)
                # Just clear state; the WS thread will notice the broken socket.
                self._mark_disconnected()

    # -- internal ---------------------------------------------------------

    def _mark_disconnected(self) -> None:
        """Clear ready state and drop pending requests."""
        was_ready = self._ready.is_set()
        self._ready.clear()
        self._advertised_max_size = None

        if was_ready:
            with self._conn_lock:
                self._last_disconnect_at = time.monotonic()
                self._retry_announced = False
                self._backoff_announced = False
            log.info("lost connection")
            old = self._inbox
            self._inbox = queue.Queue(maxsize=self._queue_max)
            shutdown_queue(old, immediate=True)

    def _reject(
        self,
        ws: websocket.WebSocketApp,
        status: int = protocol.WS_CLOSE_POLICY_VIOLATION,
    ) -> None:
        """Reject a connection from the WS thread (graceful close)."""
        self._mark_disconnected()
        try:
            ws.close(status=status)
        except Exception:
            pass
        with self._conn_lock:
            if self._ws is ws:
                self._ws = None

    def _run_ws(self) -> None:
        while not self._stopped.is_set():
            ws = websocket.WebSocketApp(
                self._url,
                on_open=self._on_open,
                on_message=self._on_message,
                on_error=self._on_error,
                on_close=self._on_close,
            )

            with self._conn_lock:
                self._ws = ws

            try:
                ws.run_forever(ping_interval=30, ping_timeout=10)
            except Exception:
                pass

            self._mark_disconnected()

            with self._conn_lock:
                if self._ws is ws:
                    self._ws = None

            if self._stopped.is_set():
                break

            # Backoff.
            now = time.monotonic()
            with self._conn_lock:
                last_disc = self._last_disconnect_at

            if (now - last_disc) < self._FAST_WINDOW_S:
                sleep_s = self._FAST_RETRY_S
            else:
                sleep_s = self._SLOW_RETRY_S

            with self._conn_lock:
                if not self._retry_announced:
                    self._retry_announced = True
                    log.info(
                        "can't connect; retrying every %.0fs for %.0f min",
                        self._FAST_RETRY_S,
                        self._FAST_WINDOW_S / 60,
                    )
                elif not self._backoff_announced and sleep_s == self._SLOW_RETRY_S:
                    self._backoff_announced = True
                    log.info("still can't connect; retrying every %.0fs", self._SLOW_RETRY_S)

            self._stopped.wait(sleep_s)

    def _on_open(self, ws: websocket.WebSocketApp) -> None:
        self._ready.clear()
        hello = protocol.Hello(role=protocol.ROLE_IDA, client_id=self._client_id, meta=self._meta)
        self.send(hello)

    def _on_message(self, ws: websocket.WebSocketApp, message: str) -> None:
        try:
            msg = protocol.parse_message_json(message)
        except ValidationError:
            self._reject(ws, protocol.WS_CLOSE_PROTOCOL_ERROR)
            return

        if isinstance(msg, protocol.HelloAck):
            if self._ready.is_set():
                # Duplicate hello_ack — protocol violation.
                self._reject(ws)
                return
            self._advertised_max_size = msg.max_size
            self._ready.set()
            log.info("connected: %s", msg.client_id)
            return

        if isinstance(msg, protocol.ProtocolError):
            log.error("protocol error: %s: %s", msg.code, msg.message)
            self._reject(ws)
            return

        if not self._ready.is_set():
            self._reject(ws)
            return

        if not isinstance(msg, (protocol.ExecRequest, protocol.ResetRequest, protocol.QuitRequest)):
            self._reject(ws)
            return

        if msg.dst != self._client_id:
            self._reject(ws)
            return

        try:
            self._inbox.put_nowait(msg)
        except queue.Full:
            self.send(protocol.error_for_request(msg, code=protocol.ERR_QUEUE_FULL, message="request queue is full"))

    def _on_error(self, ws: websocket.WebSocketApp, error: Exception) -> None:
        with self._conn_lock:
            suppress = self._retry_announced
        if not suppress:
            log.debug("websocket error: %s", error)
        self._mark_disconnected()

    def _on_close(self, ws: websocket.WebSocketApp, status_code: int, msg: str) -> None:
        with self._conn_lock:
            suppress = self._retry_announced
        if not suppress:
            log.debug("websocket closed: %s %s", status_code, msg)
        self._mark_disconnected()
