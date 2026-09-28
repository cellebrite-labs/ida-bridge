"""Bridge client helpers for the supervisor."""

import asyncio
from collections.abc import Callable
import logging

from ida_bridge import protocol
from ida_bridge.agent_client import AgentClient, open_agent_client

log = logging.getLogger(__name__)

_META = {"tool": "supervisor"}

type MatchFn = Callable[[protocol.ClientInfo], bool]
type AbortFn = Callable[[], bool]


async def bridge_quit(client_id: str) -> bool:
    """Request graceful shutdown via a dedicated quit RPC.

    Does not require session ownership. Does not save —
    call ``bridge_save`` first if persistence is needed.
    """
    async with open_agent_client(meta=_META) as client:
        resp = await client.quit(client_id, timeout_s=10)
        return bool(resp.ok)


async def bridge_save(client_id: str, *, session_id: str | None = None, persist: bool = False) -> bool:
    """Save the IDB via the bridge exec environment.

    Returns the bool result of ``idb.save()``.
    Raises on exec/connection failure.
    """
    async with open_agent_client(meta=_META) as client:
        resp = await client.exec(
            client_id,
            "_result_ = idb.save()",
            session_id=session_id,
            persist=persist,
            timeout_s=30,
        )
        if not resp.ok:
            raise RuntimeError(resp.message or "idb.save() exec failed")
        return bool(resp.result)


async def list_ida_clients() -> list[protocol.ClientInfo] | None:
    """List currently connected IDA clients.

    Returns None if the bridge responds but does not provide a valid client list.
    Raises on connection/protocol errors.
    """
    async with open_agent_client(meta=_META) as client:
        resp = await client.list(kind=protocol.LIST_KIND_IDA)
        if not resp.ok or resp.clients is None:
            return None
        return resp.clients


async def snapshot_existing() -> set[str]:
    """Return client_ids of currently connected IDA clients."""
    clients = await list_ida_clients()
    if clients is None:
        return set()
    return {c.client_id for c in clients}


async def poll_for_new_client(
    existing_ids: set[str],
    match: MatchFn,
    *,
    timeout_s: float,
    interval_s: float = 1.0,
    abort: AbortFn | None = None,
) -> protocol.ClientInfo | None:
    """Poll the bridge for a new IDA client matching `match`.

    Holds a single connection open for the duration of the poll loop,
    avoiding repeated connect/handshake/close cycles.

    If `abort` is provided, it is called each iteration; returning True
    stops the poll early (e.g. subprocess died).
    """
    deadline = asyncio.get_event_loop().time() + timeout_s

    async with open_agent_client(meta=_META) as client:
        while asyncio.get_event_loop().time() < deadline:
            if abort is not None and abort():
                return None

            matched = await _try_match(client, existing_ids, match)
            if matched is not None:
                return matched
            await asyncio.sleep(interval_s)

    return None


async def _try_match(
    client: AgentClient,
    existing_ids: set[str],
    match: MatchFn,
) -> protocol.ClientInfo | None:
    try:
        resp = await client.list(kind=protocol.LIST_KIND_IDA)
    except Exception:
        return None

    if not resp.ok or resp.clients is None:
        return None

    for c in resp.clients:
        if c.client_id in existing_ids:
            continue
        if match(c):
            return c

    return None
