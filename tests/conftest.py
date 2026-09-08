from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
import os

import pytest
import pytest_asyncio
import websockets

from ida_bridge.server import BridgeServer
from tests.harness import ServeBridge


@pytest.fixture(scope="session", autouse=True)
def _isolate_log_dir(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Keep tests off the real platform log directory. The server's
    startup log prune would otherwise touch the user's actual logs."""
    prev = os.environ.get("IDA_BRIDGE_LOG_DIR")
    os.environ["IDA_BRIDGE_LOG_DIR"] = str(tmp_path_factory.mktemp("ida-bridge-logs"))
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("IDA_BRIDGE_LOG_DIR", None)
        else:
            os.environ["IDA_BRIDGE_LOG_DIR"] = prev


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--e2e-heavy",
        action="store_true",
        help="Include heavy/large E2E fixtures under tests/fixtures/idbs/heavy/.",
    )


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "idb_fixture" not in metafunc.fixturenames:
        return

    from tests.fixtures.idb_discovery import available

    fixtures = available(include_heavy=metafunc.config.getoption("e2e_heavy"))
    metafunc.parametrize("idb_fixture", fixtures, ids=lambda fixture: fixture.name, scope="module")


@pytest_asyncio.fixture
def serve_bridge() -> ServeBridge:
    """Start a BridgeServer on an ephemeral port.

    Usage:
        async with serve_bridge(default_timeout_s=0.05) as (server, url):
            ...
    """

    @asynccontextmanager
    async def _serve(
        *,
        bridge_client_id: str | None = None,
        default_timeout_s: int | None = None,
        timeout_tick_s: float = 0.5,
        instance_id: str | None = None,
        ping_interval: float | None = None,
        ping_timeout: float | None = None,
        stateful_ttl_s: float | None = None,
        lifecycle_quit_timeout_s: float = 10.0,
        lifecycle_exit_timeout_s: float = 20.0,
    ) -> AsyncIterator[tuple[BridgeServer, str]]:
        server = BridgeServer(
            bridge_client_id=bridge_client_id,
            default_timeout_s=default_timeout_s,
            timeout_tick_s=timeout_tick_s,
            instance_id=instance_id,
            stateful_ttl_s=stateful_ttl_s,
            lifecycle_quit_timeout_s=lifecycle_quit_timeout_s,
            lifecycle_exit_timeout_s=lifecycle_exit_timeout_s,
        )
        server.start_background_tasks()
        ws_kwargs: dict = {}
        if ping_interval is not None:
            ws_kwargs["ping_interval"] = ping_interval
        if ping_timeout is not None:
            ws_kwargs["ping_timeout"] = ping_timeout
        try:
            async with websockets.serve(server.handler, "127.0.0.1", 0, **ws_kwargs) as ws_server:
                port = ws_server.sockets[0].getsockname()[1]
                url = f"ws://127.0.0.1:{port}"
                yield server, url
        finally:
            await server.stop_background_tasks()

    return _serve
