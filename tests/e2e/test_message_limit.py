"""A reply over the message limit must not cost us the instance.

The limit is lowered for this module so an ordinary payload exceeds it; the alternative is
building a 64 MiB result, which costs a minute and a lot of memory to prove the same thing.
"""

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio

from ida_bridge import protocol
from tests.e2e.conftest import IdalibInstance
from tests.e2e.helpers import BridgeInfo, spawn_idalib, start_bridge, terminate_idalib, wait_for_idalib

pytestmark = [pytest.mark.asyncio(loop_scope="module")]

# Above the protocol minimum, so the runner only gets this right by using the limit from hello_ack.
MESSAGE_LIMIT = protocol.MIN_MESSAGE_BYTES * 2


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def small_limit_idalib(
    _module_binary: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> AsyncIterator[IdalibInstance]:
    bridge: BridgeInfo
    async for bridge in start_bridge(max_message_bytes=MESSAGE_LIMIT):
        work_dir = tmp_path_factory.mktemp("small-limit")
        proc, out_idb = spawn_idalib(bridge, work_dir, binary_path=_module_binary)
        try:
            ready = await wait_for_idalib(bridge, proc, idb_path=out_idb)
            yield IdalibInstance(
                client_id=ready.client_id,
                pid=ready.pid,
                process=proc,
                out_idb=out_idb,
                bridge=bridge,
                agent_url=bridge.url,
            )
        finally:
            terminate_idalib(proc)


async def test_oversized_reply_errors_and_instance_survives(small_limit_idalib: IdalibInstance) -> None:
    async with small_limit_idalib.agent_client() as agent:
        resp = await agent.exec(small_limit_idalib.client_id, f"_result_ = 'z' * {MESSAGE_LIMIT * 4}")
        assert not resp.ok
        assert resp.code == protocol.ERR_RESPONSE_TOO_LARGE
        assert resp.message and str(MESSAGE_LIMIT) in resp.message

        after = await agent.exec(small_limit_idalib.client_id, "_result_ = 42")
        assert after.ok
        assert after.result == 42
