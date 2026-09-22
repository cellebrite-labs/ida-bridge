from ida_bridge import protocol
from ida_bridge.agent_client import AgentClient
from tests.harness import ServeBridge, connected_client, recv_typed, send_msg


async def test_remote_help_round_trip(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        async with connected_client(url, role=protocol.ROLE_AGENT, client_id="agent-1") as agent:
            req = protocol.RemoteRequest(
                id=protocol.new_req_id(),
                src="agent-1",
                dst=server.bridge_id,
                argv=["--help"],
            )
            await send_msg(agent, req)
            resp = await recv_typed(agent, protocol.RemoteResponse, timeout_s=30)
            assert resp.ok is True
            assert resp.id == req.id
            assert resp.src == server.bridge_id
            assert resp.dst == "agent-1"
            assert resp.exit_code == 0
            assert resp.stdout is not None
            assert "usage:" in resp.stdout
            assert "remote -- <command>" in resp.stdout


async def test_agent_stores_advertised_max_size(serve_bridge: ServeBridge) -> None:
    async with serve_bridge() as (server, url):
        client = AgentClient(client_id="agent-1", url=url)
        await client.connect()
        try:
            assert client._frame_limit() == server.max_size
        finally:
            await client.close()
