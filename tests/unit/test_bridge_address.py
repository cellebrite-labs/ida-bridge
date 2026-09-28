import pytest

from ida_bridge import protocol


@pytest.mark.parametrize("accessor", [protocol.bridge_url, protocol.listen_host], ids=["client", "server"])
def test_the_split_host_variable_is_rejected(monkeypatch: pytest.MonkeyPatch, accessor) -> None:
    monkeypatch.setenv("IDA_BRIDGE_HOST", "0.0.0.0")
    with pytest.raises(ValueError, match="IDA_BRIDGE_LISTEN_HOST.*IDA_BRIDGE_CONNECT_HOST"):
        accessor()


@pytest.mark.parametrize("host", ["::1", "10.0.0.1:8765"], ids=["ipv6", "host-with-port"])
def test_a_connect_host_with_a_colon_is_rejected(monkeypatch: pytest.MonkeyPatch, host: str) -> None:
    monkeypatch.setenv("IDA_BRIDGE_CONNECT_HOST", host)
    with pytest.raises(ValueError, match="IDA_BRIDGE_CONNECT_HOST"):
        protocol.bridge_url()


def test_a_listen_host_with_a_colon_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_BRIDGE_LISTEN_HOST", "::")
    with pytest.raises(ValueError, match="IDA_BRIDGE_LISTEN_HOST"):
        protocol.listen_host()
