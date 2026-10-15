"""NAT64 and IPv4-mapped addresses are judged by the IPv4 address inside them.

On IPv6-only networks with DNS64, public hosts resolve to 64:ff9b::<ipv4>. Those must be allowed when
the embedded address is public, and still blocked when it is loopback, private or metadata.
"""
import ipaddress
import socket

import pytest

from agent_audit.exceptions import SourceError
from agent_audit.netguard import BlockedURLError, assert_public_url, effective_address, is_non_public
from agent_audit.sources.openapi_adapter import _assert_public_url as openapi_assert_public_url


def _resolve_to(monkeypatch, address: str) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(family, socket.SOCK_STREAM, 6, "", (address, 443))])


@pytest.mark.parametrize("address, unwrapped", [
    ("64:ff9b::d818:3912", "216.24.57.18"),
    ("::ffff:10.0.0.1", "10.0.0.1"),
    ("2001:db8::1", "2001:db8::1"),
    ("8.8.8.8", "8.8.8.8"),
])
def test_effective_address(address, unwrapped):
    assert str(effective_address(ipaddress.ip_address(address))) == unwrapped


@pytest.mark.parametrize("address, blocked", [
    ("64:ff9b::d818:3912", False),   # public Render address over NAT64
    ("64:ff9b::7f00:1", True),       # 127.0.0.1 over NAT64
    ("64:ff9b::a00:1", True),        # 10.0.0.1 over NAT64
    ("64:ff9b::a9fe:a9fe", True),    # 169.254.169.254 (cloud metadata) over NAT64
    ("::ffff:192.168.1.5", True),    # IPv4-mapped private
    ("::1", True),
])
def test_is_non_public(address, blocked):
    assert is_non_public(ipaddress.ip_address(address)) is blocked


def test_public_host_behind_nat64_is_allowed(monkeypatch):
    monkeypatch.delenv("AGENT_AUDIT_ALLOW_PRIVATE_FETCH", raising=False)
    _resolve_to(monkeypatch, "64:ff9b::d818:3912")
    assert_public_url("https://weather-agent.example.com/openapi.json")
    openapi_assert_public_url("https://weather-agent.example.com/openapi.json")


def test_loopback_behind_nat64_is_blocked(monkeypatch):
    monkeypatch.delenv("AGENT_AUDIT_ALLOW_PRIVATE_FETCH", raising=False)
    _resolve_to(monkeypatch, "64:ff9b::7f00:1")
    with pytest.raises(BlockedURLError):
        assert_public_url("https://sneaky.example.com/openapi.json")
    with pytest.raises(SourceError):
        openapi_assert_public_url("https://sneaky.example.com/openapi.json")
