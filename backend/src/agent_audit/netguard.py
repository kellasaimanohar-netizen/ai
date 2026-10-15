"""Shared network guard — SSRF protection for any outbound URL.

Both the OpenAPI source loader (fetching specs) and the notifiers (posting
alerts) accept URLs that can originate from a target manifest, i.e. from
untrusted input. Any code that turns such a URL into an outbound request must
first pass it through :func:`assert_public_url` so an attacker cannot point it
at cloud metadata (``169.254.169.254``), loopback, or private ranges to
exfiltrate credentials or reach internal services.

Bypass for local development only with ``AGENT_AUDIT_ALLOW_PRIVATE_FETCH=1``.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


class BlockedURLError(ValueError):
    """Raised when a URL resolves to a non-public / unsafe address."""


# RFC 6052 well-known NAT64 prefix. On IPv6-only networks with DNS64, a public IPv4 host resolves to
# 64:ff9b::<ipv4>. Python reports the whole prefix as "reserved", which would block every public site
# on such networks, so the embedded IPv4 address is what gets checked.
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def effective_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """The address a connection really reaches: unwraps IPv4-mapped (::ffff:a.b.c.d) and NAT64
    (64:ff9b::a.b.c.d) IPv6 addresses to the IPv4 address inside them."""
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
        if addr in _NAT64_PREFIX:
            return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return addr


def is_non_public(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for loopback, private, link-local, reserved, multicast and unspecified addresses,
    judged on the unwrapped address."""
    a = effective_address(addr)
    return (a.is_private or a.is_loopback or a.is_link_local
            or a.is_reserved or a.is_multicast or a.is_unspecified)


def assert_public_url(url: str, *, allow_insecure_http: bool = False) -> None:
    """Refuse URLs that resolve to loopback / private / link-local / reserved /
    multicast / unspecified addresses, or (by default) plain http.

    Raises :class:`BlockedURLError` if the URL is unsafe. Honors the
    ``AGENT_AUDIT_ALLOW_PRIVATE_FETCH=1`` override for local dev.
    """
    if os.environ.get("AGENT_AUDIT_ALLOW_PRIVATE_FETCH") == "1":
        return

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedURLError(f"unsupported url scheme: {url!r}")
    if parsed.scheme == "http" and not allow_insecure_http:
        raise BlockedURLError(
            f"refusing plain http: {url!r} (use https, or set "
            "AGENT_AUDIT_ALLOW_PRIVATE_FETCH=1 for local dev)"
        )
    host = parsed.hostname
    if not host:
        raise BlockedURLError(f"url has no host: {url!r}")

    try:
        infos = socket.getaddrinfo(
            host, parsed.port or (443 if parsed.scheme == "https" else 80)
        )
    except socket.gaierror as exc:
        raise BlockedURLError(f"could not resolve host {host!r}: {exc}") from exc

    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if is_non_public(addr):
            raise BlockedURLError(
                f"refusing non-public address {addr} (host {host!r}) — "
                "blocked to prevent SSRF. Set AGENT_AUDIT_ALLOW_PRIVATE_FETCH=1 "
                "to override (local dev only)."
            )


def safe_urlopen(req_or_url, *, timeout: float = 30.0,
                 allow_insecure_http: bool = False):
    """Open a URL with SSRF protection that also covers redirects.

    - Validates the initial URL via :func:`assert_public_url`.
    - Installs a redirect handler that re-validates every redirect target, so a
      compromised endpoint cannot 302 to loopback/private/metadata after the
      initial check passes.

    Accepts either a ``urllib.request.Request`` or a URL string. Raises
    :class:`BlockedURLError` if the initial URL or any redirect target is unsafe.
    """
    import urllib.request

    url = req_or_url.full_url if isinstance(req_or_url, urllib.request.Request) else req_or_url
    assert_public_url(url, allow_insecure_http=allow_insecure_http)

    class _ReValidatingRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            assert_public_url(newurl, allow_insecure_http=allow_insecure_http)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(_ReValidatingRedirect)
    return opener.open(req_or_url, timeout=timeout)
