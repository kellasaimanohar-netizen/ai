"""AgentforceClient — drive a Salesforce Agentforce agent through the Agent API.

Salesforce's Agentforce agents are not plain request/response HTTP endpoints:
they are *session-oriented*. A turn is three logical steps —

    1. OAuth 2.0 client-credentials token mint   (once, cached until expiry)
    2. start a session for the agent              (per probe, for isolation)
    3. POST a message with a monotonic sequenceId (the actual turn)
    4. end the session                            (cleanup)

This client hides all of that behind the SAME interface every phase already
uses::

    async def invoke(payload, timeout_s) -> tuple[canonical_dict, latency_ms]

so the 17 audit phases need zero changes. The Salesforce ``messages[]`` envelope
is normalised by :class:`AgentforceAdapter` (registered in ``adapters.py``) into
the canonical shape phases read.

Why a session per probe? The audit deliberately fires adversarial / multi-turn
probes. Sharing one session would let probe N's context-poisoning bleed into
probe N+1 and corrupt unrelated findings. A fresh session per ``invoke`` keeps
each probe's verdict attributable. The multi-turn phase, which *wants* a shared
session, passes an explicit ``_session_id`` to opt out of auto-isolation.

Security posture (mirrors LiveAgentClient):
  * Secrets are read from env-var *names* declared in the manifest, never stored.
  * The token + session hosts are SSRF-guarded (no private/loopback/metadata).
  * Budget reserve/settle/release with single-owner accounting.
  * 429/5xx retry with Retry-After + exponential backoff + jitter.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import random
import socket
import time
import uuid
from typing import Any
from urllib.parse import urlparse

from agent_audit.exceptions import AgentAuditError, ConfigError
from agent_audit.live.adapters import detect_and_normalize
from agent_audit.live.budget import CallBudget
from agent_audit.netguard import is_non_public

log = logging.getLogger(__name__)

_MAX_ATTEMPTS = 4
_BASE_BACKOFF_S = 1.0
_MAX_BACKOFF_S = 30.0
# Salesforce Agent API base host (Government Cloud orgs override via config).
_DEFAULT_API_HOST = "https://api.salesforce.com"
_TOKEN_SKEW_S = 60.0  # refresh the token this many seconds before it expires


class AgentforceError(AgentAuditError):
    """An Agentforce Agent API call failed after exhausting retries."""


def _backoff_seconds(attempt: int, retry_after: float | None) -> float:
    if retry_after is not None and retry_after >= 0:
        return min(retry_after, _MAX_BACKOFF_S)
    raw = _BASE_BACKOFF_S * (2 ** attempt)
    return min(raw + random.uniform(0, _BASE_BACKOFF_S), _MAX_BACKOFF_S)


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _assert_public_url(url: str) -> None:
    """SSRF guard: refuse token/session hosts that resolve to non-public IPs."""
    if os.environ.get("AGENT_AUDIT_ALLOW_PRIVATE_FETCH") == "1":
        return
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise AgentforceError(f"Agentforce endpoints must be https, got {url!r}")
    host = parsed.hostname
    if not host:
        raise AgentforceError(f"no host in url {url!r}")
    try:
        infos = socket.getaddrinfo(host, 443)
    except socket.gaierror as exc:
        raise AgentforceError(f"cannot resolve {host!r}: {exc}") from exc
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if is_non_public(addr):
            raise AgentforceError(
                f"refusing to call non-public address {addr} (host {host!r}) — SSRF guard"
            )


class AgentforceClient:
    """Session-aware client for a Salesforce Agentforce agent.

    Config is read from ``manifest.runtime.provider.config``:

        agent_id          (str, required)  the "0Xx…" agent/bot id
        my_domain_url     (str, required)  e.g. https://acme.my.salesforce.com
        consumer_key_env  (str, required)  env var holding the OAuth client id
        consumer_secret_env (str, required) env var holding the OAuth secret
        api_host          (str, optional)  default https://api.salesforce.com
        bypass_user       (bool, optional) default True (client-credentials flow)
    """

    def __init__(
        self,
        manifest: Any,
        *,
        budget: CallBudget | None = None,
        concurrency: int = 4,
    ) -> None:
        self.manifest = manifest
        self.budget = budget or CallBudget()
        self._concurrency = max(1, concurrency)
        self._sem = asyncio.Semaphore(self._concurrency)
        self._client: Any = None

        cfg = dict(getattr(manifest.runtime.provider, "config", {}) or {})
        self._agent_id = cfg.get("agent_id")
        self._domain = (cfg.get("my_domain_url") or "").rstrip("/")
        self._api_host = (cfg.get("api_host") or _DEFAULT_API_HOST).rstrip("/")
        self._bypass_user = bool(cfg.get("bypass_user", True))
        ck_env = cfg.get("consumer_key_env")
        cs_env = cfg.get("consumer_secret_env")

        missing = [n for n, v in {
            "agent_id": self._agent_id, "my_domain_url": self._domain,
            "consumer_key_env": ck_env, "consumer_secret_env": cs_env,
        }.items() if not v]
        if missing:
            raise ConfigError(
                f"agentforce provider config missing: {', '.join(missing)} "
                "(set under runtime.provider.config)"
            )

        self._consumer_key = os.environ.get(ck_env)  # type: ignore[arg-type]
        self._consumer_secret = os.environ.get(cs_env)  # type: ignore[arg-type]
        if not self._consumer_key or not self._consumer_secret:
            raise ConfigError(
                f"Agentforce OAuth secrets not set: {ck_env}/{cs_env} env vars are empty."
            )

        _assert_public_url(self._domain)
        _assert_public_url(self._api_host)

        self._token: str | None = None
        self._token_expiry: float = 0.0
        self._token_lock = asyncio.Lock()

    # ── HTTP plumbing ───────────────────────────────────────────────────────
    async def _ensure_client(self) -> Any:
        if self._client is None:
            import httpx
            limits = httpx.Limits(max_connections=max(4, self._concurrency),
                                  max_keepalive_connections=max(2, self._concurrency))
            self._client = httpx.AsyncClient(limits=limits)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_token(self) -> str:
        """Mint (and cache) an OAuth client-credentials access token."""
        now = time.monotonic()
        if self._token and now < self._token_expiry - _TOKEN_SKEW_S:
            return self._token
        async with self._token_lock:
            if self._token and time.monotonic() < self._token_expiry - _TOKEN_SKEW_S:
                return self._token
            client = await self._ensure_client()
            token_url = f"{self._domain}/services/oauth2/token"
            resp = await client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._consumer_key,
                    "client_secret": self._consumer_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0,
            )
            if resp.status_code != 200:
                raise AgentforceError(
                    f"OAuth token mint failed ({resp.status_code}): {resp.text[:200]}"
                )
            data = resp.json()
            self._token = data["access_token"]
            # Salesforce tokens don't always return expires_in; assume 30 min.
            self._token_expiry = time.monotonic() + float(data.get("expires_in", 1800))
            log.info("agentforce: OAuth token minted (expires in ~%.0fs)",
                     self._token_expiry - time.monotonic())
            return self._token

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # ── Session lifecycle ───────────────────────────────────────────────────
    async def _start_session(self, token: str, timeout_s: float) -> str:
        client = await self._ensure_client()
        url = f"{self._api_host}/einstein/ai-agent/v1/agents/{self._agent_id}/sessions"
        body = {
            "externalSessionKey": str(uuid.uuid4()),
            "instanceConfig": {"endpoint": self._domain},
            "bypassUser": self._bypass_user,
        }
        resp = await client.post(url, json=body, headers=self._auth_headers(token),
                                 timeout=timeout_s)
        if resp.status_code not in (200, 201):
            raise AgentforceError(
                f"start session failed ({resp.status_code}): {resp.text[:200]}"
            )
        sid = resp.json().get("sessionId")
        if not sid:
            raise AgentforceError("start session returned no sessionId")
        return sid

    async def _end_session(self, token: str, session_id: str) -> None:
        try:
            client = await self._ensure_client()
            url = f"{self._api_host}/einstein/ai-agent/v1/sessions/{session_id}"
            await client.request("DELETE", url,
                                 headers={**self._auth_headers(token),
                                          "x-session-end-reason": "UserRequest"},
                                 timeout=15.0)
        except Exception as exc:  # cleanup must never mask the real result
            log.warning("agentforce: end_session(%s) failed: %s", session_id, exc)

    async def _send_message(
        self, token: str, session_id: str, text: str, seq: int, timeout_s: float,
    ) -> Any:
        client = await self._ensure_client()
        url = f"{self._api_host}/einstein/ai-agent/v1/sessions/{session_id}/messages"
        body = {"message": {"sequenceId": seq, "type": "Text", "text": text}}

        last_exc: Exception | None = None
        for attempt in range(_MAX_ATTEMPTS):
            import httpx
            try:
                resp = await client.post(url, json=body,
                                         headers=self._auth_headers(token),
                                         timeout=timeout_s)
                status = resp.status_code
                if status == 429 and attempt < _MAX_ATTEMPTS - 1:
                    wait = _backoff_seconds(attempt,
                                            _parse_retry_after(resp.headers.get("Retry-After")))
                    log.warning("agentforce 429 (attempt %d) — waiting %.1fs", attempt + 1, wait)
                    await asyncio.sleep(wait)
                    continue
                if status >= 500 and attempt < _MAX_ATTEMPTS - 1:
                    await asyncio.sleep(_backoff_seconds(attempt, None))
                    continue
                resp.raise_for_status()
                ctype = resp.headers.get("content-type", "")
                return resp.json() if "json" in ctype else resp.text
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError,
                    httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
                last_exc = exc
                if attempt < _MAX_ATTEMPTS - 1:
                    await asyncio.sleep(_backoff_seconds(attempt, None))
                else:
                    break
            except httpx.HTTPStatusError as exc:
                raise AgentforceError(
                    f"message failed ({exc.response.status_code}): {exc.response.text[:200]}"
                ) from exc
        raise AgentforceError(f"message failed after {_MAX_ATTEMPTS} attempts: {last_exc}")

    # ── Public interface (matches LiveAgentClient.invoke) ───────────────────
    async def invoke(
        self, payload: dict[str, Any], timeout_s: float = 30.0,
    ) -> tuple[dict[str, Any], float]:
        """Run one agent turn. Returns (canonical_response_dict, latency_ms).

        ``payload`` follows the same convention phases already use:
          input / message   — the probe text
          _test_name         — budget bucket
          _session_id        — opt out of per-probe isolation (multi-turn phase)
          _sequence_id       — explicit sequenceId (defaults to 1)
        """
        test_name = str(payload.get("_test_name") or payload.get("_mock_scenario") or "agentforce")
        text = str(payload.get("input") or payload.get("message") or payload.get("text") or "")
        explicit_session = payload.get("_session_id")
        seq = int(payload.get("_sequence_id") or 1)

        await self.budget.reserve(test_name)
        settled = False
        start = time.perf_counter()
        try:
            token = await self._get_token()
            async with self._sem:
                session_id = explicit_session or await self._start_session(token, timeout_s)
                try:
                    body = await self._send_message(token, session_id, text, seq, timeout_s)
                finally:
                    # Only tear down sessions we created here.
                    if not explicit_session:
                        await self._end_session(token, session_id)

            canonical = detect_and_normalize(body)
            await self.budget.settle(canonical.get("cost_usd", 0.0))
            settled = True
            latency_ms = (time.perf_counter() - start) * 1000
            return canonical, latency_ms
        finally:
            if not settled:
                await self.budget.release(test_name)
