"""LiveAgentClient — production-safe HTTP client for real agents.

Mirrors ``MockAgentClient.invoke()`` exactly:

    async def invoke(payload, timeout_s) -> tuple[dict, float]

so ``PhaseContext.call_agent`` can swap one for the other with no phase changes.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any

from agent_audit.exceptions import AgentAuditError
from agent_audit.live.adapters import detect_and_normalize
from agent_audit.live.budget import CallBudget

log = logging.getLogger(__name__)
WARM_UP_TIMEOUT_S = 60.0   # a sleeping free-tier host (Render, Railway) can need most of a minute to wake

_MAX_ATTEMPTS = 4
# After this many requests in a row fail to connect, the agent is treated as down and later requests fail at once,
# so an audit of an unreachable agent ends in seconds (as inconclusive) instead of retrying every probe.
_GIVE_UP_AFTER_CONNECT_FAILURES = 3
_BASE_BACKOFF_S = 1.0
_MAX_BACKOFF_S = 30.0


class LiveCallError(AgentAuditError):
    """A live agent call failed after exhausting retries."""


def _backoff_seconds(attempt: int, retry_after: float | None) -> float:
    if retry_after is not None and retry_after >= 0:
        return min(retry_after, _MAX_BACKOFF_S)
    raw = _BASE_BACKOFF_S * (2 ** attempt)
    jitter = random.uniform(0, _BASE_BACKOFF_S)
    return min(raw + jitter, _MAX_BACKOFF_S)


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)          # delta-seconds form
    except (ValueError, TypeError):
        return None                  # HTTP-date form — fall back to backoff


class LiveAgentClient:
    """Real-agent client with adapters, budget, and 429-aware retry."""

    def __init__(
        self,
        manifest: Any,                       # TargetManifest (avoid import cycle)
        *,
        budget: CallBudget | None = None,
        concurrency: int = 4,
    ) -> None:
        self.manifest = manifest
        self.budget = budget or CallBudget()
        self._endpoint = manifest.runtime.endpoint
        if not self._endpoint:
            raise LiveCallError("no runtime endpoint configured for live calls")
        self._headers = manifest.build_http_headers()
        self._concurrency = max(1, concurrency)
        self._sem = asyncio.Semaphore(self._concurrency)
        self._client: Any = None             # lazily created httpx.AsyncClient
        self._warmed = False
        self._warm_lock = asyncio.Lock()
        self._connect_failures = 0           # requests in a row that never connected

        # Setup stats collection for audit summary and self-healing diagnostics
        self.endpoints_tested = set()
        self.stats = {
            "total_endpoints_tested": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "blocked_403": 0,          # refused before the agent saw the request (missing login, firewall)
            "retry_attempts": 0,
            "endpoints_returning_405": [],
            "endpoints_skipped": [],
            "root_cause_analysis": "",
            "recommended_fixes": [],
            "diagnostics": []
        }

    async def _ensure_client(self) -> Any:
        if self._client is None:
            import httpx
            limits = httpx.Limits(max_connections=max(4, self._concurrency),
                                  max_keepalive_connections=max(2, self._concurrency))
            self._client = httpx.AsyncClient(limits=limits)
        await self._warm_up()
        return self._client

    async def _warm_up(self) -> None:
        """Wake a sleeping host (a free-tier server can need most of a minute) before the first real call, so the
        audit measures the agent rather than its cold start. Runs once, outside the call budget, and never fails."""
        if self._warmed:
            return
        async with self._warm_lock:
            if self._warmed:
                return
            from urllib.parse import urlparse
            p = urlparse(self._endpoint)
            if p.scheme and p.netloc:
                try:
                    await self._client.get(f"{p.scheme}://{p.netloc}/", timeout=WARM_UP_TIMEOUT_S)
                except Exception as exc:   # an unreachable agent is reported by the real calls that follow
                    log.debug("warm-up of %s did not answer: %s", p.netloc, exc)
            self._warmed = True

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def invoke(
        self, payload: dict[str, Any], timeout_s: float = 30.0,
    ) -> tuple[dict[str, Any], float]:
        """Call the live agent. Returns (canonical_response_dict, latency_ms)."""
        import httpx
        import traceback
        import uuid

        test_name = str(payload.get("_test_name") or payload.get("_mock_scenario") or "live")
        if self._connect_failures >= _GIVE_UP_AFTER_CONNECT_FAILURES:
            raise LiveCallError(
                f"the agent could not be reached: {self._connect_failures} requests in a row failed to connect, so the rest were not sent"
            )
        # Reserve a budget slot (raises BudgetExceededError if exhausted).
        await self.budget.reserve(test_name)

        # Track endpoint path in tested set
        self.endpoints_tested.add(self._endpoint)
        self.stats["total_endpoints_tested"] = len(self.endpoints_tested)

        settled = False
        try:
            client = await self._ensure_client()
            # Strip internal control keys so they never leak to the real agent.
            wire_payload = {k: v for k, v in payload.items() if not k.startswith("_")}

            # Parse OpenAPI spec info
            spec = getattr(self.manifest, "openapi_spec", {}) or {}
            paths_dict = spec.get("paths", {})
            
            # Match current endpoint path in spec to auto-select HTTP Method
            from urllib.parse import urlparse
            parsed_url = urlparse(self._endpoint)
            path_key = parsed_url.path or "/"
            
            matched_path_item = None
            matched_path_key = None
            if path_key in paths_dict:
                matched_path_item = paths_dict[path_key]
                matched_path_key = path_key
            else:
                alt_key = path_key.rstrip("/") if path_key.endswith("/") else (path_key + "/")
                if alt_key in paths_dict:
                    matched_path_item = paths_dict[alt_key]
                    matched_path_key = alt_key
                else:
                    for pk, pval in paths_dict.items():
                        if pk.rstrip("/") == path_key.rstrip("/") or path_key.endswith(pk) or pk.endswith(path_key):
                            matched_path_item = pval
                            matched_path_key = pk
                            break

            # Pre-select HTTP method based on OpenAPI spec (default POST)
            expected_method = "POST"
            if matched_path_item:
                allowed_spec = [m.upper() for m in matched_path_item.keys() if m.lower() in {"get", "post", "put", "patch", "delete"}]
                if allowed_spec and "POST" not in allowed_spec:
                    expected_method = allowed_spec[0]

            attempt_method = expected_method
            attempt_headers = dict(self._headers)
            if "user-agent" not in {k.lower() for k in attempt_headers.keys()}:
                attempt_headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            attempt_url = self._endpoint
            attempt_json = wire_payload if attempt_method not in ("GET", "DELETE") else None
            attempt_params = wire_payload if attempt_method in ("GET", "DELETE") else None
            attempt_data = None

            start = time.perf_counter()
            last_exc: Exception | None = None
            response_text = ""
            status = 0

            async with self._sem:
                for attempt in range(_MAX_ATTEMPTS):
                    if attempt > 0:
                        self.stats["retry_attempts"] += 1

                    try:
                        response = await client.request(
                            method=attempt_method,
                            url=attempt_url,
                            json=attempt_json,
                            params=attempt_params,
                            data=attempt_data,
                            headers=attempt_headers,
                            timeout=timeout_s,
                        )
                        status = response.status_code
                        response_text = response.text

                        # 1. Handle HTTP 405 Method Not Allowed
                        if status == 405:
                            if self._endpoint not in self.stats["endpoints_returning_405"]:
                                self.stats["endpoints_returning_405"].append(self._endpoint)

                            # Determine allowed methods from Allow header or spec
                            allowed_methods = []
                            if "allow" in response.headers:
                                allowed_methods = [m.strip().upper() for m in response.headers["allow"].split(",")]
                            if matched_path_item:
                                allowed_spec = [m.upper() for m in matched_path_item.keys() if m.lower() in {"get", "post", "put", "patch", "delete"}]
                                for m in allowed_spec:
                                    if m not in allowed_methods:
                                        allowed_methods.append(m)
                            if not allowed_methods:
                                allowed_methods = ["GET"]

                            other_methods = [m for m in allowed_methods if m != attempt_method]
                            if other_methods and attempt < _MAX_ATTEMPTS - 1:
                                retry_method = other_methods[0]
                                log.warning(
                                    "%s %s returned 405. Allowed methods: %s. Retrying with %s...",
                                    attempt_method, path_key, ", ".join(allowed_methods), retry_method
                                )
                                # Auto-retry with the new HTTP Method and adjust payload placement
                                attempt_method = retry_method
                                attempt_json = wire_payload if attempt_method not in ("GET", "DELETE") else None
                                attempt_params = wire_payload if attempt_method in ("GET", "DELETE") else None
                                continue

                        # 2. Handle HTTP 415 Unsupported Media Type / Wrong Content Type
                        if status == 415 and attempt < _MAX_ATTEMPTS - 1:
                            log.warning("Received 415 Unsupported Media Type for %s. Retrying with URL-encoded form data...", attempt_url)
                            attempt_headers["Content-Type"] = "application/x-www-form-urlencoded"
                            attempt_data = wire_payload
                            attempt_json = None
                            continue

                        # 3. Handle HTTP 401/403 Authentication Mismatch
                        if status in (401, 403) and attempt < _MAX_ATTEMPTS - 1:
                            token_val = None
                            auth_spec = self.manifest.runtime.auth
                            if auth_spec.token_env:
                                import os
                                token_val = os.environ.get(auth_spec.token_env)
                            if not token_val and "Authorization" in attempt_headers:
                                auth_h = attempt_headers["Authorization"]
                                if auth_h.startswith("Bearer "):
                                    token_val = auth_h[7:]
                                else:
                                    token_val = auth_h

                            if token_val:
                                api_key_params = ["api_key", "apikey", "token", "key", "auth"]
                                security_schemes = spec.get("components", {}).get("securitySchemes", {}) or spec.get("securityDefinitions", {})
                                for scheme in security_schemes.values():
                                    if isinstance(scheme, dict) and scheme.get("type") == "apiKey" and scheme.get("in") == "query":
                                        name = scheme.get("name")
                                        if name and name not in api_key_params:
                                            api_key_params.insert(0, name)

                                chosen_param = api_key_params[0]
                                log.warning("Authentication failure (status %d). Retrying with token in query param '%s'...", status, chosen_param)
                                if attempt_params is None:
                                    attempt_params = {}
                                attempt_params[chosen_param] = token_val
                                continue

                        # 429 — respect Retry-After, then back off.
                        if status == 429 and attempt < _MAX_ATTEMPTS - 1:
                            wait = _backoff_seconds(attempt, _parse_retry_after(response.headers.get("Retry-After")))
                            log.warning("429 rate-limited (attempt %d) — waiting %.1fs", attempt + 1, wait)
                            await asyncio.sleep(wait)
                            continue

                        # Transient 5xx — back off and retry.
                        if status >= 500 and attempt < _MAX_ATTEMPTS - 1:
                            wait = _backoff_seconds(attempt, None)
                            log.warning("server %s (attempt %d) — waiting %.1fs", status, attempt + 1, wait)
                            await asyncio.sleep(wait)
                            continue

                        # Non-transient errors — raise and trigger diagnostics report
                        response.raise_for_status()

                        # Success path
                        self.stats["successful_requests"] += 1
                        self._connect_failures = 0
                        body = self._safe_parse(response)
                        canonical = detect_and_normalize(body)
                        await self.budget.settle(canonical.get("cost_usd", 0.0))
                        settled = True
                        return canonical, (time.perf_counter() - start) * 1000

                    except Exception as exc:
                        last_exc = exc
                        tb = traceback.format_exc()
                        is_transient = isinstance(exc, (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError,
                                                       httpx.ConnectTimeout, httpx.PoolTimeout))

                        if is_transient and attempt < _MAX_ATTEMPTS - 1:
                            wait = _backoff_seconds(attempt, None)
                            log.warning("transient error %s (attempt %d) — waiting %.1fs", type(exc).__name__, attempt + 1, wait)
                            await asyncio.sleep(wait)
                        else:
                            # 403 WAF Fallback (Execute BEFORE logging error to prevent red UI)
                            if status == 403:
                                log.warning("WAF blocked request with 403 Forbidden. Treating as policy refusal.")
                                # Not counted as the agent answering: if every request is refused this way the
                                # report is inconclusive instead of passing every safety check.
                                self.stats["blocked_403"] += 1
                                body = {
                                    "output": "Blocked by WAF policy.",
                                    "finish_reason": "policy_refusal",
                                    "trace_id": f"trace-waf-{uuid.uuid4().hex[:8]}"
                                }
                                canonical = detect_and_normalize(body)
                                canonical["_blocked_403"] = True   # the agent itself did not answer this one
                                settled = True
                                await self.budget.settle(0.0)
                                return canonical, (time.perf_counter() - start) * 1000

                            # Final retry failed or non-transient error (Actually failed, log as red)
                            self.stats["failed_requests"] += 1

                            suggested_fix = "Verify endpoint configuration and server health."
                            if status == 415:
                                suggested_fix = "Update request Content-Type or payload matching the OpenAPI schema spec."
                            elif status == 401:
                                suggested_fix = "Verify security credentials, API keys, or environment auth tokens match the specification."
                            elif status == 404:
                                suggested_fix = "Verify the endpoint url path routing matches backend REST configuration."
                            elif status >= 500:
                                suggested_fix = "Check server side stdout/logs for internal exceptions or DB connection timeouts."

                            diag = {
                                "failed_endpoint": attempt_url,
                                "expected_http_method": expected_method,
                                "actual_http_method_used": attempt_method,
                                "response_body": response_text[:1000],
                                "stack_trace": tb,
                                "suggested_fix": suggested_fix
                            }
                            self.stats["diagnostics"].append(diag)

                            # Populate overall root cause analysis
                            self.stats["root_cause_analysis"] = f"Endpoint {attempt_url} failed with status {status or 'Connection Error'} using method {attempt_method}."
                            if suggested_fix not in self.stats["recommended_fixes"]:
                                self.stats["recommended_fixes"].append(suggested_fix)

                            if isinstance(last_exc, (httpx.ConnectError, httpx.ConnectTimeout)):
                                self._connect_failures += 1
                            raise LiveCallError(f"live call failed after {_MAX_ATTEMPTS} attempts: {last_exc}")

            raise LiveCallError(f"live call failed after {_MAX_ATTEMPTS} attempts: {last_exc}")
        finally:
            if not settled:
                await self.budget.release(test_name)

    @staticmethod
    def _safe_parse(response: Any) -> Any:
        ctype = response.headers.get("content-type", "")
        if "json" in ctype:
            try:
                return response.json()
            except (ValueError, TypeError):
                log.warning("content-type json but body wasn't parseable; using text")
                return response.text
        return response.text
