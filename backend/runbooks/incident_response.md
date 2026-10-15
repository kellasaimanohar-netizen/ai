# Incident Response Runbook

## Agent API is Down
1. Check the `main.py` FastAPI process.
2. Verify the `AGENT_API_TOKEN` in the `.env` file matches the expected token in the audit framework.
3. Review standard output for any port binding conflicts (default is 8081).

## High Latency
1. Check if the upstream LLM provider is experiencing delays.
2. Review the `p95_latency_ms` SLO.

## Rate Limit Hits
1. The agent should gracefully fallback and return a `cost_usd: 0` with a trace ID.
2. Wait for the rate limit window to expire before retrying.
