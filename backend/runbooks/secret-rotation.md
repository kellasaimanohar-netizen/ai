# Secret Rotation Runbook

1. Generate a new API token for the agent.
2. Update the AGENT_API_TOKEN environment variable in the staging environment.
3. Update any downstream services or frontend apps to use the new token.
4. Deploy the new configuration to the production environment.
5. Invalidate the old token after a 24-hour grace period.
