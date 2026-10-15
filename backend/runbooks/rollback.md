# Rollback Runbook

1. Identify the version of the agent that is failing.
2. Revert the repository to the previous stable commit.
3. Redeploy the application using the standard CI/CD pipeline.
4. Monitor the /agent/invoke endpoint to ensure stability.
