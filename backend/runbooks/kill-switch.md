# Kill-Switch Runbook

1. In the event of a critical security breach or agent hallucination loop, immediately stop the agent service.
2. If running locally, kill the Python process or Docker container.
3. If running in production, block all traffic to the /agent/invoke endpoint via the load balancer or API Gateway.
4. Notify the security and response team.
