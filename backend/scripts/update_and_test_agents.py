import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
load_dotenv()
import asyncio
import json
from database.connection import get_db_connection
from database.live_agents import seal_settings, settings_of
from routers.user_api import execute_live_agent_test, LiveAgentTestRequest
from security import create_access_token

def update_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cfg_weather = {
        'agentType': 'chat',
        'endpointUrl': 'https://weather-agent-pc6l.onrender.com/agent/invoke',
        'payloadTemplate': '{"input": "{PROMPT}"}',
        'responsePath': 'output',
        'goldenJsonl': '',
        'repeats': 1,
        'useAiJudge': False,
        'scheduleMinutes': 1440,
        'monitor': True,
        'healthMinutes': 5,
        'includeMultilingual': True,
        'includeNumberChecks': False,
        'requiresAuth': True,
        'fairnessJson': '',
        'accessJson': ''
    }
    cur.execute(
        "UPDATE live_agents SET settings_enc = ?, last_error = NULL WHERE id = ?",
        (seal_settings('default-dev-token', cfg_weather), 28)
    )
    conn.commit()
    conn.close()
    print("DB updated for Weather agent (id=28).")

async def test_agents():
    token = create_access_token(2, 'ismeet@example.com', 'USER', 'Ismeet')
    auth_header = f"Bearer {token}"
    
    # 1. Test Weather
    print("Testing Weather Agent...")
    req_weather = LiveAgentTestRequest(
        live_agent_id=28,
        agent_name="Weather",
        openapi_url="https://weather-agent-pc6l.onrender.com/openapi.json",
        repo_path=r"C:\Personal\Testing agents\Langchain\WeatherAgent",
        auth_token="default-dev-token",
        auth_type="bearer",
        payload_template=json.dumps({"input": "{PROMPT}"}),
        response_path="output"
    )
    res_w = await execute_live_agent_test(req_weather, auth_header)
    print("Weather result:", res_w.get("success"), res_w.get("data", {}).get("trust_score"), res_w.get("data", {}).get("tier"))

    # 2. Test Loan
    print("Testing Loan Agent...")
    req_loan = LiveAgentTestRequest(
        live_agent_id=24,
        agent_name="Loan",
        openapi_url="https://loan-agent-2ud4.onrender.com/openapi.json",
        repo_path=r"C:\Copilot\Agent\Loan advisor agent"
    )
    res_l = await execute_live_agent_test(req_loan, auth_header)
    print("Loan result:", res_l.get("success"), res_l.get("data", {}).get("trust_score"), res_l.get("data", {}).get("tier"))

if __name__ == "__main__":
    update_db()
    asyncio.run(test_agents())
