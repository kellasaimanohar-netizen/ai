from dotenv import load_dotenv
load_dotenv()
from database.connection import get_db_connection
from database.live_agents import seal_settings

conn = get_db_connection()
cur = conn.cursor()
cfg = {
    "payloadTemplate": "{\"input\": \"{{input}}\"}",
    "responsePath": "output",
    "endpointUrl": "https://weather-agent-pc6l.onrender.com/agent/invoke"
}
cur.execute("UPDATE live_agents SET settings_enc = %s, last_error = NULL WHERE id = 28", (seal_settings("default-dev-token", cfg),))
conn.commit()
print("Updated Weather agent successfully with default-dev-token!")
