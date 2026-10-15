"""Encrypt the API tokens that monitors stored in plain text inside live_schedules.request_json."""
import json

from database.crypto import seal_request


def run(cur) -> None:
    cur.execute("SELECT id, request_json FROM live_schedules")
    for sid, raw in cur.fetchall():
        try:
            req = json.loads(raw or "{}")
        except ValueError:
            continue
        sealed = seal_request(req)
        if sealed != req:
            cur.execute("UPDATE live_schedules SET request_json = %s WHERE id = %s", (json.dumps(sealed), sid))
