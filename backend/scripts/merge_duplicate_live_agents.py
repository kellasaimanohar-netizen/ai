"""Cleans up duplicate live agents. Shows what it would change by default; --apply makes the changes.

    python scripts/merge_duplicate_live_agents.py                       show what would change
    python scripts/merge_duplicate_live_agents.py --apply               make the changes
    python scripts/merge_duplicate_live_agents.py --apply --remove 23   also remove agent 23 (see 2)

1. A live agent that a test run created by name (never registered, so it has no OpenAPI link) is merged into
   the same user's registered agent when its runs hit that agent's OpenAPI link or endpoint. Its runs move to
   the registered agent and take its name, any monitor moves too, then the duplicate row is deleted.
2. --remove deletes the listed unregistered agents that match no registered agent. Their runs are not deleted:
   they stay in the test history, unlinked. An agent with a monitor, or a registered agent, is never removed.
3. Every run of an agent gets the agent's current name.
4. A monitor with no agent link is linked to the user's one registered agent with the same OpenAPI link.

Every change runs in one transaction. Without --apply it is rolled back, so the report is exactly what --apply does.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _runs(cur, agent_id: int) -> list[dict]:
    cur.execute("SELECT id, endpoint_url, openapi_url FROM live_agent_tests WHERE live_agent_id = ?", (agent_id,))
    return [dict(r) for r in cur.fetchall()]


def clean_up(conn, remove_ids: set[int] | None = None, apply: bool = False) -> list[str]:
    """Merges and removes duplicate live agents. Returns one line per change."""
    from database.live_agents import _saved_endpoint, normalize_url, rename_history
    remove_ids = set(remove_ids or ())
    cur = conn.cursor()
    report: list[str] = []
    try:
        cur.execute("SELECT id, user_id, name, openapi_url, settings_enc FROM live_agents ORDER BY id")
        agents = [dict(r) for r in cur.fetchall()]
        registered = [a for a in agents if a["openapi_url"]]
        reg_addresses = {}
        for a in registered:
            addrs = {normalize_url(a["openapi_url"]), _saved_endpoint(a)}
            addrs |= {normalize_url(r["endpoint_url"]) for r in _runs(cur, a["id"])}
            reg_addresses[a["id"]] = addrs - {""}

        for shell in [a for a in agents if not a["openapi_url"]]:
            runs = _runs(cur, shell["id"])
            hit = {normalize_url(r["endpoint_url"]) for r in runs} | {normalize_url(r["openapi_url"]) for r in runs}
            hit -= {""}
            target = next((a for a in registered if a["user_id"] == shell["user_id"] and reg_addresses[a["id"]] & hit), None)
            if target:
                cur.execute("UPDATE live_agent_tests SET live_agent_id = ? WHERE live_agent_id = ?", (target["id"], shell["id"]))
                cur.execute("UPDATE live_schedules SET live_agent_id = ? WHERE live_agent_id = ?", (target["id"], shell["id"]))
                cur.execute("DELETE FROM live_agents WHERE id = ?", (shell["id"],))
                report.append(f"Merged live agent {shell['id']} '{shell['name']}' into {target['id']} '{target['name']}': "
                              f"{len(runs)} run(s) moved, duplicate removed.")
            elif shell["id"] in remove_ids:
                cur.execute("SELECT COUNT(*) FROM live_schedules WHERE live_agent_id = ?", (shell["id"],))
                if cur.fetchone()[0]:
                    report.append(f"Kept live agent {shell['id']} '{shell['name']}': it has a monitor. Stop the monitor first.")
                    continue
                cur.execute("DELETE FROM live_agents WHERE id = ?", (shell["id"],))
                report.append(f"Removed live agent {shell['id']} '{shell['name']}' (user {shell['user_id']}). "
                              f"Its {len(runs)} run(s) stay in the test history, unlinked.")
            remove_ids.discard(shell["id"])
        for rid in sorted(remove_ids):
            report.append(f"Did not remove live agent {rid}: it is registered or does not exist.")

        cur.execute("SELECT id, name FROM live_agents ORDER BY id")
        for a in [dict(r) for r in cur.fetchall()]:
            n = rename_history(cur, a["id"], a["name"])
            if n:
                report.append(f"Renamed {n} run(s) of live agent {a['id']} to '{a['name']}'.")

        cur.execute("SELECT id, user_id, name, request_json FROM live_schedules WHERE live_agent_id IS NULL")
        for s in [dict(r) for r in cur.fetchall()]:
            try:
                req = json.loads(s["request_json"] or "{}")
            except ValueError:
                continue
            spec = normalize_url(req.get("openapi_url"))
            matches = [a for a in registered if a["user_id"] == s["user_id"] and spec and normalize_url(a["openapi_url"]) == spec]
            if len(matches) != 1:
                continue
            a = matches[0]
            req["live_agent_id"], req["agent_name"] = a["id"], a["name"]
            cur.execute("UPDATE live_schedules SET live_agent_id = ?, name = ?, request_json = ? WHERE id = ?",
                        (a["id"], a["name"], json.dumps(req), s["id"]))
            report.append(f"Linked monitor {s['id']} '{s['name']}' to live agent {a['id']} '{a['name']}'.")
    except Exception:
        conn.rollback()
        raise
    if apply:
        conn.commit()
    else:
        conn.rollback()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge and remove duplicate live agents.")
    parser.add_argument("--apply", action="store_true", help="make the changes (default: only show them)")
    parser.add_argument("--remove", type=int, nargs="*", default=[], help="unregistered agent ids to remove when they match nothing")
    args = parser.parse_args()
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    from database.connection import get_db_connection
    conn = get_db_connection()
    try:
        lines = clean_up(conn, set(args.remove), apply=args.apply)
    finally:
        conn.close()
    print(("Applied:" if args.apply else "Would change (nothing saved, run with --apply):") if lines else "Nothing to change.")
    for line in lines:
        print(" -", line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
