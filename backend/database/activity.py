"""The activity log: one append-only row for every action a person takes, for admins to review.

Call log_activity() in the same transaction as the change it describes. The client's IP address is picked
up from the current request (set by the middleware in backend.py), so callers do not pass it.
"""
from __future__ import annotations

from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

client_ip: ContextVar[str | None] = ContextVar("client_ip", default=None)


def log_activity(cursor, actor: dict[str, Any], event: str, details: str, *, status: str = "SUCCESS",
                 entity_type: str | None = None, entity_id: Any = None) -> None:
    """actor is the account that acted: a dict with id, email, name and role."""
    cursor.execute(
        """INSERT INTO activity_logs (timestamp, event_type, user_id, user_email, user_name, user_role, details, status,
                                      ip_address, entity_type, entity_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (datetime.now(timezone.utc).isoformat(), event, actor.get("id"), actor.get("email") or "", actor.get("name") or "",
         actor.get("role"), details, status, client_ip.get(), entity_type, None if entity_id is None else str(entity_id)),
    )
