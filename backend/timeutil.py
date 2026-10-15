"""Calendar days in the organisation's time zone.

Timestamps are stored in UTC. "Today", daily charts and date filters use APP_UTC_OFFSET (default +05:30, India),
so a test run at 02:00 local time counts on the day it ran, not the previous UTC day.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone


def _offset() -> timezone:
    raw = os.environ.get("APP_UTC_OFFSET", "+05:30").strip()
    m = re.fullmatch(r"([+-])(\d{1,2}):?(\d{2})?", raw)
    if not m:
        return timezone.utc
    minutes = int(m.group(2)) * 60 + int(m.group(3) or 0)
    return timezone(timedelta(minutes=-minutes if m.group(1) == "-" else minutes))


APP_TZ = _offset()


def local_now() -> datetime:
    return datetime.now(APP_TZ)


def local_day_start(days_ago: int = 0) -> datetime:
    """Midnight, local time, `days_ago` days before today."""
    return (local_now() - timedelta(days=days_ago)).replace(hour=0, minute=0, second=0, microsecond=0)


def utc_iso(dt: datetime) -> str:
    """The moment as a UTC ISO string, comparable with the stored created_at values."""
    return dt.astimezone(timezone.utc).isoformat()


def local_date_key(stored: object) -> str | None:
    """The local calendar day (YYYY-MM-DD) of a stored UTC timestamp, or None when it cannot be read."""
    if stored is None:
        return None
    if isinstance(stored, datetime):
        dt = stored
    else:
        try:
            dt = datetime.fromisoformat(str(stored).strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(APP_TZ).strftime("%Y-%m-%d")
