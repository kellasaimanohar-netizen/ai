"""A failed or crashed test becomes a notification for its owner; passing tests and scheduled runs
(which raise their own alerts) do not add one."""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from live_testing import scheduler


def _db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE live_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, schedule_id INTEGER, agent_name TEXT, audit_id TEXT, kind TEXT, severity TEXT, message TEXT, created_at TEXT, read_at TEXT)")
    scheduler._notify_tables_ready = True
    return c


def _rows(c):
    return [dict(r) for r in c.execute("SELECT * FROM live_alerts ORDER BY id")]


def test_not_certified_result_is_a_critical_notification():
    c = _db()
    scheduler.notify_test_result(c, 7, "Loan", "NOT_CERTIFIED", 42, 3, "AA-1", live=True)
    [row] = _rows(c)
    assert (row["user_id"], row["agent_name"], row["kind"], row["severity"], row["audit_id"]) == (7, "Loan", "test_failed", "CRITICAL", "AA-1")
    assert "42%" in row["message"] and "3 critical findings" in row["message"]


def test_inconclusive_is_a_warning_and_passing_tests_add_nothing():
    c = _db()
    scheduler.notify_test_result(c, 7, "Loan", "CERTIFIED", 95, 0, "AA-2", live=False)
    scheduler.notify_test_result(c, 7, "Loan", "CONDITIONAL", 75, 0, "AA-3", live=False)
    assert _rows(c) == []
    scheduler.notify_test_result(c, 7, "Loan", "INCONCLUSIVE", 0, 0, "AA-4", live=False)
    assert [(r["kind"], r["severity"]) for r in _rows(c)] == [("test_inconclusive", "WARNING")]


def test_crash_is_a_notification():
    c = _db()
    scheduler.notify_test_error(c, 7, "Weather", "Docker is not running", live=False)
    [row] = _rows(c)
    assert row["kind"] == "test_error" and "Docker is not running" in row["message"]


def test_scheduled_live_runs_do_not_add_a_second_notification():
    c = _db()
    token = scheduler._IN_SCHEDULED_RUN.set(True)
    try:
        scheduler.notify_test_result(c, 7, "Loan", "NOT_CERTIFIED", 10, 1, "AA-5", live=True)
        scheduler.notify_test_error(c, 7, "Loan", "boom", live=True)
    finally:
        scheduler._IN_SCHEDULED_RUN.reset(token)
    assert _rows(c) == []


def test_a_broken_database_does_not_fail_the_test():
    c = sqlite3.connect(":memory:")   # no live_alerts table
    scheduler._notify_tables_ready = True
    scheduler.notify(c, 7, "Loan", "test_failed", "CRITICAL", "x")
