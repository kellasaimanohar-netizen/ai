import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

from .connection import get_db_connection, DB_PATH, hash_password
from .pdf_storage import generate_and_store_pdf, get_pdf_path, relative_pdf_path, PDF_DIR
from .accounts import create_account
from .test_runs import record_certify_findings, record_live_findings, set_pdf_path


def run_migrations(conn=None):
    """Applies pending versioned migrations from database/migrations/. `conn` is unused and kept for older callers."""
    from .migrate import migrate
    return migrate()


def seed_users(conn):
    """Creates the first administrator, only when there are no users yet, from BOOTSTRAP_ADMIN_EMAIL,
    BOOTSTRAP_ADMIN_PASSWORD and optionally BOOTSTRAP_ADMIN_NAME. Nothing is created without them, and no
    password is ever written in the code."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM accounts")
    if cursor.fetchone()[0] != 0:
        return
    email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")
    if not email or not password:
        logging.warning("No users exist. Set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD to create the first administrator.")
        return
    create_account(cursor, "ADMIN", email, os.environ.get("BOOTSTRAP_ADMIN_NAME", "Administrator"), hash_password(password))
    conn.commit()


def sync_local_pdfs_and_versions(conn):
    """
    Synchronizes test runs:
    1. Generates and stores local PDF reports for all tests in storage/reports/
    2. Populates audit_findings table with granular checks
    """
    cursor = conn.cursor()
    
    # Check if test_runs exists
    cursor.execute("SELECT id, audit_id, test_type, user_id, agent_name, trust_score, tier, mode, duration_ms, critical_count, warning_count, pass_count, info_count, created_at, full_result_json, pdf_path FROM all_agent_tests ORDER BY created_at ASC, id ASC")
    runs = [dict(r) for r in cursor.fetchall()]

    if not runs:
        return

    # 1. Generate local PDFs for every test run
    for r in runs:
        aid = r["audit_id"]
        pdf_path = r.get("pdf_path")
        
        # Check if PDF already exists locally
        existing_pdf = get_pdf_path(aid)
        if not existing_pdf:
            full_data = {}
            if r.get("full_result_json"):
                try:
                    full_data = json.loads(r["full_result_json"])
                except Exception:
                    full_data = {}
            
            payload = {
                "audit_id": aid,
                "agent_name": r["agent_name"],
                "trust_score": r["trust_score"],
                "tier": r["tier"],
                "mode": r["mode"],
                "test_type": r["test_type"],
                "duration_ms": r["duration_ms"],
                "critical_count": r["critical_count"],
                "warning_count": r["warning_count"],
                "pass_count": r["pass_count"],
                "created_at": r["created_at"],
                "findings": full_data.get("findings", [])
            }
            new_pdf_path = generate_and_store_pdf(payload)
            set_pdf_path(cursor, r["id"], new_pdf_path)
        elif not pdf_path:
            set_pdf_path(cursor, r["id"], relative_pdf_path(existing_pdf))

    # 2. Findings rows for any test that has none yet, from its saved result
    for r in runs:
        cursor.execute("SELECT 1 FROM audit_findings WHERE test_run_id = ? LIMIT 1", (r["id"],))
        if cursor.fetchone() or not r.get("full_result_json"):
            continue
        try:
            findings = json.loads(r["full_result_json"]).get("findings", [])
        except (ValueError, AttributeError):
            continue
        record = record_live_findings if r["test_type"] == "live" else record_certify_findings
        record(cursor, r["id"], r["audit_id"], findings, r["created_at"])

    conn.commit()


def init_db():
    """Initializes database schema, seeds tables, and generates local audit PDFs."""
    conn = get_db_connection()
    try:
        run_migrations()
        seed_users(conn)
        sync_local_pdfs_and_versions(conn)
        logging.info("Database schema initialized successfully with local PDF storage.")
    finally:
        conn.close()
