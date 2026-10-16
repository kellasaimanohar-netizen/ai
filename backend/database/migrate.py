"""Versioned schema migrations for the CertifyAI PostgreSQL database.

Each file in database/migrations/ named NNNN_description.sql runs once, in order, inside its own transaction.
A NNNN_description.py file defines run(cursor) for changes SQL cannot make, such as encrypting stored secrets.
Applied versions are recorded in schema_migrations, so running this again does nothing. A failing migration is
rolled back and stops the run with its error; nothing is skipped silently.

    python -m database.migrate            apply pending migrations
    python -m database.migrate status     list applied and pending migrations
"""
from __future__ import annotations

import hashlib
import importlib.util
import logging
import re
import sys
from pathlib import Path

import psycopg2

from .connection import DATABASE_URL

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.(sql|py)$")
_LOCK_ID = 7_301_220_001   # advisory lock, so two servers starting together do not migrate at the same time


def _files() -> list[tuple[str, Path]]:
    out = []
    for p in sorted(list(MIGRATIONS_DIR.glob("*.sql")) + list(MIGRATIONS_DIR.glob("*.py")), key=lambda p: p.name):
        m = _NAME.match(p.name)
        if not m:
            raise RuntimeError(f"Migration file name must look like 0003_add_something.sql or .py: {p.name}")
        out.append((m.group(1), p))
    versions = [v for v, _ in out]
    if len(versions) != len(set(versions)):
        raise RuntimeError("Two migration files share the same number.")
    return out


def _checksum(path: Path) -> str:
    # Normalize CRLF to LF so Windows checkouts match Linux/git baseline checksums
    content = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").encode("utf-8")
    return hashlib.sha256(content).hexdigest()[:16]


def _connect():
    if not DATABASE_URL:
        raise RuntimeError("No database configured. Set DB_HOST, DB_PORT, DB_NAME, DB_USER and DB_PASSWORD in backend/.env.")
    return psycopg2.connect(DATABASE_URL)


def _run_python(path: Path, cur) -> None:
    spec = importlib.util.spec_from_file_location(f"migration_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run(cur)


def _ensure_table(cur) -> None:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            checksum   TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")


def _applied(cur) -> dict[str, tuple[str, str]]:
    cur.execute("SELECT version, name, checksum FROM schema_migrations")
    return {v: (n, c) for v, n, c in cur.fetchall()}


def migrate() -> list[str]:
    """Apply every pending migration. Returns the file names applied."""
    done: list[str] = []
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_LOCK_ID,))
            _ensure_table(cur)
            conn.commit()
            applied = _applied(cur)
            for version, path in _files():
                if version in applied:
                    if applied[version][1] != _checksum(path):
                        logging.warning("Migration %s changed after it was applied. Add a new migration instead of editing it.", path.name)
                    continue
                try:
                    if path.suffix == ".py":
                        _run_python(path, cur)
                    else:
                        cur.execute(path.read_text(encoding="utf-8"))
                    cur.execute("INSERT INTO schema_migrations (version, name, checksum) VALUES (%s, %s, %s)",
                                (version, path.name, _checksum(path)))
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    raise RuntimeError(f"Migration {path.name} failed and was rolled back: {e}") from e
                logging.info("Applied migration %s", path.name)
                done.append(path.name)
            cur.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_ID,))
            conn.commit()
    finally:
        conn.close()
    return done


def status() -> list[tuple[str, str]]:
    """Each migration file with 'applied' or 'pending'."""
    conn = _connect()
    try:
        with conn.cursor() as cur:
            _ensure_table(cur)
            conn.commit()
            applied = _applied(cur)
    finally:
        conn.close()
    return [(p.name, "applied" if v in applied else "pending") for v, p in _files()]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        for name, state in status():
            print(f"{state:8} {name}")
    else:
        applied_now = migrate()
        print("\n".join(f"applied  {n}" for n in applied_now) or "The database is up to date.")
