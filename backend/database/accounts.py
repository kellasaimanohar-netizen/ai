"""Admin and user accounts, all in the `accounts` table; `role` says which kind each one is."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

PROFILE_COLUMNS = "id, name, email, role, status, department, avatar_url, created_at, last_login"
_FIELDS = ("email", "role", "name", "password_hash", "status", "department", "avatar_url", "last_login")
_DEFAULT_DEPARTMENT = {"ADMIN": "Administration", "USER": "AI Safety & Quality Assurance"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_account(cursor, role: str, email: str, name: str, password_hash: str, *, status: str = "Active",
                   department: str | None = None, avatar_url: str | None = None, last_login: str | None = None) -> int:
    """Creates an admin or user account. Returns the new account id."""
    if role not in _DEFAULT_DEPARTMENT:
        raise ValueError(f"Unknown account role: {role!r}")
    cursor.execute(
        """INSERT INTO accounts (role, email, name, password_hash, status, department, avatar_url, last_login, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (role, email.strip().lower(), name, password_hash, status, department or _DEFAULT_DEPARTMENT[role], avatar_url,
         last_login, _now()),
    )
    return cursor.lastrowid


def get_account(cursor, account_id: int, *, with_password: bool = False) -> dict[str, Any] | None:
    cols = PROFILE_COLUMNS + (", password_hash" if with_password else "")
    cursor.execute(f"SELECT {cols} FROM accounts WHERE id = ?", (account_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def update_account(cursor, account_id: int, **fields: Any) -> None:
    """Changes any of: email, role, name, password_hash, status, department, avatar_url, last_login."""
    unknown = set(fields) - set(_FIELDS)
    if unknown:
        raise ValueError(f"Unknown account fields: {', '.join(sorted(unknown))}")
    if fields.get("role") is not None and fields["role"] not in _DEFAULT_DEPARTMENT:
        raise ValueError(f"Unknown account role: {fields['role']!r}")
    if "email" in fields and fields["email"]:
        fields["email"] = fields["email"].strip().lower()
    fields = {k: v for k, v in fields.items() if v is not None or k == "last_login"}
    cursor.execute("SELECT 1 FROM accounts WHERE id = ?", (account_id,))
    if not cursor.fetchone():
        raise LookupError(f"Account {account_id} not found")
    if fields:
        sets = ", ".join(f"{k} = ?" for k in fields)
        cursor.execute(f"UPDATE accounts SET {sets} WHERE id = ?", (*fields.values(), account_id))
