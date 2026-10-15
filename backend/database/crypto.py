"""Encryption for secrets kept in the database, such as an agent's API token.

The key comes from DATA_ENCRYPTION_KEY in backend/.env (generate one with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
Keep a copy of the key somewhere safe: without it, stored secrets cannot be read back.
"""
from __future__ import annotations

import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

_PREFIX = "enc:v1:"
_SECRET_FIELDS = ("auth_token",)


def _fernet() -> Fernet:
    key = os.getenv("DATA_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError("DATA_ENCRYPTION_KEY is not set in backend/.env, so secrets cannot be stored or read.")
    return Fernet(key.encode())


def is_encrypted(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(_PREFIX)


def encrypt(value: str | None) -> str | None:
    if value is None or value == "" or is_encrypted(value):
        return value
    return _PREFIX + _fernet().encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str | None:
    if not is_encrypted(value):
        return value
    try:
        return _fernet().decrypt(value[len(_PREFIX):].encode()).decode()
    except InvalidToken:
        raise RuntimeError("A stored secret cannot be decrypted. DATA_ENCRYPTION_KEY has changed since it was saved.") from None


def encrypt_json(data: Any) -> str:
    return encrypt(json.dumps(data))  # type: ignore[return-value]


def decrypt_json(value: str | None, default: Any = None) -> Any:
    if not value:
        return default
    return json.loads(decrypt(value) or "null")


def seal_request(req: dict) -> dict:
    """A copy of a live test request with its secrets encrypted, for storing."""
    out = dict(req)
    for field in _SECRET_FIELDS:
        if out.get(field):
            out[field] = encrypt(out[field])
    acl = out.get("access_control_config")
    if isinstance(acl, dict) and isinstance(acl.get("users"), list):
        acl = dict(acl)
        acl["users"] = [{**u, "token": encrypt(u["token"])} if isinstance(u, dict) and u.get("token") else u for u in acl["users"]]
        out["access_control_config"] = acl
    return out


def open_request(req: dict) -> dict:
    """The stored request with its secrets decrypted, for running a test."""
    out = dict(req)
    for field in _SECRET_FIELDS:
        if out.get(field):
            out[field] = decrypt(out[field])
    acl = out.get("access_control_config")
    if isinstance(acl, dict) and isinstance(acl.get("users"), list):
        acl = dict(acl)
        acl["users"] = [{**u, "token": decrypt(u["token"])} if isinstance(u, dict) and u.get("token") else u for u in acl["users"]]
        out["access_control_config"] = acl
    return out
