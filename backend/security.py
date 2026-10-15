"""Security module for CertifyAI V10.

Provides:
- bcrypt password hashing and verification with legacy SHA256 migration support.
- PyJWT token generation and verification (HS256 with strong claims: sub, user_id, role, exp, iss, aud).
- FastAPI authentication dependencies (get_current_user, require_admin, require_user).
- SSRF prevention validating IP resolution against private, loopback, link-local, and cloud metadata ranges.
"""
from __future__ import annotations

import logging
import os
import secrets
import socket
import ipaddress
import hashlib
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from typing import Optional, Any

import bcrypt
import jwt
from fastapi import Header, HTTPException, Depends
from database import get_db_connection

log = logging.getLogger(__name__)

def _load_jwt_secret() -> str:
    """Loads JWT_SECRET from the environment, never falling back to a fixed,
    checked-in secret — anyone who reads the source could forge admin JWTs
    with it. If unset, generate a random per-process secret instead; this
    keeps local/dev usage working while making the value unguessable and
    unique to the running process (tokens are invalidated on restart, which
    is the correct trade-off for a secret that was never actually provisioned).
    """
    env_secret = os.environ.get("JWT_SECRET")
    if env_secret:
        return env_secret
    log.warning(
        "JWT_SECRET is not set in the environment. Generated a random "
        "per-process secret instead of using a fixed default — all "
        "existing tokens will be invalidated on restart. Set JWT_SECRET "
        "to a stable, secret value for any deployment that must survive "
        "restarts or run more than one process."
    )
    return secrets.token_hex(32)


JWT_SECRET: str = _load_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
MIN_PASSWORD_LENGTH = 8
JWT_ISSUER = "certifyai-auth"
JWT_AUDIENCE = "certifyai-api"


# ── Password Hashing & Verification ─────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hashes a plain password using bcrypt with work factor 12."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against stored hash.

    Supports bcrypt as primary format and gracefully supports legacy 64-char
    SHA-256 hashes during migration.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        # Check if legacy 64-char hex string (SHA256)
        if len(hashed_password) == 64 and all(c in "0123456789abcdefABCDEF" for c in hashed_password):
            computed = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
            return computed.lower() == hashed_password.lower()
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


# ── JWT Token Issuance & Verification ────────────────────────────────────────

def create_access_token(
    user_id: int,
    email: str,
    role: str,
    name: str,
    expires_delta: Optional[timedelta] = None,
    issued_after_ms: Optional[int] = None,
) -> str:
    """Generates a signed HS256 JWT access token with standard claims.
    issued_after_ms: the cut-off end_sessions just set, so a token issued in the same millisecond still counts as newer."""
    now = datetime.now(timezone.utc)
    iat_ms = int(now.timestamp() * 1000)
    if issued_after_ms is not None:
        iat_ms = max(iat_ms, issued_after_ms + 1)
    exp = now + (expires_delta or timedelta(hours=JWT_EXPIRATION_HOURS))
    payload = {
        "sub": str(user_id),
        "user_id": user_id,
        "email": email.strip().lower(),
        "role": role.strip().upper(),
        "name": name.strip(),
        "iat": int(now.timestamp()),
        "iat_ms": iat_ms,   # sessions ended in the same second as this sign-in still apply
        "exp": int(exp.timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decodes and validates a JWT token."""
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        audience=JWT_AUDIENCE,
        issuer=JWT_ISSUER,
    )


# ── FastAPI Authentication & RBAC Dependencies ──────────────────────────────

def get_current_user(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """Dependency that authenticates request via Authorization: Bearer <token>.

    Rejects missing or invalid tokens with HTTP 401.
    Returns the active user record from database.
    """
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication credentials required. Please provide 'Authorization: Bearer <token>' header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]
    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Authentication token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token signature or claims.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Malformed authentication token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name, email, role, status, department, avatar_url, created_at, last_login, sessions_valid_after "
        "FROM accounts WHERE id = ?",
        (user_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=401,
            detail="Authenticated user account not found or has been removed.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = dict(row)
    if user.get("status") != "Active":
        raise HTTPException(
            status_code=403,
            detail="User account is deactivated. Contact an Administrator.",
        )
    # Signing out or changing the password moves this forward, so older tokens stop working
    valid_after = user.pop("sessions_valid_after", None)
    issued_ms = int(payload.get("iat_ms") or int(payload.get("iat") or 0) * 1000)
    if valid_after and issued_ms <= int(valid_after):
        raise HTTPException(
            status_code=401,
            detail="This session has ended. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def end_sessions(cursor, account_id: int) -> int:
    """Refuses every token issued for this account until now. Returns the cut-off (Unix ms). The caller commits."""
    cutoff = int(time.time() * 1000)
    cursor.execute("UPDATE accounts SET sessions_valid_after = ? WHERE id = ?", (cutoff, account_id))
    return cutoff


def require_admin(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """Dependency that enforces ADMIN role. Rejects non-admin users with HTTP 403."""
    if current_user.get("role") != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Access forbidden: Administrator privileges (role: ADMIN) required.",
        )
    return current_user


def require_user(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """Dependency for authenticated users (ADMIN or USER)."""
    return current_user


# ── SSRF Defense ─────────────────────────────────────────────────────────────

def is_safe_url(url_str: str) -> tuple[bool, str]:
    """Validates that a URL does not resolve to private, loopback, link-local,

    cloud metadata (169.254.169.254), or internal network IPs.
    Returns (is_safe: bool, reason: str).
    """
    if not url_str or not isinstance(url_str, str):
        return False, "Empty or invalid URL"

    try:
        parsed = urlparse(url_str.strip())
        if parsed.scheme not in ("http", "https"):
            return False, f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed."

        hostname = parsed.hostname
        if not hostname:
            return False, "URL does not contain a valid hostname."

        # Explicit forbidden names
        lower_host = hostname.lower()
        if lower_host in (
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "metadata.google.internal",
            "instance-data",
        ):
            return False, f"Access to '{hostname}' is restricted."

        # Reject userinfo in URL (e.g. http://user:pass@host)
        if parsed.username or parsed.password:
            return False, "Embedded userinfo credentials in URL are not allowed."

        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Resolve IP addresses
        try:
            addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as err:
            return False, f"Unable to resolve host '{hostname}': {err}"

        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                return False, f"Invalid resolved IP '{ip_str}'."
            # Judge IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::a.b.c.d) addresses by the IPv4 inside
            if isinstance(ip, ipaddress.IPv6Address):
                if ip.ipv4_mapped is not None:
                    ip = ip.ipv4_mapped
                elif ip in ipaddress.ip_network("64:ff9b::/96"):
                    ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)

            if ip.is_loopback:
                return False, f"Host resolves to loopback IP address {ip_str}."
            if ip.is_private:
                return False, f"Host resolves to private network IP address {ip_str} (SSRF blocked)."
            if ip.is_link_local:
                return False, f"Host resolves to link-local IP address {ip_str}."
            if ip.is_multicast:
                return False, f"Host resolves to multicast IP address {ip_str}."
            if ip.is_unspecified:
                return False, f"Host resolves to unspecified IP address {ip_str}."
            if str(ip) == "169.254.169.254":
                return False, "Access to cloud instance metadata service (169.254.169.254) is blocked."

            # Handle IPv6 NAT64 translation (RFC 6052 64:ff9b::/96)
            if ip.version == 6 and ip in ipaddress.IPv6Network("64:ff9b::/96"):
                ipv4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
                if ipv4.is_loopback or ipv4.is_private or ipv4.is_link_local or ipv4.is_unspecified or str(ipv4) == "169.254.169.254":
                    return False, f"Host resolves to restricted translated IPv4 address {ipv4}."
            elif ip.is_reserved:
                return False, f"Host resolves to reserved IP address {ip_str}."

        return True, ""
    except Exception as exc:
        return False, f"URL security check failed: {exc}"


def private_targets_allowed() -> bool:
    """Local development only: AA_ALLOW_PRIVATE_TARGETS=1 lets tests reach agents on localhost or a private network."""
    return os.environ.get("AA_ALLOW_PRIVATE_TARGETS") == "1"


def tls_verify() -> bool:
    """Certificates of the agents and specs we call are checked, unless AA_INSECURE_TLS=1 (self-signed test servers)."""
    return os.environ.get("AA_INSECURE_TLS") != "1"


def outbound_problem(url: str) -> str | None:
    """Why the server must not call this URL, or None when it may."""
    if private_targets_allowed():
        parsed = urlparse((url or "").strip())
        return None if parsed.scheme in ("http", "https") and parsed.hostname else "Only http and https addresses can be called."
    safe, reason = is_safe_url(url)
    return None if safe else reason


def check_outbound_url(url: str, what: str = "URL") -> str:
    """The URL with a scheme added, or HTTP 400 when it points at this server, a private network or cloud metadata."""
    clean = (url or "").strip()
    if clean and not clean.startswith(("http://", "https://")):
        clean = f"https://{clean}"
    if private_targets_allowed():
        parsed = urlparse(clean)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            return clean
    safe, reason = is_safe_url(clean)
    if not safe:
        raise HTTPException(status_code=400, detail=f"This {what} is not allowed: {reason}")
    return clean
