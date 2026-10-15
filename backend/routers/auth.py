import hashlib
import os
import secrets
from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends, Header, Request
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta, timezone

from database import get_db_connection
from database.accounts import create_account, update_account
from database.activity import log_activity
from mailer import send_password_reset
from security import (
    verify_password,
    hash_password,
    create_access_token,
    decode_access_token,
    end_sessions,
    get_current_user as auth_get_current_user,
    MIN_PASSWORD_LENGTH,
)

router = APIRouter(prefix="", tags=["auth"])

RESET_MINUTES = int(os.getenv("PASSWORD_RESET_MINUTES", "30"))
MAX_RESETS_PER_HOUR = 3
# Wrong passwords allowed for one account in LOCKOUT_MINUTES before sign-in is refused for the rest of that window
MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", "10"))
LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
# How long a sign-in lasts: "Keep me signed in" ticked, or not
REMEMBER_HOURS = 24 * 7
SESSION_HOURS = 12
_PROFILE = "id, name, email, role, status, department, avatar_url, password_hash, created_at"


class LoginRequest(BaseModel):
    email: str
    password: str
    remember_me: Optional[bool] = True
    role: Optional[str] = None      # 'ADMIN' or 'USER': the tab the person signed in from


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class ResetTokenRequest(BaseModel):
    token: str


def _parse_env_list(val: str | None) -> list[str]:
    """Parses comma-separated environment variable list."""
    if not val:
        return []
    return [x.strip().lower() for x in val.split(",") if x.strip()]


def _log(cursor, event: str, user: dict, details: str, status: str = "SUCCESS") -> None:
    log_activity(cursor, user, event, details, status=status, entity_type="account", entity_id=user.get("id"))


def _env_account(cursor, role: str, raw_pass: str, names: list[str], emails: list[str], raw_ident: str,
                 department: str) -> dict:
    """The account the .env login names, created the first time someone signs in with it.
    Only that one account: the .env password never opens any other account of the same role."""
    email = emails[0] if emails else raw_ident
    cursor.execute(f"SELECT {_PROFILE} FROM accounts WHERE email = ?", (email,))
    user = cursor.fetchone()
    new_hash = hash_password(raw_pass)
    if user:
        if user["role"] != role:
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        update_account(cursor, user["id"], password_hash=new_hash)
        return dict(user)
    now_iso = datetime.now(timezone.utc).isoformat()
    default_name = "Admin" if role == "ADMIN" else "User"
    new_id = create_account(cursor, role, email, names[0].capitalize() if names else default_name,
                            new_hash, department=department, last_login=now_iso)
    cursor.execute(f"SELECT {_PROFILE} FROM accounts WHERE id = ?", (new_id,))
    return dict(cursor.fetchone())


@router.post("/api/auth/login")
@router.post("/auth/login")
@router.post("/login")
def login(req: LoginRequest):
    """Signs in an admin or a user. Accounts live in the database; the .env logins can create the first ones."""
    conn = get_db_connection()
    cursor = conn.cursor()

    raw_ident = req.email.strip().lower()
    raw_pass = req.password
    want_role = (req.role or "").strip().upper() or None
    if want_role not in (None, "ADMIN", "USER"):
        conn.close()
        raise HTTPException(status_code=400, detail="Role must be ADMIN or USER.")

    # Load dynamic credentials from environment (.env)
    env_admin_users = _parse_env_list(os.getenv("ADMIN_USERNAME", ""))
    env_admin_emails = _parse_env_list(os.getenv("ADMIN_EMAIL", ""))
    env_admin_pass = os.getenv("ADMIN_PASSWORD", "")

    env_user_users = _parse_env_list(os.getenv("USER_USERNAME", ""))
    env_user_emails = _parse_env_list(os.getenv("USER_EMAIL", ""))
    env_user_pass = os.getenv("USER_PASSWORD", "")

    # An unset variable must never act as a password, so there is no built-in default login.
    is_env_admin_match = bool(env_admin_pass) and (raw_ident in env_admin_users or raw_ident in env_admin_emails) and (raw_pass == env_admin_pass)
    is_env_user_match = bool(env_user_pass) and (raw_ident in env_user_users or raw_ident in env_user_emails) and (raw_pass == env_user_pass)

    # 1. Look the account up. An email is unique; a name is used only when exactly one account has it.
    cursor.execute(f"SELECT {_PROFILE} FROM accounts WHERE email = ?", (raw_ident,))
    user = cursor.fetchone()
    if not user:
        cursor.execute(f"SELECT {_PROFILE} FROM accounts WHERE LOWER(name) = ? LIMIT 2", (raw_ident,))
        named = cursor.fetchall()
        user = named[0] if len(named) == 1 else None
    user = dict(user) if user else None

    # 2. Database password first, then the .env password. The .env password opens only the account .env names:
    #    its email when ADMIN_EMAIL / USER_EMAIL is set, otherwise the account the .env username signed in to.
    if user:
        if _recent_failures(cursor, user["id"]) >= MAX_FAILED_LOGINS:
            conn.close()
            raise HTTPException(status_code=429, detail=f"Too many failed sign-in attempts. Try again in {LOCKOUT_MINUTES} minutes or reset your password.")
        db_valid = verify_password(raw_pass, user["password_hash"])
        env_match = is_env_admin_match if user["role"] == "ADMIN" else is_env_user_match
        env_emails = env_admin_emails if user["role"] == "ADMIN" else env_user_emails
        env_pass_valid = env_match and (user["email"] in env_emails if env_emails else True)

        if not db_valid and not env_pass_valid:
            _log(cursor, "LOGIN_FAILURE", user, "Failed login attempt: invalid password", "FAILED")
            conn.commit()
            conn.close()
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        # If authenticated via .env or legacy hash, store the verified bcrypt hash
        if env_pass_valid and not db_valid:
            update_account(cursor, user["id"], password_hash=hash_password(raw_pass))
            conn.commit()

    elif is_env_admin_match and want_role in (None, "ADMIN"):
        try:
            user = _env_account(cursor, "ADMIN", raw_pass, env_admin_users, env_admin_emails, raw_ident, "Enterprise AI Governance")
        except HTTPException:
            conn.close()
            raise
        conn.commit()

    elif is_env_user_match and want_role in (None, "USER"):
        try:
            user = _env_account(cursor, "USER", raw_pass, env_user_users, env_user_emails, raw_ident, "AI Quality Assurance & Testing")
        except HTTPException:
            conn.close()
            raise
        conn.commit()

    else:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    # Said only after the password is right, so it does not reveal which emails have accounts
    if want_role and user["role"] != want_role:
        conn.close()
        tab = "Admin" if user["role"] == "ADMIN" else "User"
        raise HTTPException(status_code=403, detail=f"This is {'an admin' if user['role'] == 'ADMIN' else 'a user'} account. Sign in on the {tab} tab.")

    if user["status"] != "Active":
        conn.close()
        raise HTTPException(status_code=403, detail="User account is deactivated. Contact Administrator.")

    now_iso = datetime.now(timezone.utc).isoformat()

    # Automatic hash migration: if stored hash is legacy SHA-256, upgrade to bcrypt
    if len(user["password_hash"]) == 64:
        update_account(cursor, user["id"], password_hash=hash_password(req.password), last_login=now_iso)
    else:
        update_account(cursor, user["id"], last_login=now_iso)

    _log(cursor, "USER_LOGIN", user, "User authenticated successfully")
    conn.commit()
    conn.close()

    # Generate standard cryptographic JWT access token
    token = create_access_token(
        user_id=user["id"],
        email=user["email"],
        role=user["role"],
        name=user["name"],
        expires_delta=timedelta(hours=REMEMBER_HOURS if req.remember_me else SESSION_HOURS),
    )

    return {
        "success": True,
        "token": token,
        "access_token": token,
        "token_type": "bearer",
        "user_id": str(user["id"]),
        "name": user["name"],
        "role": user["role"],
        "user": {
            "id": user["id"],
            "user_id": str(user["id"]),
            "name": user["name"],
            "full_name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "status": user["status"],
            "department": user["department"],
            "avatar_url": user["avatar_url"],
            "created_at": user.get("created_at"),
            "last_login": now_iso
        }
    }


def _recent_failures(cursor, account_id: int) -> int:
    """Wrong passwords for this account in the lockout window, counting only those after its last successful sign-in."""
    since = (datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    cursor.execute("""SELECT COUNT(*) FROM activity_logs
                      WHERE event_type = 'LOGIN_FAILURE' AND user_id = ? AND "timestamp" > ?
                        AND "timestamp" > COALESCE((SELECT MAX("timestamp") FROM activity_logs
                                                    WHERE event_type IN ('USER_LOGIN', 'PASSWORD_RESET') AND user_id = ?), '')""",
                   (account_id, since, account_id))
    return cursor.fetchone()[0]


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.strip().encode()).hexdigest()


def _frontend_url() -> str:
    explicit = os.getenv("FRONTEND_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")
    origins = [o.strip() for o in os.getenv("AA_ALLOWED_ORIGINS", "").split(",") if o.strip()]
    return (origins[0] if origins else "http://localhost:5173").rstrip("/")


@router.post("/api/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest, request: Request, background: BackgroundTasks):
    """Emails a one-time reset link. The answer is the same whether or not the email has an account."""
    answer = {"success": True, "message": "If an account exists for that email, a password reset link has been sent to it."}
    email = req.email.strip().lower()
    if not email:
        return answer
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email, role, status FROM accounts WHERE email = ?", (email,))
        acct = cursor.fetchone()
        if not acct or acct["status"] != "Active":
            return answer
        # The activity log already records every request, so it is what the hourly limit counts
        an_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        cursor.execute("""SELECT COUNT(*) FROM activity_logs
                          WHERE event_type = 'PASSWORD_RESET_REQUESTED' AND user_id = ? AND "timestamp" > ?""", (acct["id"], an_hour_ago))
        if cursor.fetchone()[0] >= MAX_RESETS_PER_HOUR:
            return answer
        token = secrets.token_urlsafe(32)
        # An account has one open link at a time, so a new link replaces any earlier one
        cursor.execute("UPDATE accounts SET reset_token_hash = ?, reset_expires_at = now() + make_interval(mins => ?) WHERE id = ?",
                       (_token_hash(token), RESET_MINUTES, acct["id"]))
        _log(cursor, "PASSWORD_RESET_REQUESTED", dict(acct), "Password reset link requested")
        conn.commit()
    finally:
        conn.close()
    # Sent after the response, so the reply takes the same time whether or not the account exists
    background.add_task(send_password_reset, acct["email"], acct["name"], f"{_frontend_url()}/reset-password?token={token}", RESET_MINUTES)
    return answer


def _valid_reset(cursor, token: str):
    cursor.execute("""
    SELECT id AS account_id, email, name, role, status FROM accounts
    WHERE reset_token_hash = ? AND reset_expires_at > now()
    """, (_token_hash(token),))
    row = cursor.fetchone()
    return row if row and row["status"] == "Active" else None


@router.post("/api/auth/reset-password/verify")
def verify_reset_token(req: ResetTokenRequest):
    """Lets the reset page say straight away when a link has expired or was already used."""
    conn = get_db_connection()
    try:
        row = _valid_reset(conn.cursor(), req.token)
    finally:
        conn.close()
    return {"valid": bool(row), "email": row["email"] if row else None}


@router.post("/api/auth/reset-password")
def reset_password(req: ResetPasswordRequest):
    if len(req.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"The password must be at least {MIN_PASSWORD_LENGTH} characters.")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        row = _valid_reset(cursor, req.token)
        if not row:
            raise HTTPException(status_code=400, detail="This reset link is invalid, expired or already used. Request a new one.")
        update_account(cursor, row["account_id"], password_hash=hash_password(req.new_password))
        cursor.execute("UPDATE accounts SET reset_token_hash = NULL, reset_expires_at = NULL WHERE id = ?", (row["account_id"],))
        end_sessions(cursor, row["account_id"])   # anyone signed in with the old password is signed out
        _log(cursor, "PASSWORD_RESET", {"id": row["account_id"], "email": row["email"], "name": row["name"], "role": row["role"]}, "Password changed with a reset link")
        conn.commit()
    finally:
        conn.close()
    return {"success": True, "message": "Your password has been changed. You can sign in now."}


@router.get("/me")
@router.get("/api/auth/me")
def get_current_user_profile(current_user: dict = Depends(auth_get_current_user)):
    """Returns the authenticated profile validated against the JWT signature and database."""
    return {
        "success": True,
        "user_id": str(current_user["id"]),
        "name": current_user["name"],
        "role": current_user["role"],
        "user": {
            "id": current_user["id"],
            "user_id": str(current_user["id"]),
            "name": current_user["name"],
            "full_name": current_user["name"],
            "email": current_user["email"],
            "role": current_user["role"],
            "status": current_user["status"],
            "department": current_user.get("department", "AI Governance"),
            "avatar_url": current_user.get("avatar_url"),
            "created_at": current_user.get("created_at"),
            "last_login": current_user.get("last_login")
        }
    }


@router.post("/logout")
@router.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    """Ends the account's sessions, so the token cannot be used again after signing out."""
    raw = (authorization or "").strip()
    token = raw.split(" ", 1)[1].strip() if raw.lower().startswith("bearer ") else ""
    try:
        account_id = decode_access_token(token).get("user_id") if token else None
    except Exception:
        account_id = None   # an expired or invalid token is already unusable
    if account_id:
        conn = get_db_connection()
        try:
            end_sessions(conn.cursor(), account_id)
            conn.commit()
        finally:
            conn.close()
    return {"success": True, "message": "Logged out successfully"}
