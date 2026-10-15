"""Outgoing email. Sends through SMTP when SMTP_HOST is set in backend/.env.

Without SMTP nothing is sent. On a developer machine, MAIL_LOG_LINKS=1 writes the message to the server log
instead, so password reset still works: copy the link from the console.
"""
from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage


def smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST", "").strip())


def send_email(to: str, subject: str, text: str) -> bool:
    """Returns True when the message was handed to the SMTP server."""
    if not smtp_configured():
        # A reset link opens the account, so the message is logged only when MAIL_LOG_LINKS=1 (a developer machine)
        if os.getenv("MAIL_LOG_LINKS") == "1":
            logging.warning("SMTP is not configured, so this email was not sent.\nTo: %s\nSubject: %s\n\n%s", to, subject, text)
        else:
            logging.warning("SMTP is not configured, so the email to %s (%s) was not sent. Set SMTP_HOST, or MAIL_LOG_LINKS=1 "
                            "on a developer machine to print it here.", to, subject)
        return False
    msg = EmailMessage()
    msg["From"] = os.getenv("SMTP_FROM") or os.getenv("SMTP_USER", "")
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text)
    host = os.environ["SMTP_HOST"].strip()
    port = int(os.getenv("SMTP_PORT", "587"))
    user, password = os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASSWORD", "")
    try:
        if port == 465:
            server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=20)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
            server.starttls()
        with server:
            if user:
                server.login(user, password)
            server.send_message(msg)
        return True
    except Exception as e:
        logging.error("Could not send email to %s: %s", to, e)
        return False


def send_password_reset(to: str, name: str, link: str, minutes: int) -> bool:
    text = (
        f"Hello {name},\n\n"
        f"Someone asked to reset the password for your CertifyAI account. To choose a new password, open this link:\n\n"
        f"{link}\n\n"
        f"The link works once and expires in {minutes} minutes. If you did not ask for this, ignore this email; "
        f"your password stays the same.\n"
    )
    return send_email(to, "Reset your CertifyAI password", text)
