from __future__ import annotations

import asyncio
import hashlib
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, Request, Response, status
from passlib.context import CryptContext
from pydantic import EmailStr, TypeAdapter
from sqlalchemy.orm import Session as DbSession

from db_models import PasswordResetToken, Session, User

SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "gsm_session")
CSRF_COOKIE_NAME = os.getenv("CSRF_COOKIE_NAME", "gsm_csrf")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"

SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "60"))
RESET_TOKEN_TTL_MINUTES = int(os.getenv("RESET_TOKEN_TTL_MINUTES", "30"))

LOGIN_RATE_LIMIT = int(os.getenv("LOGIN_RATE_LIMIT", "5"))
LOGIN_RATE_WINDOW_SECONDS = int(os.getenv("LOGIN_RATE_WINDOW_SECONDS", "900"))
RESET_RATE_LIMIT = int(os.getenv("RESET_RATE_LIMIT", "3"))
RESET_RATE_WINDOW_SECONDS = int(os.getenv("RESET_RATE_WINDOW_SECONDS", "900"))

PASSWORD_MIN_LENGTH = 12

_email_adapter = TypeAdapter(EmailStr)
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_dummy_password_hash = _pwd_context.hash("not-the-right-password")


class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            bucket = self._attempts[key]
            while bucket and (now - bucket[0]) > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.max_attempts:
                return False
            bucket.append(now)
            return True


login_rate_limiter = RateLimiter(LOGIN_RATE_LIMIT, LOGIN_RATE_WINDOW_SECONDS)
reset_rate_limiter = RateLimiter(RESET_RATE_LIMIT, RESET_RATE_WINDOW_SECONDS)


def normalize_email(raw_email: str) -> str:
    value = raw_email.strip()
    try:
        normalized = _email_adapter.validate_python(value)
    except Exception as exc:
        raise ValueError("Please enter a valid email address.") from exc
    return normalized.lower()


def normalize_name(raw_name: str) -> str:
    value = raw_name.strip()
    if not value:
        raise ValueError("Name is required.")
    if len(value) > 120:
        raise ValueError("Name must be 120 characters or fewer.")
    if re.search(r"[\x00-\x1f\x7f]", value):
        raise ValueError("Name contains invalid characters.")
    return value


def validate_password_strength(password: str) -> list[str]:
    errors: list[str] = []
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must include at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must include at least one lowercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password must include at least one number.")
    if not re.search(r"[^\w\s]", password):
        errors.append("Password must include at least one symbol.")
    return errors


def hash_password(password: str) -> str:
    # bcrypt is intentionally slow to resist brute-force attacks.
    return _pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return _pwd_context.verify(password, password_hash)


def authenticate_user(db: DbSession, email: str, password: str) -> Optional[User]:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        _pwd_context.verify(password, _dummy_password_hash)
        return None
    if not user.is_active:
        return None
    try:
        if not verify_password(password, user.password_hash):
            return None
    except Exception:
        return None
    return user


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_client_ip(request: Request) -> str:
    # Trust proxy headers only when explicitly enabled.
    if os.getenv("TRUST_PROXY", "false").lower() == "true":
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def create_session(db: DbSession, user: User, request: Request) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    token_hash = hash_token(token)
    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=SESSION_TTL_MINUTES)
    user_agent = (request.headers.get("user-agent", "") or "")[:255]
    ip_address = (get_client_ip(request) or "")[:64]
    session = Session(
        user_id=user.id,
        session_token_hash=token_hash,
        created_at=now,
        last_seen_at=now,
        expires_at=expires_at,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(session)
    db.commit()
    return token, expires_at


def revoke_user_sessions(db: DbSession, user_id: int) -> None:
    db.query(Session).filter(Session.user_id == user_id).delete(synchronize_session=False)
    db.commit()


def issue_session_cookie(response: Response, token: str, expires_at: datetime) -> None:
    max_age = int((expires_at - datetime.utcnow()).total_seconds())
    if max_age < 0:
        max_age = 0
    # HTTP-only, Secure cookies reduce exposure to XSS and network sniffing.
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=max_age,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, samesite="lax", secure=COOKIE_SECURE)


def get_current_user_optional(request: Request, db: DbSession) -> Optional[User]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    token_hash = hash_token(token)
    session = db.query(Session).filter(Session.session_token_hash == token_hash).first()
    if not session:
        return None
    now = datetime.utcnow()
    if session.expires_at <= now:
        db.delete(session)
        db.commit()
        return None
    user_agent = (request.headers.get("user-agent", "") or "")[:255]
    if session.user_agent and session.user_agent != user_agent:
        # Basic hijack detection: invalidate the session on user-agent mismatch.
        db.delete(session)
        db.commit()
        return None
    session.last_seen_at = now
    session.expires_at = now + timedelta(minutes=SESSION_TTL_MINUTES)
    db.commit()
    return session.user


def get_current_user(request: Request, db: DbSession) -> User:
    user = get_current_user_optional(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


def get_csrf_token(request: Request) -> tuple[str, bool]:
    existing = request.cookies.get(CSRF_COOKIE_NAME)
    if existing and len(existing) >= 16:
        return existing, False
    return secrets.token_urlsafe(32), True


def set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        max_age=60 * 60 * 8,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="lax",
    )


def resolve_csrf_token(request: Request, form_token: Optional[str] = None) -> Optional[str]:
    return form_token or request.headers.get("x-csrf-token") or request.query_params.get("csrf_token")


def validate_csrf(request: Request, token: Optional[str]) -> None:
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not cookie_token or not token or not secrets.compare_digest(cookie_token, token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid CSRF token")


def create_password_reset_token(db: DbSession, user: User) -> tuple[str, datetime]:
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None),
    ).delete(synchronize_session=False)
    token = secrets.token_urlsafe(48)
    token_hash = hash_token(token)
    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)
    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        created_at=now,
        expires_at=expires_at,
    )
    db.add(reset_token)
    db.commit()
    return token, expires_at
