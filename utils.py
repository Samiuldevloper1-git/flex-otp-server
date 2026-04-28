"""
Flex OTP Service - Utility Functions
OTP generation, validation helpers, and more.
"""

import random
import secrets
import string
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from config import settings

logger = logging.getLogger("flex_otp.utils")


def generate_otp(length: int = 6) -> str:
    """Generate a cryptographically secure numeric OTP."""
    return "".join([str(secrets.randbelow(10)) for _ in range(length)])


def generate_api_key(prefix: str = "flex") -> str:
    """Generate a unique API key."""
    rand = secrets.token_urlsafe(24)
    return f"{prefix}_{rand}"


def hash_password(password: str) -> str:
    """SHA-256 hash a password. Use bcrypt in production upgrade."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    """Verify password against hash."""
    return hash_password(plain) == hashed


def utc_now() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(timezone.utc)


def utc_now_str() -> str:
    """Return ISO format UTC now string."""
    return utc_now().isoformat()


def otp_expires_at() -> str:
    """Return ISO expiry time for a new OTP."""
    return (utc_now() + timedelta(seconds=settings.OTP_EXPIRY_SECONDS)).isoformat()


def is_expired(expires_at_str: str) -> bool:
    """Check if an ISO datetime string is in the past."""
    try:
        if expires_at_str.endswith("Z"):
            expires_at_str = expires_at_str[:-1] + "+00:00"
        expires_at = datetime.fromisoformat(expires_at_str)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return utc_now() > expires_at
    except Exception:
        return True


def seconds_since(dt_str: str) -> float:
    """Return seconds elapsed since an ISO datetime string."""
    try:
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (utc_now() - dt).total_seconds()
    except Exception:
        return 9999.0


def format_datetime(dt_str: Optional[str]) -> str:
    """Format an ISO datetime string for human display."""
    if not dt_str:
        return "—"
    try:
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(dt_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return dt_str


def mask_email(email: str) -> str:
    """Mask email for safe logging: user@example.com → u***@example.com"""
    try:
        local, domain = email.split("@")
        masked_local = local[0] + "***" if len(local) > 1 else "***"
        return f"{masked_local}@{domain}"
    except Exception:
        return "***"


def sanitize_string(value: str, max_length: int = 255) -> str:
    """Strip and truncate a string for safe DB storage."""
    return value.strip()[:max_length]
