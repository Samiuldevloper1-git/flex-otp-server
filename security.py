"""
Flex OTP Service - Security Module
Rate limiting, IP blocking, API key validation, session management.
"""

import hashlib
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Request

from config import settings
from utils import utc_now_str, utc_now

logger = logging.getLogger("flex_otp.security")

# ─── In-memory rate limit store ───────────────────────────────────────────────
# {ip: [timestamp, ...]}
_request_log: dict[str, list[float]] = defaultdict(list)
# {ip: unblock_timestamp}
_temp_blocks: dict[str, float] = {}


# ─────────────────────────────────────────────────────────────────────────────
# Rate Limiting Middleware
# ─────────────────────────────────────────────────────────────────────────────

async def rate_limit_middleware(request: Request, client_ip: str) -> bool:
    """
    Returns True (blocked) if the IP exceeds rate limits.
    Skips rate limiting for admin panel static routes.
    """
    # Skip health checks
    if request.url.path in ("/health", "/docs", "/redoc", "/openapi.json"):
        return False

    now = time.time()

    # Check permanent DB block first (async check is done in route handlers)
    # Check temp in-memory block
    if client_ip in _temp_blocks:
        if now < _temp_blocks[client_ip]:
            return True
        else:
            del _temp_blocks[client_ip]

    # Sliding window rate limit
    window_start = now - settings.RATE_LIMIT_WINDOW
    _request_log[client_ip] = [t for t in _request_log[client_ip] if t > window_start]
    _request_log[client_ip].append(now)

    if len(_request_log[client_ip]) > settings.RATE_LIMIT_REQUESTS:
        _temp_blocks[client_ip] = now + settings.BLOCK_DURATION
        logger.warning("IP %s rate-limited and temp-blocked for %ds", client_ip, settings.BLOCK_DURATION)
        return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Database-backed Security Checks
# ─────────────────────────────────────────────────────────────────────────────

async def is_ip_blocked_db(db, client_ip: str) -> bool:
    """Check if IP is blocked in the database."""
    now = utc_now_str()
    row = await db.execute(
        "SELECT id FROM blocked_ips WHERE ip_address = ? AND unblock_at > ?",
        (client_ip, now),
    )
    result = await row.fetchone()
    return result is not None


async def block_ip_db(db, client_ip: str, reason: str = "abuse"):
    """Add IP to database block list."""
    unblock_at = (utc_now() + timedelta(seconds=settings.BLOCK_DURATION)).isoformat()
    await db.execute(
        """INSERT INTO blocked_ips (ip_address, reason, unblock_at)
           VALUES (?, ?, ?)
           ON CONFLICT(ip_address) DO UPDATE SET reason=excluded.reason, unblock_at=excluded.unblock_at""",
        (client_ip, reason, unblock_at),
    )
    await db.commit()


async def validate_api_key(db, api_key: str) -> Optional[dict]:
    """
    Validate API key and return client row or None.
    Returns None if key doesn't exist or is disabled.
    """
    cursor = await db.execute(
        "SELECT id, api_key, name, is_active, total_sent, total_verified FROM clients WHERE api_key = ?",
        (api_key,),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    client = dict(row)
    if not client["is_active"]:
        return None
    return client


async def check_email_cooldown(db, api_key: str, user_email: str) -> Optional[int]:
    """
    Returns remaining cooldown seconds if email was sent recently, else None.
    """
    cursor = await db.execute(
        """SELECT created_at FROM otp_codes
           WHERE api_key = ? AND user_email = ?
           ORDER BY created_at DESC LIMIT 1""",
        (api_key, user_email),
    )
    row = await cursor.fetchone()
    if row is None:
        return None

    from utils import seconds_since
    elapsed = seconds_since(row["created_at"])
    remaining = settings.OTP_COOLDOWN_SECONDS - elapsed
    if remaining > 0:
        return int(remaining)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Admin Session Management (simple token store)
# ─────────────────────────────────────────────────────────────────────────────

# {token: expiry_timestamp}
_admin_sessions: dict[str, float] = {}


def create_admin_session() -> str:
    """Create a new admin session token."""
    import secrets
    token = secrets.token_urlsafe(48)
    expiry = time.time() + (settings.SESSION_EXPIRE_HOURS * 3600)
    _admin_sessions[token] = expiry
    return token


def validate_admin_session(token: str) -> bool:
    """Validate an admin session token."""
    if token not in _admin_sessions:
        return False
    if time.time() > _admin_sessions[token]:
        del _admin_sessions[token]
        return False
    return True


def revoke_admin_session(token: str):
    """Revoke an admin session."""
    _admin_sessions.pop(token, None)


def get_admin_token_from_request(request: Request) -> Optional[str]:
    """Extract admin token from cookie or Authorization header."""
    token = request.cookies.get("admin_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    return token
