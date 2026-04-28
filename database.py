"""
Flex OTP Service - Database
Async SQLite (via aiosqlite) with easy PostgreSQL migration.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import aiosqlite

from config import settings

logger = logging.getLogger("flex_otp.db")

# ── SQLite path extracted from URL ────────────────────────────────────────────
DB_PATH = settings.DATABASE_URL.replace("sqlite+aiosqlite:///", "")


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS admin_users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key     TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL,
    email       TEXT,
    is_active   INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    total_sent  INTEGER NOT NULL DEFAULT 0,
    total_verified INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS otp_codes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key         TEXT NOT NULL,
    user_email      TEXT NOT NULL,
    otp_code        TEXT NOT NULL,
    website_name    TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT NOT NULL,
    verified_at     TEXT,
    client_ip       TEXT,
    FOREIGN KEY (api_key) REFERENCES clients(api_key)
);

CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event       TEXT NOT NULL,
    api_key     TEXT,
    user_email  TEXT,
    details     TEXT,
    client_ip   TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT UNIQUE NOT NULL,
    reason      TEXT,
    blocked_at  TEXT NOT NULL DEFAULT (datetime('now')),
    unblock_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_otp_email ON otp_codes(user_email, status);
CREATE INDEX IF NOT EXISTS idx_otp_apikey ON otp_codes(api_key);
CREATE INDEX IF NOT EXISTS idx_logs_apikey ON logs(api_key);
CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip_address);
"""


# ─────────────────────────────────────────────────────────────────────────────
# Connection helper
# ─────────────────────────────────────────────────────────────────────────────

async def get_db() -> aiosqlite.Connection:
    """Yield an aiosqlite connection (row_factory set to dict-like Row)."""
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    return conn


# ─────────────────────────────────────────────────────────────────────────────
# Init
# ─────────────────────────────────────────────────────────────────────────────

async def init_db():
    """Create all tables and default admin user."""
    async with await get_db() as db:
        await db.executescript(SCHEMA_SQL)
        await db.commit()

        # Create default admin if not exists
        import hashlib
        pw_hash = hashlib.sha256(settings.ADMIN_PASSWORD.encode()).hexdigest()
        await db.execute(
            "INSERT OR IGNORE INTO admin_users (username, password_hash) VALUES (?, ?)",
            (settings.ADMIN_USERNAME, pw_hash),
        )
        await db.commit()
    logger.info("Database initialized at %s", DB_PATH)


# ─────────────────────────────────────────────────────────────────────────────
# Cleanup job
# ─────────────────────────────────────────────────────────────────────────────

async def cleanup_expired_otps():
    """Delete expired OTPs and unblock expired IPs. Called periodically."""
    async with await get_db() as db:
        now = datetime.now(timezone.utc).isoformat()
        res = await db.execute(
            "DELETE FROM otp_codes WHERE expires_at < ? AND status = 'pending'", (now,)
        )
        deleted = res.rowcount
        await db.execute("DELETE FROM blocked_ips WHERE unblock_at < ?", (now,))
        await db.commit()
    if deleted:
        logger.info("Cleanup: removed %d expired OTP records", deleted)


async def run_cleanup_loop():
    """Background cleanup loop."""
    while True:
        await asyncio.sleep(settings.CLEANUP_INTERVAL_MINUTES * 60)
        try:
            await cleanup_expired_otps()
        except Exception as exc:
            logger.error("Cleanup error: %s", exc)
