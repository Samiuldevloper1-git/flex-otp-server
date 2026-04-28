"""
Flex OTP Service - Configuration
All settings loaded from environment or defaults.
"""

import os
import secrets
from pathlib import Path


class Settings:
    # ─── App ──────────────────────────────────────────────────
    APP_NAME: str = "Flex OTP Service"
    APP_VERSION: str = "1.0.0"
    SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_hex(32))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # ─── Database ─────────────────────────────────────────────
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./flex_otp.db")

    # ─── SMTP / Email ─────────────────────────────────────────
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    EMAIL_USER: str = os.getenv("EMAIL_USER", "flexotpservice@gmail.com")
    EMAIL_APP_PASSWORD: str = os.getenv("EMAIL_APP_PASSWORD", "jbmt fiov qyax khcl")
    SENDER_NAME: str = os.getenv("SENDER_NAME", "Flex OTP Service")

    # ─── OTP Config ───────────────────────────────────────────
    OTP_EXPIRY_SECONDS: int = int(os.getenv("OTP_EXPIRY_SECONDS", "300"))   # 5 min
    OTP_COOLDOWN_SECONDS: int = int(os.getenv("OTP_COOLDOWN_SECONDS", "60"))  # 1 min between resends
    OTP_MAX_ATTEMPTS: int = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))          # max verify tries
    OTP_LENGTH: int = 6

    # ─── Rate Limiting ────────────────────────────────────────
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))   # per window
    RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))       # seconds
    BLOCK_DURATION: int = int(os.getenv("BLOCK_DURATION", "600"))            # 10 min block

    # ─── Admin ────────────────────────────────────────────────
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "flexadmin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "FlexAdmin@Secure2026!")
    SESSION_EXPIRE_HOURS: int = int(os.getenv("SESSION_EXPIRE_HOURS", "24"))

    # ─── Cleanup ──────────────────────────────────────────────
    CLEANUP_INTERVAL_MINUTES: int = int(os.getenv("CLEANUP_INTERVAL_MINUTES", "10"))


settings = Settings()
