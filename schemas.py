"""
Flex OTP Service - Pydantic Schemas
Request / Response models with full validation.
"""

import re
from typing import Optional
from pydantic import BaseModel, field_validator, EmailStr


# ─────────────────────────────────────────────────────────────────────────────
# OTP Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class SendCodeRequest(BaseModel):
    api_key: str
    user_email: str
    website_name: str = "Our Website"

    @field_validator("api_key")
    @classmethod
    def api_key_valid(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) < 6 or len(v) > 128:
            raise ValueError("api_key must be between 6 and 128 characters")
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError("api_key contains invalid characters")
        return v

    @field_validator("user_email")
    @classmethod
    def email_valid(cls, v: str) -> str:
        v = v.strip().lower()
        pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid email address")
        if len(v) > 254:
            raise ValueError("Email address too long")
        return v

    @field_validator("website_name")
    @classmethod
    def website_name_valid(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return "Our Website"
        if len(v) > 100:
            raise ValueError("website_name too long (max 100 chars)")
        return v


class VerifyCodeRequest(BaseModel):
    api_key: str
    user_email: str
    otp_code: str

    @field_validator("api_key")
    @classmethod
    def api_key_valid(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) < 6 or len(v) > 128:
            raise ValueError("api_key must be between 6 and 128 characters")
        return v

    @field_validator("user_email")
    @classmethod
    def email_valid(cls, v: str) -> str:
        v = v.strip().lower()
        pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid email address")
        return v

    @field_validator("otp_code")
    @classmethod
    def otp_code_valid(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^\d{6}$", v):
            raise ValueError("OTP must be exactly 6 digits")
        return v


class ResendCodeRequest(BaseModel):
    api_key: str
    user_email: str
    website_name: str = "Our Website"

    @field_validator("api_key")
    @classmethod
    def api_key_valid(cls, v: str) -> str:
        return v.strip()

    @field_validator("user_email")
    @classmethod
    def email_valid(cls, v: str) -> str:
        v = v.strip().lower()
        pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid email address")
        return v


# ─────────────────────────────────────────────────────────────────────────────
# Admin
# ─────────────────────────────────────────────────────────────────────────────

class AdminLoginRequest(BaseModel):
    username: str
    password: str


class CreateApiKeyRequest(BaseModel):
    name: str
    email: Optional[str] = None

    @field_validator("name")
    @classmethod
    def name_valid(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) < 2:
            raise ValueError("name must be at least 2 characters")
        if len(v) > 100:
            raise ValueError("name too long")
        return v


class UpdateClientRequest(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None


# ─────────────────────────────────────────────────────────────────────────────
# Responses
# ─────────────────────────────────────────────────────────────────────────────

class OTPResponse(BaseModel):
    status: str
    message: str


class StatsResponse(BaseModel):
    status: str
    api_key: str
    client_name: str
    total_sent: int
    total_verified: int
    is_active: bool
