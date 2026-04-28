"""
Flex OTP Service - OTP Router
POST /send-code, /verify-code, /resend-code
"""

import asyncio
import logging
import smtplib
from concurrent.futures import ThreadPoolExecutor
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

from fastapi import APIRouter, Request, HTTPException

from database import get_db
from schemas import SendCodeRequest, VerifyCodeRequest, ResendCodeRequest, OTPResponse
from security import validate_api_key, check_email_cooldown, is_ip_blocked_db, block_ip_db
from email_service import build_html_email, build_plain_email
from utils import generate_otp, otp_expires_at, utc_now_str, is_expired
from config import settings

logger = logging.getLogger("flex_otp.otp")
router = APIRouter()
_thread_pool = ThreadPoolExecutor(max_workers=4)


def get_client_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _smtp_send(recipient: str, otp_code: str, website_name: str) -> bool:
    """Blocking SMTP send — runs in thread pool."""
    expiry_min = settings.OTP_EXPIRY_SECONDS // 60
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Your Verification Code — {otp_code}"
    msg["From"] = formataddr((settings.SENDER_NAME, settings.EMAIL_USER))
    msg["To"] = recipient
    msg.attach(MIMEText(build_plain_email(otp_code, website_name, expiry_min), "plain", "utf-8"))
    msg.attach(MIMEText(build_html_email(otp_code, website_name, expiry_min), "html", "utf-8"))
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(settings.EMAIL_USER, settings.EMAIL_APP_PASSWORD)
            s.sendmail(settings.EMAIL_USER, [recipient], msg.as_string())
        logger.info("Email sent to %s***", recipient[:3])
        return True
    except Exception as exc:
        logger.error("SMTP send failed: %s", exc)
        return False


async def log_event(db, event: str, api_key: str = None, user_email: str = None,
                    details: str = None, client_ip: str = None):
    await db.execute(
        "INSERT INTO logs (event, api_key, user_email, details, client_ip) VALUES (?,?,?,?,?)",
        (event, api_key, user_email, details, client_ip),
    )
    await db.commit()


@router.post("/send-code", response_model=OTPResponse)
async def send_code(request: Request, body: SendCodeRequest):
    client_ip = get_client_ip(request)
    api_key = body.api_key
    user_email = body.user_email
    website_name = body.website_name

    async with await get_db() as db:
        if await is_ip_blocked_db(db, client_ip):
            await log_event(db, "blocked_ip_attempt", api_key, user_email, "IP blocked", client_ip)
            raise HTTPException(403, detail={"status": "error", "message": "Your IP is blocked due to abuse."})

        client = await validate_api_key(db, api_key)
        if not client:
            await log_event(db, "invalid_api_key", api_key, user_email, "Invalid/inactive API key", client_ip)
            raise HTTPException(401, detail={"status": "error", "message": "Invalid or inactive API key."})

        cooldown = await check_email_cooldown(db, api_key, user_email)
        if cooldown is not None:
            raise HTTPException(429, detail={
                "status": "error",
                "message": f"Please wait {cooldown} seconds before requesting another code."
            })

        await db.execute(
            "UPDATE otp_codes SET status='invalidated' WHERE api_key=? AND user_email=? AND status='pending'",
            (api_key, user_email),
        )

        otp_code = generate_otp(settings.OTP_LENGTH)
        expires_at = otp_expires_at()

        await db.execute(
            """INSERT INTO otp_codes (api_key, user_email, otp_code, website_name, expires_at, client_ip)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (api_key, user_email, otp_code, website_name, expires_at, client_ip),
        )
        await db.execute(
            "UPDATE clients SET total_sent = total_sent + 1 WHERE api_key = ?", (api_key,),
        )
        await db.commit()

    # Send email via thread pool
    loop = asyncio.get_event_loop()
    sent = await loop.run_in_executor(_thread_pool, _smtp_send, user_email, otp_code, website_name)

    async with await get_db() as db:
        if not sent:
            await db.execute(
                "UPDATE otp_codes SET status='failed' WHERE api_key=? AND user_email=? AND otp_code=?",
                (api_key, user_email, otp_code),
            )
            await db.commit()
            await log_event(db, "send_failed", api_key, user_email, "SMTP failure", client_ip)
            raise HTTPException(500, detail={"status": "error", "message": "Failed to send email. Please try again."})

        await log_event(db, "otp_sent", api_key, user_email, f"website={website_name}", client_ip)

    return OTPResponse(status="success", message="OTP sent successfully. Check your email.")


@router.post("/verify-code", response_model=OTPResponse)
async def verify_code(request: Request, body: VerifyCodeRequest):
    client_ip = get_client_ip(request)
    api_key = body.api_key
    user_email = body.user_email
    otp_input = body.otp_code

    async with await get_db() as db:
        client = await validate_api_key(db, api_key)
        if not client:
            raise HTTPException(401, detail={"status": "error", "message": "Invalid or inactive API key."})

        cursor = await db.execute(
            """SELECT id, otp_code, expires_at, status, attempts FROM otp_codes
               WHERE api_key = ? AND user_email = ? AND status = 'pending'
               ORDER BY created_at DESC LIMIT 1""",
            (api_key, user_email),
        )
        row = await cursor.fetchone()

        if row is None:
            await log_event(db, "verify_no_otp", api_key, user_email, "No pending OTP", client_ip)
            raise HTTPException(404, detail={"status": "error", "message": "No pending OTP found. Please request a new code."})

        otp_id = row["id"]
        attempts = row["attempts"] + 1

        if is_expired(row["expires_at"]):
            await db.execute("UPDATE otp_codes SET status='expired' WHERE id=?", (otp_id,))
            await db.commit()
            await log_event(db, "verify_expired", api_key, user_email, "OTP expired", client_ip)
            raise HTTPException(410, detail={"status": "error", "message": "OTP has expired. Please request a new code."})

        if attempts > settings.OTP_MAX_ATTEMPTS:
            await db.execute("UPDATE otp_codes SET status='blocked', attempts=? WHERE id=?", (attempts, otp_id))
            await db.commit()
            await block_ip_db(db, client_ip, "too many OTP attempts")
            await log_event(db, "verify_max_attempts", api_key, user_email, "Max attempts exceeded", client_ip)
            raise HTTPException(429, detail={"status": "error", "message": "Too many failed attempts. Please request a new code."})

        if otp_input != row["otp_code"]:
            await db.execute("UPDATE otp_codes SET attempts=? WHERE id=?", (attempts, otp_id))
            await db.commit()
            remaining = settings.OTP_MAX_ATTEMPTS - attempts
            await log_event(db, "verify_wrong_code", api_key, user_email,
                            f"attempt {attempts}/{settings.OTP_MAX_ATTEMPTS}", client_ip)
            raise HTTPException(400, detail={
                "status": "error",
                "message": f"Incorrect OTP code. {remaining} attempt(s) remaining."
            })

        # SUCCESS
        await db.execute(
            "UPDATE otp_codes SET status='verified', verified_at=?, attempts=? WHERE id=?",
            (utc_now_str(), attempts, otp_id),
        )
        await db.execute(
            "UPDATE clients SET total_verified = total_verified + 1 WHERE api_key = ?", (api_key,),
        )
        await db.commit()
        await log_event(db, "verify_success", api_key, user_email, "Email verified", client_ip)

    return OTPResponse(status="success", message="Email verified successfully.")


@router.post("/resend-code", response_model=OTPResponse)
async def resend_code(request: Request, body: ResendCodeRequest):
    send_body = SendCodeRequest(
        api_key=body.api_key,
        user_email=body.user_email,
        website_name=body.website_name,
    )
    return await send_code(request, send_body)
