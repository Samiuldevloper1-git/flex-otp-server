"""
Flex OTP Service - Email Service
Sends beautiful HTML OTP emails via Gmail SMTP.
"""

import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from typing import Optional

from config import settings

logger = logging.getLogger("flex_otp.email")


def build_html_email(otp_code: str, website_name: str, expiry_minutes: int = 5) -> str:
    """Build a beautiful HTML email template."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Your Verification Code</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f4f8;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f4f8;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="580" cellpadding="0" cellspacing="0" style="max-width:580px;width:100%;">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0f2027 0%,#203a43 50%,#2c5364 100%);
                       border-radius:16px 16px 0 0;padding:36px 40px;text-align:center;">
              <div style="display:inline-block;background:rgba(255,255,255,0.12);
                          border-radius:50%;width:64px;height:64px;line-height:64px;
                          font-size:30px;margin-bottom:12px;">🔐</div>
              <h1 style="margin:0;color:#ffffff;font-size:26px;font-weight:700;
                          letter-spacing:1px;">Flex OTP Service</h1>
              <p style="margin:6px 0 0;color:rgba(255,255,255,0.65);font-size:13px;
                         letter-spacing:2px;text-transform:uppercase;">
                Email Verification
              </p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="background:#ffffff;padding:40px 40px 32px;">
              <p style="margin:0 0 8px;color:#374151;font-size:15px;">
                Hello from <strong style="color:#2c5364;">{website_name}</strong>,
              </p>
              <p style="margin:0 0 28px;color:#6b7280;font-size:14px;line-height:1.6;">
                We received a request to verify your email address.
                Use the code below to complete verification.
              </p>

              <!-- OTP Box -->
              <div style="background:linear-gradient(135deg,#f8faff 0%,#e8f4fd 100%);
                          border:2px dashed #93c5fd;border-radius:12px;
                          padding:28px;text-align:center;margin-bottom:28px;">
                <p style="margin:0 0 8px;color:#6b7280;font-size:12px;
                           letter-spacing:3px;text-transform:uppercase;">
                  Your Verification Code
                </p>
                <div style="font-size:48px;font-weight:800;letter-spacing:10px;
                             color:#1e3a5f;font-family:'Courier New',monospace;
                             text-shadow:0 2px 4px rgba(0,0,0,0.08);">
                  {otp_code}
                </div>
                <p style="margin:12px 0 0;color:#ef4444;font-size:12px;font-weight:600;">
                  ⏱ Valid for {expiry_minutes} minutes only
                </p>
              </div>

              <!-- Security Note -->
              <div style="background:#fefce8;border-left:4px solid #f59e0b;
                           border-radius:0 8px 8px 0;padding:14px 16px;margin-bottom:28px;">
                <p style="margin:0;color:#92400e;font-size:13px;line-height:1.6;">
                  <strong>🛡 Security Notice:</strong> If you did not request this code,
                  please ignore this email. Do not share this code with anyone.
                  Flex OTP Service will never ask for your code.
                </p>
              </div>

              <p style="margin:0;color:#9ca3af;font-size:12px;text-align:center;">
                This code was requested for <strong>{website_name}</strong>
                and is delivered by <strong>Flex OTP Service</strong>.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f9fafb;border-radius:0 0 16px 16px;
                       padding:20px 40px;border-top:1px solid #e5e7eb;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="color:#9ca3af;font-size:11px;">
                    © 2026 Flex OTP Service. Trusted email verification.
                  </td>
                  <td align="right" style="color:#9ca3af;font-size:11px;">
                    🔒 Secured & Encrypted
                  </td>
                </tr>
              </table>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def build_plain_email(otp_code: str, website_name: str, expiry_minutes: int = 5) -> str:
    """Plain text fallback email."""
    return f"""Hello from {website_name},

Your verification code is:

  {otp_code}

Valid for {expiry_minutes} minutes only.

If you did not request this code, please ignore this email.

-- Flex OTP Service
"""


async def send_otp_email(
    recipient_email: str,
    otp_code: str,
    website_name: str,
) -> bool:
    """
    Send OTP verification email via Gmail SMTP.
    Returns True on success, False on failure.
    """
    expiry_minutes = settings.OTP_EXPIRY_SECONDS // 60

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Your Verification Code — {otp_code}"
    msg["From"] = formataddr((settings.SENDER_NAME, settings.EMAIL_USER))
    msg["To"] = recipient_email
    msg["X-Mailer"] = "Flex-OTP-Service/1.0"

    plain_part = MIMEText(build_plain_email(otp_code, website_name, expiry_minutes), "plain", "utf-8")
    html_part = MIMEText(build_html_email(otp_code, website_name, expiry_minutes), "html", "utf-8")

    msg.attach(plain_part)
    msg.attach(html_part)

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(settings.EMAIL_USER, settings.EMAIL_APP_PASSWORD)
            server.sendmail(settings.EMAIL_USER, [recipient_email], msg.as_string())

        logger.info("OTP email sent to %s for %s", recipient_email[:3] + "***", website_name)
        return True

    except smtplib.SMTPAuthenticationError as exc:
        logger.error("SMTP authentication failed: %s", exc)
        return False
    except smtplib.SMTPException as exc:
        logger.error("SMTP error sending to %s: %s", recipient_email[:3] + "***", exc)
        return False
    except Exception as exc:
        logger.error("Unexpected error sending email: %s", exc)
        return False
