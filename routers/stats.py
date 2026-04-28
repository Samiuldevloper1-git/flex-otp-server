"""
Flex OTP Service - Stats Router
GET /stats/{api_key}
"""

import logging
from fastapi import APIRouter, HTTPException, Request

from database import get_db
from security import validate_api_key

logger = logging.getLogger("flex_otp.stats")
router = APIRouter()


@router.get("/stats/{api_key}")
async def get_stats(api_key: str, request: Request):
    """Return usage statistics for a given API key."""
    async with await get_db() as db:
        client = await validate_api_key(db, api_key)
        if not client:
            raise HTTPException(401, detail={"status": "error", "message": "Invalid or inactive API key."})

        # Daily breakdown (last 7 days)
        cursor = await db.execute(
            """SELECT DATE(created_at) as day, COUNT(*) as sent,
                      SUM(CASE WHEN status='verified' THEN 1 ELSE 0 END) as verified
               FROM otp_codes WHERE api_key = ?
               GROUP BY DATE(created_at)
               ORDER BY day DESC LIMIT 7""",
            (api_key,),
        )
        daily = [dict(r) for r in await cursor.fetchall()]

        # Today's stats
        cursor2 = await db.execute(
            """SELECT COUNT(*) as today_sent,
                      SUM(CASE WHEN status='verified' THEN 1 ELSE 0 END) as today_verified
               FROM otp_codes WHERE api_key = ? AND DATE(created_at) = DATE('now')""",
            (api_key,),
        )
        today = dict(await cursor2.fetchone())

    return {
        "status": "success",
        "api_key": api_key,
        "client_name": client["name"],
        "is_active": bool(client["is_active"]),
        "total_sent": client["total_sent"],
        "total_verified": client["total_verified"],
        "today_sent": today.get("today_sent") or 0,
        "today_verified": today.get("today_verified") or 0,
        "daily_breakdown": daily,
    }
