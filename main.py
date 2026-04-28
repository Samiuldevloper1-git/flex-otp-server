"""
Flex OTP Service - Main Application
Production-ready Email Verification API
Built-in keep-alive so server NEVER sleeps!
"""

import asyncio
import logging
import time
import urllib.request

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from contextlib import asynccontextmanager

from database import init_db, cleanup_expired_otps
from routers import otp, admin, stats
from security import rate_limit_middleware
from config import settings

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("flex_otp")

# ── Keep-Alive: server নিজেই নিজেকে ping করে ─────────────────────────────────
RENDER_URL = ""   # Deploy হলে auto-detect হবে
import os
SERVICE_URL = os.getenv("SERVICE_URL", "")   # Railway/Render আপনার URL দেবে


async def keep_alive_loop():
    """
    প্রতি 4 মিনিটে নিজের /health endpoint ping করে।
    এতে server কখনো ঘুমাবে না — সম্পূর্ণ ফ্রি সমাধান।
    """
    await asyncio.sleep(30)  # Startup-এর পর 30s wait
    while True:
        try:
            url = SERVICE_URL if SERVICE_URL else "http://localhost:8000/health"
            req = urllib.request.Request(url, headers={"User-Agent": "FlexOTP-KeepAlive/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                logger.info("🟢 Keep-alive ping OK (status=%s)", resp.status)
        except Exception as exc:
            logger.warning("⚠️ Keep-alive ping failed: %s", exc)
        await asyncio.sleep(240)  # 4 মিনিট পর পর


async def cleanup_loop():
    """প্রতি 10 মিনিটে expired OTP পরিষ্কার করে।"""
    while True:
        await asyncio.sleep(600)
        try:
            await cleanup_expired_otps()
        except Exception as exc:
            logger.error("Cleanup error: %s", exc)


# ── App Lifespan ──────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Flex OTP Service starting...")
    await init_db()
    logger.info("✅ Database ready")

    # Background tasks শুরু
    asyncio.create_task(keep_alive_loop())
    asyncio.create_task(cleanup_loop())
    logger.info("✅ Keep-alive & cleanup tasks started")

    yield
    logger.info("🛑 Flex OTP Service shutting down...")


# ── FastAPI App ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Flex OTP Service",
    description="Production-ready Email Verification OTP API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS — সব website থেকে call করতে পারবে
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global Middleware ─────────────────────────────────────────────────────────
@app.middleware("http")
async def global_middleware(request: Request, call_next):
    start = time.time()

    # Client IP বের করো
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )

    # Rate limit check (health/docs skip)
    if request.url.path not in ("/health", "/docs", "/redoc", "/openapi.json", "/"):
        blocked = await rate_limit_middleware(request, client_ip)
        if blocked:
            return JSONResponse(
                status_code=429,
                content={"status": "error", "message": "Too many requests. Please wait and try again."},
            )

    response = await call_next(request)
    ms = round((time.time() - start) * 1000, 2)
    response.headers["X-Response-Time"] = f"{ms}ms"
    response.headers["X-Powered-By"] = "Flex-OTP-Service"
    return response


# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(otp.router, tags=["OTP"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])
app.include_router(stats.router, tags=["Stats"])


@app.get("/health", tags=["System"])
async def health():
    """Health check — UptimeRobot / Railway এটা ping করে।"""
    return {
        "status": "success",
        "service": "Flex OTP Service",
        "version": "1.0.0",
        "message": "All systems operational 🟢",
    }


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root():
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Flex OTP Service</title>
        <meta http-equiv="refresh" content="0; url=/admin/panel">
        <style>
          body{background:#080c10;color:#00c896;font-family:monospace;
               display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
        </style>
    </head>
    <body><p>🔐 Redirecting to Admin Panel...</p></body>
    </html>
    """)


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False, log_level="info")
