"""
Flex OTP Service - Admin Router
Admin login panel, API key management, logs, stats.
"""

import logging
from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from database import get_db
from schemas import CreateApiKeyRequest, AdminLoginRequest
from security import (
    validate_admin_session, create_admin_session,
    revoke_admin_session, get_admin_token_from_request
)
from utils import generate_api_key, hash_password, verify_password, format_datetime
from config import settings

logger = logging.getLogger("flex_otp.admin")
router = APIRouter()


def require_admin(request: Request) -> str:
    token = get_admin_token_from_request(request)
    if not token or not validate_admin_session(token):
        raise HTTPException(status_code=302, headers={"Location": "/admin/login"})
    return token


# ─────────────────────────────────────────────────────────────────────────────
# Admin Login Page
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request, error: str = ""):
    token = request.cookies.get("admin_token")
    if token and validate_admin_session(token):
        return RedirectResponse("/admin/panel")
    error_html = f'<div class="error-msg">⚠ {error}</div>' if error else ""
    return HTMLResponse(LOGIN_HTML.replace("{{ERROR}}", error_html))


@router.post("/login")
async def admin_login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    async with await get_db() as db:
        cursor = await db.execute(
            "SELECT password_hash FROM admin_users WHERE username = ?", (username,)
        )
        row = await cursor.fetchone()

    if not row or not verify_password(password, row["password_hash"]):
        return RedirectResponse("/admin/login?error=Invalid+credentials", status_code=302)

    token = create_admin_session()
    response = RedirectResponse("/admin/panel", status_code=302)
    response.set_cookie("admin_token", token, httponly=True, samesite="lax",
                        max_age=settings.SESSION_EXPIRE_HOURS * 3600)
    return response


@router.get("/logout")
async def admin_logout(request: Request):
    token = request.cookies.get("admin_token")
    if token:
        revoke_admin_session(token)
    response = RedirectResponse("/admin/login", status_code=302)
    response.delete_cookie("admin_token")
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Admin Panel
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/panel", response_class=HTMLResponse)
async def admin_panel(request: Request):
    require_admin(request)
    async with await get_db() as db:
        cur = await db.execute("SELECT COUNT(*) as c FROM clients WHERE is_active=1")
        active_clients = (await cur.fetchone())["c"]
        cur = await db.execute("SELECT COUNT(*) as c FROM otp_codes")
        total_otps = (await cur.fetchone())["c"]
        cur = await db.execute("SELECT COUNT(*) as c FROM otp_codes WHERE status='verified'")
        verified_otps = (await cur.fetchone())["c"]
        cur = await db.execute("SELECT COUNT(*) as c FROM otp_codes WHERE DATE(created_at)=DATE('now')")
        today_sent = (await cur.fetchone())["c"]
        cur = await db.execute(
            "SELECT * FROM clients ORDER BY created_at DESC LIMIT 20"
        )
        clients = [dict(r) for r in await cur.fetchall()]
        cur = await db.execute(
            "SELECT * FROM logs ORDER BY created_at DESC LIMIT 50"
        )
        logs = [dict(r) for r in await cur.fetchall()]
        cur = await db.execute(
            "SELECT * FROM otp_codes ORDER BY created_at DESC LIMIT 30"
        )
        otps = [dict(r) for r in await cur.fetchall()]
        cur = await db.execute(
            "SELECT * FROM blocked_ips ORDER BY blocked_at DESC LIMIT 20"
        )
        blocked = [dict(r) for r in await cur.fetchall()]

    stats = {
        "active_clients": active_clients,
        "total_otps": total_otps,
        "verified_otps": verified_otps,
        "today_sent": today_sent,
    }
    return HTMLResponse(render_panel(stats, clients, logs, otps, blocked))


# ─────────────────────────────────────────────────────────────────────────────
# API Key Management (JSON endpoints)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/api/create-key")
async def create_api_key(request: Request, body: CreateApiKeyRequest):
    require_admin(request)
    new_key = generate_api_key("flex")
    async with await get_db() as db:
        await db.execute(
            "INSERT INTO clients (api_key, name, email) VALUES (?, ?, ?)",
            (new_key, body.name, body.email or ""),
        )
        await db.commit()
    return {"status": "success", "api_key": new_key, "name": body.name}


@router.post("/api/toggle-key/{api_key}")
async def toggle_api_key(api_key: str, request: Request):
    require_admin(request)
    async with await get_db() as db:
        cur = await db.execute("SELECT is_active FROM clients WHERE api_key=?", (api_key,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, detail="API key not found")
        new_status = 0 if row["is_active"] else 1
        await db.execute("UPDATE clients SET is_active=? WHERE api_key=?", (new_status, api_key))
        await db.commit()
    return {"status": "success", "is_active": bool(new_status)}


@router.delete("/api/delete-key/{api_key}")
async def delete_api_key(api_key: str, request: Request):
    require_admin(request)
    async with await get_db() as db:
        await db.execute("DELETE FROM clients WHERE api_key=?", (api_key,))
        await db.commit()
    return {"status": "success", "message": "API key deleted"}


@router.delete("/api/unblock-ip/{ip}")
async def unblock_ip(ip: str, request: Request):
    require_admin(request)
    async with await get_db() as db:
        await db.execute("DELETE FROM blocked_ips WHERE ip_address=?", (ip,))
        await db.commit()
    return {"status": "success", "message": f"IP {ip} unblocked"}


@router.get("/api/search-logs")
async def search_logs(request: Request, email: str = "", api_key: str = "", event: str = ""):
    require_admin(request)
    query = "SELECT * FROM logs WHERE 1=1"
    params = []
    if email:
        query += " AND user_email LIKE ?"
        params.append(f"%{email}%")
    if api_key:
        query += " AND api_key LIKE ?"
        params.append(f"%{api_key}%")
    if event:
        query += " AND event LIKE ?"
        params.append(f"%{event}%")
    query += " ORDER BY created_at DESC LIMIT 100"
    async with await get_db() as db:
        cur = await db.execute(query, params)
        rows = [dict(r) for r in await cur.fetchall()]
    return {"status": "success", "results": rows}


@router.get("/api/daily-stats")
async def daily_stats(request: Request):
    require_admin(request)
    async with await get_db() as db:
        cur = await db.execute("""
            SELECT DATE(created_at) as day,
                   COUNT(*) as total_sent,
                   SUM(CASE WHEN status='verified' THEN 1 ELSE 0 END) as total_verified
            FROM otp_codes
            GROUP BY DATE(created_at)
            ORDER BY day DESC LIMIT 30
        """)
        rows = [dict(r) for r in await cur.fetchall()]
    return {"status": "success", "data": rows}


# ─────────────────────────────────────────────────────────────────────────────
# HTML Rendering
# ─────────────────────────────────────────────────────────────────────────────

def render_panel(stats: dict, clients: list, logs: list, otps: list, blocked: list) -> str:
    clients_rows = ""
    for c in clients:
        status_badge = '<span class="badge active">Active</span>' if c["is_active"] else '<span class="badge inactive">Disabled</span>'
        clients_rows += f"""
        <tr>
          <td><code class="key-code">{c['api_key']}</code></td>
          <td>{c['name']}</td>
          <td>{c.get('email','—')}</td>
          <td>{status_badge}</td>
          <td>{c['total_sent']}</td>
          <td>{c['total_verified']}</td>
          <td>{format_datetime(c['created_at'])}</td>
          <td>
            <button class="btn-sm btn-toggle" onclick="toggleKey('{c['api_key']}', this)">
              {'Disable' if c['is_active'] else 'Enable'}
            </button>
            <button class="btn-sm btn-danger" onclick="deleteKey('{c['api_key']}')">Delete</button>
          </td>
        </tr>"""

    log_rows = ""
    for l in logs:
        log_rows += f"""
        <tr>
          <td><span class="event-badge {l['event'].split('_')[0]}">{l['event']}</span></td>
          <td>{l.get('api_key','—')[:20] if l.get('api_key') else '—'}</td>
          <td>{l.get('user_email','—')}</td>
          <td>{l.get('details','—')}</td>
          <td>{l.get('client_ip','—')}</td>
          <td>{format_datetime(l['created_at'])}</td>
        </tr>"""

    otp_rows = ""
    for o in otps:
        status_class = {"verified": "active", "pending": "pending", "expired": "expired",
                        "failed": "inactive", "blocked": "inactive"}.get(o["status"], "")
        otp_rows += f"""
        <tr>
          <td>{o.get('user_email','—')}</td>
          <td><code>{'*' * 6}</code></td>
          <td><span class="badge {status_class}">{o['status']}</span></td>
          <td>{o.get('website_name','—')}</td>
          <td>{o.get('attempts',0)}</td>
          <td>{format_datetime(o['created_at'])}</td>
          <td>{format_datetime(o.get('expires_at',''))}</td>
        </tr>"""

    blocked_rows = ""
    for b in blocked:
        blocked_rows += f"""
        <tr>
          <td>{b['ip_address']}</td>
          <td>{b.get('reason','—')}</td>
          <td>{format_datetime(b['blocked_at'])}</td>
          <td>{format_datetime(b['unblock_at'])}</td>
          <td><button class="btn-sm btn-toggle" onclick="unblockIp('{b['ip_address']}')">Unblock</button></td>
        </tr>"""

    return PANEL_HTML \
        .replace("{{ACTIVE_CLIENTS}}", str(stats["active_clients"])) \
        .replace("{{TOTAL_OTPS}}", str(stats["total_otps"])) \
        .replace("{{VERIFIED_OTPS}}", str(stats["verified_otps"])) \
        .replace("{{TODAY_SENT}}", str(stats["today_sent"])) \
        .replace("{{CLIENTS_ROWS}}", clients_rows) \
        .replace("{{LOG_ROWS}}", log_rows) \
        .replace("{{OTP_ROWS}}", otp_rows) \
        .replace("{{BLOCKED_ROWS}}", blocked_rows)


# ─────────────────────────────────────────────────────────────────────────────
# HTML Templates
# ─────────────────────────────────────────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flex OTP Service — Admin Login</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap');
  *{margin:0;padding:0;box-sizing:border-box}
  body{min-height:100vh;background:#080c10;display:flex;align-items:center;justify-content:center;font-family:'Inter',sans-serif;}
  .bg{position:fixed;inset:0;background:radial-gradient(ellipse at 20% 50%,rgba(0,200,150,0.08) 0%,transparent 60%),
      radial-gradient(ellipse at 80% 20%,rgba(0,150,255,0.07) 0%,transparent 50%);pointer-events:none;}
  .card{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:20px;
        padding:48px 40px;width:100%;max-width:420px;backdrop-filter:blur(20px);}
  .logo{text-align:center;margin-bottom:36px;}
  .logo-icon{font-size:48px;display:block;margin-bottom:12px;}
  .logo h1{color:#fff;font-size:22px;font-weight:700;letter-spacing:0.5px;}
  .logo p{color:rgba(255,255,255,0.4);font-size:13px;margin-top:4px;}
  label{display:block;color:rgba(255,255,255,0.6);font-size:12px;font-weight:600;
        letter-spacing:1px;text-transform:uppercase;margin-bottom:8px;}
  input{width:100%;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);
        border-radius:10px;padding:14px 16px;color:#fff;font-size:15px;font-family:'Inter',sans-serif;
        outline:none;transition:border-color 0.2s;margin-bottom:20px;}
  input:focus{border-color:rgba(0,200,150,0.5);}
  button{width:100%;background:linear-gradient(135deg,#00c896,#0099ff);border:none;border-radius:10px;
         padding:15px;color:#fff;font-size:16px;font-weight:700;cursor:pointer;
         letter-spacing:0.5px;transition:opacity 0.2s;}
  button:hover{opacity:0.9;}
  .error-msg{background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);
             border-radius:8px;padding:12px 16px;color:#fca5a5;font-size:14px;margin-bottom:20px;}
  .footer{text-align:center;margin-top:24px;color:rgba(255,255,255,0.2);font-size:12px;}
</style>
</head>
<body>
<div class="bg"></div>
<div class="card">
  <div class="logo">
    <span class="logo-icon">🔐</span>
    <h1>Flex OTP Service</h1>
    <p>Admin Control Panel</p>
  </div>
  {{ERROR}}
  <form method="POST" action="/admin/login">
    <label>Username</label>
    <input type="text" name="username" placeholder="Enter admin username" required autocomplete="off">
    <label>Password</label>
    <input type="password" name="password" placeholder="Enter password" required>
    <button type="submit">Sign In →</button>
  </form>
  <div class="footer">Flex OTP Service v1.0 · Secure Admin Access</div>
</div>
</body>
</html>"""


PANEL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flex OTP Service — Admin Panel</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#080c10;color:#e2e8f0;font-family:'Inter',sans-serif;min-height:100vh;}
  /* Sidebar */
  .sidebar{position:fixed;left:0;top:0;bottom:0;width:240px;background:rgba(255,255,255,0.03);
           border-right:1px solid rgba(255,255,255,0.07);padding:24px 0;z-index:100;}
  .sidebar-logo{padding:0 24px 24px;border-bottom:1px solid rgba(255,255,255,0.07);margin-bottom:16px;}
  .sidebar-logo h2{color:#fff;font-size:16px;font-weight:700;}
  .sidebar-logo span{color:rgba(0,200,150,0.8);font-size:11px;font-family:'JetBrains Mono',monospace;}
  .nav-item{display:flex;align-items:center;gap:12px;padding:12px 24px;cursor:pointer;
            color:rgba(255,255,255,0.5);font-size:14px;transition:all 0.2s;border:none;
            background:none;width:100%;text-align:left;}
  .nav-item:hover,.nav-item.active{color:#fff;background:rgba(255,255,255,0.05);}
  .nav-item.active{border-left:3px solid #00c896;color:#00c896;}
  .nav-item .icon{font-size:18px;width:22px;}
  /* Main */
  .main{margin-left:240px;padding:32px;}
  /* Header */
  .header{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;}
  .header h1{font-size:24px;font-weight:700;color:#fff;}
  .header-right{display:flex;align-items:center;gap:12px;}
  .status-dot{width:8px;height:8px;border-radius:50%;background:#00c896;
               box-shadow:0 0 8px #00c896;animation:pulse 2s infinite;}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
  .btn-logout{background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);
              color:#fca5a5;padding:8px 16px;border-radius:8px;cursor:pointer;font-size:13px;
              text-decoration:none;}
  /* Stats Grid */
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:32px;}
  .stat-card{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);
             border-radius:16px;padding:24px;}
  .stat-card .label{color:rgba(255,255,255,0.4);font-size:12px;font-weight:500;
                     letter-spacing:1px;text-transform:uppercase;margin-bottom:8px;}
  .stat-card .value{font-size:36px;font-weight:700;color:#fff;font-family:'JetBrains Mono',monospace;}
  .stat-card .icon{font-size:28px;margin-bottom:12px;}
  /* Tabs */
  .tabs{display:flex;gap:4px;background:rgba(255,255,255,0.03);padding:4px;
        border-radius:12px;margin-bottom:24px;width:fit-content;}
  .tab{padding:8px 20px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;
       color:rgba(255,255,255,0.4);border:none;background:none;transition:all 0.2s;}
  .tab.active{background:rgba(0,200,150,0.15);color:#00c896;}
  /* Panel sections */
  .panel-section{display:none;}
  .panel-section.active{display:block;}
  /* Create key form */
  .create-form{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);
               border-radius:16px;padding:24px;margin-bottom:24px;}
  .create-form h3{color:#fff;margin-bottom:16px;font-size:16px;}
  .form-row{display:flex;gap:12px;align-items:flex-end;}
  .form-group{flex:1;}
  .form-group label{display:block;color:rgba(255,255,255,0.5);font-size:12px;
                     text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;}
  .form-group input{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);
                    border-radius:8px;padding:10px 14px;color:#fff;font-size:14px;
                    outline:none;width:100%;}
  .form-group input:focus{border-color:rgba(0,200,150,0.4);}
  /* Table */
  .table-wrap{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);
              border-radius:16px;overflow:hidden;}
  .table-wrap h3{padding:20px 24px 0;color:#fff;font-size:15px;}
  table{width:100%;border-collapse:collapse;}
  th{background:rgba(255,255,255,0.05);padding:12px 16px;text-align:left;
     color:rgba(255,255,255,0.4);font-size:11px;letter-spacing:1px;text-transform:uppercase;}
  td{padding:12px 16px;border-top:1px solid rgba(255,255,255,0.05);
     font-size:13px;color:rgba(255,255,255,0.8);}
  tr:hover td{background:rgba(255,255,255,0.02);}
  .key-code{font-family:'JetBrains Mono',monospace;font-size:11px;
             background:rgba(0,200,150,0.1);color:#00c896;padding:3px 8px;border-radius:4px;}
  /* Badges */
  .badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;}
  .badge.active{background:rgba(0,200,150,0.15);color:#00c896;}
  .badge.inactive{background:rgba(239,68,68,0.15);color:#f87171;}
  .badge.pending{background:rgba(234,179,8,0.15);color:#fbbf24;}
  .badge.expired{background:rgba(107,114,128,0.2);color:#9ca3af;}
  /* Buttons */
  .btn{background:linear-gradient(135deg,#00c896,#0099ff);border:none;border-radius:8px;
       padding:10px 20px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;transition:opacity 0.2s;}
  .btn:hover{opacity:0.85;}
  .btn-sm{padding:5px 12px;font-size:12px;border-radius:6px;border:none;cursor:pointer;font-weight:500;}
  .btn-toggle{background:rgba(234,179,8,0.15);color:#fbbf24;border:1px solid rgba(234,179,8,0.2);}
  .btn-toggle:hover{background:rgba(234,179,8,0.25);}
  .btn-danger{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.2);}
  .btn-danger:hover{background:rgba(239,68,68,0.25);}
  /* Event badges */
  .event-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-family:'JetBrains Mono',monospace;}
  .event-badge.otp,.event-badge.verify{background:rgba(0,200,150,0.1);color:#00c896;}
  .event-badge.send{background:rgba(99,102,241,0.15);color:#a5b4fc;}
  .event-badge.blocked,.event-badge.invalid{background:rgba(239,68,68,0.1);color:#f87171;}
  /* Search */
  .search-bar{display:flex;gap:12px;margin-bottom:20px;}
  .search-bar input{flex:1;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);
                    border-radius:8px;padding:10px 14px;color:#fff;font-size:13px;outline:none;}
  /* Toast */
  #toast{position:fixed;bottom:24px;right:24px;background:#1e2937;border:1px solid rgba(0,200,150,0.3);
         color:#00c896;padding:14px 20px;border-radius:10px;font-size:14px;z-index:999;
         display:none;animation:slideIn 0.3s ease;}
  @keyframes slideIn{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
  @media(max-width:768px){
    .sidebar{display:none;}
    .main{margin-left:0;padding:16px;}
    .form-row{flex-direction:column;}
  }
</style>
</head>
<body>

<!-- Sidebar -->
<aside class="sidebar">
  <div class="sidebar-logo">
    <h2>🔐 Flex OTP</h2>
    <span>Admin Panel v1.0</span>
  </div>
  <button class="nav-item active" onclick="showTab('dashboard')"><span class="icon">📊</span> Dashboard</button>
  <button class="nav-item" onclick="showTab('clients')"><span class="icon">🔑</span> API Keys</button>
  <button class="nav-item" onclick="showTab('otps')"><span class="icon">📧</span> OTP Logs</button>
  <button class="nav-item" onclick="showTab('logs')"><span class="icon">📋</span> Event Logs</button>
  <button class="nav-item" onclick="showTab('blocked')"><span class="icon">🚫</span> Blocked IPs</button>
  <div style="position:absolute;bottom:24px;left:0;right:0;padding:0 24px;">
    <a href="/admin/logout" class="btn-logout" style="display:block;text-align:center;">Sign Out</a>
  </div>
</aside>

<!-- Main Content -->
<main class="main">
  <div class="header">
    <h1 id="page-title">Dashboard</h1>
    <div class="header-right">
      <div class="status-dot"></div>
      <span style="color:rgba(255,255,255,0.4);font-size:13px;">System Online</span>
      <a href="/docs" target="_blank" style="color:#00c896;font-size:13px;text-decoration:none;">API Docs ↗</a>
    </div>
  </div>

  <!-- Dashboard -->
  <div id="tab-dashboard" class="panel-section active">
    <div class="stats-grid">
      <div class="stat-card">
        <div class="icon">🔑</div>
        <div class="label">Active Clients</div>
        <div class="value">{{ACTIVE_CLIENTS}}</div>
      </div>
      <div class="stat-card">
        <div class="icon">📤</div>
        <div class="label">Total OTPs Sent</div>
        <div class="value">{{TOTAL_OTPS}}</div>
      </div>
      <div class="stat-card">
        <div class="icon">✅</div>
        <div class="label">Verified OTPs</div>
        <div class="value">{{VERIFIED_OTPS}}</div>
      </div>
      <div class="stat-card">
        <div class="icon">📅</div>
        <div class="label">Sent Today</div>
        <div class="value">{{TODAY_SENT}}</div>
      </div>
    </div>
    <div class="table-wrap" style="margin-top:24px;">
      <h3 style="padding:20px 24px;">Recent Activity</h3>
      <table>
        <thead><tr><th>Event</th><th>API Key</th><th>Email</th><th>Details</th><th>IP</th><th>Time</th></tr></thead>
        <tbody>{{LOG_ROWS}}</tbody>
      </table>
    </div>
  </div>

  <!-- API Keys -->
  <div id="tab-clients" class="panel-section">
    <div class="create-form">
      <h3>➕ Create New API Key</h3>
      <div class="form-row">
        <div class="form-group">
          <label>Client Name</label>
          <input type="text" id="new-name" placeholder="e.g. Demo Site">
        </div>
        <div class="form-group">
          <label>Email (optional)</label>
          <input type="email" id="new-email" placeholder="client@email.com">
        </div>
        <button class="btn" onclick="createKey()">Generate Key</button>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>API Key</th><th>Name</th><th>Email</th><th>Status</th><th>Sent</th><th>Verified</th><th>Created</th><th>Actions</th></tr></thead>
        <tbody id="clients-tbody">{{CLIENTS_ROWS}}</tbody>
      </table>
    </div>
  </div>

  <!-- OTP Logs -->
  <div id="tab-otps" class="panel-section">
    <div class="table-wrap">
      <h3 style="padding:20px 24px;">OTP Code Logs</h3>
      <table>
        <thead><tr><th>Email</th><th>Code</th><th>Status</th><th>Website</th><th>Attempts</th><th>Created</th><th>Expires</th></tr></thead>
        <tbody>{{OTP_ROWS}}</tbody>
      </table>
    </div>
  </div>

  <!-- Event Logs -->
  <div id="tab-logs" class="panel-section">
    <div class="search-bar">
      <input type="text" id="search-email" placeholder="Search by email...">
      <input type="text" id="search-key" placeholder="Search by API key...">
      <input type="text" id="search-event" placeholder="Search by event...">
      <button class="btn" onclick="searchLogs()">Search</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Event</th><th>API Key</th><th>Email</th><th>Details</th><th>IP</th><th>Time</th></tr></thead>
        <tbody id="log-tbody">{{LOG_ROWS}}</tbody>
      </table>
    </div>
  </div>

  <!-- Blocked IPs -->
  <div id="tab-blocked" class="panel-section">
    <div class="table-wrap">
      <h3 style="padding:20px 24px;">Blocked IP Addresses</h3>
      <table>
        <thead><tr><th>IP Address</th><th>Reason</th><th>Blocked At</th><th>Unblock At</th><th>Action</th></tr></thead>
        <tbody>{{BLOCKED_ROWS}}</tbody>
      </table>
    </div>
  </div>
</main>

<div id="toast"></div>

<script>
function showTab(name) {
  document.querySelectorAll('.panel-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.getElementById('page-title').textContent =
    {dashboard:'Dashboard',clients:'API Keys',otps:'OTP Logs',logs:'Event Logs',blocked:'Blocked IPs'}[name];
  event.currentTarget.classList.add('active');
}

function toast(msg, ok=true) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.color = ok ? '#00c896' : '#f87171';
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 3000);
}

async function createKey() {
  const name = document.getElementById('new-name').value.trim();
  const email = document.getElementById('new-email').value.trim();
  if (!name) { toast('Enter a client name', false); return; }
  const res = await fetch('/admin/api/create-key', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({name, email})
  });
  const data = await res.json();
  if (data.status === 'success') {
    toast('✅ API Key created: ' + data.api_key);
    setTimeout(() => location.reload(), 1500);
  } else { toast('Error: ' + data.detail, false); }
}

async function toggleKey(key, btn) {
  const res = await fetch('/admin/api/toggle-key/' + key, {method:'POST'});
  const data = await res.json();
  if (data.status === 'success') {
    btn.textContent = data.is_active ? 'Disable' : 'Enable';
    toast(data.is_active ? '✅ Key enabled' : '⏸ Key disabled');
    setTimeout(() => location.reload(), 1000);
  }
}

async function deleteKey(key) {
  if (!confirm('Delete API key: ' + key + '? This cannot be undone.')) return;
  const res = await fetch('/admin/api/delete-key/' + key, {method:'DELETE'});
  const data = await res.json();
  if (data.status === 'success') { toast('🗑 Key deleted'); setTimeout(() => location.reload(), 1000); }
}

async function unblockIp(ip) {
  const res = await fetch('/admin/api/unblock-ip/' + encodeURIComponent(ip), {method:'DELETE'});
  const data = await res.json();
  if (data.status === 'success') { toast('✅ IP unblocked: ' + ip); setTimeout(() => location.reload(), 1000); }
}

async function searchLogs() {
  const email = document.getElementById('search-email').value;
  const key = document.getElementById('search-key').value;
  const event = document.getElementById('search-event').value;
  const params = new URLSearchParams({email, api_key: key, event});
  const res = await fetch('/admin/api/search-logs?' + params);
  const data = await res.json();
  const tbody = document.getElementById('log-tbody');
  tbody.innerHTML = data.results.map(l => `
    <tr>
      <td><span class="event-badge ${l.event.split('_')[0]}">${l.event}</span></td>
      <td>${(l.api_key||'—').substring(0,20)}</td>
      <td>${l.user_email||'—'}</td>
      <td>${l.details||'—'}</td>
      <td>${l.client_ip||'—'}</td>
      <td>${l.created_at}</td>
    </tr>`).join('');
}
</script>
</body>
</html>"""
