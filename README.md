# 🔐 Flex OTP Service

Email Verification OTP API — সবসময় Online থাকে।

---

## ⚡ Railway-তে Deploy (সবচেয়ে সহজ — সবসময় Online)

### Step 1 — GitHub-এ Upload করুন
1. github.com → Sign Up
2. New Repository → নাম: `flex-otp-service` → Private → Create
3. সব files upload করুন (Upload files বাটন)

### Step 2 — Railway Deploy
1. **railway.app** → Login with GitHub
2. **New Project** → **Deploy from GitHub repo**
3. আপনার `flex-otp-service` select করুন
4. Deploy শুরু হবে!

### Step 3 — Environment Variable যোগ করুন
Railway Dashboard → Variables → Add:

```
EMAIL_USER         = flexotpservice@gmail.com
EMAIL_APP_PASSWORD = jbmt fiov qyax khcl
ADMIN_USERNAME     = flexadmin
ADMIN_PASSWORD     = FlexAdmin@Secure2026!
SENDER_NAME        = Flex OTP Service
SMTP_HOST          = smtp.gmail.com
SMTP_PORT          = 587
```

### Step 4 — URL নিন
Railway আপনাকে একটা URL দেবে যেমন:
`https://flex-otp-service-production.up.railway.app`

ঐ URL → Variable-এ যোগ করুন:
```
SERVICE_URL = https://আপনার-url.up.railway.app/health
```

এটা দিলে server নিজেই নিজেকে ping করবে — কখনো ঘুমাবে না! ✅

---

## 🔑 Admin Panel
```
https://আপনার-url.up.railway.app/admin/panel
Username: flexadmin
Password: FlexAdmin@Secure2026!
```

## 📡 API Endpoints

| Method | URL | কাজ |
|---|---|---|
| POST | `/send-code` | OTP পাঠায় |
| POST | `/verify-code` | OTP যাচাই করে |
| POST | `/resend-code` | আবার পাঠায় |
| GET | `/health` | Server চেক |
| GET | `/stats/{api_key}` | Usage দেখায় |
| GET | `/docs` | API documentation |

## 📧 OTP পাঠানোর উদাহরণ

```javascript
fetch('https://আপনার-url.up.railway.app/send-code', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    api_key: 'আপনার_api_key',
    user_email: 'user@gmail.com',
    website_name: 'আমার Website'
  })
})
```
