# COGNISEC-AI Backend — Real SMTP Email Delivery Guide

This guide details how to configure, test, and troubleshoot real SMTP email delivery for COGNISEC-AI out-of-band Step-Up OTP challenges and unrecognized new-device security alerts.

---

## 1. Google Account Setup (Gmail SMTP)

To dispatch emails using Gmail (`smtp.gmail.com:587`), Google requires modern **2-Step Verification** and an isolated **16-character App Password**. Standard Google account passwords are rejected by Gmail SMTP.

### Step 1: Enable Google 2-Step Verification
1. Log into your Google account: [https://myaccount.google.com/security](https://myaccount.google.com/security)
2. Under **"How you sign in to Google"**, select **2-Step Verification**.
3. Follow the Google prompts to activate 2-Step Verification on your account if not already enabled.

### Step 2: Generate a Google App Password
1. Navigate directly to App Passwords: [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Enter an App Name (e.g., `COGNISEC-AI Security Backend`).
3. Click **Create**.
4. Google will generate a unique **16-character password** (formatted as `xxxx xxxx xxxx xxxx`).
5. Copy this 16-character string. Remove spaces when pasting it into your configuration.

> **CRITICAL SECURITY RULE**: Never commit, push, or share your App Password. Keep it strictly inside your local `backend/.env` file.

---

## 2. Environment Configuration

Configure your environment variables in `backend/.env`. (Use `backend/.env.example` as a template).

```dotenv
# SMTP / Real Email Delivery Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-actual-email@gmail.com
SMTP_PASSWORD=your16charapppassword
SMTP_FROM=your-actual-email@gmail.com
SMTP_TLS=true
SMTP_TIMEOUT_SECONDS=15
SMTP_ENABLED=true
APP_BASE_URL=http://127.0.0.1:5500
EXHIBITION_MODE=false
```

### Configuration Parameters
| Parameter | Default | Description |
|---|---|---|
| `SMTP_HOST` | `smtp.gmail.com` | SMTP relay server hostname (Gmail, SendGrid, Amazon SES) |
| `SMTP_PORT` | `587` | STARTTLS port (recommended: `587`) |
| `SMTP_USER` | `None` | Authentication username (your full Gmail address) |
| `SMTP_PASSWORD` | `None` | 16-character Google App Password (no spaces) |
| `SMTP_FROM` | `noreply@cognisec.ai` | Sender email address appearing in `From` header |
| `SMTP_TLS` | `true` | Enables STARTTLS certificate validation |
| `SMTP_TIMEOUT_SECONDS` | `15` | Socket/connection timeout in seconds |
| `SMTP_ENABLED` | `false` | Master toggle: must be set to `true` to enable real delivery |
| `APP_BASE_URL` | `http://127.0.0.1:5500` | Application frontend URL inserted into security alert emails |
| `EXHIBITION_MODE` | `false` | When `false`, OTPs are strictly excluded from all API responses |

---

## 3. Restarting the Backend Server

After updating `backend/.env`, restart the Uvicorn development server:

```bash
# Terminate existing uvicorn instance (Ctrl+C), then start:
cd /path/to/cognisec-ai-final/backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 4. Diagnostics & Live Verification

### Option A: Check Configuration Diagnostics (Admin API)
Security Administrators can verify the configuration state without sending an email or exposing secrets:

```bash
curl -X GET "http://127.0.0.1:8000/api/admin/email/diagnostics" \
     -H "Authorization: Bearer <ADMIN_JWT_TOKEN>"
```
**Response Sample**:
```json
{
  "smtp_enabled": true,
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "smtp_tls": true,
  "smtp_timeout_seconds": 15,
  "smtp_user_configured": true,
  "smtp_password_configured": true,
  "sender_configured": true,
  "sender_email": "security@cognisec.ai",
  "delivery_status": "CONFIGURED_AND_READY",
  "app_base_url": "http://127.0.0.1:5500",
  "exhibition_mode": false
}
```

### Option B: Test Connection & Authentication (No Email Sent)
Validates TLS handshake and credential validity without sending a message:

```bash
curl -X POST "http://127.0.0.1:8000/api/admin/email/test-connection" \
     -H "Authorization: Bearer <ADMIN_JWT_TOKEN>"
```

### Option C: Send a Live Test Email
Sends a real test email to an administrator-specified recipient:

```bash
curl -X POST "http://127.0.0.1:8000/api/admin/email/send-test" \
     -H "Authorization: Bearer <ADMIN_JWT_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"recipient_email": "your-personal-email@example.com"}'
```

---

## 5. End-to-End User Verification Flows

### Testing Out-of-Band Step-Up OTP
1. Authenticate as a normal user.
2. Trigger an anomalous behavior or navigate to a protected portal requiring step-up authentication.
3. Call `POST /api/security/step-up/challenge` with `{"session_id": "<SESSION_ID>"}`.
4. The server generates a cryptographically secure 6-digit OTP, hashes it, stores the hash, and dispatches the code to the user's registered email.
5. In production (`EXHIBITION_MODE=false`), the response returns `{"otp": "", "delivery_status": "SENT"}`.
6. Check your inbox for subject: `"[COGNISEC-AI] Zero-Trust Step-Up Verification Code"`.
7. Submit the received 6-digit code to `POST /api/security/step-up/verify`.

### Testing Unrecognized Device Security Alerts
1. Log into an existing user account from an unfamiliar browser or with a new `device_fingerprint`.
2. The server detects the device as unfamiliar (`PENDING_CONFIRMATION`).
3. An alert email is dispatched to the user's registered address with subject: `"[COGNISEC-AI] New Sign-In Detected"`.
4. Open the email to inspect:
   - Readable UTC timestamp
   - Detected browser & platform (e.g. *Chrome 122 on macOS*)
   - Client IP address and approximate location
   - Direct button/link to review sessions in the Security Dashboard.
5. In the Security Dashboard, the user can click **"Yes, this was me"** to trust the device or **"No, secure my account"** to revoke access and terminate active sessions.

---

## 6. Troubleshooting & Common Errors

### `535 5.7.8 Username and Password not accepted`
- **Cause**: Using your normal Google account password instead of a Google App Password, or 2-Step Verification is disabled.
- **Solution**: Generate a fresh 16-character App Password at [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords). Ensure no spaces exist in `SMTP_PASSWORD`.

### `SMTP timeout: Connection to mail server timed out after 15s`
- **Cause**: Outbound port `587` blocked by firewall, VPN, ISP, or corporate proxy.
- **Solution**: Verify connectivity using `nc -zv smtp.gmail.com 587` or `telnet smtp.gmail.com 587`. Temporarily disable active VPNs.

### `SMTP mail server is not configured or disabled`
- **Cause**: `SMTP_ENABLED` is set to `false` or required parameters (`SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`) are empty.
- **Solution**: Set `SMTP_ENABLED=true` in `backend/.env` and restart the backend server.

### Email Not Arriving in Inbox
- **Cause**: Message filtered to Spam/Junk or delayed by provider greylisting.
- **Solution**: Check the `Spam` or `Promotions` folders in your email client. Add your configured `SMTP_FROM` address to your trusted contacts.
