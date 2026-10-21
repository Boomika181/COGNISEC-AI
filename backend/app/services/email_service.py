import smtplib
import ssl
import socket
import logging
import asyncio
import secrets
import re
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from typing import Tuple, Optional, Dict, Any
from app.core.config import settings

logger = logging.getLogger(__name__)

# Basic RFC 5322 regex for safe recipient validation
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class EmailService:
    """
    Zero-Trust Out-of-Band Email Delivery Service.
    Supports STARTTLS on port 587 (e.g. Gmail SMTP, SendGrid, AWS SES).
    Dispatches cryptographic one-time passwords and security alerts strictly to the
    verified email address associated with the authenticated account.
    Never accepts arbitrary unvalidated recipients or exposes passwords in logs.
    """

    @staticmethod
    def mask_email(email: Optional[str]) -> str:
        """
        Masks email address for privacy and safe audit logs (e.g. user.name@example.com -> u***e@example.com).
        """
        if not email or "@" not in email:
            return "***@***.***"
        parts = email.split("@", 1)
        local, domain = parts[0], parts[1]
        if len(local) <= 1:
            masked_local = "*"
        elif len(local) == 2:
            masked_local = local[0] + "*"
        else:
            masked_local = local[0] + "***" + local[-1]
        return f"{masked_local}@{domain}"

    @classmethod
    def validate_email_address(cls, email: Optional[str]) -> bool:
        """
        Validates email syntax safely without accepting malformed strings.
        """
        if not email or not isinstance(email, str):
            return False
        email_clean = email.strip()
        if len(email_clean) > 254:
            return False
        return bool(EMAIL_REGEX.match(email_clean))

    DEMO_DOMAINS = {
        "veritas.edu",
        "auraluxe.com",
        "aetheriahealth.org",
        "ayusync.med.in",
    }

    @classmethod
    def is_deliverable_recipient(cls, email: Optional[str]) -> Tuple[bool, str]:
        """
        Validates deliverability of recipient email address:
        1. Ensures standard RFC syntax via validate_email_address.
        2. Strictly prohibits outbound SMTP to @cognisec.ai unless the exact mailbox is verified
           to exist in the corporate mail directory (prevents Microsoft 550 5.1.10 NDR bounces).
        3. Prohibits outbound SMTP to student roll numbers / institutional demo addresses
           (e.g. 2021bce0492@bits-pilani.ac.in) to prevent Gmail NDR 'Address not found' bounces.
        4. Prohibits simulated demo portal domains (e.g. veritas.edu, auraluxe.com, etc.).
        5. Prohibits non-routable domains (e.g. invalid, localhost) in live transmission.
        """
        if not email or not cls.validate_email_address(email):
            return False, "Invalid recipient email address syntax."

        clean = email.strip().lower()
        parts = clean.split("@", 1)
        domain = parts[1]

        if domain in ("invalid", "localhost", "local"):
            return False, f"Domain '{domain}' is non-routable."

        verified_mailboxes = [
            m.strip().lower()
            for m in (getattr(settings, "VERIFIED_COGNISIC_MAILBOXES", []) + getattr(settings, "VERIFIED_RECIPIENT_MAILBOXES", []))
            if m and m.strip()
        ]

        if clean in verified_mailboxes:
            return True, "Deliverable"

        # Rule 7: Do not use @cognisec.ai addresses as real recipients unless the exact mailbox
        # is verified to exist and is intentionally configured for that purpose.
        if domain == "cognisec.ai" or domain.endswith(".cognisec.ai"):
            return False, (
                f"Recipient '{clean}' is an unverified @cognisec.ai mailbox. "
                f"Outbound SMTP suppressed to prevent Microsoft NDR (550 5.1.10) bounce."
            )

        # Institutional / student roll number demo addresses (e.g. 2021bce0492@bits-pilani.ac.in)
        if domain == "bits-pilani.ac.in" or domain.endswith(".bits-pilani.ac.in"):
            return False, (
                f"Recipient '{clean}' is an unverified student roll number / institutional demo address. "
                f"Outbound SMTP suppressed to prevent mail provider rejection (Address not found)."
            )

        # Simulated demo portal domains
        if domain in cls.DEMO_DOMAINS or any(domain.endswith("." + d) for d in cls.DEMO_DOMAINS):
            return False, (
                f"Recipient '{clean}' belongs to simulated demo domain '{domain}'. "
                f"Outbound SMTP suppressed to prevent mail provider rejection."
            )

        return True, "Deliverable"

    @classmethod
    def is_configured(cls) -> bool:
        """
        Returns True only if SMTP is explicitly enabled AND valid configuration is present.
        """
        if not getattr(settings, "SMTP_ENABLED", False):
            return False
        host = getattr(settings, "SMTP_HOST", None)
        if not host or not host.strip():
            return False
        # If host is local test server, user/password not strictly required
        if host.lower() in ("localhost", "127.0.0.1", "mailpit"):
            return True
        user = getattr(settings, "SMTP_USER", None)
        pwd = getattr(settings, "SMTP_PASSWORD", None)
        return bool(user and user.strip() and pwd and pwd.strip())

    @classmethod
    def get_diagnostics(cls) -> Dict[str, Any]:
        """
        Provides safe backend configuration diagnostic report.
        NEVER exposes the SMTP password or secret tokens.
        """
        has_host = bool(settings.SMTP_HOST and settings.SMTP_HOST.strip())
        has_user = bool(settings.SMTP_USER and settings.SMTP_USER.strip())
        has_pass = bool(settings.SMTP_PASSWORD and settings.SMTP_PASSWORD.strip())
        sender = getattr(settings, "SMTP_FROM", "")
        sender_valid = cls.validate_email_address(sender)
        enabled = bool(getattr(settings, "SMTP_ENABLED", False))

        is_ready = bool(
            enabled and has_host and sender_valid and
            (has_user or (settings.SMTP_HOST and settings.SMTP_HOST.lower() in ("localhost", "127.0.0.1")))
        )

        if is_ready:
            status_desc = "CONFIGURED_AND_READY"
        elif not enabled:
            status_desc = "DISABLED"
        else:
            status_desc = "INCOMPLETE_CONFIGURATION"

        return {
            "smtp_enabled": enabled,
            "smtp_host": settings.SMTP_HOST or "",
            "smtp_port": getattr(settings, "SMTP_PORT", 587),
            "smtp_tls": bool(getattr(settings, "SMTP_TLS", True)),
            "smtp_timeout_seconds": getattr(settings, "SMTP_TIMEOUT_SECONDS", 15),
            "smtp_user_configured": has_user,
            "smtp_password_configured": has_pass,
            "sender_configured": sender_valid,
            "sender_email": sender,
            "delivery_status": status_desc,
            "app_base_url": getattr(settings, "APP_BASE_URL", "http://127.0.0.1:5500"),
            "exhibition_mode": bool(getattr(settings, "EXHIBITION_MODE", False)),
        }

    @classmethod
    def test_connection(cls) -> Tuple[bool, str]:
        """
        Performs a live connectivity and STARTTLS authentication check against the configured SMTP server.
        Closes socket connections cleanly. Does not send an email.
        Never exposes passwords or sensitive credentials.
        """
        if not getattr(settings, "SMTP_ENABLED", False):
            return False, "SMTP is disabled (SMTP_ENABLED=false)."

        host = getattr(settings, "SMTP_HOST", "")
        if not host or not host.strip():
            return False, "SMTP host is not configured."

        is_local = host.lower() in ("localhost", "127.0.0.1", "mailpit")
        user = getattr(settings, "SMTP_USER", "")
        pwd = getattr(settings, "SMTP_PASSWORD", "")
        if not is_local and (not user or not pwd):
            return False, "SMTP username or password credentials missing."

        server = None
        timeout = getattr(settings, "SMTP_TIMEOUT_SECONDS", 15)
        port = getattr(settings, "SMTP_PORT", 587)
        use_tls = getattr(settings, "SMTP_TLS", True)

        try:
            server = smtplib.SMTP(host, port, timeout=timeout)
            server.ehlo()
            if use_tls:
                context = ssl.create_default_context()
                server.starttls(context=context)
                server.ehlo()

            if user and pwd:
                server.login(user, pwd)

            return True, f"Successfully connected and authenticated to {host}:{port} via TLS."

        except smtplib.SMTPAuthenticationError as e:
            err_text = e.smtp_error.decode("utf-8", errors="ignore") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
            logger.warning(f"[COGNISEC-AI] SMTP test auth failed: {e.smtp_code}")
            return False, f"SMTP authentication failed ({e.smtp_code}): {err_text}. Please verify your Google App Password."
        except smtplib.SMTPConnectError as e:
            logger.warning(f"[COGNISEC-AI] SMTP test connect failed to {host}:{port}: {str(e)}")
            return False, f"SMTP connection error: Unable to connect to mail server {host}:{port}."
        except (socket.timeout, TimeoutError):
            logger.warning(f"[COGNISEC-AI] SMTP test timeout connecting to {host}:{port}")
            return False, f"SMTP connection timed out after {timeout}s connecting to {host}:{port}."
        except Exception as e:
            logger.warning(f"[COGNISEC-AI] SMTP test unexpected error: {type(e).__name__} - {str(e)}")
            return False, f"SMTP test failed: {type(e).__name__} - {str(e)}"
        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass

    @classmethod
    def send_email(
        cls,
        recipient_email: str,
        subject: str,
        plain_text: str,
        html_text: Optional[str] = None,
        from_email: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Reusable, robust email delivery via configured SMTP server with STARTTLS and certificate validation.
        Validates sender and recipient, prevents credential leakage, and closes network connections cleanly.
        Returns:
            (success: bool, status_message: str)
        """
        if not cls.validate_email_address(recipient_email):
            return False, "Invalid recipient email address for authenticated account."

        masked = cls.mask_email(recipient_email)
        now_iso = datetime.now(timezone.utc).isoformat()

        sender = (from_email or getattr(settings, "SMTP_FROM", "cognisecai.security@gmail.com")).strip()
        if not cls.validate_email_address(sender):
            return False, "Invalid sender email address configured on server."

        # Handle unconfigured / disabled state first
        if not cls.is_configured():
            if getattr(settings, "EXHIBITION_MODE", False):
                logger.info(
                    f"[COGNISEC-AI] [EXHIBITION_MODE] SMTP unconfigured or disabled. Exhibition fallback active for {masked}."
                )
                return True, f"Exhibition delivery active: Simulated delivery to demo interface for {masked}."
            logger.warning(
                f"[COGNISEC-AI] SMTP mail server is not configured or disabled. Failed sending to {masked}."
            )
            return False, "SMTP mail server is not configured or disabled on the security backend. Unable to dispatch email."

        # Enforce recipient deliverability when SMTP is configured
        is_deliverable, deliverable_reason = cls.is_deliverable_recipient(recipient_email)
        if not is_deliverable:
            logger.warning(
                f"[COGNISEC-AI] [SMTP_SUPPRESSED] timestamp={now_iso} outcome=SUPPRESSED "
                f"category=UNVERIFIED_RECIPIENT recipient={masked} reason='{deliverable_reason}'"
            )
            return False, f"Email delivery suppressed: {deliverable_reason}"

        server = None
        host = getattr(settings, "SMTP_HOST", "smtp.gmail.com")
        port = getattr(settings, "SMTP_PORT", 587)
        use_tls = getattr(settings, "SMTP_TLS", True)
        timeout = getattr(settings, "SMTP_TIMEOUT_SECONDS", 15)
        user = getattr(settings, "SMTP_USER", None)
        pwd = getattr(settings, "SMTP_PASSWORD", None)

        notification_category = "SECURITY_NOTIFICATION"
        sub_lower = subject.lower()
        if "step-up" in sub_lower or "verification" in sub_lower:
            notification_category = "LOGIN_OTP"
        elif "password" in sub_lower or "recovery" in sub_lower:
            notification_category = "PASSWORD_RESET"
        elif "sign-in" in sub_lower or "device" in sub_lower:
            notification_category = "DEVICE_LOGIN_ALERT"

        msg_id = f"<cognisec-{secrets.token_hex(12)}@{sender.split('@')[-1] if '@' in sender else 'cognisec.ai'}>"

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            sender_display_name = getattr(settings, "SMTP_FROM_NAME", "COGNISEC-AI Security")
            msg["From"] = formataddr((sender_display_name, sender))
            msg["To"] = recipient_email
            msg["Message-ID"] = msg_id
            msg.attach(MIMEText(plain_text, "plain", "utf-8"))
            if html_text:
                msg.attach(MIMEText(html_text, "html", "utf-8"))

            server = smtplib.SMTP(host, port, timeout=timeout)
            server.ehlo()

            if use_tls:
                context = ssl.create_default_context()
                server.starttls(context=context)
                server.ehlo()

            if user and pwd:
                server.login(user, pwd)

            refused = server.sendmail(sender, [recipient_email], msg.as_string())
            if isinstance(refused, dict) and len(refused) > 0:
                logger.error(f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} outcome=FAILURE category=RECIPIENT_REJECTED recipient={masked} msg_id={msg_id}")
                return False, f"SMTP server rejected recipient {masked}. Please verify email address."

            logger.info(f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} outcome=SUCCESS category={notification_category} message_id={msg_id} recipient={masked}")
            return True, f"Email accepted and dispatched successfully to {masked}."

        except smtplib.SMTPAuthenticationError as e:
            err_text = e.smtp_error.decode("utf-8", errors="ignore") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
            logger.error(f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} outcome=FAILURE category=SMTP_AUTH_ERROR recipient={masked} code={e.smtp_code}")
            return False, f"SMTP authentication failure ({e.smtp_code}): Please verify your Google App Password or SMTP credentials."

        except smtplib.SMTPConnectError as e:
            logger.error(f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} outcome=FAILURE category=SMTP_CONNECT_ERROR recipient={masked}")
            return False, f"SMTP connection error: Unable to connect to mail server {host}:{port}."

        except (socket.timeout, TimeoutError):
            logger.error(f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} outcome=FAILURE category=SMTP_TIMEOUT recipient={masked} timeout_sec={timeout}")
            return False, f"SMTP timeout: Connection to mail server timed out after {timeout}s."

        except smtplib.SMTPRecipientsRefused:
            logger.error(f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} outcome=FAILURE category=RECIPIENTS_REFUSED recipient={masked}")
            return False, f"SMTP server rejected recipient address {masked}."

        except Exception as e:
            logger.error(f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} outcome=FAILURE category=SMTP_UNEXPECTED_ERROR recipient={masked} err={type(e).__name__}")
            return False, f"SMTP delivery failure: Unable to transmit email ({str(e)})"

        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    try:
                        server.close()
                    except Exception:
                        pass

    @classmethod
    async def send_email_async(
        cls,
        recipient_email: str,
        subject: str,
        plain_text: str,
        html_text: Optional[str] = None,
        from_email: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Non-blocking asynchronous wrapper avoiding event loop blockage.
        """
        return await asyncio.to_thread(
            cls.send_email,
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text,
            from_email=from_email
        )

    @classmethod
    def send_otp_email(
        cls,
        recipient_email: str,
        otp_code: str,
        expires_in_minutes: int = 5,
        challenge_id: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Transmits 6-digit OTP verification email via configured SMTP server.
        Returns:
            (success: bool, status_message: str)
        """
        subject = f"[{settings.PROJECT_NAME}] Zero-Trust Step-Up Verification Code"
        masked = cls.mask_email(recipient_email)
        chal_tag = f" challenge_id={challenge_id}" if challenge_id else ""
        logger.info(f"[COGNISEC-AI] [OTP_DELIVERY_INIT] Initiating OTP dispatch to {masked}{chal_tag}")

        plain_text = (
            f"COGNISEC-AI Zero-Trust Continuous Authentication\n"
            f"Step-Up Identity Verification Code\n\n"
            f"A step-up verification challenge was triggered for your session.\n"
            f"Your one-time verification code is: {otp_code}\n\n"
            f"This code will expire in {expires_in_minutes} minutes.\n"
            f"If you did not initiate this action, your session may have triggered an automated security policy.\n"
        )

        html_text = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #06040a; color: #ffffff; padding: 32px; border-radius: 16px; border: 1px solid #7f1d1d; max-width: 540px; margin: 0 auto;">
            <div style="border-bottom: 1px solid #450a0a; padding-bottom: 16px; margin-bottom: 24px;">
                <span style="font-size: 11px; font-family: monospace; letter-spacing: 2px; color: #ef4444; font-weight: bold; text-transform: uppercase;">COGNISEC-AI // ZERO-TRUST DEFENSE</span>
                <h2 style="color: #ffffff; font-size: 20px; margin: 8px 0 0 0; font-weight: 800;">Adaptive Step-Up Verification</h2>
            </div>
            <p style="color: #94a3b8; font-size: 13px; line-height: 1.6; margin: 0 0 20px 0;">
                An anomalous behavioral dynamic or high-value action triggered an automated step-up challenge for your authenticated session.
            </p>
            <div style="background-color: #000000; border: 2px solid #b91c1c; padding: 20px; border-radius: 12px; text-align: center; margin: 24px 0;">
                <span style="font-size: 11px; font-family: monospace; color: #f87171; letter-spacing: 1px; display: block; margin-bottom: 8px; text-transform: uppercase;">ONE-TIME CHALLENGE CODE</span>
                <span style="font-size: 36px; font-weight: 900; letter-spacing: 10px; color: #f59e0b; font-family: monospace;">{otp_code}</span>
            </div>
            <p style="color: #cbd5e1; font-size: 12px; margin: 0 0 8px 0;">
                ⏱️ Code expires in <strong style="color: #f59e0b;">{expires_in_minutes} minutes</strong>. Single use only.
            </p>
            <p style="color: #64748b; font-size: 11px; margin: 16px 0 0 0; border-top: 1px solid #1e1b4b; padding-top: 12px;">
                If you did not initiate this request, contact your SOC administrator immediately.
            </p>
        </div>
        """

        return cls.send_email(
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text
        )

    @classmethod
    def send_password_reset_email(
        cls,
        recipient_email: str,
        otp_code: str,
        expires_in_minutes: int = 5
    ) -> Tuple[bool, str]:
        """
        Transmits 6-digit password recovery code via configured SMTP server.
        Uses clear, dedicated reset template with security warnings.
        """
        subject = f"[{settings.PROJECT_NAME}] Password Reset Verification Code"
        masked = cls.mask_email(recipient_email)
        logger.info(f"[COGNISEC-AI] [PASSWORD_RESET_DISPATCH] Initiating recovery code dispatch to {masked}")

        plain_text = (
            f"COGNISEC-AI Zero-Trust Authentication\n"
            f"Account Password Recovery Request\n\n"
            f"We received a request to reset your password. Use the verification code below to set a new password:\n\n"
            f"Verification Code: {otp_code}\n\n"
            f"This code will expire in {expires_in_minutes} minutes. It can only be used once.\n\n"
            f"SECURITY NOTICE: If you did not request a password reset, your credentials may be targeted. "
            f"Please ignore this email and verify your account security immediately. Never share this code with anyone.\n"
        )

        html_text = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #06040a; color: #ffffff; padding: 32px; border-radius: 16px; border: 1px solid #7f1d1d; max-width: 540px; margin: 0 auto;">
            <div style="border-bottom: 1px solid #450a0a; padding-bottom: 16px; margin-bottom: 24px;">
                <span style="font-size: 11px; font-family: monospace; letter-spacing: 2px; color: #ef4444; font-weight: bold; text-transform: uppercase;">COGNISEC-AI // ACCOUNT SECURITY</span>
                <h2 style="color: #ffffff; font-size: 20px; margin: 8px 0 0 0; font-weight: 800;">Password Reset Request</h2>
            </div>
            <p style="color: #94a3b8; font-size: 13px; line-height: 1.6; margin: 0 0 20px 0;">
                A password reset request was initiated for your account. Enter the single-use recovery code below to establish a new password.
            </p>
            <div style="background-color: #000000; border: 2px solid #b91c1c; padding: 20px; border-radius: 12px; text-align: center; margin: 24px 0;">
                <span style="font-size: 11px; font-family: monospace; color: #f87171; letter-spacing: 1px; display: block; margin-bottom: 8px; text-transform: uppercase;">PASSWORD RECOVERY CODE</span>
                <span style="font-size: 36px; font-weight: 900; letter-spacing: 10px; color: #f59e0b; font-family: monospace;">{otp_code}</span>
            </div>
            <p style="color: #cbd5e1; font-size: 12px; margin: 0 0 8px 0;">
                ⏱️ Code expires in <strong style="color: #f59e0b;">{expires_in_minutes} minutes</strong>. Single use only.
            </p>
            <p style="color: #64748b; font-size: 11px; margin: 16px 0 0 0; border-top: 1px solid #1e1b4b; padding-top: 12px;">
                SECURITY NOTICE: If you did not request this reset, your account may be under reconnaissance. Please contact your security administrator.
            </p>
        </div>
        """

        return cls.send_email(
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text
        )

    @classmethod
    def send_new_device_login_alert(
        cls,
        recipient_email: str,
        user_name: str,
        device_summary: str,
        ip_address: str,
        location_summary: str,
        timestamp_str: str,
        device_nickname: Optional[str] = None,
        is_recognized: bool = False,
        review_url: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Dispatches a 'COGNISEC-AI — New Sign-In Detected' security alert email to the registered account owner.
        Includes device nickname, approximate location, timestamp, and recognized trust state.
        Returns: (success: bool, status_message: str)
        """
        subject = f"[{settings.PROJECT_NAME}] New Sign-In Detected"
        app_url = review_url or getattr(settings, "APP_BASE_URL", "http://127.0.0.1:5500")
        nick_str = device_nickname or "Unassigned"
        recog_str = "Yes (Trusted Device)" if is_recognized else "No (New / Unrecognized Device)"

        plain_text = (
            f"COGNISEC-AI Security Alert: New Sign-In Detected\n\n"
            f"Hello {user_name},\n\n"
            f"A sign-in was detected for your account with the following security attributes:\n"
            f"- Time (UTC): {timestamp_str}\n"
            f"- Device Nickname: {nick_str}\n"
            f"- Hardware / Browser: {device_summary}\n"
            f"- Recognized Device: {recog_str}\n"
            f"- Approximate Location: {location_summary}\n"
            f"- Client IP: {ip_address}\n\n"
            f"VERIFICATION & RESPONSE GUIDANCE:\n"
            f"If this sign-in was YOU, verify and mark the hardware as TRUSTED in your Security Dashboard:\n"
            f"{app_url}\n\n"
            f"IMPORTANT: If you did not sign in recently from this device, your credentials may be compromised.\n"
            f"Deny the alert immediately in your dashboard to revoke this device and terminate all active sessions.\n"
        )

        recog_badge = (
            '<span style="color: #22c55e; font-weight: bold;">Yes (Trusted)</span>'
            if is_recognized
            else '<span style="color: #ef4444; font-weight: bold;">No (Unrecognized / Action Required)</span>'
        )

        html_text = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #06040a; color: #ffffff; padding: 32px; border-radius: 16px; border: 1px solid #7f1d1d; max-width: 540px; margin: 0 auto;">
            <div style="border-bottom: 1px solid #450a0a; padding-bottom: 16px; margin-bottom: 24px;">
                <span style="font-size: 11px; font-family: monospace; letter-spacing: 2px; color: #ef4444; font-weight: bold; text-transform: uppercase;">COGNISEC-AI // ZERO-TRUST DEFENSE</span>
                <h2 style="color: #ffffff; font-size: 20px; margin: 8px 0 0 0; font-weight: 800;">🔔 New Sign-In Detected</h2>
            </div>
            <p style="color: #94a3b8; font-size: 13px; line-height: 1.6; margin: 0 0 16px 0;">
                Hello <strong style="color: #ffffff;">{user_name}</strong>, a sign-in occurred from an unrecognized device on your registered account:
            </p>
            <div style="background-color: #0b0713; border: 1px solid #991b1b; padding: 18px; border-radius: 12px; margin: 20px 0; font-size: 12px; font-family: monospace; line-height: 1.8;">
                <div style="color: #cbd5e1;"><strong style="color: #f87171;">Time (UTC):</strong> {timestamp_str}</div>
                <div style="color: #cbd5e1;"><strong style="color: #f87171;">Device Nickname:</strong> {nick_str}</div>
                <div style="color: #cbd5e1;"><strong style="color: #f87171;">Hardware / Browser:</strong> {device_summary}</div>
                <div style="color: #cbd5e1;"><strong style="color: #f87171;">Recognized:</strong> {recog_badge}</div>
                <div style="color: #cbd5e1;"><strong style="color: #f87171;">Approx. Location:</strong> {location_summary}</div>
                <div style="color: #cbd5e1;"><strong style="color: #f87171;">IP Address:</strong> {ip_address}</div>
            </div>
            <p style="color: #f59e0b; font-size: 12px; line-height: 1.6; margin: 16px 0;">
                ⚠️ <strong>Was this you?</strong><br>
                • <strong>YES:</strong> Confirm this device in your Security Dashboard to add it to your trusted hardware inventory.<br>
                • <strong>NO:</strong> Deny this device immediately to revoke access and terminate all unauthorized sessions.
            </p>
            <div style="text-align: center; margin: 24px 0;">
                <a href="{app_url}" style="background-color: #dc2626; color: #ffffff; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 12px; display: inline-block; font-family: monospace;">REVIEW SECURITY SESSIONS →</a>
            </div>
            <p style="color: #64748b; font-size: 11px; margin: 20px 0 0 0; border-top: 1px solid #1e1b4b; padding-top: 12px;">
                This security notification was dispatched automatically by COGNISEC Zero-Trust Continuous Protection.
            </p>
        </div>
        """

        return cls.send_email(
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text
        )
