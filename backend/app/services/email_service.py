import smtplib
import ssl
import socket
import logging
import asyncio
import html
import secrets
import re
import time
import threading
import random
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate
from typing import Tuple, Optional, Dict, Any, Union
from app.core.config import settings
from app.utils.email_time import (
    compute_expiry_display,
    format_appointment_datetime,
    format_email_timestamp,
)

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

    DELIVERY_STATE_PENDING = "PENDING"
    DELIVERY_STATE_SENDING = "SENDING"
    DELIVERY_STATE_SMTP_ACCEPTED = "SMTP_ACCEPTED"
    DELIVERY_STATE_DELIVERY_CONFIRMED = "DELIVERY_CONFIRMED"
    DELIVERY_STATE_FAILED = "FAILED"
    DELIVERY_STATE_RETRY_PENDING = "RETRY_PENDING"

    _delivery_lock = threading.Lock()
    _delivery_cache: Dict[str, Dict[str, Any]] = {}
    _last_delivery_by_thread: Dict[int, Dict[str, Any]] = {}

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

    SYNTHETIC_DEMO_ACCOUNTS = {
        "student.alex@veritas.edu",
        "customer.jane@auraluxe.com",
        "dr.sarah@aetheriahealth.org",
        "dr.boomika@ayusync.med.in",
        "user.portal@cognisec.ai",
        "boomika.ram@cognisec.ai",
    }

    @classmethod
    def is_demo_mailbox_override_active(cls) -> Tuple[bool, Optional[str]]:
        """
        Determines whether the exhibition demo mailbox override is permitted and active.
        Guards:
        1. EXHIBITION_DEMO_MAILBOX_OVERRIDE must be explicitly enabled.
        2. Prohibited unconditionally in production environments.
        3. Only permitted in approved environments (development, staging, demo, exhibition, test, testing)
           or when EXHIBITION_MODE is explicitly True.
        4. Validates that DEMO_OTP_RECIPIENT_EMAIL is configured with valid email syntax.
        Returns:
            (is_active: bool, validated_destination_email: Optional[str])
        """
        if not getattr(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", False):
            return False, None

        env = (getattr(settings, "ENVIRONMENT", "") or "").strip().lower()
        if env in ("production", "prod"):
            logger.warning("[COGNISEC-AI] Security Guard: EXHIBITION_DEMO_MAILBOX_OVERRIDE rejected in production environment.")
            return False, None

        approved_envs = {"development", "dev", "demo", "exhibition", "staging", "test", "testing"}
        is_exhibition_mode = bool(getattr(settings, "EXHIBITION_MODE", False))
        if env not in approved_envs and not is_exhibition_mode:
            logger.warning(f"[COGNISEC-AI] Security Guard: Environment '{env}' is not an approved demo/exhibition environment.")
            return False, None

        raw_dest = getattr(settings, "DEMO_OTP_RECIPIENT_EMAIL", None)
        if not raw_dest or not isinstance(raw_dest, str) or not raw_dest.strip():
            logger.warning("[COGNISEC-AI] Security Guard: EXHIBITION_DEMO_MAILBOX_OVERRIDE enabled but no destination email configured.")
            return False, None

        dest = raw_dest.strip().lower()
        if not cls.validate_email_address(dest):
            logger.warning(f"[COGNISEC-AI] Security Guard: Configured destination email '{cls.mask_email(dest)}' has invalid syntax.")
            return False, None

        return True, dest

    @classmethod
    def resolve_delivery_recipient(cls, email: Optional[str]) -> str:
        """
        Resolves destination recipient email for OTP transmission.
        In normal / production operation: strictly returns the clean registered user email.
        When EXHIBITION_DEMO_MAILBOX_OVERRIDE is securely active in an approved demo environment:
        Redirects synthetic demonstration accounts and mock domains to the configured demo mailbox.
        Real registered user addresses are never redirected unless they are synthetic demo accounts.
        """
        if not email or not isinstance(email, str):
            return ""

        clean = email.strip().lower()

        is_active, target_mailbox = cls.is_demo_mailbox_override_active()
        if not is_active or not target_mailbox:
            return clean

        # When override is active, check if the address is a synthetic demonstration address
        if clean in cls.SYNTHETIC_DEMO_ACCOUNTS:
            return target_mailbox

        domain = clean.split("@", 1)[1] if "@" in clean else ""
        if domain in cls.DEMO_DOMAINS or domain == "cognisec.ai" or domain.endswith(".cognisec.ai"):
            return target_mailbox

        # Real registered addresses outside synthetic demo scope are preserved
        return clean

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

        # Simulated demo portal domains and RFC 2606 non-production domains (outside unit-test mocks)
        if domain in cls.DEMO_DOMAINS or any(domain.endswith("." + d) for d in cls.DEMO_DOMAINS):
            return False, (
                f"Recipient '{clean}' belongs to simulated demo domain '{domain}'. "
                f"Outbound SMTP suppressed to prevent mail provider rejection."
            )
        env = (getattr(settings, "ENVIRONMENT", "") or "").strip().lower()
        smtp_host = (getattr(settings, "SMTP_HOST", "") or "").strip().lower()
        rfc_test_domains = {"example.com", "example.org", "example.net"}
        if env not in ("test", "testing") and smtp_host not in ("localhost", "127.0.0.1", "mailpit") and (
            domain in rfc_test_domains
            or any(domain.endswith("." + d) for d in rfc_test_domains)
            or domain.endswith(".test")
            or domain.endswith(".example")
        ):
            return False, (
                f"Recipient '{clean}' belongs to synthetic test domain '{domain}'. "
                f"Outbound SMTP suppressed outside test mode."
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

        missing_variables = []
        if not enabled:
            missing_variables.append("SMTP_ENABLED")
        if not has_host:
            missing_variables.append("SMTP_HOST")
        is_local = bool(settings.SMTP_HOST and settings.SMTP_HOST.lower() in ("localhost", "127.0.0.1", "mailpit"))
        if not is_local:
            if not has_user:
                missing_variables.append("SMTP_USER")
            if not has_pass:
                missing_variables.append("SMTP_PASSWORD")
        if not sender_valid:
            missing_variables.append("SMTP_FROM")

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
            "missing_variables": missing_variables,
            "delivery_status": status_desc,
            "app_base_url": getattr(settings, "APP_BASE_URL", "http://127.0.0.1:5500"),
            "exhibition_mode": bool(getattr(settings, "EXHIBITION_MODE", False)),
            "exhibition_demo_override_enabled": bool(getattr(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", False)),
            "demo_mailbox_override_active": cls.is_demo_mailbox_override_active()[0],
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
    def _record_delivery_state(cls, correlation_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        tid = threading.get_ident()
        with cls._delivery_lock:
            now_ts = time.time()
            # Prune expired cache entries (> 180s) to keep memory bounded
            stale = [k for k, v in cls._delivery_cache.items() if (now_ts - v.get("_ts", 0)) > 180]
            for k in stale:
                cls._delivery_cache.pop(k, None)
            entry = dict(payload)
            entry["correlation_id"] = correlation_id
            entry["_ts"] = now_ts
            cls._delivery_cache[correlation_id] = entry
            cls._last_delivery_by_thread[tid] = entry
            return dict(entry)

    @classmethod
    def get_delivery_status(cls, correlation_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not correlation_id:
            return None
        with cls._delivery_lock:
            entry = cls._delivery_cache.get(correlation_id)
            if not entry:
                return None
            out = dict(entry)
            out.pop("_ts", None)
            return out

    @classmethod
    def get_last_delivery_result(cls) -> Optional[Dict[str, Any]]:
        tid = threading.get_ident()
        with cls._delivery_lock:
            entry = cls._last_delivery_by_thread.get(tid)
            if not entry:
                return None
            out = dict(entry)
            out.pop("_ts", None)
            return out

    @classmethod
    def send_email_with_status(
        cls,
        recipient_email: str,
        subject: str,
        plain_text: str,
        html_text: Optional[str] = None,
        from_email: Optional[str] = None,
        correlation_id: Optional[str] = None,
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        """
        Reusable email delivery via configured SMTP server with:
        - Idempotency/correlation deduplication so duplicate requests do not resend
        - Bounded exponential backoff with jitter for transient network/SMTP failures
        - No retries for permanent authentication, configuration, or recipient rejections
        - Accurate delivery state reporting:
          PENDING -> SENDING -> RETRY_PENDING -> SMTP_ACCEPTED / FAILED
          (DELIVERY_CONFIRMED is only returned if a provider supplies genuine delivery confirmation)
        """
        corr_id = (correlation_id or f"mail_{secrets.token_hex(8)}").strip()

        # Idempotency check for an already-accepted or in-flight logical send operation
        if correlation_id:
            with cls._delivery_lock:
                existing = cls._delivery_cache.get(corr_id)
                if existing and (time.time() - existing.get("_ts", 0)) <= 120:
                    if existing.get("delivery_status") in (
                        cls.DELIVERY_STATE_SMTP_ACCEPTED,
                        cls.DELIVERY_STATE_DELIVERY_CONFIRMED,
                    ):
                        logger.info(
                            f"[COGNISEC-AI] [SMTP_DEDUP] correlation_id={corr_id} already {existing.get('delivery_status')}; skipping duplicate send."
                        )
                        dedup_out = dict(existing)
                        dedup_out.pop("_ts", None)
                        dedup_out["deduplicated"] = True
                        return dedup_out

        if not cls.validate_email_address(recipient_email):
            return cls._record_delivery_state(corr_id, {
                "success": False,
                "delivery_status": cls.DELIVERY_STATE_FAILED,
                "smtp_code": None,
                "attempts": 0,
                "message": "Invalid recipient email address for authenticated account.",
                "error": "INVALID_RECIPIENT",
            })

        masked = cls.mask_email(recipient_email)
        now_iso = datetime.now(timezone.utc).isoformat()

        sender = (from_email or getattr(settings, "SMTP_FROM", "cognisecai.security@gmail.com")).strip()
        if not cls.validate_email_address(sender):
            return cls._record_delivery_state(corr_id, {
                "success": False,
                "delivery_status": cls.DELIVERY_STATE_FAILED,
                "smtp_code": None,
                "attempts": 0,
                "message": "Invalid sender email address configured on server.",
                "error": "INVALID_SENDER",
            })

        if not cls.is_configured():
            diag = cls.get_diagnostics()
            missing_str = ", ".join(diag.get("missing_variables") or [])
            if getattr(settings, "EXHIBITION_MODE", False):
                logger.info(
                    f"[COGNISEC-AI] [EXHIBITION_MODE] SMTP unconfigured or disabled ({missing_str}). Exhibition fallback active for {masked}."
                )
                return cls._record_delivery_state(corr_id, {
                    "success": True,
                    "delivery_status": cls.DELIVERY_STATE_PENDING,
                    "smtp_code": None,
                    "attempts": 0,
                    "message": f"Exhibition delivery active: Simulated delivery to demo interface for {masked}.",
                    "error": None,
                })
            logger.warning(
                f"[COGNISEC-AI] SMTP mail server is not configured or disabled (missing: {missing_str}). Failed sending to {masked}."
            )
            return cls._record_delivery_state(corr_id, {
                "success": False,
                "delivery_status": cls.DELIVERY_STATE_FAILED,
                "smtp_code": None,
                "attempts": 0,
                "message": f"SMTP mail server is not configured or disabled on the security backend (missing: {missing_str or 'SMTP_ENABLED'}). Unable to dispatch email.",
                "error": "SMTP_NOT_CONFIGURED",
            })

        is_deliverable, deliverable_reason = cls.is_deliverable_recipient(recipient_email)
        if not is_deliverable:
            logger.warning(
                f"[COGNISEC-AI] [SMTP_SUPPRESSED] timestamp={now_iso} correlation_id={corr_id} outcome=SUPPRESSED "
                f"category=UNVERIFIED_RECIPIENT recipient={masked} reason='{deliverable_reason}'"
            )
            return cls._record_delivery_state(corr_id, {
                "success": False,
                "delivery_status": cls.DELIVERY_STATE_FAILED,
                "smtp_code": None,
                "attempts": 0,
                "message": f"Email delivery suppressed: {deliverable_reason}",
                "error": "RECIPIENT_SUPPRESSED",
            })

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

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        sender_display_name = getattr(settings, "SMTP_FROM_NAME", "CogniSec Security")
        msg["From"] = formataddr((sender_display_name, sender))
        msg["To"] = recipient_email
        msg["Reply-To"] = sender
        msg["Date"] = formatdate(timeval=datetime.now(timezone.utc).timestamp(), usegmt=True)
        msg.attach(MIMEText(plain_text, "plain", "utf-8"))
        if html_text:
            msg.attach(MIMEText(html_text, "html", "utf-8"))
        raw_msg = msg.as_string()

        env = (getattr(settings, "ENVIRONMENT", "") or "").strip().lower()
        base_backoff = 0.05 if env in ("test", "testing") else 0.4
        total_allowed = max(1, 1 + max(0, int(max_retries)))
        last_err_msg = "SMTP delivery failure."
        last_smtp_code: Optional[int] = None

        for attempt in range(1, total_allowed + 1):
            cls._record_delivery_state(corr_id, {
                "success": False,
                "delivery_status": cls.DELIVERY_STATE_SENDING,
                "smtp_code": None,
                "attempts": attempt,
                "message": "Sending verification email...",
                "error": None,
            })

            server = None
            is_transient = False
            try:
                server = smtplib.SMTP(host, port, timeout=timeout)
                server.ehlo()

                if use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()

                if user and pwd:
                    server.login(user, pwd)

                refused = server.sendmail(sender, [recipient_email], raw_msg)
                if isinstance(refused, dict) and len(refused) > 0:
                    refusal_desc = ", ".join(f"{r}: {c}" for r, c in refused.items())
                    logger.error(
                        f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} correlation_id={corr_id} outcome=FAILED "
                        f"category=RECIPIENT_REJECTED recipient={masked} refused={refusal_desc}"
                    )
                    return cls._record_delivery_state(corr_id, {
                        "success": False,
                        "delivery_status": cls.DELIVERY_STATE_FAILED,
                        "smtp_code": 550,
                        "attempts": attempt,
                        "message": f"SMTP server rejected recipient {masked}. Refusal details: {refusal_desc}",
                        "error": "RECIPIENT_REJECTED",
                    })

                logger.info(
                    f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} correlation_id={corr_id} outcome=SMTP_ACCEPTED "
                    f"category={notification_category} recipient={masked} smtp_host={host}:{port} attempt={attempt}"
                )
                return cls._record_delivery_state(corr_id, {
                    "success": True,
                    "delivery_status": cls.DELIVERY_STATE_SMTP_ACCEPTED,
                    "smtp_code": 250,
                    "attempts": attempt,
                    "message": f"Email submitted to the mail server for {masked}. Check your inbox and spam folder.",
                    "error": None,
                })

            except smtplib.SMTPAuthenticationError as e:
                last_smtp_code = getattr(e, "smtp_code", 535)
                logger.error(
                    f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} correlation_id={corr_id} outcome=FAILED "
                    f"category=SMTP_AUTH_ERROR recipient={masked} code={last_smtp_code}"
                )
                last_err_msg = f"SMTP authentication failure ({last_smtp_code}): Please verify your Google App Password or SMTP credentials."
                is_transient = False

            except smtplib.SMTPRecipientsRefused:
                last_smtp_code = 550
                logger.error(
                    f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} correlation_id={corr_id} outcome=FAILED "
                    f"category=RECIPIENTS_REFUSED recipient={masked}"
                )
                last_err_msg = f"SMTP server rejected recipient address {masked}."
                is_transient = False

            except smtplib.SMTPDataError as e:
                last_smtp_code = getattr(e, "smtp_code", None)
                is_transient = bool(last_smtp_code and 400 <= int(last_smtp_code) < 500)
                logger.error(
                    f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} correlation_id={corr_id} outcome={'RETRY_PENDING' if is_transient else 'FAILED'} "
                    f"category=SMTP_DATA_ERROR recipient={masked} code={last_smtp_code}"
                )
                last_err_msg = f"SMTP data error ({last_smtp_code}): Unable to transmit email."

            except smtplib.SMTPConnectError:
                is_transient = True
                logger.warning(
                    f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} correlation_id={corr_id} attempt={attempt}/{total_allowed} "
                    f"category=SMTP_CONNECT_ERROR recipient={masked}"
                )
                last_err_msg = f"SMTP connection error: Unable to connect to mail server {host}:{port}."

            except (smtplib.SMTPServerDisconnected, socket.timeout, TimeoutError, OSError) as e:
                is_transient = True
                is_to = isinstance(e, (socket.timeout, TimeoutError))
                cat = "SMTP_TIMEOUT" if is_to else "SMTP_TRANSIENT_NETWORK"
                logger.warning(
                    f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} correlation_id={corr_id} attempt={attempt}/{total_allowed} "
                    f"category={cat} recipient={masked}"
                )
                last_err_msg = (
                    f"SMTP timeout: Connection to mail server timed out after {timeout}s."
                    if is_to else f"SMTP transient network error: {type(e).__name__}"
                )

            except Exception as e:
                is_transient = False
                logger.error(
                    f"[COGNISEC-AI] [SMTP_DISPATCH] timestamp={now_iso} correlation_id={corr_id} outcome=FAILED "
                    f"category=SMTP_UNEXPECTED_ERROR recipient={masked} err={type(e).__name__}"
                )
                last_err_msg = f"SMTP delivery failure: Unable to transmit email ({type(e).__name__})"

            finally:
                if server:
                    try:
                        server.quit()
                    except Exception:
                        try:
                            server.close()
                        except Exception:
                            pass

            if not is_transient or attempt >= total_allowed:
                return cls._record_delivery_state(corr_id, {
                    "success": False,
                    "delivery_status": cls.DELIVERY_STATE_FAILED,
                    "smtp_code": last_smtp_code,
                    "attempts": attempt,
                    "message": last_err_msg,
                    "error": last_err_msg,
                })

            # Transient failure with remaining retries -> RETRY_PENDING with exponential backoff + jitter
            cls._record_delivery_state(corr_id, {
                "success": False,
                "delivery_status": cls.DELIVERY_STATE_RETRY_PENDING,
                "smtp_code": last_smtp_code,
                "attempts": attempt,
                "message": "Sending verification email...",
                "error": last_err_msg,
            })
            delay = base_backoff * (2 ** (attempt - 1)) + random.uniform(0.01, base_backoff)
            time.sleep(delay)

        return cls._record_delivery_state(corr_id, {
            "success": False,
            "delivery_status": cls.DELIVERY_STATE_FAILED,
            "smtp_code": last_smtp_code,
            "attempts": total_allowed,
            "message": last_err_msg,
            "error": last_err_msg,
        })

    @classmethod
    def send_email(
        cls,
        recipient_email: str,
        subject: str,
        plain_text: str,
        html_text: Optional[str] = None,
        from_email: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Reusable, robust email delivery via configured SMTP server with STARTTLS, certificate validation,
        bounded transient retries, and correlation deduplication.
        Returns:
            (success: bool, status_message: str)
        """
        result = cls.send_email_with_status(
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text,
            from_email=from_email,
            correlation_id=correlation_id,
        )
        return bool(result.get("success")), str(result.get("message") or "")
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
        challenge_id: Optional[str] = None,
        issued_at: Optional[Union[datetime, str]] = None,
        expires_at: Optional[Union[datetime, str]] = None,
        recipient_timezone: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Transmits 6-digit OTP verification email via configured SMTP server.
        Uses original cybersecurity dark aesthetic (#080808, red accents, amber OTP digits).
        Returns:
            (success: bool, status_message: str)
        """
        subject = "CogniSec AI - Login Verification Code"
        masked = cls.mask_email(recipient_email)
        chal_tag = f" challenge_id={challenge_id}" if challenge_id else ""
        logger.info(f"[COGNISEC-AI] [OTP_DELIVERY_INIT] Initiating OTP dispatch to {masked}{chal_tag}")

        issued_display, expires_display, remaining_label = compute_expiry_display(
            issued_at=issued_at,
            expires_at=expires_at,
            expires_in_minutes=expires_in_minutes,
            target_tz=recipient_timezone,
        )
        safe_issued = html.escape(issued_display)
        safe_expires = html.escape(expires_display)
        safe_remaining = html.escape(remaining_label)

        plain_text = (
            f"COGNISEC-AI Zero-Trust Continuous Authentication\n"
            f"Step-Up Identity Verification Code\n\n"
            f"A step-up verification challenge was triggered for your session.\n"
            f"Your one-time verification code is: {otp_code}\n\n"
            f"Issued: {issued_display}\n"
            f"Expires: {expires_display} ({remaining_label})\n"
            f"Challenge ID: {challenge_id or 'N/A'}\n\n"
            f"If you did not initiate this action, contact your SOC administrator immediately.\n"
        )

        html_text = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 24px 0; background-color: #080808; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #ffffff;">
  <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background-color: #080808; margin: 0; padding: 20px 0;">
    <tr>
      <td align="center">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width: 520px; background-color: #121013; border: 1px solid #dc2626; border-radius: 14px; overflow: hidden; box-shadow: 0 0 40px rgba(220, 38, 38, 0.15); margin: 0 auto; text-align: left;">
          <tr>
            <td style="padding: 22px 28px 18px 28px; border-bottom: 1px solid #331414; background-color: #181114;">
              <span style="font-size: 20px; vertical-align: middle; margin-right: 8px;">🔒</span>
              <span style="font-family: 'SFMono-Regular', Consolas, 'Courier New', Courier, monospace; font-size: 14px; font-weight: 800; color: #ef4444; letter-spacing: 2px; text-transform: uppercase; vertical-align: middle;">COGNISEC-AI</span>
              <span style="font-family: 'SFMono-Regular', Consolas, 'Courier New', Courier, monospace; font-size: 11px; color: #94a3b8; letter-spacing: 1px; text-transform: uppercase; margin-left: 8px; vertical-align: middle;">// ZERO-TRUST IDENTITY</span>
            </td>
          </tr>
          <tr>
            <td style="padding: 28px;">
              <h2 style="margin: 0 0 10px 0; font-size: 20px; font-weight: 800; color: #ffffff; letter-spacing: -0.3px;">Identity Verification</h2>
              <p style="margin: 0 0 20px 0; font-size: 13px; line-height: 1.6; color: #94a3b8;">
                A Zero-Trust authentication challenge was triggered for your session. Enter the one-time security code below to complete continuous identity verification.
              </p>
              <div style="background-color: #050406; border: 2px solid #b91c1c; border-radius: 10px; padding: 22px 16px; text-align: center; margin: 22px 0;">
                <span style="display: block; font-family: 'SFMono-Regular', Consolas, 'Courier New', Courier, monospace; font-size: 11px; font-weight: 700; color: #f87171; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 8px;">ONE-TIME CHALLENGE CODE</span>
                <span style="display: block; font-family: 'SFMono-Regular', Consolas, 'Courier New', Courier, monospace; font-size: 36px; font-weight: 900; letter-spacing: 10px; color: #f59e0b;">{otp_code}</span>
              </div>
              <p style="margin: 0 0 16px 0; font-size: 12px; color: #cbd5e1; line-height: 1.7;">
                ⏱️ <strong style="color: #e2e8f0;">Issued:</strong> {safe_issued}<br>
                ⏳ <strong style="color: #e2e8f0;">Expires:</strong> <strong style="color: #f59e0b;">{safe_expires}</strong> ({safe_remaining}). Single use only.<br>
                🛡️ Protect your account: Never share this security code with anyone.
              </p>
              <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #291a1d; font-size: 11px; color: #64748b; line-height: 1.5; font-family: 'SFMono-Regular', Consolas, 'Courier New', Courier, monospace;">
                SECURITY NOTICE: This verification was dispatched for {recipient_email}. If you did not initiate this request, contact your SOC administrator immediately.
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

        return cls.send_email(
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text
        )

    @classmethod
    def send_payment_otp_email(
        cls,
        recipient_email: str,
        otp_code: str,
        order_id: str,
        amount: float,
        item_summary: str,
        expires_in_minutes: int = 5,
        challenge_id: Optional[str] = None,
        issued_at: Optional[Union[datetime, str]] = None,
        expires_at: Optional[Union[datetime, str]] = None,
        recipient_timezone: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Transmits 6-digit payment authorization OTP code via SMTP for NYRAA / Aura Luxe Retail checkout.
        Uses a warm white, charcoal black, and orange retail e-commerce presentation.
        """
        subject = f"NYRAA — Payment Authorization Code for Order {order_id}"
        masked = cls.mask_email(recipient_email)
        logger.info(
            f"[COGNISEC-AI] [PAYMENT_OTP_DISPATCH] Dispatching payment verification code to {masked} "
            f"for order={order_id}, amount={amount}"
        )

        raw_summary = (item_summary or "Aura Luxe Retail Order").strip()
        qty_matches = re.findall(r"(?:^|,\s*)(\d+)\s*[x×]\s*", raw_summary, flags=re.IGNORECASE)
        total_qty = sum(int(q) for q in qty_matches) if qty_matches else 1
        product_display = re.sub(r"^\d+\s*[x×]\s*", "", raw_summary, count=1, flags=re.IGNORECASE).strip() or raw_summary

        issued_display, expires_display, remaining_label = compute_expiry_display(
            issued_at=issued_at,
            expires_at=expires_at,
            expires_in_minutes=expires_in_minutes,
            target_tz=recipient_timezone,
        )
        expiry_label = remaining_label
        clean_otp = str(otp_code).strip()
        amount_display = f"₹{float(amount):,.2f}"

        safe_product = html.escape(product_display)
        safe_order_id = html.escape(str(order_id or "").strip())
        safe_qty = html.escape(str(total_qty))
        safe_amount = html.escape(amount_display)
        safe_otp = html.escape(clean_otp)
        safe_expiry = html.escape(expiry_label)
        safe_issued = html.escape(issued_display)
        safe_expires = html.escape(expires_display)
        safe_masked = html.escape(masked)

        plain_text = (
            "NYRAA | RETAIL — AURA LUXE RETAIL\n"
            "COGNISEC-AI Zero-Trust Checkout\n\n"
            "Secure Your Purchase\n\n"
            "Your payment authorization code is ready. Verify this transaction to securely complete your purchase.\n\n"
            "--- ORDER SUMMARY ---\n"
            f"Product: {product_display}\n"
            f"Order Reference: {order_id}\n"
            f"Quantity: {total_qty}\n"
            f"Total Amount: {amount_display}\n"
            "Currency: INR\n\n"
            "PAYMENT AUTHORIZATION CODE:\n"
            f"{clean_otp}\n\n"
            f"Issued: {issued_display}\n"
            f"Expires: {expires_display} ({expiry_label})\n"
            "(Use this code solely to authorize this checkout transaction — not for account login, recovery, or other portals.)\n\n"
            "SECURITY INFORMATION:\n"
            "- This code authorizes the displayed payment transaction only.\n"
            "- Never share the code.\n"
            "- If the transaction was not initiated by the account owner, do not authorize it.\n"
            "- Contact customer support if the transaction is unfamiliar.\n\n"
            "NYRAA Retail\n"
            "Secured by COGNISEC-AI\n"
            "Automated notification; do not reply.\n"
        )

        html_text = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NYRAA — Payment Authorization Code</title>
  <style type="text/css">
    @media only screen and (max-width: 480px) {{
      .nyraa-outer {{ padding: 14px 8px !important; }}
      .nyraa-pad {{ padding-left: 16px !important; padding-right: 16px !important; }}
      .nyraa-otp {{ font-size: 26px !important; letter-spacing: 5px !important; padding: 12px 16px !important; }}
      .nyraa-h1 {{ font-size: 21px !important; }}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background-color:#f6f2eb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1c1917;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f6f2eb;margin:0;padding:0;width:100%;">
    <tr>
      <td class="nyraa-outer" align="center" style="padding:28px 12px;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:600px;width:100%;table-layout:fixed;background-color:#ffffff;border:1px solid #e7e0d6;border-radius:16px;overflow:hidden;">
          <!-- Top Warm Orange Bar -->
          <tr>
            <td style="height:4px;background-color:#ea580c;line-height:4px;font-size:4px;">&nbsp;</td>
          </tr>

          <!-- Header -->
          <tr>
            <td class="nyraa-pad" style="padding:22px 26px 18px 26px;background-color:#fffcf7;border-bottom:1px solid #ede6dc;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                <tr>
                  <td style="vertical-align:middle;">
                    <span style="font-size:20px;font-weight:800;letter-spacing:3px;color:#1c1917;text-transform:uppercase;">
                      NYRAA
                    </span>
                    <span style="display:inline-block;margin-left:8px;padding:3px 7px;background-color:#fff7ed;border:1px solid #fdba74;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:1.2px;color:#c2410c;text-transform:uppercase;vertical-align:middle;">
                      RETAIL
                    </span>
                    <div style="margin-top:4px;font-size:11px;font-weight:600;color:#78716c;letter-spacing:0.4px;">
                      Aura Luxe Retail
                    </div>
                  </td>
                  <td align="right" style="vertical-align:middle;">
                    <span style="display:inline-block;padding:5px 10px;background-color:#1c1917;border-radius:6px;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;color:#fdba74;">
                      COGNISEC-AI Zero-Trust Checkout
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main Heading & Supporting Text -->
          <tr>
            <td class="nyraa-pad" style="padding:26px 26px 16px 26px;">
              <h1 class="nyraa-h1" style="margin:0 0 10px 0;font-size:24px;line-height:1.3;font-weight:800;color:#1c1917;letter-spacing:-0.3px;">
                Secure Your Purchase
              </h1>
              <p style="margin:0;font-size:14px;line-height:1.6;color:#57534e;">
                Your payment authorization code is ready. Verify this transaction to securely complete your purchase.
              </p>
            </td>
          </tr>

          <!-- Order Summary Card -->
          <tr>
            <td class="nyraa-pad" style="padding:4px 26px 20px 26px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#faf7f2;border:1px solid #e7e0d6;border-radius:12px;overflow:hidden;">
                <tr>
                  <td colspan="2" style="padding:11px 16px;background-color:#f3ede3;border-bottom:1px solid #e7e0d6;font-size:11px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:#9a3412;">
                    Order Summary
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 16px;border-bottom:1px solid #ede6dc;color:#78716c;font-size:12px;font-weight:600;width:38%;vertical-align:top;">
                    Product
                  </td>
                  <td style="padding:10px 16px;border-bottom:1px solid #ede6dc;color:#1c1917;font-size:13px;font-weight:700;vertical-align:top;word-break:break-word;">
                    {safe_product}
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 16px;border-bottom:1px solid #ede6dc;color:#78716c;font-size:12px;font-weight:600;width:38%;vertical-align:top;">
                    Order Reference
                  </td>
                  <td style="padding:10px 16px;border-bottom:1px solid #ede6dc;color:#1c1917;font-size:13px;font-weight:600;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;vertical-align:top;word-break:break-all;">
                    {safe_order_id}
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 16px;border-bottom:1px solid #ede6dc;color:#78716c;font-size:12px;font-weight:600;width:38%;vertical-align:top;">
                    Quantity
                  </td>
                  <td style="padding:10px 16px;border-bottom:1px solid #ede6dc;color:#1c1917;font-size:13px;font-weight:600;vertical-align:top;">
                    {safe_qty}
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 16px;border-bottom:1px solid #ede6dc;color:#78716c;font-size:12px;font-weight:600;width:38%;vertical-align:top;">
                    Currency
                  </td>
                  <td style="padding:10px 16px;border-bottom:1px solid #ede6dc;color:#1c1917;font-size:13px;font-weight:600;vertical-align:top;">
                    INR
                  </td>
                </tr>
                <tr>
                  <td style="padding:12px 16px;color:#1c1917;font-size:13px;font-weight:700;width:38%;vertical-align:middle;">
                    Total Amount
                  </td>
                  <td style="padding:12px 16px;color:#ea580c;font-size:16px;font-weight:800;vertical-align:middle;">
                    {safe_amount}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- OTP Section -->
          <tr>
            <td class="nyraa-pad" style="padding:0 26px 22px 26px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#fff7ed;border:2px solid #ea580c;border-radius:12px;">
                <tr>
                  <td align="center" style="padding:20px 16px;">
                    <div style="font-size:11px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase;color:#c2410c;margin-bottom:12px;">
                      PAYMENT AUTHORIZATION CODE
                    </div>
                    <div class="nyraa-otp" style="display:inline-block;max-width:100%;box-sizing:border-box;padding:14px 24px;background-color:#1c1917;border-radius:10px;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:30px;line-height:1.2;font-weight:800;letter-spacing:7px;color:#ffffff;">
                      {safe_otp}
                    </div>
                    <div style="margin-top:12px;font-size:12px;line-height:1.6;color:#44403c;">
                      <strong>Issued:</strong> {safe_issued}<br />
                      <strong>Expires:</strong> <strong style="color:#c2410c;">{safe_expires}</strong> ({safe_expiry}) &bull; Valid for checkout authorization for {safe_masked}
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Security Information -->
          <tr>
            <td class="nyraa-pad" style="padding:0 26px 24px 26px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#faf7f2;border-left:3px solid #ea580c;border-radius:6px;">
                <tr>
                  <td style="padding:14px 16px;">
                    <div style="font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#9a3412;margin-bottom:8px;">
                      Checkout Security Notice
                    </div>
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#57534e;">
                          &bull;&nbsp; This code authorizes the displayed payment transaction only.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#57534e;">
                          &bull;&nbsp; Never share the code.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#57534e;">
                          &bull;&nbsp; If the transaction was not initiated by the account owner, do not authorize it.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#57534e;">
                          &bull;&nbsp; Contact customer support if the transaction is unfamiliar.
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td class="nyraa-pad" style="padding:18px 26px 22px 26px;background-color:#1c1917;text-align:center;">
              <div style="font-size:12px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#ffffff;">
                NYRAA Retail
              </div>
              <div style="margin-top:4px;font-size:11px;font-weight:600;color:#fdba74;">
                Secured by COGNISEC-AI
              </div>
              <div style="margin-top:6px;font-size:11px;color:#a8a29e;">
                Automated notification; do not reply.
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

        return cls.send_email(
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text,
            correlation_id=challenge_id,
        )

    @classmethod
    def send_exam_otp_email(
        cls,
        recipient_email: str,
        otp_code: str,
        course_name: Optional[str] = None,
        assessment_name: Optional[str] = None,
        expires_in_minutes: int = 5,
        challenge_id: Optional[str] = None,
        issued_at: Optional[Union[datetime, str]] = None,
        expires_at: Optional[Union[datetime, str]] = None,
        recipient_timezone: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Dispatches a BITS Pilani Academic Portal / COGNISEC-AI examination launch
        authorization OTP email with responsive inline-CSS HTML and plain-text fallback.
        """
        masked_email = cls.mask_email(recipient_email)
        raw_course = (course_name or "").strip()
        raw_assessment = (assessment_name or "").strip()

        course_display: Optional[str] = None
        if raw_assessment:
            exam_display = raw_assessment
            if raw_course and raw_course != raw_assessment:
                course_display = raw_course
        elif "•" in raw_course:
            parts = [p.strip() for p in raw_course.split("•", 1)]
            course_display = parts[0] or None
            exam_display = parts[1] or raw_course
        elif raw_course:
            exam_display = raw_course
        else:
            exam_display = "Proctored Online Examination"

        issued_display, expires_display, remaining_label = compute_expiry_display(
            issued_at=issued_at,
            expires_at=expires_at,
            expires_in_minutes=expires_in_minutes,
            target_tz=recipient_timezone,
        )
        expiry_label = remaining_label
        clean_otp = str(otp_code).strip()

        safe_exam = html.escape(exam_display)
        safe_course = html.escape(course_display) if course_display else ""
        safe_masked_email = html.escape(masked_email)
        safe_otp = html.escape(clean_otp)
        safe_expiry = html.escape(expiry_label)
        safe_issued = html.escape(issued_display)
        safe_expires = html.escape(expires_display)

        subject = "BITS Pilani Academic Portal — Examination Access Authorization Code"

        course_plain_line = f"Course / Subject: {course_display}\n" if course_display else ""
        plain_text = (
            "BITS PILANI ACADEMIC PORTAL | COGNISEC-AI ZERO-TRUST SECURITY\n"
            "EXAMINATION ACCESS AUTHORIZATION\n\n"
            "Verify Your Identity to Launch Your Examination\n\n"
            "A secure examination launch request has been initiated for your academic account. "
            "Enter the verification code below to authorize examination access.\n\n"
            "--- EXAMINATION DETAILS ---\n"
            f"Examination / Assessment: {exam_display}\n"
            f"{course_plain_line}"
            "Portal: BITS Pilani Academic Portal\n"
            "Verification Purpose: Examination Launch Authorization\n"
            f"Registered Email: {masked_email}\n\n"
            "YOUR EXAMINATION VERIFICATION CODE:\n"
            f"{otp_code}\n\n"
            f"Issued: {issued_display}\n"
            f"Expires: {expires_display} ({expiry_label})\n\n"
            "SECURITY INFORMATION:\n"
            "- Valid only for the current examination authorization request.\n"
            "- Never share this code with another person.\n"
            "- If you did not initiate this request, contact the appropriate administrator.\n\n"
            "BITS Pilani Academic Portal\n"
            "Secured by COGNISEC-AI Zero-Trust Authentication\n"
            "Automated security notification; do not reply.\n"
        )

        course_row_html = ""
        if course_display:
            course_row_html = f"""
                    <tr>
                      <td style="padding:10px 16px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.6px;width:42%;vertical-align:top;">
                        Course / Subject
                      </td>
                      <td style="padding:10px 16px;border-bottom:1px solid #1e293b;color:#e2e8f0;font-size:13px;font-weight:600;vertical-align:top;">
                        {safe_course}
                      </td>
                    </tr>"""

        html_text = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="color-scheme" content="dark" />
  <meta name="supported-color-schemes" content="dark" />
  <title>Examination Access Authorization</title>
  <style type="text/css">
    @media only screen and (max-width: 480px) {{
      .exam-outer {{ padding: 12px 8px !important; }}
      .exam-pad {{ padding-left: 14px !important; padding-right: 14px !important; }}
      .exam-otp {{ font-size: 24px !important; letter-spacing: 5px !important; padding: 10px 14px !important; }}
      .exam-h1 {{ font-size: 18px !important; }}
      .exam-badge {{ display: none !important; }}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background-color:#050914;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e2e8f0;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#050914;margin:0;padding:0;width:100%;">
    <tr>
      <td class="exam-outer" align="center" style="padding:24px 12px;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:600px;width:100%;table-layout:fixed;background-color:#0b1222;border:1px solid #1e3a5f;border-radius:14px;overflow:hidden;">
          <!-- Top Accent Bar -->
          <tr>
            <td style="height:4px;background-color:#2563eb;line-height:4px;font-size:4px;">&nbsp;</td>
          </tr>

          <!-- Header -->
          <tr>
            <td class="exam-pad" style="padding:20px 18px 18px 18px;background-color:#080f1d;border-bottom:1px solid #1e293b;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                <tr>
                  <td style="vertical-align:middle;">
                    <div style="font-size:12px;font-weight:700;letter-spacing:1.3px;text-transform:uppercase;color:#60a5fa;">
                      BITS Pilani Academic Portal
                    </div>
                    <div style="margin-top:4px;font-size:11px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:#94a3b8;">
                      COGNISEC-AI Zero-Trust Security
                    </div>
                  </td>
                  <td class="exam-badge" align="right" style="vertical-align:middle;white-space:nowrap;width:96px;">
                    <span style="display:inline-block;padding:4px 8px;background-color:#0f172a;border:1px solid #1d4ed8;border-radius:6px;font-size:9px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;color:#93c5fd;">
                      Exam Shield
                    </span>
                  </td>
                </tr>
                <tr>
                  <td colspan="2" style="padding-top:16px;">
                    <div style="display:inline-block;padding:5px 10px;background-color:#172554;border-left:3px solid #f59e0b;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:1.3px;text-transform:uppercase;color:#fbbf24;">
                      EXAMINATION ACCESS AUTHORIZATION
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main Content -->
          <tr>
            <td class="exam-pad" style="padding:22px 18px 14px 18px;">
              <h1 class="exam-h1" style="margin:0 0 12px 0;font-size:21px;line-height:1.35;font-weight:700;color:#f8fafc;">
                Verify Your Identity to Launch Your Examination
              </h1>
              <p style="margin:0;font-size:14px;line-height:1.6;color:#cbd5e1;">
                A secure examination launch request has been initiated for your academic account. Enter the verification code below to authorize examination access.
              </p>
            </td>
          </tr>

          <!-- Examination Details Card -->
          <tr>
            <td class="exam-pad" style="padding:6px 18px 18px 18px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#070d1a;border:1px solid #1e293b;border-radius:10px;overflow:hidden;">
                <tr>
                  <td colspan="2" style="padding:11px 14px;background-color:#0f172a;border-bottom:1px solid #1e293b;font-size:11px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:#60a5fa;">
                    Examination Authorization Details
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;width:40%;vertical-align:top;">
                    Examination / Assessment
                  </td>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#f8fafc;font-size:13px;font-weight:700;vertical-align:top;word-break:break-word;">
                    {safe_exam}
                  </td>
                </tr>{course_row_html}
                <tr>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;width:40%;vertical-align:top;">
                    Portal
                  </td>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#e2e8f0;font-size:13px;font-weight:600;vertical-align:top;">
                    BITS Pilani Academic Portal
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;width:40%;vertical-align:top;">
                    Verification Purpose
                  </td>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#e2e8f0;font-size:13px;font-weight:600;vertical-align:top;">
                    Examination Launch Authorization
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 14px;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;width:40%;vertical-align:top;">
                    Registered Email
                  </td>
                  <td style="padding:10px 14px;color:#93c5fd;font-size:13px;font-weight:600;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;vertical-align:top;word-break:break-all;">
                    {safe_masked_email}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- OTP Focal Section -->
          <tr>
            <td class="exam-pad" style="padding:0 18px 20px 18px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#050914;border:2px solid #f59e0b;border-radius:12px;">
                <tr>
                  <td align="center" style="padding:18px 12px;">
                    <div style="font-size:11px;font-weight:700;letter-spacing:1.3px;text-transform:uppercase;color:#fbbf24;margin-bottom:12px;">
                      YOUR EXAMINATION VERIFICATION CODE
                    </div>
                    <div class="exam-otp" style="display:inline-block;max-width:100%;box-sizing:border-box;padding:12px 18px;background-color:#0b1222;border:1px solid #334155;border-radius:8px;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:28px;line-height:1.2;font-weight:800;letter-spacing:6px;color:#ffffff;">
                      {safe_otp}
                    </div>
                    <div style="margin-top:14px;font-size:12px;line-height:1.6;color:#cbd5e1;">
                      <strong style="color:#e2e8f0;">Issued:</strong> {safe_issued}<br />
                      <strong style="color:#e2e8f0;">Expires:</strong> <strong style="color:#fbbf24;">{safe_expires}</strong> ({safe_expiry})
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Security Information -->
          <tr>
            <td class="exam-pad" style="padding:0 18px 22px 18px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#08101e;border-left:3px solid #3b82f6;border-radius:6px;">
                <tr>
                  <td style="padding:14px 16px;">
                    <div style="font-size:11px;font-weight:700;letter-spacing:1.1px;text-transform:uppercase;color:#60a5fa;margin-bottom:8px;">
                      Security Notice
                    </div>
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#94a3b8;">
                          &bull;&nbsp; Valid only for the current examination authorization request.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#94a3b8;">
                          &bull;&nbsp; Never share this code with another person.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#94a3b8;">
                          &bull;&nbsp; If you did not initiate this request, contact the appropriate administrator.
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td class="exam-pad" style="padding:18px 18px 20px 18px;background-color:#070c17;border-top:1px solid #1e293b;text-align:center;">
              <div style="font-size:12px;font-weight:700;color:#e2e8f0;letter-spacing:0.3px;">
                BITS Pilani Academic Portal
              </div>
              <div style="margin-top:4px;font-size:11px;font-weight:600;color:#60a5fa;">
                Secured by COGNISEC-AI Zero-Trust Authentication
              </div>
              <div style="margin-top:6px;font-size:11px;color:#64748b;">
                Automated security notification; do not reply.
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

        return cls.send_email(
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text,
            correlation_id=challenge_id,
        )

    @classmethod
    def send_recovery_otp_email(
        cls,
        recipient_email: str,
        otp_code: str,
        portal: str,
        security_reference_id: str,
        request_timestamp: Optional[Union[datetime, str]] = None,
        expires_in_minutes: int = 5,
        challenge_id: Optional[str] = None,
        issued_at: Optional[Union[datetime, str]] = None,
        expires_at: Optional[Union[datetime, str]] = None,
        recipient_timezone: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Dispatches a reusable, portal-branded suspended-portal recovery OTP email
        across College (BITS Pilani Academic Portal), Shopping (Aura Luxe Retail),
        and Healthcare (Apollo MedVigil EHR).
        """
        portal_key = (portal or "").strip().lower()
        portal_display_map = {
            "college": "BITS Pilani Academic Portal",
            "shopping": "Aura Luxe Retail",
            "ecommerce": "Aura Luxe Retail",
            "healthcare": "Apollo MedVigil EHR",
        }
        portal_display = portal_display_map.get(portal_key) or (portal or "Protected Portal").strip()

        masked_email = cls.mask_email(recipient_email)
        clean_ref = (security_reference_id or "N/A").strip()
        issued_display, expires_display, remaining_label = compute_expiry_display(
            issued_at=issued_at or request_timestamp,
            expires_at=expires_at,
            expires_in_minutes=expires_in_minutes,
            target_tz=recipient_timezone,
        )
        ts_display = format_email_timestamp(
            request_timestamp if request_timestamp is not None else (issued_at or datetime.now(timezone.utc)),
            target_tz=recipient_timezone,
        )
        expiry_label = remaining_label
        clean_otp = str(otp_code).strip()

        safe_portal = html.escape(portal_display)
        safe_ref = html.escape(clean_ref)
        safe_ts = html.escape(ts_display)
        safe_masked_email = html.escape(masked_email)
        safe_otp = html.escape(clean_otp)
        safe_expiry = html.escape(expiry_label)
        safe_issued = html.escape(issued_display)
        safe_expires = html.escape(expires_display)

        subject = f"COGNISEC-AI — Portal Access Recovery Verification Code ({portal_display})"

        plain_text = (
            "COGNISEC-AI | ZERO-TRUST SECURITY RECOVERY\n"
            "PORTAL ACCESS RECOVERY\n\n"
            "Verify Your Identity to Continue Portal Recovery\n\n"
            "A security restriction has been placed on your portal following unsuccessful identity verification attempts. "
            "Complete the registered-email verification step to continue the authorized recovery process.\n\n"
            "--- PORTAL IDENTIFICATION ---\n"
            f"Portal Name: {portal_display}\n"
            "Recovery Purpose: Suspended Portal Identity Verification\n"
            f"Security Reference ID: {clean_ref}\n"
            f"Recovery request: {ts_display}\n"
            f"Registered Email: {masked_email}\n\n"
            "YOUR PORTAL RECOVERY CODE:\n"
            f"{clean_otp}\n\n"
            f"Issued: {issued_display}\n"
            f"Expires: {expires_display} ({expiry_label})\n\n"
            "IMPORTANT RECOVERY NOTICE:\n"
            "Email verification does not automatically restore suspended portal access.\n"
            "After successful OTP verification, your recovery request will remain pending until the required "
            "authorized Security Administrator/SOC clearance is completed.\n\n"
            "SECURITY NOTICE:\n"
            "- This code is valid only for the current recovery request.\n"
            "- Never share this code with anyone.\n"
            "- If you did not request recovery, contact your security administrator.\n"
            "- The suspended portal remains protected until authorized clearance.\n\n"
            "COGNISEC-AI Zero-Trust Security\n"
            "Automated security notification.\n"
            "Do not reply to this email.\n"
        )

        html_text = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="color-scheme" content="dark" />
  <meta name="supported-color-schemes" content="dark" />
  <title>Portal Access Recovery</title>
  <style type="text/css">
    @media only screen and (max-width: 480px) {{
      .recov-outer {{ padding: 12px 8px !important; }}
      .recov-pad {{ padding-left: 14px !important; padding-right: 14px !important; }}
      .recov-otp {{ font-size: 24px !important; letter-spacing: 5px !important; padding: 10px 14px !important; }}
      .recov-h1 {{ font-size: 18px !important; }}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background-color:#050914;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e2e8f0;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#050914;margin:0;padding:0;width:100%;">
    <tr>
      <td class="recov-outer" align="center" style="padding:24px 12px;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:600px;width:100%;table-layout:fixed;background-color:#0b1222;border:1px solid #7c2d12;border-radius:14px;overflow:hidden;">
          <!-- Top Security Accent Bar -->
          <tr>
            <td style="height:4px;background-color:#dc2626;line-height:4px;font-size:4px;">&nbsp;</td>
          </tr>

          <!-- Header -->
          <tr>
            <td class="recov-pad" style="padding:20px 18px 18px 18px;background-color:#080f1d;border-bottom:1px solid #1e293b;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                <tr>
                  <td style="vertical-align:middle;">
                    <div style="font-size:13px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase;color:#f8fafc;">
                      COGNISEC-AI
                    </div>
                    <div style="margin-top:4px;font-size:11px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:#fb923c;">
                      ZERO-TRUST SECURITY RECOVERY
                    </div>
                  </td>
                  <td align="right" style="vertical-align:middle;white-space:nowrap;width:110px;">
                    <span style="display:inline-block;padding:4px 8px;background-color:#1f1014;border:1px solid #dc2626;border-radius:6px;font-size:9px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;color:#fca5a5;">
                      Restricted
                    </span>
                  </td>
                </tr>
                <tr>
                  <td colspan="2" style="padding-top:16px;">
                    <div style="display:inline-block;padding:5px 10px;background-color:#1c1117;border-left:3px solid #ef4444;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;color:#fca5a5;">
                      PORTAL ACCESS RECOVERY
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main Heading & Supporting Copy -->
          <tr>
            <td class="recov-pad" style="padding:22px 18px 14px 18px;">
              <h1 class="recov-h1" style="margin:0 0 12px 0;font-size:21px;line-height:1.35;font-weight:700;color:#f8fafc;">
                Verify Your Identity to Continue Portal Recovery
              </h1>
              <p style="margin:0;font-size:14px;line-height:1.6;color:#cbd5e1;">
                A security restriction has been placed on your portal following unsuccessful identity verification attempts. Complete the registered-email verification step to continue the authorized recovery process.
              </p>
            </td>
          </tr>

          <!-- Portal Identification Card -->
          <tr>
            <td class="recov-pad" style="padding:6px 18px 18px 18px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#070d1a;border:1px solid #334155;border-radius:10px;overflow:hidden;">
                <tr>
                  <td colspan="2" style="padding:11px 14px;background-color:#0f172a;border-bottom:1px solid #1e293b;font-size:11px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:#fb923c;">
                    Portal Identification
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;width:40%;vertical-align:top;">
                    Portal Name
                  </td>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#f8fafc;font-size:13px;font-weight:700;vertical-align:top;word-break:break-word;">
                    {safe_portal}
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;width:40%;vertical-align:top;">
                    Recovery Purpose
                  </td>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#e2e8f0;font-size:13px;font-weight:600;vertical-align:top;">
                    Suspended Portal Identity Verification
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;width:40%;vertical-align:top;">
                    Security Reference ID
                  </td>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#fbbf24;font-size:12px;font-weight:700;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;vertical-align:top;word-break:break-all;">
                    {safe_ref}
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;width:40%;vertical-align:top;">
                    Recovery Request
                  </td>
                  <td style="padding:10px 14px;border-bottom:1px solid #1e293b;color:#cbd5e1;font-size:12px;font-weight:600;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;vertical-align:top;word-break:break-word;">
                    {safe_ts}
                  </td>
                </tr>
                <tr>
                  <td style="padding:10px 14px;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;width:40%;vertical-align:top;">
                    Registered Email
                  </td>
                  <td style="padding:10px 14px;color:#fdba74;font-size:13px;font-weight:600;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;vertical-align:top;word-break:break-all;">
                    {safe_masked_email}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- OTP Focal Section -->
          <tr>
            <td class="recov-pad" style="padding:0 18px 20px 18px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#050914;border:2px solid #f59e0b;border-radius:12px;">
                <tr>
                  <td align="center" style="padding:18px 12px;">
                    <div style="font-size:11px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;color:#fb923c;margin-bottom:12px;">
                      YOUR PORTAL RECOVERY CODE
                    </div>
                    <div class="recov-otp" style="display:inline-block;max-width:100%;box-sizing:border-box;padding:12px 18px;background-color:#0b1222;border:1px solid #dc2626;border-radius:8px;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:28px;line-height:1.2;font-weight:800;letter-spacing:6px;color:#ffffff;">
                      {safe_otp}
                    </div>
                    <div style="margin-top:12px;font-size:12px;line-height:1.6;color:#cbd5e1;">
                      <strong style="color:#e2e8f0;">Issued:</strong> {safe_issued}<br />
                      <strong style="color:#e2e8f0;">Expires:</strong> <strong style="color:#fbbf24;">{safe_expires}</strong> ({safe_expiry})
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Important Recovery Notice -->
          <tr>
            <td class="recov-pad" style="padding:0 18px 16px 18px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#1a0e13;border:1px solid #b91c1c;border-left:4px solid #ef4444;border-radius:8px;">
                <tr>
                  <td style="padding:14px 16px;">
                    <div style="font-size:11px;font-weight:800;letter-spacing:1.1px;text-transform:uppercase;color:#fca5a5;margin-bottom:6px;">
                      Important Recovery Notice
                    </div>
                    <div style="font-size:13px;line-height:1.5;font-weight:700;color:#fecaca;margin-bottom:6px;">
                      Email verification does not automatically restore suspended portal access.
                    </div>
                    <div style="font-size:12px;line-height:1.55;color:#e2e8f0;">
                      After successful OTP verification, your recovery request will remain pending until the required authorized Security Administrator/SOC clearance is completed.
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Security Notice -->
          <tr>
            <td class="recov-pad" style="padding:0 18px 22px 18px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#08101e;border-left:3px solid #f59e0b;border-radius:6px;">
                <tr>
                  <td style="padding:14px 16px;">
                    <div style="font-size:11px;font-weight:700;letter-spacing:1.1px;text-transform:uppercase;color:#fbbf24;margin-bottom:8px;">
                      Security Notice
                    </div>
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#94a3b8;">
                          &bull;&nbsp; This code is valid only for the current recovery request.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#94a3b8;">
                          &bull;&nbsp; Never share this code with anyone.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#94a3b8;">
                          &bull;&nbsp; If you did not request recovery, contact your security administrator.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#94a3b8;">
                          &bull;&nbsp; The suspended portal remains protected until authorized clearance.
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td class="recov-pad" style="padding:18px 18px 20px 18px;background-color:#070c17;border-top:1px solid #1e293b;text-align:center;">
              <div style="font-size:12px;font-weight:700;color:#e2e8f0;letter-spacing:0.3px;">
                COGNISEC-AI Zero-Trust Security
              </div>
              <div style="margin-top:6px;font-size:11px;color:#94a3b8;">
                Automated security notification.
              </div>
              <div style="margin-top:4px;font-size:11px;color:#64748b;">
                Do not reply to this email.
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

        return cls.send_email(
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text,
            correlation_id=challenge_id,
        )

    @classmethod
    def send_appointment_otp_email(
        cls,
        recipient_email: str,
        otp_code: str,
        patient_name: str,
        doctor_name: str,
        appointment_date: str,
        time_slot: str,
        department: str,
        expires_in_minutes: int = 5,
        challenge_id: Optional[str] = None,
        appointment_reference: Optional[str] = None,
        consultation_mode: Optional[str] = None,
        issued_at: Optional[Union[datetime, str]] = None,
        expires_at: Optional[Union[datetime, str]] = None,
        recipient_timezone: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Transmits 6-digit appointment confirmation OTP code via SMTP for AyuSync MedCare.
        Uses a clean white, light grey, teal, and emerald green clinical healthcare presentation.
        """
        subject = "AYUSYNC MEDCARE — Appointment Identity Verification Code"
        masked = cls.mask_email(recipient_email)
        logger.info(
            f"[COGNISEC-AI] [APPOINTMENT_OTP_DISPATCH] Dispatching appointment verification code to {masked} "
            f"for doctor={doctor_name}, date={appointment_date}, slot={time_slot}"
        )

        issued_display, expires_display, remaining_label = compute_expiry_display(
            issued_at=issued_at,
            expires_at=expires_at,
            expires_in_minutes=expires_in_minutes,
            target_tz=recipient_timezone,
        )
        appointment_display = format_appointment_datetime(
            appointment_date=appointment_date,
            time_slot=time_slot,
            target_tz=recipient_timezone,
        )
        expiry_label = remaining_label
        clean_otp = str(otp_code).strip()
        dept_display = (department or "General Medicine").strip().title()
        ref_display = (appointment_reference or "").strip()
        mode_display = (consultation_mode or "").strip()

        safe_patient = html.escape(str(patient_name or "").strip() or "Patient")
        safe_doctor = html.escape(str(doctor_name or "").strip())
        safe_dept = html.escape(dept_display)
        safe_date = html.escape(str(appointment_date or "").strip())
        safe_slot = html.escape(str(time_slot or "").strip())
        safe_apt_display = html.escape(appointment_display)
        safe_ref = html.escape(ref_display)
        safe_mode = html.escape(mode_display)
        safe_otp = html.escape(clean_otp)
        safe_expiry = html.escape(expiry_label)
        safe_issued = html.escape(issued_display)
        safe_expires = html.escape(expires_display)
        safe_masked = html.escape(masked)

        optional_plain = ""
        if ref_display:
            optional_plain += f"Appointment Reference: {ref_display}\n"
        if mode_display:
            optional_plain += f"Consultation Mode: {mode_display}\n"

        plain_text = (
            "AYUSYNC MEDCARE | HOSPITALS\n"
            "Tertiary Multispecialty & Academic Medical Center\n"
            "COGNISEC-AI Zero-Trust Healthcare\n\n"
            "Appointment Identity Verification\n\n"
            "Your clinical appointment requires identity verification. Please use the secure verification code below to confirm your appointment.\n\n"
            "--- APPOINTMENT DETAILS ---\n"
            f"Patient Name: {patient_name}\n"
            f"Consultant / Doctor: {doctor_name}\n"
            f"Department / Specialty: {dept_display}\n"
            f"Appointment: {appointment_display}\n"
            f"Appointment Date: {appointment_date}\n"
            f"Appointment Time: {time_slot}\n"
            f"{optional_plain}\n"
            "YOUR SECURE APPOINTMENT VERIFICATION CODE:\n"
            f"    >>  {clean_otp}  <<\n\n"
            f"Issued: {issued_display}\n"
            f"Expires: {expires_display} ({expiry_label})\n"
            f"Enter this 6-digit code in the AyuSync MedCare Healthcare portal verification prompt for {masked}.\n\n"
            "SECURITY NOTICE:\n"
            "- This code is for the displayed appointment verification only.\n"
            "- Never share your verification code.\n"
            "- If you did not request this verification, contact the hospital.\n"
            "- Verification does not replace clinical appointment confirmation.\n\n"
            "AYUSYNC MEDCARE\n"
            "COGNISEC-AI Zero-Trust Healthcare Security\n"
            "Automated notification — please do not reply.\n"
        )

        optional_rows_html = ""
        if ref_display:
            optional_rows_html += f"""
                <tr>
                  <td class="ayu-detail-label" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;font-weight:600;width:40%;vertical-align:top;">
                    Appointment Reference
                  </td>
                  <td class="ayu-detail-val" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#0f172a;font-size:13px;font-weight:700;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;vertical-align:top;word-break:break-all;">
                    {safe_ref}
                  </td>
                </tr>"""
        if mode_display:
            optional_rows_html += f"""
                <tr>
                  <td class="ayu-detail-label" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;font-weight:600;width:40%;vertical-align:top;">
                    Consultation Mode
                  </td>
                  <td class="ayu-detail-val" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#0f766e;font-size:13px;font-weight:700;vertical-align:top;">
                    {safe_mode}
                  </td>
                </tr>"""

        html_text = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AYUSYNC MEDCARE — Appointment Identity Verification</title>
  <style>
    @media only screen and (max-width: 600px) {{
      .ayu-container {{ width: 100% !important; border-radius: 10px !important; }}
      .ayu-pad {{ padding-left: 16px !important; padding-right: 16px !important; }}
      .ayu-otp {{ font-size: 24px !important; letter-spacing: 5px !important; padding: 12px 16px !important; }}
      .ayu-header-stack {{ display: block !important; width: 100% !important; text-align: left !important; padding-top: 8px !important; }}
      .ayu-detail-label, .ayu-detail-val {{ display: block !important; width: 100% !important; box-sizing: border-box !important; }}
      .ayu-detail-label {{ padding-bottom: 2px !important; }}
      .ayu-detail-val {{ padding-top: 2px !important; border-top: none !important; }}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a;-webkit-font-smoothing:antialiased;">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f1f5f9;margin:0;padding:0;">
    <tr>
      <td align="center" style="padding:24px 12px;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" class="ayu-container" style="max-width:600px;width:100%;background-color:#ffffff;border:1px solid #cbd5e1;border-radius:14px;overflow:hidden;">

          <!-- Header -->
          <tr>
            <td class="ayu-pad" style="padding:22px 28px 18px 28px;background-color:#ffffff;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                <tr>
                  <td class="ayu-header-stack" style="vertical-align:middle;">
                    <span style="font-size:20px;font-weight:800;letter-spacing:1.2px;color:#0f172a;text-transform:uppercase;">AYUSYNC MEDCARE</span>
                    <span style="display:inline-block;margin-left:8px;padding:3px 9px;background-color:#0d9488;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:1px;color:#ffffff;text-transform:uppercase;vertical-align:middle;">HOSPITALS</span>
                    <div style="margin-top:4px;font-size:12px;color:#475569;font-weight:500;">
                      Tertiary Multispecialty &amp; Academic Medical Center
                    </div>
                  </td>
                  <td class="ayu-header-stack" align="right" style="vertical-align:middle;">
                    <span style="display:inline-block;padding:5px 10px;background-color:#ecfdf5;border:1px solid #a7f3d0;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:0.6px;color:#047857;text-transform:uppercase;">
                      COGNISEC-AI SECURE VERIFICATION
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Teal Divider -->
          <tr>
            <td style="height:3px;background-color:#0d9488;font-size:0;line-height:0;">&nbsp;</td>
          </tr>

          <!-- Main Heading & Intro -->
          <tr>
            <td class="ayu-pad" style="padding:24px 28px 16px 28px;">
              <div style="font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#0d9488;margin-bottom:6px;">
                COGNISEC-AI Zero-Trust Healthcare
              </div>
              <h1 style="margin:0 0 10px 0;font-size:22px;line-height:1.3;font-weight:800;color:#0f172a;letter-spacing:-0.3px;">
                Appointment Identity Verification
              </h1>
              <p style="margin:0;font-size:14px;line-height:1.6;color:#475569;">
                Your clinical appointment requires identity verification. Please use the secure verification code below to confirm your appointment.
              </p>
            </td>
          </tr>

          <!-- Appointment Details Card -->
          <tr>
            <td class="ayu-pad" style="padding:0 28px 20px 28px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
                <tr>
                  <td colspan="2" style="padding:12px 16px;background-color:#f0fdfa;border-bottom:1px solid #ccfbf1;font-size:11px;font-weight:800;letter-spacing:1.1px;text-transform:uppercase;color:#0f766e;">
                    Appointment Details
                  </td>
                </tr>
                <tr>
                  <td class="ayu-detail-label" style="padding:10px 16px;color:#64748b;font-size:12px;font-weight:600;width:40%;vertical-align:top;">
                    Patient Name
                  </td>
                  <td class="ayu-detail-val" style="padding:10px 16px;color:#0f172a;font-size:13px;font-weight:700;vertical-align:top;">
                    {safe_patient}
                  </td>
                </tr>
                <tr>
                  <td class="ayu-detail-label" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;font-weight:600;width:40%;vertical-align:top;">
                    Consultant / Doctor
                  </td>
                  <td class="ayu-detail-val" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#0f172a;font-size:13px;font-weight:700;vertical-align:top;">
                    {safe_doctor}
                  </td>
                </tr>
                <tr>
                  <td class="ayu-detail-label" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;font-weight:600;width:40%;vertical-align:top;">
                    Department / Specialty
                  </td>
                  <td class="ayu-detail-val" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#0f172a;font-size:13px;font-weight:600;vertical-align:top;">
                    {safe_dept}
                  </td>
                </tr>
                <tr>
                  <td class="ayu-detail-label" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;font-weight:600;width:40%;vertical-align:top;">
                    Appointment
                  </td>
                  <td class="ayu-detail-val" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#0f766e;font-size:13px;font-weight:700;vertical-align:top;">
                    {safe_apt_display}
                  </td>
                </tr>
                <tr>
                  <td class="ayu-detail-label" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;font-weight:600;width:40%;vertical-align:top;">
                    Appointment Date
                  </td>
                  <td class="ayu-detail-val" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#0f172a;font-size:13px;font-weight:600;vertical-align:top;">
                    {safe_date}
                  </td>
                </tr>
                <tr>
                  <td class="ayu-detail-label" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;font-weight:600;width:40%;vertical-align:top;">
                    Appointment Time
                  </td>
                  <td class="ayu-detail-val" style="padding:10px 16px;border-top:1px solid #e2e8f0;color:#0f172a;font-size:13px;font-weight:600;vertical-align:top;">
                    {safe_slot}
                  </td>
                </tr>{optional_rows_html}
              </table>
            </td>
          </tr>

          <!-- OTP Section -->
          <tr>
            <td class="ayu-pad" style="padding:0 28px 20px 28px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f0fdfa;border:2px solid #0d9488;border-radius:12px;">
                <tr>
                  <td align="center" style="padding:22px 16px;">
                    <div style="font-size:11px;font-weight:800;letter-spacing:1.4px;text-transform:uppercase;color:#0f766e;margin-bottom:12px;">
                      YOUR SECURE APPOINTMENT VERIFICATION CODE
                    </div>
                    <div class="ayu-otp" style="display:inline-block;max-width:100%;box-sizing:border-box;padding:14px 26px;background-color:#0f766e;border:1px solid #059669;border-radius:10px;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:32px;line-height:1.2;font-weight:800;letter-spacing:8px;color:#ffffff;">
                      {safe_otp}
                    </div>
                    <div style="margin-top:12px;font-size:12px;line-height:1.6;color:#065f46;font-weight:600;">
                      Issued: <strong style="color:#0f172a;">{safe_issued}</strong><br />
                      Expires: <strong style="color:#047857;">{safe_expires}</strong> ({safe_expiry}) &bull; Single-use verification
                    </div>
                    <div style="margin-top:6px;font-size:12px;line-height:1.5;color:#334155;">
                      Enter this 6-digit code in the AyuSync MedCare Healthcare portal verification prompt for <strong>{safe_masked}</strong>.
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Security Notice -->
          <tr>
            <td class="ayu-pad" style="padding:0 28px 24px 28px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f8fafc;border-left:3px solid #059669;border-radius:6px;">
                <tr>
                  <td style="padding:14px 16px;">
                    <div style="font-size:11px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:#047857;margin-bottom:8px;">
                      Clinical Security Notice
                    </div>
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#475569;">
                          &bull;&nbsp; This code is for the displayed appointment verification only.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#475569;">
                          &bull;&nbsp; Never share your verification code.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#475569;">
                          &bull;&nbsp; If you did not request this verification, contact the hospital.
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:3px 0;font-size:12px;line-height:1.55;color:#475569;">
                          &bull;&nbsp; Verification does not replace clinical appointment confirmation.
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td class="ayu-pad" style="padding:18px 28px 22px 28px;background-color:#f8fafc;border-top:1px solid #e2e8f0;text-align:center;">
              <div style="font-size:12px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:#0f172a;">
                AYUSYNC MEDCARE
              </div>
              <div style="margin-top:4px;font-size:11px;font-weight:600;color:#0d9488;">
                COGNISEC-AI Zero-Trust Healthcare Security
              </div>
              <div style="margin-top:6px;font-size:11px;color:#64748b;">
                Automated notification &mdash; please do not reply.
              </div>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

        return cls.send_email(
            recipient_email=recipient_email,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text,
            correlation_id=challenge_id,
        )

    @classmethod
    def send_password_reset_email(
        cls,
        recipient_email: str,
        otp_code: str,
        expires_in_minutes: int = 5,
        issued_at: Optional[Union[datetime, str]] = None,
        expires_at: Optional[Union[datetime, str]] = None,
        recipient_timezone: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Transmits 6-digit password recovery code via configured SMTP server.
        Restores dark cybersecurity visual theme with red accents and amber digits.
        """
        subject = "CogniSec AI - Password Reset Code"
        masked = cls.mask_email(recipient_email)
        logger.info(f"[COGNISEC-AI] [PASSWORD_RESET_DISPATCH] Initiating recovery code dispatch to {masked}")

        issued_display, expires_display, remaining_label = compute_expiry_display(
            issued_at=issued_at,
            expires_at=expires_at,
            expires_in_minutes=expires_in_minutes,
            target_tz=recipient_timezone,
        )
        safe_issued = html.escape(issued_display)
        safe_expires = html.escape(expires_display)
        safe_remaining = html.escape(remaining_label)

        plain_text = (
            f"CogniSec AI Password Reset\n\n"
            f"Your one-time password recovery code is:\n"
            f"    >>  {otp_code}  <<\n\n"
            f"Please enter this code in your portal to set a new password.\n"
            f"Issued: {issued_display}\n"
            f"Expires: {expires_display} ({remaining_label})\n\n"
            f"Account: {recipient_email}\n\n"
            f"If you did not request a password reset, please review your active sessions immediately.\n"
        )

        html_text = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 24px 0; background-color: #080808; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #ffffff;">
  <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background-color: #080808; margin: 0; padding: 20px 0;">
    <tr>
      <td align="center">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width: 520px; background-color: #121013; border: 1px solid #dc2626; border-radius: 12px; overflow: hidden; box-shadow: 0 0 40px rgba(220, 38, 38, 0.15);">
          <tr>
            <td style="background-color: #0a060a; padding: 20px 28px; border-bottom: 1px solid #7f1d1d; text-align: left;">
              <span style="font-size: 20px; vertical-align: middle; margin-right: 8px;">🔒</span>
              <span style="font-family: 'SFMono-Regular', Consolas, 'Courier New', Courier, monospace; font-size: 14px; font-weight: 800; color: #ef4444; letter-spacing: 2px; text-transform: uppercase; vertical-align: middle;">COGNISEC-AI</span>
              <span style="font-family: 'SFMono-Regular', Consolas, 'Courier New', Courier, monospace; font-size: 11px; color: #94a3b8; letter-spacing: 1px; text-transform: uppercase; margin-left: 8px; vertical-align: middle;">// ACCOUNT SECURITY</span>
            </td>
          </tr>
          <tr>
            <td style="padding: 28px;">
              <h2 style="margin: 0 0 10px 0; font-size: 20px; font-weight: 800; color: #ffffff; letter-spacing: -0.3px;">Password Recovery Code</h2>
              <p style="margin: 0 0 20px 0; font-size: 13px; line-height: 1.6; color: #94a3b8;">
                A password reset authorization was requested for your account. Please enter the recovery code below to establish a new password.
              </p>
              <div style="background-color: #050406; border: 2px solid #b91c1c; border-radius: 10px; padding: 22px 16px; text-align: center; margin: 22px 0;">
                <span style="display: block; font-family: 'SFMono-Regular', Consolas, 'Courier New', Courier, monospace; font-size: 11px; font-weight: 700; color: #f87171; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 8px;">PASSWORD RECOVERY CODE</span>
                <span style="display: block; font-family: 'SFMono-Regular', Consolas, 'Courier New', Courier, monospace; font-size: 36px; font-weight: 900; letter-spacing: 10px; color: #f59e0b;">{otp_code}</span>
              </div>
              <p style="margin: 0 0 16px 0; font-size: 12px; color: #cbd5e1; line-height: 1.7;">
                ⏱️ <strong style="color: #e2e8f0;">Issued:</strong> {safe_issued}<br>
                ⏳ <strong style="color: #e2e8f0;">Expires:</strong> <strong style="color: #f59e0b;">{safe_expires}</strong> ({safe_remaining}). Single use only.<br>
                🛡️ Never provide this code to anyone, including support staff.
              </p>
              <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #291a1d; font-size: 11px; color: #64748b; line-height: 1.5; font-family: 'SFMono-Regular', Consolas, 'Courier New', Courier, monospace;">
                SECURITY NOTICE: If you did not request this password recovery, someone may be attempting to access your account. Secure your credentials immediately.
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

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
        timestamp_str: Union[datetime, str],
        device_nickname: Optional[str] = None,
        is_recognized: bool = False,
        review_url: Optional[str] = None,
        recipient_timezone: Optional[str] = None,
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
        display_ts = format_email_timestamp(timestamp_str, target_tz=recipient_timezone)
        safe_ts = html.escape(display_ts)

        plain_text = (
            f"COGNISEC-AI Security Alert: New Sign-In Detected\n\n"
            f"Hello {user_name},\n\n"
            f"A sign-in was detected for your account with the following security attributes:\n"
            f"- Event Time: {display_ts}\n"
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
                <div style="color: #cbd5e1;"><strong style="color: #f87171;">Event Time:</strong> {safe_ts}</div>
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

    @classmethod
    def send_password_changed_notification(
        cls,
        recipient_email: str,
        user_name: str,
        application: str,
        timestamp_str: Union[datetime, str],
        ip_address: str = "unknown",
        recipient_timezone: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Dispatches a security confirmation email after a cognitive-verified password change.
        Never includes passwords, cognitive answers, or secret tokens.
        """
        import html as _html
        resolved_recipient = cls.resolve_delivery_recipient(recipient_email)
        masked = cls.mask_email(resolved_recipient)
        portal_label = (application or "platform").strip().capitalize()
        display_ts = format_email_timestamp(timestamp_str, target_tz=recipient_timezone)
        safe_name = _html.escape(user_name or "User")
        safe_portal = _html.escape(portal_label)
        safe_ts = _html.escape(display_ts)
        safe_ip = _html.escape(ip_address or "unknown")
        subject = f"[{settings.PROJECT_NAME}] Password Successfully Changed"
        logger.info(f"[COGNISEC-AI] [PASSWORD_CHANGE_NOTIFY] Dispatching confirmation notice to {masked} portal={portal_label}")

        plain_text = (
            f"COGNISEC-AI Security Confirmation\n\n"
            f"Hello {user_name or 'User'},\n\n"
            f"Your COGNISEC-AI account password was successfully changed after multi-factor cognitive verification.\n"
            f"- Portal: {portal_label}\n"
            f"- Timestamp: {display_ts}\n"
            f"- Request Origin IP: {ip_address or 'unknown'}\n\n"
            f"All previous active sessions and application grants have been invalidated for your security.\n"
            f"If you did NOT authorize this password change, contact your security administrator immediately.\n"
        )

        html_text = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #06040a; color: #ffffff; padding: 32px; border-radius: 16px; border: 1px solid #166534; max-width: 540px; margin: 0 auto;">
            <div style="border-bottom: 1px solid #14532d; padding-bottom: 16px; margin-bottom: 20px;">
                <span style="font-size: 11px; font-family: monospace; letter-spacing: 2px; color: #4ade80; font-weight: bold; text-transform: uppercase;">COGNISEC-AI // ACCOUNT SECURITY</span>
                <h2 style="color: #ffffff; font-size: 20px; margin: 8px 0 0 0; font-weight: 800;">🔑 Password Changed</h2>
            </div>
            <p style="color: #cbd5e1; font-size: 13px; line-height: 1.6; margin: 0 0 16px 0;">
                Hello <strong style="color: #ffffff;">{safe_name}</strong>, your COGNISEC-AI account password was updated after completing two-part cognitive verification.
            </p>
            <div style="background-color: #0b0713; border: 1px solid #166534; padding: 16px; border-radius: 12px; margin: 18px 0; font-size: 12px; font-family: monospace; line-height: 1.8;">
                <div style="color: #cbd5e1;"><strong style="color: #4ade80;">Portal:</strong> {safe_portal}</div>
                <div style="color: #cbd5e1;"><strong style="color: #4ade80;">Event Time:</strong> {safe_ts}</div>
                <div style="color: #cbd5e1;"><strong style="color: #4ade80;">Client IP:</strong> {safe_ip}</div>
            </div>
            <p style="color: #94a3b8; font-size: 12px; line-height: 1.6; margin: 0;">
                For Zero Trust hygiene, all prior active sessions and portal grants were invalidated. If you did not authorize this change, contact security immediately.
            </p>
        </div>
        """

        return cls.send_email(
            recipient_email=resolved_recipient,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text
        )

    @classmethod
    def send_portal_security_notification(
        cls,
        recipient_email: str,
        user_name: str,
        portal: str,
        event_type: str,
        lock_reason: str,
        security_reference_id: str,
        timestamp_str: Union[datetime, str],
        device_summary: str = "Unknown Device Context",
        is_admin_notice: bool = False,
        target_account_email: Optional[str] = None,
        recipient_timezone: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Dispatches a sanitized portal security alert email (lockout, re-entry attempt,
        recovery request, or clearance) to the registered account owner or SOC Administrator.
        Never exposes passwords, OTP codes, cognitive answers, tokens, or internal risk scores.
        """
        import html as _html
        resolved_recipient = cls.resolve_delivery_recipient(recipient_email)
        portal_label = (portal or "platform").strip().capitalize()
        audience = "SOC ADMINISTRATOR ALERT" if is_admin_notice else "PORTAL SECURITY NOTICE"
        display_ts = format_email_timestamp(timestamp_str, target_tz=recipient_timezone)
        safe_name = _html.escape(user_name or "User")
        safe_portal = _html.escape(portal_label)
        safe_evt = _html.escape(event_type or "PORTAL_SECURITY_EVENT")
        safe_reason = _html.escape(lock_reason or "Repeated failed verification attempts")
        safe_ref = _html.escape(security_reference_id or "N/A")
        safe_ts = _html.escape(display_ts)
        safe_dev = _html.escape(device_summary or "Unknown Device Context")
        acct_line = f"\n- Target Account: {cls.mask_email(target_account_email)}" if (is_admin_notice and target_account_email) else ""
        acct_html = (
            f'<div style="color: #cbd5e1;"><strong style="color: #fca5a5;">Account:</strong> {_html.escape(cls.mask_email(target_account_email))}</div>'
            if (is_admin_notice and target_account_email)
            else ""
        )

        subject = f"[{settings.PROJECT_NAME}] {portal_label} Portal Security Notice ({safe_evt}) — Ref {security_reference_id}"
        plain_text = (
            f"COGNISEC-AI // {audience}\n\n"
            f"Hello {user_name or 'Security Officer'},\n\n"
            f"Event Type: {event_type}\n"
            f"- Portal: {portal_label}{acct_line}\n"
            f"- Security Reference ID: {security_reference_id}\n"
            f"- Event Time: {display_ts}\n"
            f"- Device Context: {device_summary}\n"
            f"- Summary: {lock_reason}\n\n"
            f"Portal access remains restricted until authorized security recovery is completed.\n"
        )
        html_text = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #09060e; color: #ffffff; padding: 28px; border-radius: 16px; border: 1px solid #991b1b; max-width: 560px; margin: 0 auto;">
            <div style="border-bottom: 1px solid #7f1d1d; padding-bottom: 14px; margin-bottom: 18px;">
                <span style="font-size: 11px; font-family: monospace; letter-spacing: 2px; color: #f87171; font-weight: bold; text-transform: uppercase;">COGNISEC-AI // {audience}</span>
                <h2 style="color: #ffffff; font-size: 19px; margin: 8px 0 0 0; font-weight: 800;">🛡️ {safe_evt}</h2>
            </div>
            <p style="color: #cbd5e1; font-size: 13px; line-height: 1.6; margin: 0 0 14px 0;">
                Hello <strong style="color: #ffffff;">{safe_name}</strong>, a portal security enforcement event was recorded in COGNISEC-AI.
            </p>
            <div style="background-color: #120b1c; border: 1px solid #7f1d1d; padding: 15px; border-radius: 12px; margin: 16px 0; font-size: 12px; font-family: monospace; line-height: 1.8;">
                <div style="color: #cbd5e1;"><strong style="color: #fca5a5;">Portal:</strong> {safe_portal}</div>
                {acct_html}
                <div style="color: #cbd5e1;"><strong style="color: #fca5a5;">Security Ref:</strong> {safe_ref}</div>
                <div style="color: #cbd5e1;"><strong style="color: #fca5a5;">Event Type:</strong> {safe_evt}</div>
                <div style="color: #cbd5e1;"><strong style="color: #fca5a5;">Event Time:</strong> {safe_ts}</div>
                <div style="color: #cbd5e1;"><strong style="color: #fca5a5;">Device Context:</strong> {safe_dev}</div>
                <div style="color: #cbd5e1;"><strong style="color: #fca5a5;">Details:</strong> {safe_reason}</div>
            </div>
            <p style="color: #94a3b8; font-size: 12px; line-height: 1.5; margin: 0;">
                If this activity was unexpected, review active devices and await authorized administrator recovery before re-entering the portal.
            </p>
        </div>
        """
        return cls.send_email(
            recipient_email=resolved_recipient,
            subject=subject,
            plain_text=plain_text,
            html_text=html_text,
        )
