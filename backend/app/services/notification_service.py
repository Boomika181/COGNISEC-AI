import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.device import Device
from app.models.notification import DeviceNotification
from app.models.security_event import SecurityEvent
from app.services.email_service import EmailService
from app.services.device_service import DeviceService
from app.core.config import settings

logger = logging.getLogger(__name__)


def utc_now():
    return datetime.now(timezone.utc)


class NotificationService:
    # Notification deduplication cache: (email, ip) -> last_alert_time
    _recent_failed_alerts: Dict[str, datetime] = {}

    @classmethod
    def notify_new_device_login(
        cls,
        db: Session,
        user: User,
        device: Device,
        ip_address: str,
        session_id: str,
        location_summary: Optional[str] = None
    ) -> DeviceNotification:
        """
        Creates a persistent new device login notification record and dispatches an email alert.
        """
        now = utc_now()
        dev_summary = (
            f"{device.browser_name or 'Browser'} on {device.os_name or 'OS'} "
            f"({device.nickname or device.device_type})"
        )
        loc_str = location_summary or (
            f"{device.city}, {device.country} ({device.location_source})"
            if device.city else f"Network IP {ip_address}"
        )

        time_display = now.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Deduplication: at most 1 new-device alert per (user_id, device_id) within 10 minutes
        recent_cutoff = now - timedelta(minutes=10)
        recent_notif = db.query(DeviceNotification).filter(
            DeviceNotification.user_id == user.id,
            DeviceNotification.device_id == device.id,
            DeviceNotification.notification_type == "NEW_DEVICE_LOGIN",
            DeviceNotification.created_at >= recent_cutoff
        ).order_by(DeviceNotification.id.desc()).first()

        if recent_notif:
            logger.info(
                f"[COGNISEC-AI] [NOTIF_DEDUP] Suppressing duplicate new-device alert for user={user.id} "
                f"device={device.id} (existing notif_id={recent_notif.id})"
            )
            return recent_notif

        # 1. Create notification record in database first (so email failure never loses the event)
        notif = DeviceNotification(
            user_id=user.id,
            device_id=device.id,
            notification_type="NEW_DEVICE_LOGIN",
            title="New Sign-In Detected",
            message=f"A sign-in occurred from an unrecognized device ({dev_summary}) at IP {ip_address}.",
            device_summary=dev_summary,
            ip_address=ip_address,
            location_summary=loc_str,
            status="PENDING_CONFIRMATION",
            email_delivery_status="PENDING",
            confirmation_token=secrets.token_urlsafe(32),
            is_read=False,
            created_at=now
        )
        db.add(notif)
        db.commit()
        db.refresh(notif)

        # 2. Record security audit event
        sec_event = SecurityEvent(
            user_id=user.id,
            session_id=session_id,
            application="platform",
            event_type="UNRECOGNIZED_DEVICE_LOGIN",
            severity="MEDIUM",
            anomaly_score=0.3,
            risk_score=0.35,
            decision="ALLOW",
            details=f"New device '{dev_summary}' logged in from IP {ip_address} ({loc_str})."
        )
        db.add(sec_event)
        db.commit()

        dev_nickname = device.nickname or (f"{device.browser_name} on {device.os_name}" if device.browser_name else device.device_type)
        is_recog = bool(device.is_trusted)

        # 3. Dispatch security alert email to registered owner address
        # In test environments, dispatch synchronously so test assertions on mocks succeed immediately.
        # In live/production/development, dispatch in a background thread so SMTP delays never freeze the login request.
        if getattr(settings, "ENVIRONMENT", "").lower() in ("test", "testing"):
            email_sent, email_msg = EmailService.send_new_device_login_alert(
                recipient_email=user.email,
                user_name=user.name,
                device_summary=dev_summary,
                ip_address=ip_address,
                location_summary=loc_str,
                timestamp_str=time_display,
                device_nickname=dev_nickname,
                is_recognized=is_recog
            )
            if email_sent:
                notif.email_delivery_status = "SENT"
            else:
                if "not configured" in email_msg.lower() or "disabled" in email_msg.lower():
                    notif.email_delivery_status = "SKIPPED_UNCONFIGURED"
                else:
                    notif.email_delivery_status = "FAILED"
                notif.email_error = email_msg[:490]
            db.commit()
            db.refresh(notif)
        else:
            import threading
            notif_id = notif.id
            recip = user.email
            uname = user.name

            def _send_alert_bg():
                from app.database.connection import SessionLocal
                es, em = EmailService.send_new_device_login_alert(
                    recipient_email=recip,
                    user_name=uname,
                    device_summary=dev_summary,
                    ip_address=ip_address,
                    location_summary=loc_str,
                    timestamp_str=time_display,
                    device_nickname=dev_nickname,
                    is_recognized=is_recog
                )
                try:
                    with SessionLocal() as bg_db:
                        n = bg_db.query(DeviceNotification).filter(DeviceNotification.id == notif_id).first()
                        if n:
                            n.email_delivery_status = "SENT" if es else ("SKIPPED_UNCONFIGURED" if "not configured" in em.lower() or "disabled" in em.lower() else "FAILED")
                            if not es:
                                n.email_error = em[:490]
                            bg_db.commit()
                except Exception as err:
                    logger.warning(f"[COGNISEC-AI] Failed updating notification email status: {err}")

            threading.Thread(target=_send_alert_bg, daemon=True).start()

        return notif

    @classmethod
    def handle_failed_login(
        cls,
        db: Session,
        email: str,
        ip_address: str,
        user_agent: Optional[str] = None
    ):
        """
        Records security audit event for failed login attempts.
        Applies deduplication to prevent email flooding.
        """
        now = utc_now()
        user = db.query(User).filter(User.email == email.lower()).first()

        # Record security event if user exists
        if user:
            sec_event = SecurityEvent(
                user_id=user.id,
                application="platform",
                event_type="LOGIN_ATTEMPT_FAILED",
                severity="LOW",
                anomaly_score=0.1,
                risk_score=0.15,
                decision="ALLOW",
                details=f"Failed authentication attempt for target '{email}' from IP {ip_address}."
            )
            db.add(sec_event)
            db.commit()

        # Deduplicate alerts: at most 1 alert every 5 minutes per (email, ip)
        cache_key = f"{email.lower()}:{ip_address}"
        last_alert = cls._recent_failed_alerts.get(cache_key)
        if last_alert and (now - last_alert) < timedelta(minutes=5):
            return

        cls._recent_failed_alerts[cache_key] = now

        # If user exists, create an in-app security notification
        if user:
            notif = DeviceNotification(
                user_id=user.id,
                notification_type="SUSPICIOUS_LOGIN_FAILED",
                title="Failed Sign-In Attempt",
                message=f"An unsuccessful password attempt was detected for your account from IP {ip_address}.",
                device_summary="Unrecognized Requester",
                ip_address=ip_address,
                location_summary="External Network",
                status="READ",
                email_delivery_status="SKIPPED_UNCONFIGURED",
                is_read=False,
                created_at=now
            )
            db.add(notif)
            db.commit()

    @staticmethod
    def get_user_notifications(
        db: Session,
        user_id: int,
        unread_only: bool = False,
        limit: int = 50
    ) -> Tuple[List[DeviceNotification], int]:
        """
        Retrieves notifications for the authenticated user and counts unread items.
        Returns: (notifications: List[DeviceNotification], unread_count: int)
        """
        query = db.query(DeviceNotification).filter(DeviceNotification.user_id == user_id)
        if unread_only:
            query = query.filter(DeviceNotification.is_read == False)

        notifications = query.order_by(DeviceNotification.created_at.desc()).limit(limit).all()

        unread_count = db.query(DeviceNotification).filter(
            DeviceNotification.user_id == user_id,
            DeviceNotification.is_read == False
        ).count()

        return notifications, unread_count

    @classmethod
    def mark_read(cls, db: Session, notification_id: str, user_id: int) -> bool:
        """
        Marks a specific notification as read, ensuring it belongs to the given user.
        """
        query = db.query(DeviceNotification).filter(DeviceNotification.user_id == user_id)
        if isinstance(notification_id, int) or (isinstance(notification_id, str) and notification_id.isdigit()):
            query = query.filter(DeviceNotification.id == int(notification_id))
        else:
            query = query.filter(DeviceNotification.notification_id == str(notification_id))

        notif = query.first()
        if notif:
            notif.is_read = True
            db.commit()
            db.refresh(notif)
            return True
        return False

    @staticmethod
    def mark_all_read(db: Session, user_id: int) -> int:
        """
        Marks all notifications for user as read. Returns count of rows updated.
        """
        updated = db.query(DeviceNotification).filter(
            DeviceNotification.user_id == user_id,
            DeviceNotification.is_read == False
        ).update({"is_read": True}, synchronize_session=False)
        db.commit()
        return updated

    @classmethod
    def respond_to_notification(
        cls,
        db: Session,
        notification_id: str,
        user_id: int,
        decision: str
    ) -> Tuple[Optional[DeviceNotification], Optional[Device]]:
        """
        Handles user decision on a device notification:
        - "yes" / "confirm": Marks device TRUSTED, updates notification status.
        - "no" / "deny": Revokes device, invalidates its active sessions, updates notification status.
        Strictly enforces that User A cannot confirm/deny User B's alerts.
        """
        query = db.query(DeviceNotification)
        if isinstance(notification_id, int) or (isinstance(notification_id, str) and notification_id.isdigit()):
            query = query.filter(DeviceNotification.id == int(notification_id))
        else:
            query = query.filter(DeviceNotification.notification_id == str(notification_id))

        notif = query.first()
        if not notif:
            return None, None

        if notif.user_id != user_id:
            raise PermissionError("Access forbidden: You cannot confirm or deny another user's notification.")

        dec = decision.strip().lower()
        now = utc_now()
        device = db.query(Device).filter(Device.id == notif.device_id).first() if notif.device_id else None

        if dec in ("yes", "confirm", "trusted"):
            notif.status = "CONFIRMED_TRUSTED"
            notif.is_read = True
            notif.confirmed_at = now
            if device:
                DeviceService.confirm_device_as_trusted(db, device.device_id, user_id=user_id)
            db.commit()
            db.refresh(notif)
            return notif, device

        elif dec in ("no", "deny", "revoke", "secure"):
            notif.status = "CONFIRMED_DENIED"
            notif.is_read = True
            notif.confirmed_at = now
            if device:
                DeviceService.revoke_device(db, device.device_id, user_id=user_id, reason="Owner denied sign-in")
            db.commit()
            db.refresh(notif)
            return notif, device

        raise ValueError("Invalid decision parameter. Expected 'yes' or 'no'.")
