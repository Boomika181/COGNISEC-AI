from datetime import datetime, timezone
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from app.models.device import Device
from app.models.session import Session as UserSession
from app.models.security_event import SecurityEvent
from app.core.user_agent import UserAgentParser
from app.services.geo_service import GeoLocationService


def utc_now():
    return datetime.now(timezone.utc)


class DeviceService:
    @staticmethod
    def register_or_update_device(
        db: Session,
        user_id: int,
        device_fingerprint: str,
        user_agent: Optional[str] = None,
        platform: Optional[str] = None,
        client_ip: Optional[str] = "127.0.0.1",
        nickname: Optional[str] = None,
        client_lat: Optional[float] = None,
        client_lon: Optional[float] = None,
        client_accuracy: Optional[float] = None,
        client_source: Optional[str] = None,
        browser: Optional[str] = None,
        os: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_type: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        location_accuracy: Optional[float] = None,
        location_source: Optional[str] = None,
        **kwargs
    ) -> Tuple[Device, bool]:
        """
        Registers a new device or updates an existing device record.
        Returns: (Device, is_new_device_bool)
        """
        effective_ua = browser if (browser and browser != "testclient") else (user_agent or browser or "")
        effective_platform = os if (os and os not in ("Desktop", "Unknown")) else (platform or os or "")
        effective_ip = ip_address or client_ip or "127.0.0.1"
        effective_lat = latitude if latitude is not None else client_lat
        effective_lon = longitude if longitude is not None else client_lon
        effective_acc = location_accuracy if location_accuracy is not None else client_accuracy
        effective_src = location_source or client_source

        # Parse device details from user-agent
        ua_info = UserAgentParser.parse(effective_ua, effective_platform)
        browser_raw = (effective_ua or ua_info["summary"])[:490]
        os_raw = (effective_platform or ua_info["os_name"])[:490]

        # Resolve location evidence
        geo_info = GeoLocationService.resolve_location(
            ip_address=effective_ip,
            client_lat=effective_lat,
            client_lon=effective_lon,
            client_accuracy=effective_acc,
            client_source=effective_src
        )

        now = utc_now()
        safe_fingerprint = (device_fingerprint or "unknown_fp").strip()

        # Query for existing device belonging to this user with matching fingerprint
        device = db.query(Device).filter(
            Device.user_id == user_id,
            Device.device_fingerprint == safe_fingerprint
        ).first()

        if device:
            # Existing device recognized: update last seen & environmental evidence
            device.last_seen = now
            device.last_ip = (client_ip or device.last_ip or "127.0.0.1")[:45]
            if user_agent:
                device.browser = browser_raw
                device.browser_name = ua_info["browser_name"]
                device.browser_version = ua_info["browser_version"]
            if platform or ua_info["os_name"] != "Unknown":
                device.os = os_raw
                device.os_name = ua_info["os_name"]
                device.os_version = ua_info["os_version"]
            if ua_info["device_type"] != "Unknown":
                device.device_type = ua_info["device_type"]

            # Update location if fresh location was provided
            if geo_info["location_source"] in ("GPS", "IP_APPROXIMATE"):
                if geo_info["latitude"] is not None:
                    device.latitude = geo_info["latitude"]
                    device.longitude = geo_info["longitude"]
                    device.location_accuracy = geo_info["location_accuracy"]
                if geo_info["city"]:
                    device.city = geo_info["city"]
                    device.region = geo_info["region"]
                    device.country = geo_info["country"]
                device.location_source = geo_info["location_source"]
                device.location_updated_at = now

            db.commit()
            db.refresh(device)
            return device, False

        # Unfamiliar device for this user:
        # Check if user has any existing devices
        existing_devices_count = db.query(Device).filter(Device.user_id == user_id).count()
        is_first_device = (existing_devices_count == 0)

        # Initial device is trusted; subsequent unfamiliar devices are strictly PENDING_CONFIRMATION
        initial_trust_state = "TRUSTED" if is_first_device else "PENDING_CONFIRMATION"
        is_trusted_bool = bool(is_first_device)

        default_nickname = nickname or (f"My {ua_info['os_name']} {ua_info['device_type']}" if ua_info['os_name'] != "Unknown" else f"Device #{existing_devices_count + 1}")

        new_device = Device(
            user_id=user_id,
            device_fingerprint=safe_fingerprint,
            nickname=default_nickname[:95],
            browser=browser_raw,
            browser_name=ua_info["browser_name"],
            browser_version=ua_info["browser_version"],
            os=os_raw,
            os_name=ua_info["os_name"],
            os_version=ua_info["os_version"],
            device_type=ua_info["device_type"],
            trust_state=initial_trust_state,
            is_trusted=is_trusted_bool,
            last_ip=(client_ip or "127.0.0.1")[:45],
            latitude=geo_info["latitude"],
            longitude=geo_info["longitude"],
            city=geo_info["city"],
            region=geo_info["region"],
            country=geo_info["country"],
            location_source=geo_info["location_source"],
            location_accuracy=geo_info["location_accuracy"],
            location_updated_at=now,
            first_seen=now,
            last_seen=now
        )
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        return new_device, True

    @staticmethod
    def get_user_devices(db: Session, user_id: int) -> List[Device]:
        return db.query(Device).filter(Device.user_id == user_id).order_by(Device.last_seen.desc()).all()

    @staticmethod
    def get_device_by_id(db: Session, device_id_or_pk: str, user_id: Optional[int] = None) -> Optional[Device]:
        query = db.query(Device)
        if isinstance(device_id_or_pk, int) or (isinstance(device_id_or_pk, str) and device_id_or_pk.isdigit()):
            query = query.filter(Device.id == int(device_id_or_pk))
        else:
            query = query.filter(Device.device_id == str(device_id_or_pk))

        if user_id is not None:
            query = query.filter(Device.user_id == user_id)
        return query.first()

    @staticmethod
    def revoke_device(
        db: Session,
        device_id_or_pk: str,
        user_id: Optional[int] = None,
        reason: str = "User initiated revocation"
    ) -> Optional[Device]:
        """
        Revokes trust for a device and terminates all its active sessions server-side.
        """
        device = DeviceService.get_device_by_id(db, device_id_or_pk, user_id=user_id)
        if not device:
            return None

        device.trust_state = "REVOKED"
        device.is_trusted = False

        # Invalidate / terminate all active sessions tied to this device
        active_sessions = db.query(UserSession).filter(
            UserSession.device_id == device.id,
            UserSession.status.in_(["ACTIVE", "STEP_UP_REQUIRED", "RESTRICTED", "PENDING_OBSERVATION", "PENDING_OTP"])
        ).all()
        now = utc_now()
        for s in active_sessions:
            s.status = "TERMINATED"
            s.logout_time = now

        # Record audit event
        sec_event = SecurityEvent(
            user_id=device.user_id,
            application="platform",
            event_type="DEVICE_REVOKED",
            severity="MEDIUM",
            anomaly_score=0.2,
            risk_score=0.40,
            decision="TERMINATE_SESSION",
            details=f"Device '{device.nickname or device.device_id}' revoked ({reason}). Active sessions invalidated."
        )
        db.add(sec_event)
        db.commit()
        db.refresh(device)
        return device

    @staticmethod
    def confirm_device_as_trusted(
        db: Session,
        device_id_or_pk: str,
        user_id: Optional[int] = None
    ) -> Optional[Device]:
        """
        Promotes a device to TRUSTED after account owner confirmation.
        """
        device = DeviceService.get_device_by_id(db, device_id_or_pk, user_id=user_id)
        if not device:
            return None

        device.trust_state = "TRUSTED"
        device.is_trusted = True

        sec_event = SecurityEvent(
            user_id=device.user_id,
            application="platform",
            event_type="DEVICE_CONFIRMED_TRUSTED",
            severity="LOW",
            anomaly_score=0.0,
            risk_score=0.0,
            decision="ALLOW",
            details=f"Device '{device.nickname or device.device_id}' confirmed as trusted by account owner."
        )
        db.add(sec_event)
        db.commit()
        db.refresh(device)
        return device

    @staticmethod
    def update_device_nickname(
        db: Session,
        device_id_or_pk: str,
        nickname: str,
        user_id: Optional[int] = None
    ) -> Optional[Device]:
        device = DeviceService.get_device_by_id(db, device_id_or_pk, user_id=user_id)
        if not device:
            return None
        device.nickname = (nickname.strip() or device.nickname)[:95]
        db.commit()
        db.refresh(device)
        return device
