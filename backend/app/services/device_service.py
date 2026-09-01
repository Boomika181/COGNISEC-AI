from datetime import datetime, timezone
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from app.models.device import Device


class DeviceService:
    @staticmethod
    def register_or_update_device(
        db: Session,
        user_id: int,
        device_fingerprint: str,
        browser: Optional[str] = None,
        os: Optional[str] = None,
        device_type: Optional[str] = "Desktop"
    ) -> Tuple[Device, bool]:
        """
        Finds existing device or creates a new one.
        Returns (Device, is_new_device_boolean).
        """
        safe_browser = (browser or "Unknown")[:490]
        safe_os = (os or "Unknown")[:490]
        safe_device_type = (device_type or "Desktop")[:45]

        device = db.query(Device).filter(
            Device.user_id == user_id,
            Device.device_fingerprint == device_fingerprint
        ).first()

        now_utc = datetime.now(timezone.utc)

        if device:
            device.last_seen = now_utc
            if browser:
                device.browser = safe_browser
            if os:
                device.os = safe_os
            db.commit()
            db.refresh(device)
            return device, False

        # If user has no devices yet, the very first registered device is trusted automatically
        existing_count = db.query(Device).filter(Device.user_id == user_id).count()
        is_first_device = (existing_count == 0)

        new_device = Device(
            user_id=user_id,
            device_fingerprint=device_fingerprint,
            browser=safe_browser,
            os=safe_os,
            device_type=safe_device_type,
            is_trusted=is_first_device,
            first_seen=now_utc,
            last_seen=now_utc
        )
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        return new_device, True

    @staticmethod
    def get_user_devices(db: Session, user_id: int) -> List[Device]:
        return db.query(Device).filter(Device.user_id == user_id).all()

    @staticmethod
    def get_all_devices(db: Session) -> List[Device]:
        return db.query(Device).order_by(Device.last_seen.desc()).all()

    @staticmethod
    def set_device_trust(db: Session, device_id: int, is_trusted: bool) -> Optional[Device]:
        device = db.query(Device).filter(Device.id == device_id).first()
        if device:
            device.is_trusted = is_trusted
            db.commit()
            db.refresh(device)
        return device
