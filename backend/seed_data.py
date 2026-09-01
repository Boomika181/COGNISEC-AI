import sys
import os
import json
from datetime import datetime, timedelta, timezone

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.database.connection import SessionLocal, engine
from app.database.base import Base
import app.models
from app.models.user import User
from app.models.device import Device
from app.models.session import Session as DbSession
from app.models.behavior import BehaviorLog, BehaviorProfile
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.core.security import get_password_hash


def seed_database():
    print("⚡ Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    now_utc = datetime.now(timezone.utc)

    try:
        # 1. Admin Account
        admin_email = "admin.soc@cognisec.ai"
        admin = db.query(User).filter(User.email == admin_email).first()
        if not admin:
            admin = User(
                name="Boomika Ram (SOC Lead)",
                email=admin_email,
                password_hash=get_password_hash("Admin@123"),
                role="ADMIN",
                account_status="ACTIVE",
                created_at=now_utc
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
            print(f"✓ Seeded Admin: {admin.email} (Password: Admin@123)")

        # 2. Demo Normal User
        user_email = "user.portal@cognisec.ai"
        user = db.query(User).filter(User.email == user_email).first()
        if not user:
            user = User(
                name="Boomika Ram",
                email=user_email,
                password_hash=get_password_hash("User@123"),
                role="USER",
                account_status="ACTIVE",
                created_at=now_utc
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print(f"✓ Seeded User: {user.email} (Password: User@123)")

        # 3. Portal Demo Users
        portal_users = [
            ("Jane Doe (VIP)", "customer.jane@auraluxe.com", "Customer@123", "ecommerce"),
            ("Alex Mercer (CS Major)", "student.alex@veritas.edu", "Student@123", "college"),
            ("Dr. Sarah Lin, MD", "dr.sarah@aetheriahealth.org", "Doctor@123", "healthcare")
        ]

        created_users = [admin, user]
        for name, email, pwd, app in portal_users:
            p_user = db.query(User).filter(User.email == email).first()
            if not p_user:
                p_user = User(
                    name=name,
                    email=email,
                    password_hash=get_password_hash(pwd),
                    role="USER",
                    account_status="ACTIVE",
                    created_at=now_utc
                )
                db.add(p_user)
                db.commit()
                db.refresh(p_user)
                created_users.append(p_user)
                print(f"✓ Seeded Portal User: {p_user.email}")
            else:
                created_users.append(p_user)

        # 4. Seed Devices & Baselines for normal users
        for u in created_users:
            dev = db.query(Device).filter(Device.user_id == u.id).first()
            if not dev:
                dev = Device(
                    user_id=u.id,
                    device_fingerprint=f"fp_macbook_tpm_{u.id}_982a",
                    browser="Chrome 128.0 (macOS)",
                    os="macOS Sonoma 14.5",
                    device_type="Desktop",
                    is_trusted=True,
                    first_seen=now_utc - timedelta(days=15),
                    last_seen=now_utc
                )
                db.add(dev)

            prof = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == u.id).first()
            if not prof:
                prof = BehaviorProfile(
                    user_id=u.id,
                    sample_count=12,
                    profile_version=2,
                    last_updated=now_utc,
                    baseline_features=json.dumps({
                        "means": {
                            "typing_speed_wpm": 68.4,
                            "avg_flight_time_ms": 118.2,
                            "avg_dwell_time_ms": 86.5,
                            "mouse_velocity_avg": 680.0,
                            "mouse_acceleration_avg": 410.0,
                            "mouse_curvature_entropy": 0.46,
                            "click_frequency": 1.3,
                            "scroll_speed_avg": 380.0,
                            "idle_duration_sec": 2.1,
                            "navigation_entropy": 0.38
                        },
                        "stds": {
                            "typing_speed_wpm": 6.2,
                            "avg_flight_time_ms": 12.5,
                            "avg_dwell_time_ms": 8.0,
                            "mouse_velocity_avg": 65.0,
                            "mouse_acceleration_avg": 45.0,
                            "mouse_curvature_entropy": 0.05,
                            "click_frequency": 0.25,
                            "scroll_speed_avg": 40.0,
                            "idle_duration_sec": 0.8,
                            "navigation_entropy": 0.04
                        }
                    })
                )
                db.add(prof)

        db.commit()

        # 5. Seed initial security alerts for SOC Dashboard demonstration
        existing_alerts = db.query(Alert).count()
        if existing_alerts == 0:
            ev1 = SecurityEvent(
                user_id=user.id,
                application="ecommerce",
                event_type="UNRECOGNIZED_DEVICE_ACCESS",
                severity="MEDIUM",
                anomaly_score=0.48,
                risk_score=0.52,
                decision="STEP_UP_VERIFICATION",
                details=json.dumps({"factors": ["Access attempt from unrecognized hardware fingerprint"]}),
                timestamp=now_utc - timedelta(minutes=32)
            )
            db.add(ev1)
            db.commit()
            db.refresh(ev1)

            al1 = Alert(
                user_id=user.id,
                security_event_id=ev1.id,
                application="ecommerce",
                alert_type="NEW_HARDWARE_FINGERPRINT",
                message="New device login attempt detected for Boomika Ram (MacBook Pro M3 • IP 103.21.124.9).",
                severity="MEDIUM",
                status="OPEN",
                created_at=now_utc - timedelta(minutes=32)
            )
            db.add(al1)

            ev2 = SecurityEvent(
                user_id=created_users[2].id,
                application="ecommerce",
                event_type="HIGH_RISK_CHECKOUT_ATTEMPT",
                severity="HIGH",
                anomaly_score=0.74,
                risk_score=0.78,
                decision="RESTRICT",
                details=json.dumps({"factors": ["Erratic cursor velocity vectors", "High value checkout ($1,420)"]}),
                timestamp=now_utc - timedelta(minutes=14)
            )
            db.add(ev2)
            db.commit()
            db.refresh(ev2)

            al2 = Alert(
                user_id=created_users[2].id,
                security_event_id=ev2.id,
                application="ecommerce",
                alert_type="BEHAVIOR_ANOMALY_RESTRICTION",
                message="High-value cart checkout restricted due to non-human cursor velocity vector in Aura Luxe Retail.",
                severity="HIGH",
                status="OPEN",
                created_at=now_utc - timedelta(minutes=14)
            )
            db.add(al2)
            db.commit()
            print("✓ Seeded sample SOC security events and alerts.")

        print("🎉 Database seeding completed successfully!")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
