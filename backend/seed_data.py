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
from app.services.profile_service import ProfileService


def seed_database():
    print("⚡ Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    now_utc = datetime.now(timezone.utc)

    try:
        # 1. Primary SOC Admin Account
        primary_admin_email = "cognisecai.security@gmail.com"
        primary_admin = db.query(User).filter(User.email == primary_admin_email).first()
        if not primary_admin:
            primary_admin = User(
                name="CogniSec SOC Administrator",
                email=primary_admin_email,
                password_hash=get_password_hash("cognisecai2026"),
                role="ADMIN",
                account_status="ACTIVE",
                created_at=now_utc
            )
            db.add(primary_admin)
            db.commit()
            db.refresh(primary_admin)
            print(f"✓ Seeded Primary Admin: {primary_admin.email}")

        # 1B. Secondary Admin Account
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
            ("Jane Doe (VIP)", "customer.jane@auraluxe.com", "Customer@123", "ecommerce", "USER"),
            ("Alex Mercer (CS Major)", "student.alex@veritas.edu", "Student@123", "college", "USER"),
            ("Dr. Sarah Lin, MD", "dr.sarah@aetheriahealth.org", "Doctor@123", "healthcare", "DOCTOR"),
            ("Student Demo", "2021bce0492@bits-pilani.ac.in", "Student@123", "college", "USER"),
            ("Dr. Boomika Ram", "dr.boomika@ayusync.med.in", "Doctor@123", "healthcare", "DOCTOR"),
            ("Boomika Ram (Customer)", "boomika.ram@cognisec.ai", "Customer@123", "ecommerce", "USER"),
            ("Customer Default", "customer@cognisec.ai", "Customer@123", "ecommerce", "USER")
        ]

        created_users = [admin, user]
        for name, email, pwd, app, r in portal_users:
            p_user = db.query(User).filter(User.email == email).first()
            if not p_user:
                p_user = User(
                    name=name,
                    email=email,
                    password_hash=get_password_hash(pwd),
                    role=r,
                    account_status="ACTIVE",
                    created_at=now_utc
                )
                db.add(p_user)
                db.commit()
                db.refresh(p_user)
                created_users.append(p_user)
                print(f"✓ Seeded Portal User: {p_user.email}")
            else:
                if p_user.role != r:
                    p_user.role = r
                    db.commit()
                created_users.append(p_user)

        # 4. Initialize genuine uncalibrated baselines for normal users (clean cold-start)
        for u in created_users:
            ProfileService.get_or_create_profile(db, u.id)
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
