#!/usr/bin/env python3
"""
COGNISEC-AI: Local Administrator Provisioning Script
Safely provisions or verifies the primary SOC administrator account:
- Email: cognisecai.security@gmail.com
- Password: cognisecai2026 (stored securely using bcrypt hash)
- Role: ADMIN
- Status: ACTIVE

Never exposes plaintext passwords or privileged tokens.
"""

import sys
import os

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.dirname(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from datetime import datetime, timezone
from app.database.connection import SessionLocal
from app.models.user import User
from app.core.config import settings
from app.core.security import get_password_hash, verify_password


def provision_admin():
    admin_email = (getattr(settings, "ADMIN_EMAIL", None) or "cognisecai.security@gmail.com").strip().lower()
    admin_pwd = (getattr(settings, "ADMIN_INITIAL_PASSWORD", None) or "cognisecai2026")

    print(f"🔒 [COGNISEC-AI] Checking provisioning state for SOC Administrator: {admin_email}")

    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == admin_email).first()
        if not admin:
            admin = User(
                name="CogniSec SOC Administrator",
                email=admin_email,
                password_hash=get_password_hash(admin_pwd),
                role="ADMIN",
                account_status="ACTIVE",
                created_at=datetime.now(timezone.utc)
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
            print(f"✓ Successfully provisioned new SOC Administrator: ID={admin.id}, Email={admin.email}, Role={admin.role}")
        else:
            updated = False
            if admin.role != "ADMIN":
                admin.role = "ADMIN"
                updated = True
                print("  • Updated role to ADMIN")
            if admin.account_status != "ACTIVE":
                admin.account_status = "ACTIVE"
                updated = True
                print("  • Updated account status to ACTIVE")
            if admin.password_hash and not verify_password(admin_pwd, admin.password_hash):
                admin.password_hash = get_password_hash(admin_pwd)
                updated = True
                print("  • Synchronized password hash for local development credentials")

            if updated:
                db.commit()
                db.refresh(admin)
                print(f"✓ Updated existing administrator record: ID={admin.id}, Email={admin.email}")
            else:
                print(f"✓ Administrator record already configured and valid: ID={admin.id}, Email={admin.email}, Role={admin.role}")

        # Verify password validation via verify_password
        valid = verify_password(admin_pwd, admin.password_hash)
        print(f"✓ Password hash verification: {'VALID (bcrypt)' if valid else 'INVALID'}")
        return True
    except Exception as err:
        print(f"❌ Provisioning error: {err}")
        return False
    finally:
        db.close()


if __name__ == "__main__":
    success = provision_admin()
    sys.exit(0 if success else 1)
