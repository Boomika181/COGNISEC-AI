#!/usr/bin/env python3
"""
COGNISEC-AI Local Development Account Recovery Tool
Safely restores access to an existing account without resetting user data or exposing credentials.
"""
import sys
import os
import getpass
import argparse

# Add backend directory to sys.path
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.database.connection import SessionLocal
from app.models.user import User
from app.services.auth_service import AuthService
from app.schemas.auth import validate_password_strength


def recover_account(email: str, password: str = None) -> bool:
    email = email.strip().lower()
    db = SessionLocal()
    try:
        user = AuthService.get_user_by_email(db, email)
        if not user:
            print(f"[!] Error: No user account found for email: {email}", file=sys.stderr)
            return False

        if not password:
            print(f"[*] Account located: ID={user.id}, Name={user.name}, Role={user.role}, Status={user.account_status}")
            password = getpass.getpass("Enter new secure password: ")
            confirm = getpass.getpass("Confirm new password: ")
            if password != confirm:
                print("[!] Error: Passwords do not match.", file=sys.stderr)
                return False

        # Validate password policy
        try:
            validate_password_strength(password)
        except ValueError as ve:
            print(f"[!] Password policy error: {ve}", file=sys.stderr)
            return False

        # Update password hash in place (preserves all records, devices, sessions, biometrics)
        AuthService.update_user_password(db, email, password)
        print(f"[+] Success: Password for {email} successfully updated in database.")
        print(f"[+] All existing records, devices, biometrics, and sessions preserved.")
        return True
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="COGNISEC-AI Local Development Account Recovery")
    parser.add_argument("--email", "-e", help="Account email address to recover", default=None)
    parser.add_argument("--password", "-p", help="Direct password (stdin only recommended; avoids bash history)", default=None)
    args = parser.parse_args()

    email = args.email
    if not email:
        email = input("Enter account email address: ").strip()

    success = recover_account(email, args.password)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
