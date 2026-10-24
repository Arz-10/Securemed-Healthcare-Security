"""
seed_dev_accounts.py – Safe, interactive development account setup utility.

Usage:
    python seed_dev_accounts.py

Requirements & Guarantees:
  - Interactive password prompt without echoing (getpass).
  - Secure Werkzeug password hashing (pbkdf2:sha256).
  - Explicit confirmation before updating any existing account.
  - Strict role validation ('admin', 'doctor', 'patient').
  - Automatic creation of corresponding doctor or patient profile records.
  - Full transactional safety (commits on success, rolls back on error).
  - Never prints passwords, secrets, or raw connection strings.
"""

import os
import sys
import getpass
import re
from werkzeug.security import generate_password_hash

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

from database.db import get_connection, close_connection
from database.audit import log_audit_event, EVENT_USER_MANAGEMENT, OUTCOME_SUCCESS, OUTCOME_FAILED

VALID_ROLES = {"admin", "doctor", "patient"}


def validate_username(username: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_-]{3,50}$", username))


def validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def prompt_password(prompt_label: str = "Enter password: ") -> str:
    while True:
        pwd1 = getpass.getpass(prompt_label)
        if len(pwd1) < 8:
            print("Password must be at least 8 characters long. Please try again.")
            continue
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd1 != pwd2:
            print("Passwords do not match. Please try again.")
            continue
        return pwd1


def create_dev_account(
    conn,
    username: str,
    password: str,
    role: str,
    full_name: str,
    email: str,
    phone: str = None,
    role_fields: dict = None,
) -> tuple[bool, str]:
    """
    Safely provision a development user account with Werkzeug password hashing
    and corresponding role profile records in doctors or patients table.
    """
    role = role.lower().strip()
    if role not in VALID_ROLES:
        return False, f"Invalid role '{role}'. Allowed: {', '.join(sorted(VALID_ROLES))}"

    if not validate_username(username):
        return False, "Invalid username format. Must be 3-50 alphanumeric characters."

    if not validate_email(email):
        return False, "Invalid email format."

    if not full_name or not full_name.strip():
        return False, "Full name is required."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    role_fields = role_fields or {}
    cursor = conn.cursor(dictionary=True)

    try:
        # Check existing account
        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s LIMIT 1", (username, email))
        if cursor.fetchone():
            return False, f"An account with username '{username}' or email '{email}' already exists."

        hashed = generate_password_hash(password)
        cursor.execute(
            """
            INSERT INTO users (username, password, role, full_name, email, phone, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, 1)
            """,
            (username, hashed, role, full_name.strip(), email.strip(), phone),
        )
        user_id = cursor.lastrowid

        if role == "doctor":
            spec = role_fields.get("specialisation") or "General Medicine"
            dept = role_fields.get("department") or "General"
            lic = role_fields.get("licence_number") or f"MD-{user_id:04d}"
            cursor.execute(
                """
                INSERT INTO doctors (user_id, specialisation, licence_number, department)
                VALUES (%s, %s, %s, %s)
                """,
                (user_id, spec, lic, dept),
            )
        elif role == "patient":
            dob = role_fields.get("date_of_birth") or None
            gender = role_fields.get("gender") or None
            if gender and gender not in {"male", "female", "other"}:
                gender = None
            blood = role_fields.get("blood_group") or None
            emg = role_fields.get("emergency_contact") or None
            addr = role_fields.get("address") or None
            cursor.execute(
                """
                INSERT INTO patients (user_id, date_of_birth, gender, blood_group, address, emergency_contact)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (user_id, dob, gender, blood, addr, emg),
            )

        conn.commit()
        log_audit_event(
            EVENT_USER_MANAGEMENT,
            OUTCOME_SUCCESS,
            user_id=user_id,
            details=f"account provisioned via utility: role={role}, username={username}",
        )
        return True, f"Account '{username}' (User ID: {user_id}, Role: {role}) provisioned successfully."

    except Exception as exc:
        conn.rollback()
        return False, f"Database error during account provisioning: {exc.__class__.__name__}"


def setup_account():
    print("\n========================================================")
    print("      SecureMed — Development Account Provisioner       ")
    print("========================================================")
    print("Select an account option:")
    print("  1) Configure default 'admin' account password")
    print("  2) Provision new Doctor account")
    print("  3) Provision new Patient account")
    print("  4) Provision custom user account")
    print("  5) Exit")

    choice = input("\nEnter choice [1-5]: ").strip()
    if choice == "5" or not choice:
        print("Setup aborted.")
        return

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if choice == "1":
            username = "admin"
            cursor.execute("SELECT id, username, role, full_name, email FROM users WHERE username = %s", (username,))
            existing = cursor.fetchone()
            if existing:
                print(f"\nExisting account found for '{username}' ({existing['full_name']} <{existing['email']}>).")
                confirm = input("Are you sure you want to update this account's password? [y/N]: ").strip().lower()
                if confirm != "y":
                    print("Update cancelled.")
                    return
                new_pwd = prompt_password(f"Enter new password for '{username}': ")
                hashed = generate_password_hash(new_pwd)
                cursor.execute(
                    "UPDATE users SET password = %s, is_active = 1, updated_at = NOW() WHERE username = %s",
                    (hashed, username),
                )
                conn.commit()
                log_audit_event(
                    EVENT_USER_MANAGEMENT,
                    OUTCOME_SUCCESS,
                    user_id=existing["id"],
                    details=f"admin password updated via setup utility for username={username}",
                )
                print(f"\n[SUCCESS] Password for '{username}' updated successfully.")
            else:
                print(f"\nAccount '{username}' not found. Creating default admin account.")
                full_name = "System Administrator"
                email = "admin@securemed.local"
                pwd = prompt_password(f"Enter password for '{username}': ")
                success, msg = create_dev_account(
                    conn, username, pwd, "admin", full_name, email
                )
                if success:
                    print(f"\n[SUCCESS] {msg}")
                else:
                    print(f"\n[ERROR] {msg}")

        elif choice in ["2", "3", "4"]:
            role = "doctor" if choice == "2" else ("patient" if choice == "3" else "")
            if not role:
                role_input = input("Enter role (admin / doctor / patient): ").strip().lower()
                if role_input not in VALID_ROLES:
                    print(f"Invalid role '{role_input}'. Aborting.")
                    return
                role = role_input

            username = input(f"Enter username for new {role} (alphanumeric, 3-50 chars): ").strip()
            full_name = input("Enter full name: ").strip()
            email = input("Enter email address: ").strip()
            pwd = prompt_password(f"Enter password for '{username}': ")

            role_fields = {}
            if role == "doctor":
                role_fields["specialisation"] = input("Enter doctor specialisation (e.g. Cardiology, General Medicine) [optional]: ").strip() or "General Medicine"
                role_fields["department"] = input("Enter department (e.g. Outpatient, Internal Medicine) [optional]: ").strip() or "General"
                role_fields["licence_number"] = input("Enter medical licence number [optional]: ").strip()
            elif role == "patient":
                role_fields["date_of_birth"] = input("Enter date of birth (YYYY-MM-DD) [optional]: ").strip() or None
                role_fields["gender"] = input("Enter gender (male / female / other) [optional]: ").strip().lower() or None
                role_fields["blood_group"] = input("Enter blood group (e.g. O+, A+, B+) [optional]: ").strip() or None
                role_fields["emergency_contact"] = input("Enter emergency contact phone [optional]: ").strip() or None

            success, msg = create_dev_account(
                conn, username, pwd, role, full_name, email, role_fields=role_fields
            )
            if success:
                print(f"\n[SUCCESS] {msg}")
            else:
                print(f"\n[ERROR] {msg}")

    except Exception as exc:
        if conn:
            conn.rollback()
        print(f"\n[ERROR] Account setup failed: {exc.__class__.__name__}")
    finally:
        close_connection(conn, cursor)


if __name__ == "__main__":
    setup_account()
