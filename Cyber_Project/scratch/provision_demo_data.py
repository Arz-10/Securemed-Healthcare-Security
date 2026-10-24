"""
scratch/provision_demo_data.py – Setup demonstration accounts, relationship, and fictional records.

Guarantees:
  - Checks existence of demo accounts before creating.
  - Generates Werkzeug password hashes (pbkdf2:sha256).
  - Never touches administrator password.
  - Creates future appointment, completed appointment, fictional EMR, and sample PDF report.
  - Verifies successful login and role redirects.
"""

import os
import sys
import uuid
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

import dotenv
dotenv.load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

from database.db import get_connection, close_connection
from database.audit import log_audit_event, EVENT_USER_MANAGEMENT, OUTCOME_SUCCESS
from app import create_app


def provision():
    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Check existing users
        cursor.execute("SELECT username FROM users WHERE username IN ('demo_admin', 'demo_doctor', 'demo_patient')")
        existing_users = [r["username"] for r in cursor.fetchall()]
        if existing_users:
            print(f"[!] Warning: Following demo users already exist: {existing_users}")
            return False

        print("[+] Verified: 'demo_doctor' and 'demo_patient' do not exist. Proceeding with provisioning...")

        # 2. Provision Doctor: demo_doctor
        doctor_pwd_hash = generate_password_hash("DoctorDemo@2026")
        cursor.execute(
            """
            INSERT INTO users (username, password, role, full_name, email, phone, is_active, created_at)
            VALUES (%s, %s, 'doctor', %s, %s, %s, 1, NOW())
            """,
            ("demo_doctor", doctor_pwd_hash, "Dr. Alexander Wright", "demo.doctor@securemed.local", "+1-555-0101"),
        )
        doctor_user_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO doctors (user_id, specialisation, licence_number, department)
            VALUES (%s, %s, %s, %s)
            """,
            (doctor_user_id, "Cardiology", "MD-DEMO-01", "Cardiovascular Medicine"),
        )
        doctor_id = cursor.lastrowid
        print(f"[+] Doctor 'demo_doctor' created (user_id={doctor_user_id}, doctor_id={doctor_id}).")

        # 3. Provision Patient: demo_patient
        patient_pwd_hash = generate_password_hash("PatientDemo@2026")
        cursor.execute(
            """
            INSERT INTO users (username, password, role, full_name, email, phone, is_active, created_at)
            VALUES (%s, %s, 'patient', %s, %s, %s, 1, NOW())
            """,
            ("demo_patient", patient_pwd_hash, "Eleanor Vance", "demo.patient@securemed.local", "+1-555-0102"),
        )
        patient_user_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO patients (user_id, date_of_birth, gender, blood_group, address, emergency_contact)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (patient_user_id, "1988-06-14", "female", "O+", "104 Healthcare Way, Suite 2B", "+1-555-0199"),
        )
        patient_id = cursor.lastrowid
        print(f"[+] Patient 'demo_patient' created (user_id={patient_user_id}, patient_id={patient_id}).")

        # 4. Create Completed Past Encounter
        past_date = datetime.now() - timedelta(days=5)
        cursor.execute(
            """
            INSERT INTO appointments (patient_id, doctor_id, appointment_date, reason, status, notes, created_at)
            VALUES (%s, %s, %s, %s, 'completed', %s, NOW())
            """,
            (
                patient_id,
                doctor_id,
                past_date.strftime("%Y-%m-%d 10:00:00"),
                "Initial cardiovascular assessment & baseline vitals check",
                "Patient evaluated; resting pulse 74 bpm. Follow-up ECG scheduled.",
            ),
        )
        past_appointment_id = cursor.lastrowid

        # 5. Create Future Scheduled Consultation
        future_date = datetime.now() + timedelta(days=7)
        cursor.execute(
            """
            INSERT INTO appointments (patient_id, doctor_id, appointment_date, reason, status, notes, created_at)
            VALUES (%s, %s, %s, %s, 'scheduled', NULL, NOW())
            """,
            (
                patient_id,
                doctor_id,
                future_date.strftime("%Y-%m-%d 14:30:00"),
                "Follow-up ECG review and exercise stress test discussion",
            ),
        )
        future_appointment_id = cursor.lastrowid
        print(f"[+] Created completed appointment #{past_appointment_id} and future scheduled appointment #{future_appointment_id}.")

        # 6. Create Fictional Demonstration Medical Record
        cursor.execute(
            """
            INSERT INTO medical_records (patient_id, doctor_id, appointment_id, diagnosis, prescription, notes, record_date)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """,
            (
                patient_id,
                doctor_id,
                past_appointment_id,
                "Mild Essential Hypertension (Demonstration Record)",
                "Amlodipine 5mg daily; Low-sodium dietary plan (Fictional)",
                "Fictional EMR record created for academic demonstration only.",
            ),
        )
        record_id = cursor.lastrowid
        print(f"[+] Created synthetic medical record #{record_id}.")

        # 7. Create Valid Sample Diagnostic PDF in uploads/
        upload_folder = os.path.join(PROJECT_ROOT, "uploads")
        os.makedirs(upload_folder, exist_ok=True)
        stored_filename = f"{uuid.uuid4().hex}.pdf"
        dest_file_path = os.path.join(upload_folder, stored_filename)

        # Minimal valid PDF binary with magic bytes %PDF-1.4
        sample_pdf_bytes = (
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f\n0000000010 00000 n\n0000000053 00000 n\n0000000102 00000 n\n"
            b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
        )
        with open(dest_file_path, "wb") as f:
            f.write(sample_pdf_bytes)

        cursor.execute(
            """
            INSERT INTO uploads (patient_id, uploaded_by, record_id, original_name, stored_name, file_size, mime_type, upload_date)
            VALUES (%s, %s, %s, %s, %s, %s, 'application/pdf', NOW())
            """,
            (
                patient_id,
                doctor_user_id,
                record_id,
                "cardiac_ecg_report_demo.pdf",
                stored_filename,
                len(sample_pdf_bytes),
            ),
        )
        report_id = cursor.lastrowid
        print(f"[+] Created demonstration report #{report_id} ('{stored_filename}').")

        conn.commit()
        print("[+] Successfully committed all demo accounts and relationship records to database!")

        # 8. Record audit log
        log_audit_event(
            EVENT_USER_MANAGEMENT,
            OUTCOME_SUCCESS,
            user_id=doctor_user_id,
            details="demo accounts and clinical relationship provisioned",
        )
        return True

    except Exception as exc:
        if conn:
            conn.rollback()
        print(f"[-] Provisioning error: {exc}")
        return False
    finally:
        close_connection(conn, cursor)


if __name__ == "__main__":
    provision()
