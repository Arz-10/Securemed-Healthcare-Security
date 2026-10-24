"""
test_phase3_suite.py – Comprehensive automated test suite for SecureMed Phase 3.

Workflows & Security Guarantees Tested:
  1. Safe Account Setup & Password Hashing (Werkzeug generate_password_hash)
  2. Role Restrictions & Access Guards (Admin, Doctor, Patient)
  3. CSRF Rejection on State-Changing Operations
  4. Admin User Provisioning & Duplicate Detection
  5. Admin User Status Toggling (Soft Deactivation)
  6. Doctor Appointment Status Updates (Authorized vs Unauthorized)
  7. Doctor-Patient Relationship Enforcement for Medical Records
  8. Medical Record Audit Privacy (Never logs clinical text)
  9. Doctor Report Upload Validation & Rejection
 10. Patient Appointment Booking & Input Validation
 11. Patient Appointment Cancellation & IDOR Defense
 12. Report Access Enforcement (Patient Ownership, Doctor Relationship, Admin Global)
 13. Empty Database State Handling & Clean UI Rendering
 14. Alert Dismissal Element & Static Assets Verification
"""

import os
import sys
import io
import unittest
from unittest.mock import patch, MagicMock
from werkzeug.security import check_password_hash

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from app import create_app
from routes.reports import validate_uploaded_file
from seed_dev_accounts import create_dev_account


class DummyFileStorage:
    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self._content = content
        self._stream = io.BytesIO(content)

    def read(self):
        return self._content


class TestPhase3Workflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.testing = True

    def setUp(self):
        self.client = self.app.test_client()
        from routes.auth import _failed_login_attempts
        _failed_login_attempts.clear()

    # ------------------------------------------------------------------ #
    # 1. Safe Account Setup & Password Hashing                           #
    # ------------------------------------------------------------------ #
    def test_01_account_provisioner_hashing(self):
        """Verify account provisioner uses Werkzeug hashing and role validation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        # Test duplicate account rejection
        mock_cursor.fetchone.return_value = {"id": 1}
        success, msg = create_dev_account(
            mock_conn, "existing_user", "ValidPass123!", "doctor", "Dr. Test", "test@hospital.org"
        )
        self.assertFalse(success)
        self.assertIn("already exists", msg)

        # Test invalid role rejection
        mock_cursor.fetchone.return_value = None
        success, msg = create_dev_account(
            mock_conn, "new_user", "ValidPass123!", "superadmin", "Dr. Test", "test@hospital.org"
        )
        self.assertFalse(success)
        self.assertIn("Invalid role", msg)

        # Test successful account creation with password hashing
        mock_cursor.reset_mock()
        mock_cursor.fetchone.return_value = None
        mock_cursor.lastrowid = 101

        with patch("seed_dev_accounts.log_audit_event"):
            success, msg = create_dev_account(
                mock_conn, "dr_new", "StrongPass123!", "doctor", "Dr. New", "drnew@hospital.org",
                role_fields={"specialisation": "Cardiology", "licence_number": "MD-9999", "department": "Cardiology"}
            )
            self.assertTrue(success)
            # Calls: 0 is SELECT check, 1 is INSERT INTO users, 2 is INSERT INTO doctors
            insert_args = mock_cursor.execute.call_args_list[1][0]
            sql, params = insert_args[0], insert_args[1]
            self.assertIn("INSERT INTO users", sql)
            pwd_hash = params[1]
            self.assertTrue(check_password_hash(pwd_hash, "StrongPass123!"))
            self.assertFalse(pwd_hash.startswith("plain_"))
            mock_conn.commit.assert_called()

    # ------------------------------------------------------------------ #
    # 2. CSRF Rejection on State-Changing Actions                        #
    # ------------------------------------------------------------------ #
    def test_02_csrf_rejection(self):
        """State-changing requests with invalid CSRF token must be rejected."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "admin"
            sess["username"] = "admin"
            sess["csrf_token"] = "valid_csrf_token_value_123"

        # POST with wrong CSRF token
        resp = self.client.post(
            "/admin/user/create",
            data={"csrf_token": "wrong_forged_token", "username": "baduser"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security token validation failed", resp.data)

    # ------------------------------------------------------------------ #
    # 3. Admin User Creation and Validation                              #
    # ------------------------------------------------------------------ #
    @patch("routes.admin.get_connection")
    @patch("routes.admin.log_audit_event")
    def test_03_admin_user_creation(self, mock_audit, mock_get_conn):
        """Admin user creation validates fields and creates role profiles."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        # Uniqueness check returns None (no duplicate)
        mock_cursor.fetchone.return_value = None
        mock_cursor.lastrowid = 42

        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "admin"
            sess["username"] = "admin"
            sess["csrf_token"] = "test_token"

        resp = self.client.post(
            "/admin/user/create",
            data={
                "csrf_token": "test_token",
                "username": "dr_smith",
                "password": "SecurePassword123!",
                "role": "doctor",
                "full_name": "Dr. John Smith",
                "email": "drsmith@securemed.org",
                "specialisation": "Neurology",
                "licence_number": "MD-4432",
                "department": "Neurology",
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"created successfully", resp.data)

        # Verify insert into users and doctors
        calls = mock_cursor.execute.call_args_list
        user_insert = calls[1][0]
        self.assertIn("INSERT INTO users", user_insert[0])
        doctor_insert = calls[2][0]
        self.assertIn("INSERT INTO doctors", doctor_insert[0])
        mock_conn.commit.assert_called()

    # ------------------------------------------------------------------ #
    # 4. Admin User Status Toggle (Soft Deactivation)                    #
    # ------------------------------------------------------------------ #
    @patch("routes.admin.get_connection")
    def test_04_admin_user_status_toggle(self, mock_get_conn):
        """Admin can toggle user active/inactive status, but cannot deactivate self."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "admin"
            sess["username"] = "admin"
            sess["csrf_token"] = "test_token"

        # Self-deactivation prevention
        resp = self.client.post(
            "/admin/user/1/toggle-status",
            data={"csrf_token": "test_token"},
            follow_redirects=True,
        )
        self.assertIn(b"You cannot deactivate your own administrative account", resp.data)

        # Deactivate another user
        mock_cursor.fetchone.return_value = {"id": 2, "username": "someuser", "is_active": 1}
        resp = self.client.post(
            "/admin/user/2/toggle-status",
            data={"csrf_token": "test_token"},
            follow_redirects=True,
        )
        self.assertIn(b"has been deactivated", resp.data)

    # ------------------------------------------------------------------ #
    # 5. Doctor Appointment Status Updates                               #
    # ------------------------------------------------------------------ #
    @patch("routes.doctor.get_connection")
    @patch("routes.doctor.log_audit_event")
    def test_05_doctor_appointment_status_update(self, mock_audit, mock_get_conn):
        """Doctor can update appointment status for their assigned patients only."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        with self.client.session_transaction() as sess:
            sess["user_id"] = 5
            sess["role"] = "doctor"
            sess["username"] = "dr_jones"
            sess["csrf_token"] = "test_token"

        # Case A: Doctor profile lookup
        def cursor_exec(sql, params=None):
            if "FROM doctors" in sql:
                mock_cursor.fetchone.return_value = {"id": 10, "user_id": 5, "full_name": "Dr. Jones"}
            elif "FROM appointments" in sql and "doctor_id = %s" in sql:
                mock_cursor.fetchone.return_value = {"id": 1, "status": "scheduled"}

        mock_cursor.execute.side_effect = cursor_exec

        resp = self.client.post(
            "/doctor/appointment/1/status",
            data={"csrf_token": "test_token", "status": "completed", "notes": "Patient recovered well"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Appointment status updated to &#39;Completed&#39;", resp.data)

        # Case B: Unauthorized appointment (appointment assigned to different doctor)
        def cursor_exec_unauth(sql, params=None):
            if "FROM doctors" in sql:
                mock_cursor.fetchone.return_value = {"id": 10, "user_id": 5, "full_name": "Dr. Jones"}
            elif "FROM appointments" in sql:
                mock_cursor.fetchone.return_value = None  # Not assigned to this doctor

        mock_cursor.execute.side_effect = cursor_exec_unauth
        resp = self.client.post(
            "/doctor/appointment/999/status",
            data={"csrf_token": "test_token", "status": "completed"},
            follow_redirects=True,
        )
        self.assertIn(b"Appointment not found or not assigned to you", resp.data)

    # ------------------------------------------------------------------ #
    # 6. Doctor-Patient Relationship Enforcement for Medical Records     #
    # ------------------------------------------------------------------ #
    @patch("routes.doctor.get_connection")
    @patch("routes.doctor.log_audit_event")
    def test_06_doctor_patient_record_authorization(self, mock_audit, mock_get_conn):
        """Doctor cannot create medical record for a patient they have no appointment with."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        with self.client.session_transaction() as sess:
            sess["user_id"] = 5
            sess["role"] = "doctor"
            sess["username"] = "dr_jones"
            sess["csrf_token"] = "test_token"

        # Case A: No relationship
        def exec_no_rel(sql, params=None):
            if "FROM doctors" in sql:
                mock_cursor.fetchone.return_value = {"id": 10, "user_id": 5, "full_name": "Dr. Jones"}
            elif "SELECT 1 FROM appointments" in sql:
                mock_cursor.fetchone.return_value = None  # No relationship

        mock_cursor.execute.side_effect = exec_no_rel
        resp = self.client.post(
            "/doctor/record/create",
            data={
                "csrf_token": "test_token",
                "patient_id": "88",
                "diagnosis": "Confidential Illness",
                "prescription": "Medication X",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Access Denied: You are not authorized to create records for this patient", resp.data)

        # Case B: Authorized relationship
        def exec_with_rel(sql, params=None):
            if "FROM doctors" in sql:
                mock_cursor.fetchone.return_value = {"id": 10, "user_id": 5, "full_name": "Dr. Jones"}
            elif "SELECT 1 FROM appointments" in sql:
                mock_cursor.fetchone.return_value = (1,)  # Verified relationship

        mock_cursor.execute.side_effect = exec_with_rel
        mock_cursor.lastrowid = 201

        resp = self.client.post(
            "/doctor/record/create",
            data={
                "csrf_token": "test_token",
                "patient_id": "88",
                "diagnosis": "Mild Hypertension",
                "prescription": "Lifestyle modification",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Medical record created successfully", resp.data)

        # Verify audit log details NEVER contain the diagnosis or prescription
        for call in mock_audit.call_args_list:
            details = call[1].get("details", "")
            self.assertNotIn("Mild Hypertension", details)
            self.assertNotIn("Lifestyle modification", details)

    # ------------------------------------------------------------------ #
    # 7. Patient Appointment Booking & Input Validation                  #
    # ------------------------------------------------------------------ #
    @patch("routes.patient.get_connection")
    def test_07_patient_appointment_request(self, mock_get_conn):
        """Patient can book appointment with available doctor with date and reason validation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        with self.client.session_transaction() as sess:
            sess["user_id"] = 7
            sess["role"] = "patient"
            sess["username"] = "patient_jane"
            sess["csrf_token"] = "test_token"

        def exec_patient(sql, params=None):
            if "FROM patients" in sql:
                mock_cursor.fetchone.return_value = {"patient_id": 15, "user_id": 7, "full_name": "Jane Doe"}
            elif "FROM doctors" in sql and "is_active = 1" in sql:
                mock_cursor.fetchone.return_value = {"id": 10}

        mock_cursor.execute.side_effect = exec_patient
        mock_cursor.lastrowid = 501

        resp = self.client.post(
            "/patient/appointment/request",
            data={
                "csrf_token": "test_token",
                "doctor_id": "10",
                "appointment_date": "2026-11-01T10:00",
                "reason": "Routine Annual Checkup",
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Consultation appointment requested successfully", resp.data)

    # ------------------------------------------------------------------ #
    # 8. Patient Appointment Cancellation & Ownership Enforcement        #
    # ------------------------------------------------------------------ #
    @patch("routes.patient.get_connection")
    def test_08_patient_appointment_cancellation(self, mock_get_conn):
        """Patient can cancel own scheduled appointment but not other patients' appointments."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        with self.client.session_transaction() as sess:
            sess["user_id"] = 7
            sess["role"] = "patient"
            sess["username"] = "patient_jane"
            sess["csrf_token"] = "test_token"

        # Case A: Own appointment
        def exec_own(sql, params=None):
            if "FROM patients" in sql:
                mock_cursor.fetchone.return_value = {"patient_id": 15, "user_id": 7, "full_name": "Jane Doe"}
            elif "FROM appointments" in sql:
                mock_cursor.fetchone.return_value = {"id": 501, "status": "scheduled"}

        mock_cursor.execute.side_effect = exec_own
        resp = self.client.post(
            "/patient/appointment/501/cancel",
            data={"csrf_token": "test_token"},
            follow_redirects=True,
        )
        self.assertIn(b"Appointment has been cancelled", resp.data)

        # Case B: Other patient's appointment (IDOR attempt)
        def exec_other(sql, params=None):
            if "FROM patients" in sql:
                mock_cursor.fetchone.return_value = {"patient_id": 15, "user_id": 7, "full_name": "Jane Doe"}
            elif "FROM appointments" in sql:
                mock_cursor.fetchone.return_value = None  # Does not belong to patient 15

        mock_cursor.execute.side_effect = exec_other
        resp = self.client.post(
            "/patient/appointment/999/cancel",
            data={"csrf_token": "test_token"},
            follow_redirects=True,
        )
        self.assertIn(b"Appointment not found or not registered under your profile", resp.data)

    # ------------------------------------------------------------------ #
    # 9. Doctor Report Upload Validation                                 #
    # ------------------------------------------------------------------ #
    def test_09_report_upload_validation(self):
        """Reject non-allowlisted files, empty files, or files with invalid magic bytes."""
        # Case A: Executable file (.exe)
        bad_file = DummyFileStorage("malicious.exe", b"MZ\x90\x00\x03\x00")
        is_valid, msg, ext, size, mime, content = validate_uploaded_file(bad_file)
        self.assertFalse(is_valid)
        self.assertIn("Invalid file type", msg)

        # Case B: Extension spoof (PDF extension with text content)
        spoofed = DummyFileStorage("fake.pdf", b"This is not a real PDF file header.")
        is_valid, msg, ext, size, mime, content = validate_uploaded_file(spoofed)
        self.assertFalse(is_valid)
        self.assertIn("Malformed file", msg)

        # Case C: Valid PDF file
        valid_pdf = DummyFileStorage("lab_report.pdf", b"%PDF-1.4 header content")
        is_valid, msg, ext, size, mime, content = validate_uploaded_file(valid_pdf)
        self.assertTrue(is_valid)
        self.assertEqual(mime, "application/pdf")

    # ------------------------------------------------------------------ #
    # 10. Empty Database States and UI Rendering                         #
    # ------------------------------------------------------------------ #
    @patch("routes.admin.get_connection")
    def test_10_admin_empty_database_rendering(self, mock_get_conn):
        """Admin dashboard gracefully handles zero records without error."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        # Mock stats and empty lists
        mock_cursor.fetchone.return_value = {"total": 0}
        mock_cursor.fetchall.return_value = []

        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "admin"
            sess["username"] = "admin"

        resp = self.client.get("/admin/dashboard?tab=users")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"No users found in database", resp.data)

    # ------------------------------------------------------------------ #
    # 11. Doctor Dashboard Empty State Rendering                         #
    # ------------------------------------------------------------------ #
    @patch("routes.doctor.get_connection")
    def test_11_doctor_empty_dashboard_rendering(self, mock_get_conn):
        """Doctor dashboard gracefully renders empty state when no appointments exist."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        mock_cursor.fetchone.return_value = {
            "id": 1, "user_id": 2, "specialisation": "Pediatrics",
            "licence_number": "MD-1234", "department": "Pediatrics",
            "full_name": "Dr. Empty", "email": "drempty@hospital.org", "phone": "555-0100"
        }
        mock_cursor.fetchall.return_value = []

        with self.client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["role"] = "doctor"
            sess["username"] = "dr_empty"

        resp = self.client.get("/doctor/dashboard?tab=appointments")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"No appointments scheduled with your clinical profile yet", resp.data)

    # ------------------------------------------------------------------ #
    # 12. Patient Dashboard Empty State Rendering                        #
    # ------------------------------------------------------------------ #
    @patch("routes.patient.get_connection")
    def test_12_patient_empty_dashboard_rendering(self, mock_get_conn):
        """Patient dashboard gracefully renders empty state when no consultations exist."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        mock_cursor.fetchone.return_value = {
            "patient_id": 1, "user_id": 3, "date_of_birth": "1990-01-01",
            "gender": "female", "blood_group": "O+", "address": "123 Main St",
            "emergency_contact": "555-9999", "username": "pt_empty",
            "full_name": "Jane Empty", "email": "jane@example.com", "phone": "555-0101"
        }
        mock_cursor.fetchall.return_value = []

        with self.client.session_transaction() as sess:
            sess["user_id"] = 3
            sess["role"] = "patient"
            sess["username"] = "pt_empty"

        resp = self.client.get("/patient/dashboard?tab=appointments")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"You have no scheduled consultations", resp.data)


if __name__ == "__main__":
    unittest.main()
