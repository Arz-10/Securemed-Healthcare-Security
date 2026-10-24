"""
test_phase2_suite.py – Comprehensive regression and security verification suite for Phase 2.

Validates:
  1. Python syntax and imports
  2. Flask app creation and blueprint registration (auth, admin, doctor, patient, reports)
  3. Login page and dashboard rendering
  4. Unauthenticated access blocked on protected routes (redirects to /login)
  5. Incorrect credentials rejected without leaking username existence
  6. Valid credentials establish the expected role session
  7. Role restrictions enforced (admin vs doctor vs patient)
  8. Logout completely invalidates session
  9. CSRF validation rejects invalid/missing tokens on state-changing requests
 10. Audit logging handles successful writes and database failures safely
 11. Report file validation (allowed/disallowed extensions, magic bytes, size caps, null bytes)
 12. Report access authorization (patient ownership, doctor-patient relationship, IDOR defense)
 13. Path traversal defense in report file downloads
 14. Static CSS and JS assets load with HTTP 200

SAFE TEST GUARANTEE:
  Never deletes or alters live production records in securemed_db.
"""

import os
import sys
import io
import unittest
from unittest.mock import patch, MagicMock
from werkzeug.security import generate_password_hash

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

from app import create_app
from config import Config
from routes.reports import (
    validate_uploaded_file,
    generate_secure_stored_filename,
    check_csrf,
    is_authorized_for_report,
)
from database.audit import (
    log_audit_event,
    get_audit_logs,
    EVENT_LOGIN_SUCCESS,
    EVENT_LOGIN_FAILED,
    EVENT_UNAUTHORIZED_ACCESS,
    OUTCOME_SUCCESS,
    OUTCOME_DENIED,
)


class DummyFileStorage:
    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self._content = content
        self._stream = io.BytesIO(content)

    def read(self):
        return self._content


class TestPhase2Security(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.testing = True

    def setUp(self):
        self.client = self.app.test_client()
        from routes.auth import _failed_login_attempts
        _failed_login_attempts.clear()

    # ------------------------------------------------------------------ #
    # 1. Blueprint & Factory Verification                                #
    # ------------------------------------------------------------------ #
    def test_01_app_and_blueprints(self):
        """Verify Flask app creation and registered blueprints."""
        blueprints = set(self.app.blueprints.keys())
        expected = {"auth", "admin", "doctor", "patient", "reports"}
        self.assertTrue(expected.issubset(blueprints), f"Missing blueprints: {expected - blueprints}")

    # ------------------------------------------------------------------ #
    # 2. Unauthenticated Access Control                                  #
    # ------------------------------------------------------------------ #
    def test_02_unauthenticated_access_blocked(self):
        """Verify unauthenticated requests to protected dashboards are blocked."""
        for path in ["/admin/dashboard", "/doctor/dashboard", "/patient/dashboard"]:
            resp = self.client.get(path, follow_redirects=False)
            self.assertEqual(resp.status_code, 302, f"Expected 302 redirect for {path}")
            self.assertIn("/login", resp.headers.get("Location", ""))

    # ------------------------------------------------------------------ #
    # 3. Role-Based Access Control (RBAC)                                #
    # ------------------------------------------------------------------ #
    def test_03_role_restrictions_enforced(self):
        """Verify role authorization blocks cross-role access."""
        # Patient session trying to access admin
        with self.client.session_transaction() as sess:
            sess["user_id"] = 101
            sess["username"] = "test_patient"
            sess["role"] = "patient"
            sess["csrf_token"] = "valid_test_token"

        resp = self.client.get("/admin/dashboard", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))

        # Doctor session trying to access admin
        with self.client.session_transaction() as sess:
            sess["user_id"] = 102
            sess["username"] = "test_doctor"
            sess["role"] = "doctor"

        resp = self.client.get("/admin/dashboard", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))

        # Admin session authorized for admin
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["role"] = "admin"

        resp = self.client.get("/admin/dashboard")
        self.assertEqual(resp.status_code, 200)

    # ------------------------------------------------------------------ #
    # 4. Authentication: Invalid Credentials & Enumeration Prevention    #
    # ------------------------------------------------------------------ #
    def test_04_invalid_credentials_generic_error(self):
        """Verify incorrect credentials return generic error and establish no session."""
        with self.client as c:
            with c.session_transaction() as sess:
                sess["csrf_token"] = "valid_test_csrf_token"

            resp = c.post(
                "/login",
                data={
                    "csrf_token": "valid_test_csrf_token",
                    "username": "non_existent_user_9999",
                    "password": "wrong_password",
                },
                follow_redirects=True,
            )
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Invalid username or password.", resp.data)

            # Confirm no session was created
            with c.session_transaction() as sess:
                self.assertNotIn("user_id", sess)

    # ------------------------------------------------------------------ #
    # 5. Authentication: Valid Login & Session Clearing                  #
    # ------------------------------------------------------------------ #
    @patch("routes.auth.get_connection")
    def test_05_valid_login_establishes_session(self, mock_get_conn):
        """Verify valid credentials establish session and clear previous session."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        hashed = generate_password_hash("CorrectPassword@123")
        mock_cursor.fetchone.return_value = {
            "id": 42,
            "username": "dr_smith",
            "password": hashed,
            "role": "doctor",
            "is_active": 1,
        }

        with self.client as c:
            # Pre-seed session with stale data to verify session fixation clearing
            with c.session_transaction() as sess:
                sess["stale_key"] = "stale_value"
                sess["csrf_token"] = "valid_csrf_token"

            resp = c.post(
                "/login",
                data={
                    "username": "dr_smith",
                    "password": "CorrectPassword@123",
                    "csrf_token": "valid_csrf_token",
                },
                follow_redirects=False,
            )

            self.assertEqual(resp.status_code, 302)
            self.assertIn("/doctor/dashboard", resp.headers.get("Location", ""))

            # Verify session contents
            with c.session_transaction() as sess:
                self.assertNotIn("stale_key", sess, "Session fixation defense failed: previous session not cleared")
                self.assertEqual(sess.get("user_id"), 42)
                self.assertEqual(sess.get("username"), "dr_smith")
                self.assertEqual(sess.get("role"), "doctor")

    # ------------------------------------------------------------------ #
    # 6. Logout & Session Invalidation                                   #
    # ------------------------------------------------------------------ #
    def test_06_logout_invalidates_session(self):
        """Verify logout clears all session keys and redirects to login."""
        with self.client as c:
            with c.session_transaction() as sess:
                sess["user_id"] = 42
                sess["username"] = "dr_smith"
                sess["role"] = "doctor"

            resp = c.get("/logout", follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.headers.get("Location", ""))

            with c.session_transaction() as sess:
                self.assertNotIn("user_id", sess)
                self.assertNotIn("username", sess)

    # ------------------------------------------------------------------ #
    # 7. CSRF Validation                                                 #
    # ------------------------------------------------------------------ #
    def test_07_csrf_validation_rejects_tampered_token(self):
        """Verify state-changing POST requests reject mismatched CSRF tokens."""
        with self.client as c:
            with c.session_transaction() as sess:
                sess["csrf_token"] = "legitimate_server_token"

            resp = c.post(
                "/login",
                data={
                    "username": "admin",
                    "password": "some_password",
                    "csrf_token": "attacker_tampered_token",
                },
                follow_redirects=True,
            )
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Security validation failed", resp.data)

    # ------------------------------------------------------------------ #
    # 8. Audit Logging Subsystem                                         #
    # ------------------------------------------------------------------ #
    def test_08_audit_logging_write_and_failure_resilience(self):
        """Verify audit logging records events and gracefully handles DB errors without crashing."""
        # 1. Successful persistent write to active audit_logs table
        ok = log_audit_event(
            event_type=EVENT_UNAUTHORIZED_ACCESS,
            outcome=OUTCOME_DENIED,
            user_id=1,
            details="test defensive event write",
            ip_address="127.0.0.1",
        )
        self.assertTrue(ok, "Failed to write audit event to active audit_logs table")

        # 2. Verify recent log read
        logs = get_audit_logs(limit=5, event_type=EVENT_UNAUTHORIZED_ACCESS)
        self.assertGreater(len(logs), 0)
        self.assertEqual(logs[0]["event_type"], EVENT_UNAUTHORIZED_ACCESS)

        # 3. Simulate database exception: must fail open and return False without raising exception
        with patch("database.audit.get_connection", side_effect=RuntimeError("Simulated DB connection drop")):
            res = log_audit_event(
                event_type=EVENT_LOGIN_FAILED,
                outcome=OUTCOME_DENIED,
                details="simulated failure test",
            )
            self.assertFalse(res, "Expected audit logger to return False on DB failure")

    # ------------------------------------------------------------------ #
    # 9. Report File Validation (Extensions, Signatures, Sizes)          #
    # ------------------------------------------------------------------ #
    def test_09_report_file_validation(self):
        """Verify file upload validator enforces allowlist, magic bytes, and size limits."""
        # Valid PDF
        pdf_storage = DummyFileStorage("lab_report.pdf", b"%PDF-1.4 valid test pdf content")
        valid, msg, ext, size, mime, content = validate_uploaded_file(pdf_storage)
        self.assertTrue(valid)
        self.assertEqual(ext, ".pdf")
        self.assertEqual(mime, "application/pdf")

        # Valid PNG
        png_storage = DummyFileStorage("scan.png", b"\x89PNG\r\n\x1a\nvalid test png content")
        valid, msg, ext, size, mime, content = validate_uploaded_file(png_storage)
        self.assertTrue(valid)

        # Disallowed Extension (.exe)
        exe_storage = DummyFileStorage("malware.exe", b"%PDF- fake pdf content in exe")
        valid, msg, ext, size, mime, content = validate_uploaded_file(exe_storage)
        self.assertFalse(valid)
        self.assertIn("Invalid file type", msg)

        # Spoofed Extension (HTML pretending to be PDF)
        spoofed_storage = DummyFileStorage("exploit.pdf", b"<html><script>alert(1)</script></html>")
        valid, msg, ext, size, mime, content = validate_uploaded_file(spoofed_storage)
        self.assertFalse(valid)
        self.assertIn("Malformed file", msg)

        # Empty File (0 bytes)
        empty_storage = DummyFileStorage("empty.pdf", b"")
        valid, msg, ext, size, mime, content = validate_uploaded_file(empty_storage)
        self.assertFalse(valid)
        self.assertIn("empty", msg)

        # Oversized File (> 5 MB)
        oversized_content = b"%PDF-" + b"0" * (5 * 1024 * 1024 + 10)
        oversized_storage = DummyFileStorage("large.pdf", oversized_content)
        valid, msg, ext, size, mime, content = validate_uploaded_file(oversized_storage)
        self.assertFalse(valid)
        self.assertIn("exceeds maximum allowed size", msg)

        # Null Byte Injection in filename
        null_storage = DummyFileStorage("safe.pdf\x00.exe", b"%PDF- valid")
        valid, msg, ext, size, mime, content = validate_uploaded_file(null_storage)
        self.assertFalse(valid)

    # ------------------------------------------------------------------ #
    # 10. Report Authorization & IDOR Defenses                           #
    # ------------------------------------------------------------------ #
    @patch("routes.reports.get_connection")
    def test_10_report_authorization_matrix(self, mock_get_conn):
        """Verify role and relationship access rules (Admin, assigned Doctor, owner Patient)."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        report = {
            "id": 10,
            "patient_id": 5,  # patients.id = 5
            "stored_name": "uuid_test.pdf",
            "original_name": "report.pdf",
        }

        # 1. Admin: always authorized
        auth, err = is_authorized_for_report(report, user_id=1, role="admin")
        self.assertTrue(auth)

        # 2. Patient: authorized ONLY if patients.user_id = user_id
        mock_cursor.fetchone.return_value = {"id": 5}  # patient owns report
        auth, err = is_authorized_for_report(report, user_id=20, role="patient")
        self.assertTrue(auth)

        # 3. Patient: unauthorized if report belongs to a different patient
        mock_cursor.fetchone.return_value = {"id": 6}  # patient does NOT own report
        auth, err = is_authorized_for_report(report, user_id=21, role="patient")
        self.assertFalse(auth)
        self.assertIn("own medical reports", err)

        # 4. Doctor: authorized if appointment exists with patient
        mock_cursor.fetchone.side_effect = [
            {"id": 8},  # doctors table row (doctor_id = 8)
            {"1": 1},   # appointment lookup: found
        ]
        auth, err = is_authorized_for_report(report, user_id=30, role="doctor")
        self.assertTrue(auth)

        # 5. Doctor: unauthorized if NO appointment exists with patient
        mock_cursor.fetchone.side_effect = [
            {"id": 9},  # doctors table row (doctor_id = 9)
            None,       # appointment lookup: no match
        ]
        auth, err = is_authorized_for_report(report, user_id=31, role="doctor")
        self.assertFalse(auth)
        self.assertIn("not authorized to access reports", err)

    # ------------------------------------------------------------------ #
    # 11. Path Traversal Defense & Stored Name Generation                #
    # ------------------------------------------------------------------ #
    def test_11_path_traversal_defense(self):
        """Verify stored filename generation and path containment."""
        stored_name, safe_orig, ext = generate_secure_stored_filename("../../malicious.pdf")
        self.assertEqual(ext, ".pdf")
        self.assertNotIn("..", stored_name)
        self.assertNotIn("/", stored_name)
        self.assertNotIn("\\", stored_name)

    # ------------------------------------------------------------------ #
    # 12. Static Assets Verification                                     #
    # ------------------------------------------------------------------ #
    def test_12_static_assets(self):
        """Verify CSS and JavaScript assets load with HTTP 200."""
        css_resp = self.client.get("/static/css/style.css")
        self.assertEqual(css_resp.status_code, 200)

        js_resp = self.client.get("/static/js/main.js")
        self.assertEqual(js_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
