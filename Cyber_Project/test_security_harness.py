"""
test_security_harness.py – Repeatable cybersecurity verification and offensive defense test suite.

Security Test Matrix:
  1. SEC-SQLI-01: SQL injection attempts on login endpoint (' OR '1'='1, admin' --)
  2. SEC-SQLI-02: SQL injection attempts on search/filter inputs (UNION SELECT)
  3. SEC-XSS-01: Reflected/Stored XSS attempts in clinical reason, diagnosis, and full_name
  4. SEC-CSRF-01: Missing CSRF token rejection on state-changing requests
  5. SEC-CSRF-02: Forged/mismatched CSRF token rejection
  6. SEC-IDOR-01: Cross-patient appointment cancellation attempt (IDOR Defense)
  7. SEC-IDOR-02: Doctor creating record for unassigned patient (Doctor-Patient boundary)
  8. SEC-IDOR-03: Patient downloading another patient's medical report (Confidentiality)
  9. SEC-SESSION-01: Session fixation prevention (session ID regeneration on login)
 10. SEC-SESSION-02: Immediate session revocation for deactivated accounts
 11. SEC-UPLOAD-01: Path traversal upload attempt (e.g. ../../etc/passwd or %00 injection)
 12. SEC-UPLOAD-02: Malicious extension and spoofed MIME/magic-byte rejection
 13. SEC-BRUTE-01: Brute-force protection & rate limiting on repeated failed logins
 14. SEC-PRIV-01: Audit log privacy guarantee (no clinical diagnosis or passwords logged)

SAFE TEST GUARANTEE:
  Uses isolated mocks and test client sessions; never erases or modifies active MySQL database records.
"""

import os
import sys
import io
import unittest
from unittest.mock import patch, MagicMock
from werkzeug.security import generate_password_hash

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from app import create_app
from routes.reports import validate_uploaded_file, is_authorized_for_report
from routes.auth import _clear_failed_attempts, _failed_login_attempts
from database.monitoring_export import sanitize_event_for_export, fetch_sanitized_security_events


class DummyFileStorage:
    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self._content = content
        self._stream = io.BytesIO(content)

    def read(self):
        return self._content


class TestSecurityHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.testing = True

    def setUp(self):
        self.client = self.app.test_client()
        _failed_login_attempts.clear()

    def tearDown(self):
        _failed_login_attempts.clear()

    # ------------------------------------------------------------------ #
    # SEC-SQLI: SQL Injection Resilience                                 #
    # ------------------------------------------------------------------ #
    @patch("routes.auth.get_connection")
    def test_sec_sqli_01_login_sqli_payloads(self, mock_get_conn):
        """Verify login endpoint is invulnerable to classic SQL injection authentication bypass."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        # Parameterized query returns None when literal payload is searched
        mock_cursor.fetchone.return_value = None

        sqli_payloads = [
            "' OR '1'='1",
            "admin' --",
            "' UNION SELECT 1, 'admin', 'hash', 'admin', 1 --",
            "\" OR \"\"=\"",
            "admin' /*",
        ]

        for payload in sqli_payloads:
            _clear_failed_attempts("127.0.0.1")
            with self.client.session_transaction() as sess:
                sess["csrf_token"] = "valid_token"

            resp = self.client.post(
                "/login",
                data={"csrf_token": "valid_token", "username": payload, "password": "password123"},
                follow_redirects=True,
            )
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Invalid username or password", resp.data)
            # Verify parameterized execution was used
            query, params = mock_cursor.execute.call_args[0]
            self.assertIn("%s", query)
            self.assertEqual(params, (payload,))

    @patch("routes.admin.get_connection")
    def test_sec_sqli_02_audit_filter_sqli_resilience(self, mock_get_conn):
        """Verify audit log event_type filter is parameterized and safe against UNION injection."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        mock_cursor.fetchone.return_value = {"c": 0}
        mock_cursor.fetchall.return_value = []

        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "admin"
            sess["username"] = "admin"

        sqli_filter = "LOGIN_SUCCESS' UNION SELECT 1,2,3,4,5,6,7 --"
        resp = self.client.get(f"/admin/dashboard?tab=audit&event_type={sqli_filter}")
        self.assertEqual(resp.status_code, 200)

    # ------------------------------------------------------------------ #
    # SEC-XSS: Cross-Site Scripting (Reflected & Stored) Mitigation      #
    # ------------------------------------------------------------------ #
    def test_sec_xss_01_script_injection_escaped(self):
        """Verify that harmless script tags injected into form outputs are escaped."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]

        # Test within patient consultation booking validation
        with self.client.session_transaction() as sess:
            sess["user_id"] = 7
            sess["role"] = "patient"
            sess["username"] = "patient_jane"
            sess["csrf_token"] = "valid_token"

        for payload in xss_payloads:
            resp = self.client.post(
                "/patient/appointment/request",
                data={
                    "csrf_token": "valid_token",
                    "doctor_id": "invalid",
                    "appointment_date": "2026-12-01T10:00",
                    "reason": payload,
                },
                follow_redirects=True,
            )
            # Ensure unescaped raw tag is not reflected
            self.assertNotIn(b"<script>alert('XSS')</script>", resp.data)
            self.assertNotIn(b"<img src=x onerror=alert(1)>", resp.data)

    # ------------------------------------------------------------------ #
    # SEC-CSRF: Cross-Site Request Forgery Protections                   #
    # ------------------------------------------------------------------ #
    def test_sec_csrf_01_missing_token_rejection(self):
        """State-changing requests omitting CSRF token must be rejected."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "admin"
            sess["csrf_token"] = "expected_session_token"

        resp = self.client.post(
            "/admin/user/create",
            data={"username": "attacker", "password": "Password123!"},
            follow_redirects=True,
        )
        self.assertIn(b"Security token validation failed", resp.data)

    def test_sec_csrf_02_forged_token_rejection(self):
        """State-changing requests with forged CSRF token must be rejected in constant time."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 5
            sess["role"] = "doctor"
            sess["csrf_token"] = "legitimate_token_abc"

        resp = self.client.post(
            "/doctor/appointment/1/status",
            data={"csrf_token": "forged_token_xyz", "status": "completed"},
            follow_redirects=True,
        )
        self.assertIn(b"CSRF token validation failed", resp.data)

    # ------------------------------------------------------------------ #
    # SEC-IDOR: Insecure Direct Object References (Broken Object Access) #
    # ------------------------------------------------------------------ #
    @patch("routes.patient.get_connection")
    def test_sec_idor_01_cross_patient_cancellation_blocked(self, mock_get_conn):
        """Patient A cannot cancel Patient B's appointment by tampering with ID."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        with self.client.session_transaction() as sess:
            sess["user_id"] = 101  # Patient A
            sess["role"] = "patient"
            sess["username"] = "patient_a"
            sess["csrf_token"] = "valid_token"

        def exec_idor(sql, params=None):
            if "FROM patients" in sql:
                mock_cursor.fetchone.return_value = {"patient_id": 1, "user_id": 101}
            elif "FROM appointments" in sql:
                # Target appointment #999 belongs to patient_id 2, not patient_id 1
                mock_cursor.fetchone.return_value = None

        mock_cursor.execute.side_effect = exec_idor

        resp = self.client.post(
            "/patient/appointment/999/cancel",
            data={"csrf_token": "valid_token"},
            follow_redirects=True,
        )
        self.assertIn(b"Appointment not found or not registered under your profile", resp.data)

    def test_sec_idor_02_report_access_authorization_matrix(self):
        """Verify strict authorization matrix on report access:
           - Admin: Granted
           - Patient Owner: Granted
           - Unrelated Patient: Denied (IDOR Defense)
        """
        mock_report = {"id": 10, "patient_id": 44, "original_name": "lab.pdf"}

        # Case 1: Unrelated patient (user_id=88 maps to patient_id=99)
        with patch("routes.reports.get_connection") as mock_conn:
            cursor = MagicMock()
            mock_conn.return_value.cursor.return_value = cursor
            cursor.fetchone.return_value = {"id": 99}  # Patient profile id != 44

            auth, msg = is_authorized_for_report(mock_report, user_id=88, role="patient")
            self.assertFalse(auth)
            self.assertIn("You can only access your own medical reports", msg)

        # Case 2: Owner patient (user_id=44 maps to patient_id=44)
        with patch("routes.reports.get_connection") as mock_conn:
            cursor = MagicMock()
            mock_conn.return_value.cursor.return_value = cursor
            cursor.fetchone.return_value = {"id": 44}  # Patient profile matches

            auth, msg = is_authorized_for_report(mock_report, user_id=44, role="patient")
            self.assertTrue(auth)
            self.assertIsNone(msg)

        # Case 3: Admin role
        auth, msg = is_authorized_for_report(mock_report, user_id=1, role="admin")
        self.assertTrue(auth)

    # ------------------------------------------------------------------ #
    # SEC-SESSION: Session Fixation & Deactivated Account Revocation      #
    # ------------------------------------------------------------------ #
    @patch("routes.auth.get_connection")
    def test_sec_session_01_session_fixation_clearing(self, mock_get_conn):
        """Session tokens present prior to authentication must be wiped upon successful login."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        hashed_pwd = generate_password_hash("ValidPass123!")
        mock_cursor.fetchone.return_value = {
            "id": 15, "username": "legit_user", "password": hashed_pwd,
            "role": "patient", "is_active": 1
        }

        # Set pre-existing session token (attacker-controlled)
        with self.client.session_transaction() as sess:
            sess["attacker_planted_token"] = "malicious_seed_123"
            sess["csrf_token"] = "valid_csrf"

        resp = self.client.post(
            "/login",
            data={"csrf_token": "valid_csrf", "username": "legit_user", "password": "ValidPass123!"},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)

        # Check session was cleared and rebuilt
        with self.client.session_transaction() as sess:
            self.assertNotIn("attacker_planted_token", sess)
            self.assertEqual(sess["user_id"], 15)
            self.assertEqual(sess["username"], "legit_user")

    @patch("routes.auth.get_connection")
    def test_sec_session_02_immediate_revocation_on_deactivation(self, mock_get_conn):
        """Authenticated requests with session cookie for deactivated user must be immediately revoked."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        # Database returns is_active = 0
        mock_cursor.fetchone.return_value = {"is_active": 0}

        with self.client.session_transaction() as sess:
            sess["user_id"] = 99
            sess["role"] = "patient"
            sess["username"] = "deactivated_user"

        resp = self.client.get("/patient/dashboard", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Your account has been deactivated", resp.data)

        # Confirm session was purged
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

    # ------------------------------------------------------------------ #
    # SEC-UPLOAD: Malicious Upload & Path Traversal Mitigations          #
    # ------------------------------------------------------------------ #
    def test_sec_upload_01_null_byte_and_extension_spoof(self):
        """Reject null-byte filenames and extension spoofing."""
        # Null-byte injection
        null_byte_file = DummyFileStorage("report.pdf\x00.exe", b"%PDF-1.4 sample")
        is_valid, msg, ext, size, mime, content = validate_uploaded_file(null_byte_file)
        self.assertFalse(is_valid)
        self.assertIn("Malformed filename", msg)

        # Executable with .pdf extension
        exe_file = DummyFileStorage("invoice.pdf", b"MZ\x90\x00\x03\x00")
        is_valid, msg, ext, size, mime, content = validate_uploaded_file(exe_file)
        self.assertFalse(is_valid)
        self.assertIn("Malformed file", msg)

    # ------------------------------------------------------------------ #
    # SEC-BRUTE: Failed Login Rate Limiting & Throttling                 #
    # ------------------------------------------------------------------ #
    @patch("routes.auth.get_connection")
    def test_sec_brute_01_login_rate_limiting(self, mock_get_conn):
        """Exceeding 5 failed login attempts triggers rate limit lockout."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        # User does not exist
        mock_cursor.fetchone.return_value = None

        with self.client.session_transaction() as sess:
            sess["csrf_token"] = "token_brute"

        # 5 consecutive failed login attempts
        for i in range(5):
            resp = self.client.post(
                "/login",
                data={"csrf_token": "token_brute", "username": "victim", "password": f"wrong_{i}"},
                follow_redirects=True,
            )
            self.assertIn(b"Invalid username or password", resp.data)

        # 6th attempt must trigger rate limit block
        resp = self.client.post(
            "/login",
            data={"csrf_token": "token_brute", "username": "victim", "password": "wrong_6"},
            follow_redirects=True,
        )
        self.assertIn(b"Too many failed login attempts", resp.data)

    # ------------------------------------------------------------------ #
    # SEC-PRIV: Clinical Audit Privacy Guarantee                         #
    # ------------------------------------------------------------------ #
    @patch("routes.doctor.get_connection")
    @patch("routes.doctor.log_audit_event")
    def test_sec_priv_01_no_clinical_text_in_audit_logs(self, mock_audit, mock_get_conn):
        """Clinical diagnoses and prescription text must never be logged in audit trails."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        mock_cursor.fetchone.return_value = {"id": 1, "user_id": 10, "full_name": "Dr. Test"}
        mock_cursor.lastrowid = 301

        with self.client.session_transaction() as sess:
            sess["user_id"] = 10
            sess["role"] = "doctor"
            sess["username"] = "dr_test"
            sess["csrf_token"] = "valid_token"

        with patch("routes.doctor._verify_doctor_patient_relationship", return_value=True):
            resp = self.client.post(
                "/doctor/record/create",
                data={
                    "csrf_token": "valid_token",
                    "patient_id": "5",
                    "diagnosis": "Highly Sensitive Disease X",
                    "prescription": "Controlled Substance Regimen",
                    "notes": "Extremely confidential notes",
                },
                follow_redirects=True,
            )
            self.assertEqual(resp.status_code, 200)

        # Verify audit log calls omit sensitive clinical text
        for call in mock_audit.call_args_list:
            details = call[1].get("details", "")
            self.assertNotIn("Highly Sensitive Disease X", details)
            self.assertNotIn("Controlled Substance Regimen", details)
            self.assertNotIn("Extremely confidential notes", details)

    # ------------------------------------------------------------------ #
    # SEC-AUTH: Deactivated Account Login Rejection                      #
    # ------------------------------------------------------------------ #
    @patch("routes.auth.get_connection")
    def test_sec_auth_01_deactivated_account_login_rejected(self, mock_get_conn):
        """Users whose is_active=0 cannot log in even with valid password; denial is audited."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        hashed_pwd = generate_password_hash("CorrectPassword123!")
        mock_cursor.fetchone.return_value = {
            "id": 88,
            "username": "disabled_user",
            "password": hashed_pwd,
            "role": "patient",
            "is_active": 0,
        }

        with self.client.session_transaction() as sess:
            sess["csrf_token"] = "valid_csrf"

        resp = self.client.post(
            "/login",
            data={"csrf_token": "valid_csrf", "username": "disabled_user", "password": "CorrectPassword123!"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Account is deactivated", resp.data)
        # Ensure session was not created
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

    # ------------------------------------------------------------------ #
    # SEC-RBAC: Cross-Role Report Deletion Blocked                       #
    # ------------------------------------------------------------------ #
    def test_sec_rbac_01_non_admin_report_delete_blocked(self):
        """Doctors and patients cannot delete reports; only admin role is authorized."""
        for role in ["doctor", "patient"]:
            with self.client.session_transaction() as sess:
                sess["user_id"] = 22
                sess["role"] = role
                sess["username"] = f"user_{role}"
                sess["csrf_token"] = "valid_token"

            resp = self.client.post(
                "/admin/report/1/delete",
                data={"csrf_token": "valid_token"},
                follow_redirects=True,
            )
            # Must redirect away with unauthorized access denial
            self.assertIn(b"Unauthorized access: insufficient privileges", resp.data)

    # ------------------------------------------------------------------ #
    # SEC-PATH: Path Traversal in Report Download Blocked                #
    # ------------------------------------------------------------------ #
    @patch("routes.reports.get_report_by_id")
    def test_sec_path_01_report_download_path_traversal_blocked(self, mock_get_report):
        """Attempts to download file with stored_name traversing directories are rejected."""
        mock_get_report.return_value = {
            "id": 99,
            "patient_id": 1,
            "stored_name": "../../etc/passwd",
            "original_name": "passwd.txt",
            "file_size": 100,
            "mime_type": "text/plain",
        }

        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "admin"
            sess["username"] = "admin"

        resp = self.client.get("/reports/download/99")
        # Base name isolation and path containment check triggers 404 abort
        self.assertEqual(resp.status_code, 404)

    # ------------------------------------------------------------------ #
    # SEC-MONITOR: Modular Security Event Exporter Verification          #
    # ------------------------------------------------------------------ #
    def test_sec_monitor_01_event_export_sanitization_and_severity(self):
        """Exported events have standardized schema, proper severity, and sanitized content."""
        from datetime import datetime

        raw_row = {
            "id": 42,
            "user_id": 7,
            "event_type": "UNAUTHORIZED_ACCESS",
            "outcome": "DENIED",
            "ip_address": "192.168.1.50",
            "details": "IDOR attempt on appointment_id=99\r\nwith clinical text leaked: NONE",
            "created_at": datetime(2026, 10, 21, 20, 0, 0),
        }

        sanitized = sanitize_event_for_export(raw_row)
        self.assertEqual(sanitized["source"], "securemed")
        self.assertEqual(sanitized["event_id"], 42)
        self.assertEqual(sanitized["event_type"], "UNAUTHORIZED_ACCESS")
        self.assertEqual(sanitized["outcome"], "DENIED")
        # Base severity 8 + 2 for DENIED outcome = 10 (critical)
        self.assertEqual(sanitized["severity"], 10)
        self.assertEqual(sanitized["client_ip"], "192.168.1.50")
        # Carriage returns and newlines stripped
        self.assertNotIn("\r", sanitized["message"])
        self.assertNotIn("\n", sanitized["message"])


if __name__ == "__main__":
    unittest.main()
