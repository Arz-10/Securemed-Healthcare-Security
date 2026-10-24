"""
demonstrate_security_controls.py – Repeatable, non-destructive demonstration runner for SecureMed.

Demonstrates the 10 attack prevention and audit evidence scenarios:
  1. Invalid login and failed-login audit event
  2. Rate limiting after repeated failed logins (Brute-Force Protection)
  3. Unauthenticated access to a protected dashboard
  4. Cross-role access denial (RBAC)
  5. Cross-patient IDOR report download attempt
  6. CSRF rejection on a state-changing request
  7. SQL injection payload handling in authentication
  8. XSS payload escaping in patient input
  9. Malicious file-type and spoofed extension rejection
 10. Account deactivation invalidating an active session
"""

import os
import sys
import io
from unittest.mock import patch, MagicMock
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()

from app import create_app
from routes.auth import _clear_failed_attempts, _failed_login_attempts
from routes.reports import validate_uploaded_file, is_authorized_for_report


class DummyFile:
    def __init__(self, filename, content):
        self.filename = filename
        self._content = content
    def read(self):
        return self._content


def print_scenario_header(num, title):
    print(f"\n{'='*75}")
    print(f"SCENARIO {num}: {title}")
    print(f"{'='*75}")


def run_demonstrations():
    app = create_app()
    app.testing = True
    client = app.test_client()

    print("\n" + "#"*75)
    print("  SECUREMED DEFENSIVE CYBERSECURITY DEMONSTRATION & AUDIT EVIDENCE")
    print("#"*75)

    # ------------------------------------------------------------------
    # 1. Invalid Login and Failed-Login Audit Event
    # ------------------------------------------------------------------
    print_scenario_header(1, "Invalid Login & Failed-Login Audit Event")
    _clear_failed_attempts("127.0.0.1")
    with patch("routes.auth.get_connection") as mock_conn, \
         patch("routes.auth.log_audit_event") as mock_audit:
        mock_cursor = MagicMock()
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None  # user not found

        with client.session_transaction() as sess:
            sess["csrf_token"] = "valid_token_1"

        test_user = "unknown_user"
        test_pass = "WrongPassword999!"
        resp = client.post(
            "/login",
            data={"csrf_token": "valid_token_1", "username": test_user, "password": test_pass},
            follow_redirects=True,
        )

        audit_call = mock_audit.call_args_list[-1] if mock_audit.call_args_list else None
        event_type = audit_call[0][0] if audit_call else "N/A"
        outcome = audit_call[0][1] if audit_call else "N/A"
        details = audit_call[1].get("details", "") if audit_call else "N/A"

        print(f"Test Input:       username='{test_user}', password='***'")
        print(f"Expected Defense: Generic authentication error; event recorded in audit log")
        print(f"HTTP Result:      HTTP {resp.status_code} | Flash: 'Invalid username or password.'")
        print(f"Audit Evidence:   event_type='{event_type}', outcome='{outcome}', details='{details}'")
        assert resp.status_code == 200
        assert b"Invalid username or password" in resp.data

    # ------------------------------------------------------------------
    # 2. Rate Limiting After Repeated Failed Logins
    # ------------------------------------------------------------------
    print_scenario_header(2, "Rate Limiting After Repeated Failed Logins")
    _clear_failed_attempts("127.0.0.1")
    with patch("routes.auth.get_connection") as mock_conn, \
         patch("routes.auth.log_audit_event") as mock_audit:
        mock_cursor = MagicMock()
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None

        with client.session_transaction() as sess:
            sess["csrf_token"] = "valid_token_2"

        # Execute 5 failures
        for i in range(5):
            client.post("/login", data={"csrf_token": "valid_token_2", "username": "victim_account", "password": f"bad_{i}"})

        # 6th attempt must trigger rate limiter
        resp = client.post("/login", data={"csrf_token": "valid_token_2", "username": "victim_account", "password": "bad_6"}, follow_redirects=True)
        audit_call = mock_audit.call_args_list[-1] if mock_audit.call_args_list else None
        event_type = audit_call[0][0] if audit_call else "N/A"
        outcome = audit_call[0][1] if audit_call else "N/A"
        details = audit_call[1].get("details", "") if audit_call else "N/A"

        print(f"Test Input:       6 consecutive rapid failed login attempts from client IP")
        print(f"Expected Defense: Sliding-window rate limiter locks out client; records DENIED audit event")
        print(f"HTTP Result:      HTTP {resp.status_code} | Flash: 'Too many failed login attempts.'")
        print(f"Audit Evidence:   event_type='{event_type}', outcome='{outcome}', details='{details}'")
        assert b"Too many failed login attempts" in resp.data
    _clear_failed_attempts("127.0.0.1")

    # ------------------------------------------------------------------
    # 3. Unauthenticated Access to a Protected Dashboard
    # ------------------------------------------------------------------
    print_scenario_header(3, "Unauthenticated Access to Protected Dashboard")
    with patch("routes.auth.log_audit_event") as mock_audit:
        with client.session_transaction() as sess:
            sess.clear()

        resp = client.get("/admin/dashboard", follow_redirects=False)
        audit_call = mock_audit.call_args_list[-1] if mock_audit.call_args_list else None
        event_type = audit_call[0][0] if audit_call else "N/A"
        outcome = audit_call[0][1] if audit_call else "N/A"
        details = audit_call[1].get("details", "") if audit_call else "N/A"

        print(f"Test Input:       GET /admin/dashboard without active session")
        print(f"Expected Defense: Intercepted by @login_required; redirected to /login with warning")
        print(f"HTTP Result:      HTTP {resp.status_code} (Redirect to {resp.headers.get('Location', '')})")
        print(f"Audit Evidence:   event_type='{event_type}', outcome='{outcome}', details='{details}'")
        assert resp.status_code == 302

    # ------------------------------------------------------------------
    # 4. Cross-Role Access Denial (RBAC)
    # ------------------------------------------------------------------
    print_scenario_header(4, "Cross-Role Access Denial (RBAC Boundary)")
    with patch("routes.auth.log_audit_event") as mock_audit:
        with client.session_transaction() as sess:
            sess["user_id"] = 77
            sess["role"] = "patient"
            sess["username"] = "patient_alice"

        resp = client.get("/admin/dashboard", follow_redirects=False)
        audit_call = mock_audit.call_args_list[-1] if mock_audit.call_args_list else None
        event_type = audit_call[0][0] if audit_call else "N/A"
        outcome = audit_call[0][1] if audit_call else "N/A"
        details = audit_call[1].get("details", "") if audit_call else "N/A"

        print(f"Test Input:       Patient session accessing /admin/dashboard")
        print(f"Expected Defense: Intercepted by @role_required('admin'); access denied")
        print(f"HTTP Result:      HTTP {resp.status_code} (Redirect to /login)")
        print(f"Audit Evidence:   event_type='{event_type}', outcome='{outcome}', details='{details}'")
        assert resp.status_code == 302

    # ------------------------------------------------------------------
    # 5. Cross-Patient IDOR Report Download Attempt
    # ------------------------------------------------------------------
    print_scenario_header(5, "Cross-Patient IDOR Report Download Attempt")
    with patch("routes.reports.get_report_by_id") as mock_get_rep, \
         patch("routes.reports.get_connection") as mock_conn, \
         patch("routes.reports.log_audit_event") as mock_audit:
        # Report belongs to patient_id 999
        mock_get_rep.return_value = {"id": 55, "patient_id": 999, "stored_name": "report.pdf", "original_name": "lab.pdf"}
        # Authenticated user is patient_id 111
        cursor = MagicMock()
        mock_conn.return_value.cursor.return_value = cursor
        cursor.fetchone.return_value = {"id": 111}

        with client.session_transaction() as sess:
            sess["user_id"] = 33
            sess["role"] = "patient"
            sess["username"] = "patient_bob"

        resp = client.get("/reports/download/55")
        audit_call = mock_audit.call_args_list[-1] if mock_audit.call_args_list else None
        event_type = audit_call[0][0] if audit_call else "N/A"
        outcome = audit_call[0][1] if audit_call else "N/A"
        details = audit_call[1].get("details", "") if audit_call else "N/A"

        print(f"Test Input:       Patient (ID 111) requests Report 55 owned by Patient 999")
        print(f"Expected Defense: IDOR ownership check fails; returns HTTP 403 Forbidden")
        print(f"HTTP Result:      HTTP {resp.status_code} Forbidden")
        print(f"Audit Evidence:   event_type='{event_type}', outcome='{outcome}', details='{details}'")
        assert resp.status_code == 403

    # ------------------------------------------------------------------
    # 6. CSRF Rejection on State-Changing Request
    # ------------------------------------------------------------------
    print_scenario_header(6, "CSRF Rejection on State-Changing Request")
    with patch("routes.admin.log_audit_event") as mock_audit:
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "admin"
            sess["csrf_token"] = "genuine_token_abc"

        # POST with forged token
        resp = client.post(
            "/admin/user/create",
            data={"csrf_token": "forged_token_xyz", "username": "attacker", "password": "Password123!"},
            follow_redirects=True,
        )
        audit_call = mock_audit.call_args_list[-1] if mock_audit.call_args_list else None
        event_type = audit_call[0][0] if audit_call else "N/A"
        outcome = audit_call[0][1] if audit_call else "N/A"
        details = audit_call[1].get("details", "") if audit_call else "N/A"

        print(f"Test Input:       POST /admin/user/create with mismatched CSRF token")
        print(f"Expected Defense: Constant-time comparison rejects state-changing operation")
        print(f"HTTP Result:      HTTP {resp.status_code} | Flash: 'Security token validation failed.'")
        print(f"Audit Evidence:   event_type='{event_type}', outcome='{outcome}', details='{details}'")
        assert b"Security token validation failed" in resp.data

    # ------------------------------------------------------------------
    # 7. SQL Injection Payload Handling
    # ------------------------------------------------------------------
    print_scenario_header(7, "SQL Injection Payload Handling in Authentication")
    _clear_failed_attempts("127.0.0.1")
    with patch("routes.auth.get_connection") as mock_conn, \
         patch("routes.auth.log_audit_event") as mock_audit:
        mock_cursor = MagicMock()
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None

        with client.session_transaction() as sess:
            sess.clear()
            sess["csrf_token"] = "valid_token_7"

        sqli_payload = "' OR '1'='1"
        resp = client.post(
            "/login",
            data={"csrf_token": "valid_token_7", "username": sqli_payload, "password": "pwd"},
            follow_redirects=True,
        )
        user_query_call = None
        for call_item in mock_cursor.execute.call_args_list:
            if "WHERE username = %s" in call_item[0][0]:
                user_query_call = call_item
                break

        query = user_query_call[0][0] if user_query_call else mock_cursor.execute.call_args[0][0]
        params = user_query_call[0][1] if user_query_call else mock_cursor.execute.call_args[0][1]
        audit_call = mock_audit.call_args_list[-1] if mock_audit.call_args_list else None
        event_type = audit_call[0][0] if audit_call else "N/A"
        outcome = audit_call[0][1] if audit_call else "N/A"

        print(f"Test Input:       username=\"' OR '1'='1\", password='pwd'")
        print(f"Expected Defense: Parameterized SQL (%s placeholder) treats payload as literal; rejects login")
        print(f"Executed SQL:     {query} with params={params}")
        print(f"HTTP Result:      HTTP {resp.status_code} | Flash: 'Invalid username or password.'")
        print(f"Audit Evidence:   event_type='{event_type}', outcome='{outcome}'")
        assert "%s" in query
        assert params == (sqli_payload,)
    _clear_failed_attempts("127.0.0.1")

    # ------------------------------------------------------------------
    # 8. XSS Payload Escaping in Form Output
    # ------------------------------------------------------------------
    print_scenario_header(8, "XSS Payload Escaping in Patient Form Input")
    with client.session_transaction() as sess:
        sess["user_id"] = 7
        sess["role"] = "patient"
        sess["username"] = "patient_x"
        sess["csrf_token"] = "valid_token_8"

    xss_payload = "<script>alert('pwned')</script>"
    resp = client.post(
        "/patient/appointment/request",
        data={
            "csrf_token": "valid_token_8",
            "doctor_id": "invalid_id",
            "appointment_date": "2026-12-01T10:00",
            "reason": xss_payload,
        },
        follow_redirects=True,
    )

    print(f"Test Input:       reason='<script>alert(\\'pwned\\')</script>'")
    print(f"Expected Defense: Jinja2 auto-escapes HTML entities; raw tags never rendered")
    print(f"HTTP Result:      HTTP {resp.status_code} | Raw script tag present in DOM: False")
    assert b"<script>alert('pwned')</script>" not in resp.data

    # ------------------------------------------------------------------
    # 9. Malicious File-Type Rejection
    # ------------------------------------------------------------------
    print_scenario_header(9, "Malicious File-Type & Spoofed Extension Rejection")
    # File named invoice.pdf with Windows executable PE magic bytes
    spoofed_file = DummyFile("invoice.pdf", b"MZ\x90\x00\x03\x00\x00\x00malicious_payload")
    is_valid, err, ext, size, mime, content = validate_uploaded_file(spoofed_file)

    print(f"Test Input:       File 'invoice.pdf' containing binary header 'MZ' (PE Executable)")
    print(f"Expected Defense: Magic-byte validator rejects header mismatch despite valid .pdf extension")
    print(f"Validator Result: is_valid={is_valid} | Error: '{err}'")
    assert not is_valid
    assert "Malformed file" in err

    # ------------------------------------------------------------------
    # 10. Account Deactivation Invalidating an Existing Session
    # ------------------------------------------------------------------
    print_scenario_header(10, "Account Deactivation Invalidating Active Session")
    with patch("routes.auth.get_connection") as mock_conn, \
         patch("routes.auth.log_audit_event") as mock_audit:
        mock_cursor = MagicMock()
        mock_conn.return_value.cursor.return_value = mock_cursor
        # Database reports user is_active = 0
        mock_cursor.fetchone.return_value = {"is_active": 0}

        with client.session_transaction() as sess:
            sess["user_id"] = 88
            sess["role"] = "patient"
            sess["username"] = "disabled_user"

        resp = client.get("/patient/dashboard", follow_redirects=True)
        audit_call = mock_audit.call_args_list[-1] if mock_audit.call_args_list else None
        event_type = audit_call[0][0] if audit_call else "N/A"
        outcome = audit_call[0][1] if audit_call else "N/A"
        details = audit_call[1].get("details", "") if audit_call else "N/A"

        print(f"Test Input:       Active session cookie for user_id=88 with is_active=0 in DB")
        print(f"Expected Defense: Mid-session check purges session; redirects to login with warning")
        print(f"HTTP Result:      HTTP {resp.status_code} | Flash: 'Your account has been deactivated.'")
        print(f"Audit Evidence:   event_type='{event_type}', outcome='{outcome}', details='{details}'")
        assert b"Your account has been deactivated" in resp.data

    print("\n" + "="*75)
    print("  ALL 10 CYBERSECURITY DEFENSE SCENARIOS SUCCESSFULLY DEMONSTRATED")
    print("="*75 + "\n")


if __name__ == "__main__":
    run_demonstrations()
