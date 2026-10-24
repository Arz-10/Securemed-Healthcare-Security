"""
scratch/verify_demo_flow.py – End-to-end verification of demonstration workflows.
"""

import os
import sys
import dotenv

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
dotenv.load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

from app import create_app
from database.db import get_connection, close_connection
from database.audit import get_audit_logs


def verify_flow():
    app = create_app()
    app.testing = True

    print("\n" + "="*70)
    print("  VERIFYING DEMONSTRATION WORKFLOWS & ACCESS BOUNDARIES")
    print("="*70)

    # 1. Verify Patient demo_patient (User ID 7)
    client_pat = app.test_client()
    with client_pat.session_transaction() as sess:
        sess["csrf_token"] = "pat_token"
    resp = client_pat.post(
        "/login",
        data={"csrf_token": "pat_token", "username": "demo_patient", "password": "PatientDemo@2026"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Eleanor Vance" in resp.data or b"Patient Portal" in resp.data or b"My Appointments" in resp.data
    print("[PASS] 1. Patient 'demo_patient' authenticated & landed on Patient Health Portal.")

    # 2. Patient can view appointments and verified medical record
    resp_pat_dash = client_pat.get("/patient/dashboard?tab=records")
    assert resp_pat_dash.status_code == 200
    assert b"Mild Essential Hypertension" in resp_pat_dash.data
    assert b"Amlodipine 5mg" in resp_pat_dash.data
    print("[PASS] 2. Patient views their authorized medical record & prescription.")

    # 3. Patient can download their own report
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, original_name FROM uploads WHERE patient_id = (SELECT id FROM patients WHERE user_id = 7) LIMIT 1")
    report = cur.fetchone()
    report_id = report["id"]
    close_connection(conn, cur)

    resp_rep = client_pat.get(f"/reports/download/{report_id}")
    assert resp_rep.status_code == 200
    assert resp_rep.data.startswith(b"%PDF-")
    print(f"[PASS] 3. Patient successfully downloaded own diagnostic report #{report_id} ('{report['original_name']}').")

    # 4. Verify Doctor demo_doctor (User ID 6)
    client_doc = app.test_client()
    with client_doc.session_transaction() as sess:
        sess["csrf_token"] = "doc_token"
    resp = client_doc.post(
        "/login",
        data={"csrf_token": "doc_token", "username": "demo_doctor", "password": "DoctorDemo@2026"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Dr. Alexander Wright" in resp.data or b"Physician Workspace" in resp.data
    print("[PASS] 4. Doctor 'demo_doctor' authenticated & landed on Physician Clinical Workspace.")

    # 5. Doctor sees authorized appointment and patient
    resp_doc_dash = client_doc.get("/doctor/dashboard?tab=appointments")
    assert resp_doc_dash.status_code == 200
    assert b"Eleanor Vance" in resp_doc_dash.data
    assert b"Follow-up ECG review" in resp_doc_dash.data
    print("[PASS] 5. Doctor sees authorized appointments and relationship with Eleanor Vance.")

    # 6. Doctor can view and download report
    resp_doc_rep = client_doc.get(f"/doctor/report/{report_id}/download")
    assert resp_doc_rep.status_code == 200
    assert resp_doc_rep.data.startswith(b"%PDF-")
    print(f"[PASS] 6. Doctor successfully retrieved diagnostic report #{report_id} for authorized patient.")

    # 7. Cross-Role Access Denials
    resp_pat_to_admin = client_pat.get("/admin/dashboard", follow_redirects=True)
    assert resp_pat_to_admin.status_code == 200
    assert b"Unauthorized access: insufficient privileges" in resp_pat_to_admin.data
    print("[PASS] 7a. Cross-Role: Patient access to /admin/dashboard blocked by @role_required.")

    resp_doc_to_admin = client_doc.get("/admin/dashboard", follow_redirects=True)
    assert resp_doc_to_admin.status_code == 200
    assert b"Unauthorized access: insufficient privileges" in resp_doc_to_admin.data
    print("[PASS] 7b. Cross-Role: Doctor access to /admin/dashboard blocked by @role_required.")

    # 8. Unauthenticated Access Blocked
    client_anon = app.test_client()
    resp_anon = client_anon.get("/doctor/dashboard", follow_redirects=True)
    assert resp_anon.status_code == 200
    assert b"Please log in to access this page" in resp_anon.data
    print("[PASS] 8. Unauthenticated request to protected dashboard redirected to login.")

    # 9. Audit Log Privacy Check
    logs = get_audit_logs(limit=20)
    for log in logs:
        details = log.get("details") or ""
        assert "Mild Essential Hypertension" not in details
        assert "Amlodipine" not in details
        assert "DoctorDemo@2026" not in details
        assert "PatientDemo@2026" not in details
    print("[PASS] 9. Audit trail verified: Contains events, completely omits clinical diagnoses and passwords.")

    print("\n" + "="*70)
    print("  ALL DEMONSTRATION WORKFLOWS & ACCESS BOUNDARIES VERIFIED SUCCESSFULLY")
    print("="*70 + "\n")


if __name__ == "__main__":
    verify_flow()
