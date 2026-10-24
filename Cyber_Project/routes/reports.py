"""
routes/reports.py – Secure medical report utilities and file handling.

Security Implementations:
  - File extension allowlist validation
  - Strict magic byte signature verification (PDF, PNG, JPG/JPEG)
  - 5 MB individual file size enforcement
  - Null byte injection prevention
  - Unguessable server-side UUID4 filename generation
  - Canonical path containment verification to defeat path traversal
  - Constant-time CSRF token verification (secrets.compare_digest)
  - Parameterized SQL for all database queries
  - Role-aware authorization logic (Admin, treating Doctor, owner Patient)
  - Security audit logging integration
"""

import os
import uuid
import secrets
from flask import (
    Blueprint,
    current_app,
    session,
    request,
    flash,
    redirect,
    url_for,
    send_from_directory,
    abort,
)
from werkzeug.utils import secure_filename
from database.db import get_connection, close_connection
from database.audit import (
    log_audit_event,
    EVENT_REPORT_DOWNLOAD,
    EVENT_UNAUTHORIZED_ACCESS,
    OUTCOME_SUCCESS,
    OUTCOME_FAILED,
    OUTCOME_DENIED,
)

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")

DEFAULT_ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}
DEFAULT_MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB

# Strict binary magic byte signatures
MAGIC_SIGNATURES = {
    ".pdf": [b"%PDF-"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
}

MIME_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}


def validate_uploaded_file(file_storage):
    """
    Validate uploaded file:
      - File presence
      - Extension allowlist
      - Null byte rejection
      - Empty file rejection
      - Maximum file size (5 MB limit)
      - Content format via magic byte signatures

    Returns:
      (is_valid: bool, error_msg: str or None, ext: str, size: int, mime_type: str, content: bytes)
    """
    if not file_storage or not file_storage.filename or file_storage.filename.strip() == "":
        return False, "No file selected for upload.", None, None, None, None

    filename = file_storage.filename.strip()

    # Reject null bytes in filenames
    if "\x00" in filename:
        return False, "Malformed filename detected.", None, None, None, None

    ext = os.path.splitext(filename)[1].lower()

    allowed = (
        current_app.config.get("ALLOWED_EXTENSIONS", DEFAULT_ALLOWED_EXTENSIONS)
        if current_app
        else DEFAULT_ALLOWED_EXTENSIONS
    )

    if ext not in allowed:
        return (
            False,
            f"Invalid file type '{ext}'. Only PDF, PNG, JPG, and JPEG files are accepted.",
            None,
            None,
            None,
            None,
        )

    # Read content into memory for atomic inspection
    content = file_storage.read()
    file_size = len(content)

    if file_size == 0:
        return False, "The uploaded file is empty (0 bytes).", None, None, None, None

    max_size = (
        current_app.config.get("MAX_UPLOAD_SIZE", DEFAULT_MAX_UPLOAD_SIZE)
        if current_app
        else DEFAULT_MAX_UPLOAD_SIZE
    )

    if file_size > max_size:
        return (
            False,
            f"File exceeds maximum allowed size of 5 MB ({file_size} bytes).",
            None,
            None,
            None,
            None,
        )

    expected_signatures = MAGIC_SIGNATURES.get(ext, [])
    if not any(content.startswith(sig) for sig in expected_signatures):
        return (
            False,
            f"Malformed file: file content does not match valid {ext[1:].upper()} format.",
            None,
            None,
            None,
            None,
        )

    mime_type = MIME_TYPES.get(ext, "application/octet-stream")
    return True, None, ext, file_size, mime_type, content


def generate_secure_stored_filename(original_filename: str) -> tuple[str, str, str]:
    """
    Generate an unguessable server-side stored filename using UUID4.
    Returns:
      (stored_name: str, safe_original_name: str, extension: str)
    """
    ext = os.path.splitext(original_filename)[1].lower()
    stored_name = f"{uuid.uuid4().hex}{ext}"
    safe_orig = secure_filename(original_filename) or f"report{ext}"
    return stored_name, safe_orig, ext


def check_csrf() -> bool:
    """
    Verify CSRF token for state-changing requests using constant-time comparison.
    Both tokens must be non-empty strings and match in constant time.
    """
    expected = session.get("csrf_token")
    token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")

    if not expected or not token or not secrets.compare_digest(str(token), str(expected)):
        return False

    return True


def get_report_by_id(report_id: int):
    """
    Retrieve report record from database by primary key using parameterized query.
    Returns None if not found or on database error.
    """
    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, patient_id, uploaded_by, record_id, original_name, stored_name, file_size, mime_type, upload_date FROM uploads WHERE id = %s",
            (int(report_id),)
        )
        return cursor.fetchone()
    except Exception as exc:
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.warning("Error querying report by id: %s", exc.__class__.__name__)
        return None
    finally:
        close_connection(conn, cursor)


def is_authorized_for_report(report: dict, user_id: int, role: str) -> tuple[bool, str | None]:
    """
    Check if the user is authorized to access the given report:
      - Admin: authorized for all reports
      - Patient: authorized only if report belongs to this patient profile (patients.user_id = user_id)
      - Doctor: authorized only if doctor has an appointment record with the report's patient

    Never exposes clinical data in return messages.
    """
    if not report:
        return False, "Report not found."

    if role == "admin":
        return True, None

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if role == "patient":
            cursor.execute("SELECT id FROM patients WHERE user_id = %s", (int(user_id),))
            pat = cursor.fetchone()
            if not pat:
                return False, "Patient profile not found."
            if report.get("patient_id") == pat["id"]:
                return True, None
            return False, "Unauthorized: You can only access your own medical reports."

        elif role == "doctor":
            cursor.execute("SELECT id FROM doctors WHERE user_id = %s", (int(user_id),))
            doc = cursor.fetchone()
            if not doc:
                return False, "Doctor profile not found."
            cursor.execute(
                "SELECT 1 FROM appointments WHERE doctor_id = %s AND patient_id = %s LIMIT 1",
                (doc["id"], report.get("patient_id")),
            )
            if cursor.fetchone():
                return True, None
            return False, "Unauthorized: You are not authorized to access reports for this patient."

        return False, "Unauthorized access role."
    except Exception as exc:
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.warning("Authorization query error: %s", exc.__class__.__name__)
        return False, "Authorization check error."
    finally:
        close_connection(conn, cursor)


def download_report_file(report_id: int):
    """
    Secure report download controller with complete access enforcement:
      - Authenticates user from session
      - Verifies patient ownership or doctor relationship
      - Defends against path traversal using canonical path containment checks
      - Serves file safely outside public directory via send_from_directory
      - Records security audit events for both authorized and unauthorized attempts
    """
    if "user_id" not in session:
        log_audit_event(
            EVENT_UNAUTHORIZED_ACCESS,
            OUTCOME_DENIED,
            user_id=None,
            details=f"unauthenticated download attempt for report_id={report_id}",
        )
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("auth.login"))

    user_id = session.get("user_id")
    role = session.get("role")

    report = get_report_by_id(report_id)
    if not report:
        log_audit_event(
            EVENT_REPORT_DOWNLOAD,
            OUTCOME_FAILED,
            user_id=user_id,
            details=f"report_id={report_id} not found",
        )
        abort(404)

    authorized, error_msg = is_authorized_for_report(report, user_id, role)
    if not authorized:
        log_audit_event(
            EVENT_UNAUTHORIZED_ACCESS,
            OUTCOME_DENIED,
            user_id=user_id,
            details=f"unauthorized download attempt: report_id={report_id}",
        )
        abort(403)

    stored_name = os.path.basename(report.get("stored_name", ""))
    upload_folder = os.path.abspath(current_app.config["UPLOAD_FOLDER"])
    file_path = os.path.abspath(os.path.join(upload_folder, stored_name))

    # Path containment check: ensure resolved path is strictly inside upload_folder
    if not stored_name or not file_path.startswith(upload_folder + os.sep) or not os.path.isfile(file_path):
        log_audit_event(
            EVENT_REPORT_DOWNLOAD,
            OUTCOME_FAILED,
            user_id=user_id,
            details=f"report_id={report_id} missing or invalid on disk",
        )
        flash("Report file not found on server storage.", "danger")
        abort(404)

    log_audit_event(
        EVENT_REPORT_DOWNLOAD,
        OUTCOME_SUCCESS,
        user_id=user_id,
        details=f"report_id={report_id}, file_size={report.get('file_size')}",
    )

    return send_from_directory(
        upload_folder,
        stored_name,
        as_attachment=True,
        download_name=report.get("original_name", "medical_report.pdf"),
        mimetype=report.get("mime_type"),
    )


@reports_bp.route("/download/<int:id>", methods=["GET"])
def download(id):
    """Canonical download endpoint for reports."""
    return download_report_file(id)
