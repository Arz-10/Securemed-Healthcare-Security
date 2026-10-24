"""
routes/admin.py – Administrator management subsystem.

Features:
  - Role-protected dashboard with live database metrics
  - User creation with validation, Werkzeug password hashing, and role binding
  - User active/inactive status toggling (soft-deactivation)
  - System-wide oversight for doctors, patients, and appointments
  - Paginated/filtered audit log inspection
  - Medical report metadata management and secure file deletion
"""

import os
import re
from flask import (
    Blueprint,
    render_template,
    session,
    redirect,
    url_for,
    request,
    flash,
    current_app,
)
from werkzeug.security import generate_password_hash
from database.db import get_connection, close_connection
from database.audit import (
    log_audit_event,
    get_audit_logs,
    get_audit_logs_count,
    EVENT_USER_MANAGEMENT,
    EVENT_REPORT_DELETION,
    EVENT_UNAUTHORIZED_ACCESS,
    OUTCOME_SUCCESS,
    OUTCOME_FAILED,
    OUTCOME_DENIED,
)
from routes.auth import login_required, role_required
from routes.reports import check_csrf, download_report_file

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

VALID_ROLES = {"admin", "doctor", "patient"}


def _validate_username(u: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_-]{3,50}$", u))


def _validate_email(e: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e))


@admin_bp.route("/dashboard")
@login_required
@role_required("admin")
def dashboard():
    """Render administrative console with live database records."""
    active_tab = request.args.get("tab", "overview")
    audit_filter = request.args.get("event_type", "").strip() or None
    outcome_filter = request.args.get("outcome", "").strip() or None
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    per_page = 50
    offset = (page - 1) * per_page
    total_audit_count = 0
    total_pages = 1


    conn = cursor = None
    stats = {"users": 0, "doctors": 0, "patients": 0, "appointments": 0, "reports": 0, "audit_logs": 0}
    users = []
    doctors = []
    patients = []
    appointments = []
    reports = []
    audit_events = []

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. System Statistics
        cursor.execute("SELECT COUNT(*) AS c FROM users")
        stats["users"] = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) AS c FROM doctors")
        stats["doctors"] = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) AS c FROM patients")
        stats["patients"] = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) AS c FROM appointments")
        stats["appointments"] = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) AS c FROM uploads")
        stats["reports"] = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) AS c FROM audit_logs")
        stats["audit_logs"] = cursor.fetchone()["c"]

        # 2. Users Table
        cursor.execute(
            """
            SELECT id, username, role, full_name, email, phone, is_active, created_at
            FROM users
            ORDER BY created_at DESC
            LIMIT 200
            """
        )
        users = cursor.fetchall()

        # 3. Doctors Directory
        cursor.execute(
            """
            SELECT d.id AS doctor_id, d.user_id, d.specialisation, d.licence_number, d.department,
                   u.full_name, u.email, u.phone, u.is_active
            FROM doctors d
            JOIN users u ON d.user_id = u.id
            ORDER BY u.full_name ASC
            """
        )
        doctors = cursor.fetchall()

        # 4. Patients Directory
        cursor.execute(
            """
            SELECT p.id AS patient_id, p.user_id, p.date_of_birth, p.gender, p.blood_group,
                   p.emergency_contact, u.full_name, u.email, u.phone, u.is_active
            FROM patients p
            JOIN users u ON p.user_id = u.id
            ORDER BY u.full_name ASC
            """
        )
        patients = cursor.fetchall()

        # 5. Appointments List
        cursor.execute(
            """
            SELECT a.id, a.appointment_date, a.status, a.reason, a.created_at,
                   doc_u.full_name AS doctor_name, pat_u.full_name AS patient_name
            FROM appointments a
            JOIN doctors d ON a.doctor_id = d.id
            JOIN users doc_u ON d.user_id = doc_u.id
            JOIN patients p ON a.patient_id = p.id
            JOIN users pat_u ON p.user_id = pat_u.id
            ORDER BY a.appointment_date DESC
            LIMIT 100
            """
        )
        appointments = cursor.fetchall()

        # 6. Medical Reports Metadata
        cursor.execute(
            """
            SELECT u.id, u.original_name, u.stored_name, u.file_size, u.mime_type, u.upload_date, u.patient_id,
                   COALESCE(pat_u.full_name, 'Unknown') AS patient_name,
                   COALESCE(up_u.full_name, 'System') AS uploader_name,
                   COALESCE(up_u.role, 'system') AS uploader_role
            FROM uploads u
            LEFT JOIN patients p ON u.patient_id = p.id
            LEFT JOIN users pat_u ON p.user_id = pat_u.id
            LEFT JOIN users up_u ON u.uploaded_by = up_u.id
            ORDER BY u.upload_date DESC
            LIMIT 100
            """
        )
        reports = cursor.fetchall()

        # 7. Audit Events with pagination and multi-dimensional filtering
        total_audit_count = get_audit_logs_count(event_type=audit_filter, outcome=outcome_filter)
        total_pages = max(1, (total_audit_count + per_page - 1) // per_page)
        if page > total_pages:
            page = total_pages
            offset = (page - 1) * per_page
        audit_events = get_audit_logs(
            limit=per_page,
            offset=offset,
            event_type=audit_filter,
            outcome=outcome_filter,
        )

    except Exception as exc:
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.warning("Error loading admin dashboard: %s", exc.__class__.__name__)
        flash("Could not load administrative data from database.", "danger")
    finally:
        close_connection(conn, cursor)

    return render_template(
        "admin/dashboard.html",
        active_tab=active_tab,
        stats=stats,
        users=users,
        doctors=doctors,
        patients=patients,
        appointments=appointments,
        reports=reports,
        audit_events=audit_events,
        current_audit_filter=audit_filter or "",
        current_outcome_filter=outcome_filter or "",
        current_page=page,
        total_pages=total_pages,
        total_audit_count=total_audit_count,
    )


@admin_bp.route("/user/create", methods=["POST"])
@login_required
@role_required("admin")
def create_user():
    """Create a new user account and associated role profile."""
    if not check_csrf():
        log_audit_event(
            EVENT_UNAUTHORIZED_ACCESS,
            OUTCOME_DENIED,
            user_id=session.get("user_id"),
            details="CSRF token validation failed on user creation",
        )
        flash("Security token validation failed. Please try again.", "danger")
        return redirect(url_for("admin.dashboard", tab="users"))

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "").strip().lower()
    full_name = (request.form.get("full_name") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    phone = (request.form.get("phone") or "").strip() or None

    # Server-side validation
    if not _validate_username(username):
        flash("Username must be 3-50 alphanumeric characters.", "danger")
        return redirect(url_for("admin.dashboard", tab="users"))

    if len(password) < 8:
        flash("Password must be at least 8 characters long.", "danger")
        return redirect(url_for("admin.dashboard", tab="users"))

    if role not in VALID_ROLES:
        flash(f"Invalid role '{role}' selected.", "danger")
        return redirect(url_for("admin.dashboard", tab="users"))

    if not full_name:
        flash("Full name is required.", "danger")
        return redirect(url_for("admin.dashboard", tab="users"))

    if not _validate_email(email):
        flash("A valid email address is required.", "danger")
        return redirect(url_for("admin.dashboard", tab="users"))

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Uniqueness checks
        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s LIMIT 1", (username, email))
        if cursor.fetchone():
            flash("An account with this username or email already exists.", "danger")
            return redirect(url_for("admin.dashboard", tab="users"))

        hashed_password = generate_password_hash(password)
        cursor.execute(
            """
            INSERT INTO users (username, password, role, full_name, email, phone, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, 1)
            """,
            (username, hashed_password, role, full_name, email, phone),
        )
        user_id = cursor.lastrowid

        # Insert corresponding role profile
        if role == "doctor":
            specialisation = (request.form.get("specialisation") or "").strip() or "General Medicine"
            licence_number = (request.form.get("licence_number") or "").strip() or f"MD-{user_id:04d}"
            department = (request.form.get("department") or "").strip() or "General"
            cursor.execute(
                """
                INSERT INTO doctors (user_id, specialisation, licence_number, department)
                VALUES (%s, %s, %s, %s)
                """,
                (user_id, specialisation, licence_number, department),
            )
        elif role == "patient":
            dob = request.form.get("date_of_birth") or None
            gender = request.form.get("gender") or None
            if gender not in {"male", "female", "other"}:
                gender = None
            blood_group = (request.form.get("blood_group") or "").strip() or None
            emergency_contact = (request.form.get("emergency_contact") or "").strip() or None
            cursor.execute(
                """
                INSERT INTO patients (user_id, date_of_birth, gender, blood_group, emergency_contact)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, dob, gender, blood_group, emergency_contact),
            )

        conn.commit()
        log_audit_event(
            EVENT_USER_MANAGEMENT,
            OUTCOME_SUCCESS,
            user_id=session.get("user_id"),
            details=f"action=create_user, created_user_id={user_id}, role={role}, username={username}",
        )
        flash(f"Account for {full_name} ({role.capitalize()}) created successfully.", "success")

    except Exception as exc:
        if conn:
            conn.rollback()
        log_audit_event(
            EVENT_USER_MANAGEMENT,
            OUTCOME_FAILED,
            user_id=session.get("user_id"),
            details=f"action=create_user, username={username}, error={exc.__class__.__name__}",
        )
        flash("Error creating user account in database.", "danger")
    finally:
        close_connection(conn, cursor)

    return redirect(url_for("admin.dashboard", tab="users"))


@admin_bp.route("/user/<int:id>/toggle-status", methods=["POST"])
@login_required
@role_required("admin")
def toggle_user_status(id: int):
    """Safely activate or deactivate a user account without hard-deleting records."""
    if not check_csrf():
        flash("Security token validation failed.", "danger")
        return redirect(url_for("admin.dashboard", tab="users"))

    if id == session.get("user_id"):
        flash("You cannot deactivate your own administrative account.", "warning")
        return redirect(url_for("admin.dashboard", tab="users"))

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id, username, is_active FROM users WHERE id = %s", (id,))
        user = cursor.fetchone()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("admin.dashboard", tab="users"))

        new_status = 0 if user["is_active"] else 1
        cursor.execute("UPDATE users SET is_active = %s, updated_at = NOW() WHERE id = %s", (new_status, id))
        conn.commit()

        status_text = "activated" if new_status == 1 else "deactivated"
        log_audit_event(
            EVENT_USER_MANAGEMENT,
            OUTCOME_SUCCESS,
            user_id=session.get("user_id"),
            details=f"action=toggle_status, target_user_id={id}, new_status={status_text}",
        )
        flash(f"User {user['username']} has been {status_text}.", "success")

    except Exception as exc:
        if conn:
            conn.rollback()
        flash("Error updating user status.", "danger")
    finally:
        close_connection(conn, cursor)

    return redirect(url_for("admin.dashboard", tab="users"))


@admin_bp.route("/report/<int:id>/download", methods=["GET"])
@login_required
@role_required("admin")
def download_report(id: int):
    """Download report file under administrator privileges."""
    return download_report_file(id)


@admin_bp.route("/report/<int:id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_report(id: int):
    """Delete report metadata and remove physical file from server storage."""
    if not check_csrf():
        log_audit_event(
            EVENT_UNAUTHORIZED_ACCESS,
            OUTCOME_DENIED,
            user_id=session.get("user_id"),
            details=f"action=delete_report, report_id={id}, reason=csrf_failure",
        )
        flash("Invalid security token.", "danger")
        return redirect(url_for("admin.dashboard", tab="reports"))

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT stored_name, original_name FROM uploads WHERE id = %s", (id,))
        rep = cursor.fetchone()
        if not rep:
            flash("Report not found.", "danger")
            return redirect(url_for("admin.dashboard", tab="reports"))

        cursor.execute("DELETE FROM uploads WHERE id = %s", (id,))
        conn.commit()

        # Delete physical file
        stored_name = os.path.basename(rep["stored_name"])
        upload_folder = os.path.abspath(current_app.config["UPLOAD_FOLDER"])
        file_path = os.path.abspath(os.path.join(upload_folder, stored_name))

        if file_path.startswith(upload_folder + os.sep) and os.path.isfile(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass

        log_audit_event(
            EVENT_REPORT_DELETION,
            OUTCOME_SUCCESS,
            user_id=session.get("user_id"),
            details=f"report_id={id}, original_name={rep['original_name']}",
        )
        flash(f"Medical report '{rep['original_name']}' deleted successfully.", "success")

    except Exception as exc:
        if conn:
            conn.rollback()
        log_audit_event(
            EVENT_REPORT_DELETION,
            OUTCOME_FAILED,
            user_id=session.get("user_id"),
            details=f"report_id={id}, error={exc.__class__.__name__}",
        )
        flash("Error deleting medical report.", "danger")
    finally:
        close_connection(conn, cursor)

    return redirect(url_for("admin.dashboard", tab="reports"))
