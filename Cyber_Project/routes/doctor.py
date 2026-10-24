"""
routes/doctor.py – Attending physician clinical portal blueprint.

Workflows & Security Guarantees:
  - Role-protected dashboard (@login_required, @role_required("doctor"))
  - Physician identity resolved strictly from session["user_id"]
  - Appointment oversight and status progression (scheduled -> completed / cancelled)
  - Authorized patient directory (only patients with an appointment relationship)
  - Medical record authoring with strict doctor-patient relationship enforcement
  - Report upload with magic-byte validation and audit logging
  - Secure report download through canonical access controller
  - CSRF verification on all state-changing endpoints
  - Absolute privacy of diagnosis and clinical text in audit logs
"""

import os
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
from database.db import get_connection, close_connection
from database.audit import (
    log_audit_event,
    EVENT_APPOINTMENT_CHANGE,
    EVENT_MEDICAL_RECORD_CHANGE,
    EVENT_REPORT_UPLOAD,
    EVENT_UPLOAD_REJECTED,
    EVENT_UNAUTHORIZED_ACCESS,
    OUTCOME_SUCCESS,
    OUTCOME_FAILED,
    OUTCOME_DENIED,
)
from routes.auth import login_required, role_required
from routes.reports import (
    check_csrf,
    validate_uploaded_file,
    generate_secure_stored_filename,
    download_report_file,
)

doctor_bp = Blueprint("doctor", __name__, url_prefix="/doctor")

VALID_APPOINTMENT_STATUSES = {"scheduled", "completed", "cancelled"}


def _get_doctor_profile(user_id: int):
    """Retrieve doctor profile bound to authenticated user_id."""
    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT d.id, d.user_id, d.specialisation, d.licence_number, d.department,
                   u.full_name, u.email, u.phone
            FROM doctors d
            JOIN users u ON d.user_id = u.id
            WHERE d.user_id = %s
            LIMIT 1
            """,
            (int(user_id),),
        )
        return cursor.fetchone()
    finally:
        close_connection(conn, cursor)


def _verify_doctor_patient_relationship(doctor_id: int, patient_id: int) -> bool:
    """Verify server-side that the doctor has an appointment relationship with patient_id."""
    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM appointments WHERE doctor_id = %s AND patient_id = %s LIMIT 1",
            (int(doctor_id), int(patient_id)),
        )
        return cursor.fetchone() is not None
    finally:
        close_connection(conn, cursor)


@doctor_bp.route("/dashboard")
@login_required
@role_required("doctor")
def dashboard():
    """Render clinical physician workspace with authorized patients, appointments, and records."""
    user_id = session.get("user_id")
    doctor = _get_doctor_profile(user_id)
    if not doctor:
        flash("Physician profile record not found. Please contact an administrator.", "warning")
        return render_template(
            "doctor/dashboard.html",
            doctor=None,
            appointments=[],
            patients=[],
            records=[],
            reports=[],
            active_tab="appointments",
        )

    doctor_id = doctor["id"]
    active_tab = request.args.get("tab", "appointments")

    conn = cursor = None
    appointments = []
    patients = []
    records = []
    reports = []

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Appointments for this doctor
        cursor.execute(
            """
            SELECT a.id, a.patient_id, a.doctor_id, a.appointment_date, a.reason,
                   a.status, a.notes, a.created_at,
                   u.full_name AS patient_name, u.email AS patient_email, u.phone AS patient_phone,
                   p.gender, p.blood_group, p.date_of_birth
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            JOIN users u ON p.user_id = u.id
            WHERE a.doctor_id = %s
            ORDER BY a.appointment_date DESC
            """,
            (doctor_id,),
        )
        appointments = cursor.fetchall()

        # 2. Authorized patients (only patients having appointments with this doctor)
        cursor.execute(
            """
            SELECT p.id AS patient_id, u.full_name, u.email, u.phone,
                   p.date_of_birth, p.gender, p.blood_group, p.emergency_contact,
                   COUNT(a.id) AS appointment_count
            FROM patients p
            JOIN users u ON p.user_id = u.id
            JOIN appointments a ON a.patient_id = p.id
            WHERE a.doctor_id = %s
            GROUP BY p.id, u.full_name, u.email, u.phone, p.date_of_birth, p.gender, p.blood_group, p.emergency_contact
            ORDER BY u.full_name ASC
            """,
            (doctor_id,),
        )
        patients = cursor.fetchall()

        # 3. Medical records created by this doctor
        cursor.execute(
            """
            SELECT m.id, m.patient_id, m.doctor_id, m.appointment_id,
                   m.diagnosis, m.prescription, m.notes, m.record_date,
                   u.full_name AS patient_name,
                   a.appointment_date
            FROM medical_records m
            JOIN patients p ON m.patient_id = p.id
            JOIN users u ON p.user_id = u.id
            LEFT JOIN appointments a ON m.appointment_id = a.id
            WHERE m.doctor_id = %s
            ORDER BY m.record_date DESC
            """,
            (doctor_id,),
        )
        records = cursor.fetchall()

        # 4. Reports for authorized patients
        cursor.execute(
            """
            SELECT up.id, up.patient_id, up.uploaded_by, up.record_id,
                   up.original_name, up.file_size, up.mime_type, up.upload_date,
                   u.full_name AS patient_name,
                   uploader.full_name AS uploader_name
            FROM uploads up
            JOIN patients p ON up.patient_id = p.id
            JOIN users u ON p.user_id = u.id
            JOIN users uploader ON up.uploaded_by = uploader.id
            WHERE up.patient_id IN (
                SELECT DISTINCT patient_id FROM appointments WHERE doctor_id = %s
            )
            ORDER BY up.upload_date DESC
            """,
            (doctor_id,),
        )
        reports = cursor.fetchall()

    except Exception as exc:
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.error("Doctor dashboard query error: %s", exc.__class__.__name__)
        flash("An error occurred while loading clinical records.", "danger")
    finally:
        close_connection(conn, cursor)

    return render_template(
        "doctor/dashboard.html",
        doctor=doctor,
        appointments=appointments,
        patients=patients,
        records=records,
        reports=reports,
        active_tab=active_tab,
    )


@doctor_bp.route("/appointment/<int:id>/status", methods=["POST"])
@login_required
@role_required("doctor")
def update_appointment_status(id: int):
    """Update appointment status (scheduled -> completed/cancelled)."""
    if not check_csrf():
        flash("CSRF token validation failed. Action rejected.", "danger")
        return redirect(url_for("doctor.dashboard", tab="appointments"))

    user_id = session.get("user_id")
    doctor = _get_doctor_profile(user_id)
    if not doctor:
        flash("Physician profile not found.", "danger")
        return redirect(url_for("doctor.dashboard"))

    new_status = (request.form.get("status") or "").strip().lower()
    clinical_notes = (request.form.get("notes") or "").strip() or None

    if new_status not in VALID_APPOINTMENT_STATUSES:
        flash(f"Invalid status '{new_status}'. Allowed: scheduled, completed, cancelled.", "danger")
        return redirect(url_for("doctor.dashboard", tab="appointments"))

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Verify ownership: appointment belongs to this doctor
        cursor.execute(
            "SELECT id, status FROM appointments WHERE id = %s AND doctor_id = %s",
            (int(id), doctor["id"]),
        )
        appt = cursor.fetchone()
        if not appt:
            log_audit_event(
                EVENT_UNAUTHORIZED_ACCESS,
                OUTCOME_DENIED,
                user_id=user_id,
                details=f"doctor_id={doctor['id']} attempted unauthorized status change on appointment_id={id}",
            )
            flash("Appointment not found or not assigned to you.", "danger")
            return redirect(url_for("doctor.dashboard", tab="appointments"))

        # Transition guard: finalized appointments (completed or cancelled) cannot be modified
        if appt["status"] in {"completed", "cancelled"} and appt["status"] != new_status:
            flash(f"Appointment #{id} is already '{appt['status']}' and cannot be modified.", "warning")
            return redirect(url_for("doctor.dashboard", tab="appointments"))


        if clinical_notes:
            cursor.execute(
                "UPDATE appointments SET status = %s, notes = %s WHERE id = %s AND doctor_id = %s",
                (new_status, clinical_notes, int(id), doctor["id"]),
            )
        else:
            cursor.execute(
                "UPDATE appointments SET status = %s WHERE id = %s AND doctor_id = %s",
                (new_status, int(id), doctor["id"]),
            )
        conn.commit()

        log_audit_event(
            EVENT_APPOINTMENT_CHANGE,
            OUTCOME_SUCCESS,
            user_id=user_id,
            details=f"appointment_id={id} status changed to {new_status}",
        )
        flash(f"Appointment status updated to '{new_status.title()}'.", "success")

    except Exception as exc:
        if conn:
            conn.rollback()
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.error("Appointment update error: %s", exc.__class__.__name__)
        flash("Failed to update appointment status.", "danger")
    finally:
        close_connection(conn, cursor)

    return redirect(url_for("doctor.dashboard", tab="appointments"))


@doctor_bp.route("/record/create", methods=["POST"])
@login_required
@role_required("doctor")
def create_medical_record():
    """Create a new medical record for an authorized patient."""
    if not check_csrf():
        flash("CSRF token validation failed. Action rejected.", "danger")
        return redirect(url_for("doctor.dashboard", tab="records"))

    user_id = session.get("user_id")
    doctor = _get_doctor_profile(user_id)
    if not doctor:
        flash("Physician profile not found.", "danger")
        return redirect(url_for("doctor.dashboard"))

    try:
        patient_id = int(request.form.get("patient_id", 0))
    except (ValueError, TypeError):
        flash("Invalid patient selection.", "danger")
        return redirect(url_for("doctor.dashboard", tab="records"))

    appointment_id_raw = request.form.get("appointment_id")
    appointment_id = None
    if appointment_id_raw and appointment_id_raw.strip():
        try:
            appointment_id = int(appointment_id_raw)
        except ValueError:
            appointment_id = None

    diagnosis = (request.form.get("diagnosis") or "").strip()
    prescription = (request.form.get("prescription") or "").strip() or None
    notes = (request.form.get("notes") or "").strip() or None

    if not diagnosis:
        flash("Diagnosis is required to create a medical record.", "danger")
        return redirect(url_for("doctor.dashboard", tab="records"))

    # Server-side doctor-patient relationship authorization
    if not _verify_doctor_patient_relationship(doctor["id"], patient_id):
        log_audit_event(
            EVENT_UNAUTHORIZED_ACCESS,
            OUTCOME_DENIED,
            user_id=user_id,
            details=f"doctor_id={doctor['id']} attempted unauthorized record creation for patient_id={patient_id}",
        )
        flash("Access Denied: You are not authorized to create records for this patient.", "danger")
        return redirect(url_for("doctor.dashboard", tab="records"))

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # If appointment_id provided, verify it belongs to this doctor and patient
        if appointment_id:
            cursor.execute(
                "SELECT id FROM appointments WHERE id = %s AND doctor_id = %s AND patient_id = %s",
                (appointment_id, doctor["id"], patient_id),
            )
            if not cursor.fetchone():
                appointment_id = None

        cursor.execute(
            """
            INSERT INTO medical_records (patient_id, doctor_id, appointment_id, diagnosis, prescription, notes, record_date)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """,
            (patient_id, doctor["id"], appointment_id, diagnosis, prescription, notes),
        )
        conn.commit()
        record_id = cursor.lastrowid

        # Security & Privacy: Never log clinical text or diagnosis in audit logs
        log_audit_event(
            EVENT_MEDICAL_RECORD_CHANGE,
            OUTCOME_SUCCESS,
            user_id=user_id,
            details=f"created record_id={record_id} for patient_id={patient_id}",
        )
        flash("Medical record created successfully.", "success")

    except Exception as exc:
        if conn:
            conn.rollback()
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.error("Medical record creation error: %s", exc.__class__.__name__)
        flash("Failed to save medical record.", "danger")
    finally:
        close_connection(conn, cursor)

    return redirect(url_for("doctor.dashboard", tab="records"))


@doctor_bp.route("/report/upload", methods=["POST"])
@login_required
@role_required("doctor")
def upload_report():
    """Upload a validated diagnostic report for an authorized patient."""
    if not check_csrf():
        flash("CSRF token validation failed. Action rejected.", "danger")
        return redirect(url_for("doctor.dashboard", tab="reports"))

    user_id = session.get("user_id")
    doctor = _get_doctor_profile(user_id)
    if not doctor:
        flash("Physician profile not found.", "danger")
        return redirect(url_for("doctor.dashboard"))

    try:
        patient_id = int(request.form.get("patient_id", 0))
    except (ValueError, TypeError):
        flash("Invalid patient selection.", "danger")
        return redirect(url_for("doctor.dashboard", tab="reports"))

    # Server-side authorization check
    if not _verify_doctor_patient_relationship(doctor["id"], patient_id):
        log_audit_event(
            EVENT_UNAUTHORIZED_ACCESS,
            OUTCOME_DENIED,
            user_id=user_id,
            details=f"doctor_id={doctor['id']} attempted unauthorized report upload for patient_id={patient_id}",
        )
        flash("Access Denied: You are not authorized to upload reports for this patient.", "danger")
        return redirect(url_for("doctor.dashboard", tab="reports"))

    file_storage = request.files.get("report_file")
    is_valid, err_msg, ext, file_size, mime_type, content = validate_uploaded_file(file_storage)

    if not is_valid:
        log_audit_event(
            EVENT_UPLOAD_REJECTED,
            OUTCOME_FAILED,
            user_id=user_id,
            details=f"rejected report upload: {err_msg}",
        )
        flash(err_msg, "danger")
        return redirect(url_for("doctor.dashboard", tab="reports"))

    stored_name, safe_orig, _ = generate_secure_stored_filename(file_storage.filename)
    upload_folder = os.path.abspath(current_app.config["UPLOAD_FOLDER"])
    dest_path = os.path.join(upload_folder, stored_name)

    # Atomic write to storage
    try:
        with open(dest_path, "wb") as f:
            f.write(content)
    except Exception as exc:
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.error("File write error: %s", exc.__class__.__name__)
        flash("Failed to write report to storage.", "danger")
        return redirect(url_for("doctor.dashboard", tab="reports"))

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO uploads (patient_id, uploaded_by, record_id, original_name, stored_name, file_size, mime_type, upload_date)
            VALUES (%s, %s, NULL, %s, %s, %s, %s, NOW())
            """,
            (patient_id, user_id, safe_orig, stored_name, file_size, mime_type),
        )
        conn.commit()
        report_id = cursor.lastrowid

        log_audit_event(
            EVENT_REPORT_UPLOAD,
            OUTCOME_SUCCESS,
            user_id=user_id,
            details=f"report_id={report_id} uploaded for patient_id={patient_id}, size={file_size}",
        )
        flash(f"Report '{safe_orig}' uploaded successfully.", "success")

    except Exception as exc:
        if conn:
            conn.rollback()
        # Clean up orphaned physical file if database insert failed
        if os.path.exists(dest_path):
            try:
                os.remove(dest_path)
            except OSError:
                pass
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.error("Report database insertion error: %s", exc.__class__.__name__)
        flash("Failed to register report in database.", "danger")
    finally:
        close_connection(conn, cursor)

    return redirect(url_for("doctor.dashboard", tab="reports"))


@doctor_bp.route("/report/<int:id>/download")
@login_required
@role_required("doctor")
def download_report(id: int):
    """Download an authorized diagnostic report."""
    return download_report_file(id)
