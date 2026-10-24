"""
routes/patient.py – Registered patient portal blueprint.

Workflows & Security Guarantees:
  - Role-protected dashboard (@login_required, @role_required("patient"))
  - Patient identity derived strictly from session["user_id"]
  - Access control: Patients cannot access other patients' records or appointments (IDOR prevention)
  - Consultation appointment booking with active physicians
  - Appointment cancellation for pending scheduled encounters
  - Electronic health record timeline review
  - Authorized diagnostic report downloads via secure controller
  - CSRF verification on all state-changing endpoints
"""

from datetime import datetime
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
    EVENT_UNAUTHORIZED_ACCESS,
    OUTCOME_SUCCESS,
    OUTCOME_FAILED,
    OUTCOME_DENIED,
)
from routes.auth import login_required, role_required
from routes.reports import check_csrf, download_report_file

patient_bp = Blueprint("patient", __name__, url_prefix="/patient")


def _get_patient_profile(user_id: int):
    """Retrieve patient record bound to authenticated user_id."""
    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT p.id AS patient_id, p.user_id, p.date_of_birth, p.gender,
                   p.blood_group, p.address, p.emergency_contact,
                   u.username, u.full_name, u.email, u.phone
            FROM patients p
            JOIN users u ON p.user_id = u.id
            WHERE p.user_id = %s
            LIMIT 1
            """,
            (int(user_id),),
        )
        return cursor.fetchone()
    finally:
        close_connection(conn, cursor)


@patient_bp.route("/dashboard")
@login_required
@role_required("patient")
def dashboard():
    """Render patient personal health workspace."""
    user_id = session.get("user_id")
    patient = _get_patient_profile(user_id)
    if not patient:
        flash("Patient profile record not found. Please contact an administrator.", "warning")
        return render_template(
            "patient/dashboard.html",
            patient=None,
            appointments=[],
            records=[],
            reports=[],
            doctors=[],
            active_tab="appointments",
        )

    patient_id = patient["patient_id"]
    active_tab = request.args.get("tab", "appointments")

    conn = cursor = None
    appointments = []
    records = []
    reports = []
    doctors = []

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Appointments for this patient
        cursor.execute(
            """
            SELECT a.id, a.patient_id, a.doctor_id, a.appointment_date, a.reason,
                   a.status, a.notes, a.created_at,
                   u.full_name AS doctor_name, u.email AS doctor_email,
                   d.specialisation, d.department, d.licence_number
            FROM appointments a
            JOIN doctors d ON a.doctor_id = d.id
            JOIN users u ON d.user_id = u.id
            WHERE a.patient_id = %s
            ORDER BY a.appointment_date DESC
            """,
            (patient_id,),
        )
        appointments = cursor.fetchall()

        # 2. Medical records for this patient
        cursor.execute(
            """
            SELECT m.id, m.patient_id, m.doctor_id, m.appointment_id,
                   m.diagnosis, m.prescription, m.notes, m.record_date,
                   u.full_name AS doctor_name,
                   d.specialisation, d.department
            FROM medical_records m
            JOIN doctors d ON m.doctor_id = d.id
            JOIN users u ON d.user_id = u.id
            WHERE m.patient_id = %s
            ORDER BY m.record_date DESC
            """,
            (patient_id,),
        )
        records = cursor.fetchall()

        # 3. Reports belonging to this patient
        cursor.execute(
            """
            SELECT up.id, up.patient_id, up.uploaded_by, up.record_id,
                   up.original_name, up.file_size, up.mime_type, up.upload_date,
                   uploader.full_name AS uploader_name
            FROM uploads up
            JOIN users uploader ON up.uploaded_by = uploader.id
            WHERE up.patient_id = %s
            ORDER BY up.upload_date DESC
            """,
            (patient_id,),
        )
        reports = cursor.fetchall()

        # 4. Available active doctors for booking
        cursor.execute(
            """
            SELECT d.id AS doctor_id, u.full_name, d.specialisation, d.department
            FROM doctors d
            JOIN users u ON d.user_id = u.id
            WHERE u.is_active = 1
            ORDER BY u.full_name ASC
            """
        )
        doctors = cursor.fetchall()

    except Exception as exc:
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.error("Patient dashboard error: %s", exc.__class__.__name__)
        flash("An error occurred while loading your health portal.", "danger")
    finally:
        close_connection(conn, cursor)

    return render_template(
        "patient/dashboard.html",
        patient=patient,
        appointments=appointments,
        records=records,
        reports=reports,
        doctors=doctors,
        active_tab=active_tab,
    )


@patient_bp.route("/appointment/request", methods=["POST"])
@login_required
@role_required("patient")
def request_appointment():
    """Request a consultation appointment with an attending physician."""
    if not check_csrf():
        flash("CSRF token validation failed. Action rejected.", "danger")
        return redirect(url_for("patient.dashboard", tab="appointments"))

    user_id = session.get("user_id")
    patient = _get_patient_profile(user_id)
    if not patient:
        flash("Patient profile not found.", "danger")
        return redirect(url_for("patient.dashboard"))

    try:
        doctor_id = int(request.form.get("doctor_id", 0))
    except (ValueError, TypeError):
        flash("Please select a valid doctor.", "danger")
        return redirect(url_for("patient.dashboard", tab="appointments"))

    raw_date = (request.form.get("appointment_date") or "").strip()
    reason = (request.form.get("reason") or "").strip()

    if not raw_date:
        flash("Appointment date and time are required.", "danger")
        return redirect(url_for("patient.dashboard", tab="appointments"))

    if not reason or len(reason) < 3:
        flash("Please provide a reason for the consultation (minimum 3 characters).", "danger")
        return redirect(url_for("patient.dashboard", tab="appointments"))

    # Parse appointment date/time
    appointment_dt = None
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            appointment_dt = datetime.strptime(raw_date, fmt)
            break
        except ValueError:
            pass

    if not appointment_dt:
        flash("Invalid date/time format. Please use the date picker.", "danger")
        return redirect(url_for("patient.dashboard", tab="appointments"))

    if appointment_dt < datetime.now():
        flash("Appointment date and time must be in the future.", "danger")
        return redirect(url_for("patient.dashboard", tab="appointments"))


    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Verify doctor exists and is active
        cursor.execute(
            """
            SELECT d.id
            FROM doctors d
            JOIN users u ON d.user_id = u.id
            WHERE d.id = %s AND u.is_active = 1
            LIMIT 1
            """,
            (doctor_id,),
        )
        if not cursor.fetchone():
            flash("Selected physician is not currently available for appointments.", "danger")
            return redirect(url_for("patient.dashboard", tab="appointments"))

        # Insert new scheduled appointment
        cursor.execute(
            """
            INSERT INTO appointments (patient_id, doctor_id, appointment_date, reason, status, notes, created_at)
            VALUES (%s, %s, %s, %s, 'scheduled', NULL, NOW())
            """,
            (patient["patient_id"], doctor_id, appointment_dt, reason),
        )
        conn.commit()
        appointment_id = cursor.lastrowid

        log_audit_event(
            EVENT_APPOINTMENT_CHANGE,
            OUTCOME_SUCCESS,
            user_id=user_id,
            details=f"requested appointment_id={appointment_id} with doctor_id={doctor_id}",
        )
        flash("Consultation appointment requested successfully.", "success")

    except Exception as exc:
        if conn:
            conn.rollback()
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.error("Appointment request error: %s", exc.__class__.__name__)
        flash("Failed to request appointment.", "danger")
    finally:
        close_connection(conn, cursor)

    return redirect(url_for("patient.dashboard", tab="appointments"))


@patient_bp.route("/appointment/<int:id>/cancel", methods=["POST"])
@login_required
@role_required("patient")
def cancel_appointment(id: int):
    """Allow patient to cancel their own scheduled appointment."""
    if not check_csrf():
        flash("CSRF token validation failed. Action rejected.", "danger")
        return redirect(url_for("patient.dashboard", tab="appointments"))

    user_id = session.get("user_id")
    patient = _get_patient_profile(user_id)
    if not patient:
        flash("Patient profile not found.", "danger")
        return redirect(url_for("patient.dashboard"))

    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Enforce patient ownership and status
        cursor.execute(
            "SELECT id, status FROM appointments WHERE id = %s AND patient_id = %s",
            (int(id), patient["patient_id"]),
        )
        appt = cursor.fetchone()
        if not appt:
            log_audit_event(
                EVENT_UNAUTHORIZED_ACCESS,
                OUTCOME_DENIED,
                user_id=user_id,
                details=f"patient_id={patient['patient_id']} attempted unauthorized cancellation on appointment_id={id}",
            )
            flash("Appointment not found or not registered under your profile.", "danger")
            return redirect(url_for("patient.dashboard", tab="appointments"))

        if appt["status"] != "scheduled":
            flash(f"Only 'scheduled' appointments can be cancelled (current status: {appt['status']}).", "warning")
            return redirect(url_for("patient.dashboard", tab="appointments"))

        cursor.execute(
            "UPDATE appointments SET status = 'cancelled' WHERE id = %s AND patient_id = %s",
            (int(id), patient["patient_id"]),
        )
        conn.commit()

        log_audit_event(
            EVENT_APPOINTMENT_CHANGE,
            OUTCOME_SUCCESS,
            user_id=user_id,
            details=f"patient_id={patient['patient_id']} cancelled appointment_id={id}",
        )
        flash("Appointment has been cancelled.", "info")

    except Exception as exc:
        if conn:
            conn.rollback()
        if current_app and hasattr(current_app, "logger"):
            current_app.logger.error("Appointment cancellation error: %s", exc.__class__.__name__)
        flash("Failed to cancel appointment.", "danger")
    finally:
        close_connection(conn, cursor)

    return redirect(url_for("patient.dashboard", tab="appointments"))


@patient_bp.route("/report/<int:id>/download")
@login_required
@role_required("patient")
def download_report(id: int):
    """Download an authorized diagnostic report belonging to this patient."""
    return download_report_file(id)
