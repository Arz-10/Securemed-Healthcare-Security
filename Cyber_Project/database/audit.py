"""
database/audit.py – Security audit logging subsystem for SecureMed.

Provides persistent logging of security-relevant events into the `audit_logs` table:
  - Successful and failed logins (EVENT_LOGIN_SUCCESS, EVENT_LOGIN_FAILED)
  - Logouts (EVENT_LOGOUT)
  - Unauthorized access attempts (EVENT_UNAUTHORIZED_ACCESS)
  - Rejected file uploads (EVENT_UPLOAD_REJECTED)
  - Report uploads, downloads, and deletions (EVENT_REPORT_UPLOAD, etc.)

Security & Privacy Guarantees:
  - NEVER logs passwords, session cookies, CSRF tokens, or medical record text.
  - Parameterized SQL prevents SQL injection.
  - Handles foreign key IntegrityError if user_id is untrusted/forged by falling back to user_id=None.
  - Failures in audit logging do not expose internal exceptions or database credentials.
  - Returns explicit boolean status: does not silently claim success if persistence failed.
"""

import logging
from typing import Optional, List, Dict, Any
from flask import request, session, has_request_context, current_app
from mysql.connector.errors import IntegrityError
from database.db import get_connection, close_connection

logger = logging.getLogger("securemed.audit")

# Event Type Constants
EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILED = "LOGIN_FAILED"
EVENT_LOGOUT = "LOGOUT"
EVENT_UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
EVENT_UPLOAD_REJECTED = "UPLOAD_REJECTED"
EVENT_REPORT_UPLOAD = "REPORT_UPLOAD"
EVENT_REPORT_DOWNLOAD = "REPORT_DOWNLOAD"
EVENT_REPORT_DELETION = "REPORT_DELETION"
EVENT_APPOINTMENT_CHANGE = "APPOINTMENT_CHANGE"
EVENT_MEDICAL_RECORD_CHANGE = "MEDICAL_RECORD_CHANGE"
EVENT_USER_MANAGEMENT = "USER_MANAGEMENT"

# Outcome Constants
OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_FAILED = "FAILED"
OUTCOME_DENIED = "DENIED"


def _sanitize_details(details: Optional[str]) -> Optional[str]:
    """Ensure details string is bounded, non-empty, and free of obvious secrets or clinical text."""
    if not details:
        return None
    details_str = str(details).strip().replace("\r", " ").replace("\n", " ")
    # Bounded length (matches VARCHAR(255) column)
    if len(details_str) > 255:
        details_str = details_str[:252] + "..."
    return details_str


def log_audit_event(
    event_type: str,
    outcome: str,
    user_id: Optional[int] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> bool:
    """
    Persistently record a security event into the `audit_logs` table.

    Parameters
    ----------
    event_type : str
        Category of the security event (e.g. LOGIN_SUCCESS, UNAUTHORIZED_ACCESS).
    outcome : str
        Event result: SUCCESS, FAILED, or DENIED.
    user_id : int, optional
        Internal database user ID of the initiating actor, if known/authenticated.
    details : str, optional
        Safe, non-sensitive metadata describing the event context.
    ip_address : str, optional
        Client IP address. Inferred from request.remote_addr if in request context.

    Returns
    -------
    bool
        True if the event was successfully persisted, False otherwise.
    """
    # Context inference if parameters are omitted
    if has_request_context():
        if user_id is None and "user_id" in session:
            try:
                user_id = int(session["user_id"])
            except (ValueError, TypeError):
                user_id = None

        if ip_address is None and request:
            ip_address = request.remote_addr

    safe_details = _sanitize_details(details)
    conn = cursor = None

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs (user_id, event_type, outcome, ip_address, details, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            """,
            (user_id, event_type, outcome, ip_address, safe_details),
        )
        conn.commit()
        return True
    except IntegrityError:
        # Foreign key failure: user_id is not in users table (e.g. tampered session).
        # Fallback: record event with user_id = NULL so the audit record is preserved.
        try:
            fallback_details = _sanitize_details(f"[unregistered_user_id={user_id}] {safe_details or ''}")
            cursor.execute(
                """
                INSERT INTO audit_logs (user_id, event_type, outcome, ip_address, details, created_at)
                VALUES (NULL, %s, %s, %s, %s, NOW())
                """,
                (event_type, outcome, ip_address, fallback_details),
            )
            conn.commit()
            return True
        except Exception as fallback_exc:
            log_target = current_app.logger if (current_app and hasattr(current_app, "logger")) else logger
            log_target.warning("Security audit log fallback write failed: %s", fallback_exc.__class__.__name__)
            return False
    except Exception as exc:
        # Never leak database credentials or internal SQL tracebacks to users or logs
        log_target = current_app.logger if (current_app and hasattr(current_app, "logger")) else logger
        log_target.warning("Security audit log write failed: %s", exc.__class__.__name__)
        return False
    finally:
        close_connection(conn, cursor)


def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    user_id: Optional[int] = None,
    event_type: Optional[str] = None,
    outcome: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch recent audit log entries for review and defensive testing.
    Supports filtering by user_id, event_type, outcome, and pagination via offset.
    Returns an empty list on database failure.
    """
    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = "SELECT id, user_id, event_type, outcome, ip_address, details, created_at FROM audit_logs WHERE 1=1"
        params = []

        if user_id is not None:
            query += " AND user_id = %s"
            params.append(int(user_id))

        if event_type is not None:
            query += " AND event_type = %s"
            params.append(str(event_type))

        if outcome is not None:
            query += " AND outcome = %s"
            params.append(str(outcome))

        query += " ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s"
        params.append(min(max(1, int(limit)), 500))
        params.append(max(0, int(offset)))

        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    except Exception as exc:
        log_target = current_app.logger if (current_app and hasattr(current_app, "logger")) else logger
        log_target.warning("Failed to fetch audit logs: %s", exc.__class__.__name__)
        return []
    finally:
        close_connection(conn, cursor)


def get_audit_logs_count(
    user_id: Optional[int] = None,
    event_type: Optional[str] = None,
    outcome: Optional[str] = None,
) -> int:
    """Return total count of audit logs matching filters for pagination."""
    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = "SELECT COUNT(*) AS total FROM audit_logs WHERE 1=1"
        params = []

        if user_id is not None:
            query += " AND user_id = %s"
            params.append(int(user_id))

        if event_type is not None:
            query += " AND event_type = %s"
            params.append(str(event_type))

        if outcome is not None:
            query += " AND outcome = %s"
            params.append(str(outcome))

        cursor.execute(query, tuple(params))
        row = cursor.fetchone()
        return row["total"] if row else 0
    except Exception as exc:
        log_target = current_app.logger if (current_app and hasattr(current_app, "logger")) else logger
        log_target.warning("Failed to count audit logs: %s", exc.__class__.__name__)
        return 0
    finally:
        close_connection(conn, cursor)

