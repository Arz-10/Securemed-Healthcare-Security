# SecureMed — Application Architecture & System Design

This document details the software architecture, component boundaries, relational database schema, and request flow for SecureMed.

---

## 1. Architectural Overview

SecureMed is architected around the Flask Application Factory pattern, featuring modular blueprints that strictly segregate role-specific healthcare workflows. All business logic interacts with a local MySQL relational database using parameterized queries and defensive connection management.

```
                      +-----------------------------+
                      |   Client Web Browser        |
                      +--------------+--------------+
                                     |  HTTP / CSRF Token / Session Cookie
                                     v
                      +-----------------------------+
                      |   Flask Application Core    |
                      |   (app.py / config.py)      |
                      +--------------+--------------+
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
         v                           v                           v
+-----------------+         +-----------------+         +-----------------+
|   routes/auth   |         |   routes/admin  |         |  routes/doctor  |
|   (Login/Logout |         |   (User mgmt,   |         |  (Appointments, |
|    Rate limit)  |         |    Audit, Org)  |         |   EMR, Reports) |
+-----------------+         +-----------------+         +-----------------+
         |                           |                           |
         +---------------------------+---------------------------+
         |                           |
         v                           v
+-----------------+         +-----------------+
|  routes/patient |         |  routes/reports |
|  (Appointments, |         |  (Magic bytes,  |
|   Records, View)|         |   File stream)  |
+-----------------+         +-----------------+
         |                           |
         +-------------+-------------+
                       |
                       v
        +-------------------------------+
        |  Database & Security Services |
        |  - database/db.py             |
        |  - database/audit.py          |
        +---------------+---------------+
                        | Parameterized SQL
                        v
        +-------------------------------+
        |  MySQL Database Engine        |
        |  (securemed_db)               |
        +-------------------------------+
```

---

## 2. Component Structure

| Component | Path | Responsibility |
| :--- | :--- | :--- |
| **App Core** | `app.py` | Factory pattern (`create_app`), global CSRF injector, error handlers, blueprint registration. |
| **Config** | `config.py` | Environment variable resolution, upload folder configuration, cookie security parameters. |
| **Auth Blueprint** | `routes/auth.py` | Authentication, constant-time password check, session fixation clearing, deactivation checks, rate limiting. |
| **Admin Blueprint** | `routes/admin.py` | User account provisioning, soft activation/deactivation, appointments & reports oversight, audit log filter. |
| **Doctor Blueprint** | `routes/doctor.py` | Consultations review, appointment status lifecycle, authorized patient EMR authoring, report uploads. |
| **Patient Blueprint** | `routes/patient.py` | Personal profile review, consultation appointment booking with active physicians, appointment cancellation. |
| **Reports Blueprint** | `routes/reports.py` | Binary magic-byte validation, secure UUID filename generation, canonical path containment, download controller. |
| **Database Connector** | `database/db.py` | Safe connection establishment (`mysql.connector`), cursor pooling, connection release. |
| **Audit Subsystem** | `database/audit.py` | Parameterized security event persistence, unauthenticated user fallback, query filtering, pagination. |

---

## 3. Role Boundaries & Authorization Matrix

SecureMed enforces server-side Role-Based Access Control (RBAC) on every endpoint. No client-supplied role or ID is trusted.

| Operation | Admin | Doctor | Patient | Unauthenticated |
| :--- | :---: | :---: | :---: | :---: |
| Access `/login` | Yes | Yes | Yes | Yes |
| Access `/admin/dashboard` | **Granted** | Denied (403/Redirect) | Denied (403/Redirect) | Denied (302 $\rightarrow$ /login) |
| Provision User Accounts | **Granted** | Denied | Denied | Denied |
| Toggle Account Active Status | **Granted** | Denied | Denied | Denied |
| Access `/doctor/dashboard` | Denied | **Granted** | Denied | Denied |
| Author Medical Record (EMR) | Denied | **Authorized Patients Only** | Denied | Denied |
| Update Appointment Status | Denied | **Assigned Appointments Only**| Denied | Denied |
| Access `/patient/dashboard` | Denied | Denied | **Granted** | Denied |
| Book Consultation Appointment | Denied | Denied | **Granted (Active MDs)** | Denied |
| Cancel Scheduled Appointment | Denied | Denied | **Own Appointments Only**| Denied |
| Download Medical Report | **Granted** | **Treated Patients Only** | **Own Reports Only** | Denied |
| View System Audit Logs | **Granted** | Denied | Denied | Denied |

---

## 4. Relational Database Schema (`securemed_db`)

The database consists of 7 normalized relational tables:

```
users (id, username, password, role, full_name, email, phone, is_active, created_at, updated_at)
  |
  +---> doctors (id, user_id, specialisation, licence_number, department)
  |
  +---> patients (id, user_id, date_of_birth, gender, blood_group, address, emergency_contact)
  |        |
  |        v
  |     appointments (id, patient_id, doctor_id, appointment_date, reason, status, notes, created_at)
  |        |
  |        v
  |     medical_records (id, patient_id, doctor_id, appointment_id, diagnosis, prescription, notes, record_date)
  |        |
  |        v
  +---> uploads (id, patient_id, uploaded_by, record_id, original_name, stored_name, file_size, mime_type, upload_date)
  |
  +---> audit_logs (id, user_id, event_type, outcome, ip_address, details, created_at)
```

### Table Relationships:
1. **`users` $\rightarrow$ `doctors`**: `1 : 0..1` via `doctors.user_id = users.id` (CASCADE on delete).
2. **`users` $\rightarrow$ `patients`**: `1 : 0..1` via `patients.user_id = users.id` (CASCADE on delete).
3. **`patients` $\rightarrow$ `appointments`**: `1 : N` via `appointments.patient_id = patients.id`.
4. **`doctors` $\rightarrow$ `appointments`**: `1 : N` via `appointments.doctor_id = doctors.id`.
5. **`patients` & `doctors` $\rightarrow$ `medical_records`**: `1 : N` via `medical_records.patient_id = patients.id` and `medical_records.doctor_id = doctors.id`.
6. **`patients` $\rightarrow$ `uploads`**: `1 : N` via `uploads.patient_id = patients.id`.
7. **`users` $\rightarrow$ `uploads`**: `1 : N` via `uploads.uploaded_by = users.id`.
8. **`users` $\rightarrow$ `audit_logs`**: `1 : N` via `audit_logs.user_id = users.id` (nullable for anonymous/unauthenticated security events).

---

## 5. Security Request Lifecycle

1. **Incoming Request**: Client issues request with Session Cookie and form data.
2. **CSRF Guard**: For state-changing requests (`POST`), `check_csrf()` verifies `secrets.compare_digest(request.form['csrf_token'], session['csrf_token'])`. Rejects in constant time if invalid.
3. **Authentication Guard**: `@login_required` verifies session validity. Queries `users.is_active` to ensure account was not deactivated mid-session.
4. **Role Authorization**: `@role_required(role)` verifies user's session role matches target route.
5. **Object-Level Authorization (IDOR Defense)**:
   - Doctor accessing patient/record verifies `SELECT 1 FROM appointments WHERE doctor_id = %s AND patient_id = %s`.
   - Patient accessing report/record verifies `patients.user_id = session['user_id']`.
6. **Database Execution**: Parameterized SQL query execution via `mysql-connector-python`.
7. **Audit Event Dispatch**: `log_audit_event()` persists structured metadata into `audit_logs`.
8. **Response Generation**: Jinja2 auto-escapes all context variables before returning HTML to client.
