# SecureMed — College Cybersecurity Project Submission & Viva Dossier

This document provides the complete academic and technical submission dossier for **SecureMed**, structured for project examination, technical evaluation, and viva voce defense.

---

## 1. Project Abstract

**SecureMed** is a defense-in-depth healthcare web application designed to protect sensitive Electronic Medical Records (EMR) and Patient Health Information (PHI) against common web application vulnerabilities (OWASP Top 10). Built using Python (Flask 3.x), MySQL 8.x, and a modern responsive interface, SecureMed enforces role-based access control (RBAC) across three distinct healthcare domains: Hospital Administrators, Attending Physicians, and Registered Patients. The system features constant-time password verification, sliding-window failed login rate limiting, session fixation protection, real-time mid-session account revocation, parameterized SQL execution, binary magic-byte upload validation, non-sensitive audit logging, and a modular SIEM export interface. All 40 automated security and workflow test cases pass with a 100% success rate without modifying or exposing active clinical records.

---

## 2. Problem Statement & Objectives

### Problem Statement
Healthcare information systems are primary targets for cyberattacks due to the extreme value of protected health information on illicit markets. Vulnerabilities such as Insecure Direct Object References (IDOR), SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), unrestricted file uploads, and deficient audit logging frequently lead to unauthorized data exposure, patient identity theft, and regulatory penalties. Existing academic demonstrations often simplify these workflows into single-user dashboards with naive authentication, leaving real-world access boundaries and audit trails untested.

### Objectives
1. **Architect a Multi-Role Healthcare Portal**: Implement functional and isolated workflows for Administrators (system governance), Doctors (clinical encounters & EMR authoring), and Patients (appointment requests & health history review).
2. **Implement Defense-in-Depth Cybersecurity Controls**:
   - Thwart broken access control and IDOR by enforcing server-side doctor-patient relationship validation and ownership checks.
   - Prevent SQL Injection through 100% parameterized SQL.
   - Enforce constant-time CSRF protection on all state-changing endpoints.
   - Secure diagnostic file uploads through binary magic-byte inspection, UUID-based filename isolation, and path containment outside public web roots.
   - Mitigate brute-force attacks via sliding-window IP rate limiting.
   - Prevent session fixation and enforce instant revocation of deactivated user sessions.
3. **Establish Privacy-Preserving Audit Trails**: Build an immutable security event logging subsystem that records vital operational and security events while strictly omitting clinical diagnosis text, prescriptions, passwords, and tokens.
4. **Develop Repeatable Security Verification**: Create an automated test harness covering offensive simulations and verifiable defensive evidence.
5. **Prepare Modular Monitoring & SIEM Export**: Provide a sanitized JSON export utility formatted for ingestion by security monitoring tools (Wazuh, Suricata, SIEM).

---

## 3. System Architecture & Database Design

### System Architecture
SecureMed employs the **Flask Application Factory Pattern** (`create_app`), ensuring modular blueprint encapsulation:
- **`routes/auth.py`**: Handles user authentication, rate limiting, and session security.
- **`routes/admin.py`**: Manages user provisioning, account activation/deactivation, and audit review.
- **`routes/doctor.py`**: Oversees clinical appointments, authorized patient directories, and medical record authoring.
- **`routes/patient.py`**: Manages consultation bookings, personal health history, and report downloads.
- **`routes/reports.py`**: Enforces binary file validation, path containment, and secure delivery.
- **`database/db.py` & `database/audit.py`**: Provides connection handling and security audit persistence.
- **`database/monitoring_export.py`**: Provides SIEM-compatible sanitized event export.

### Relational Database Schema (`securemed_db`)
The database contains 7 normalized relational tables:
1. **`users`**: Base credentials and identity (`id`, `username`, `password`, `role`, `full_name`, `email`, `phone`, `is_active`, `created_at`, `updated_at`).
2. **`doctors`**: Physician profiles (`id`, `user_id` FK $\rightarrow$ `users.id`, `specialisation`, `licence_number`, `department`).
3. **`patients`**: Patient demographics (`id`, `user_id` FK $\rightarrow$ `users.id`, `date_of_birth`, `gender`, `blood_group`, `emergency_contact`).
4. **`appointments`**: Consultation schedule (`id`, `patient_id` FK $\rightarrow$ `patients.id`, `doctor_id` FK $\rightarrow$ `doctors.id`, `appointment_date`, `reason`, `status`, `notes`, `created_at`).
5. **`medical_records`**: EMR clinical entries (`id`, `patient_id`, `doctor_id`, `appointment_id`, `diagnosis`, `prescription`, `notes`, `record_date`).
6. **`uploads`**: Diagnostic report metadata (`id`, `patient_id`, `uploaded_by`, `record_id`, `original_name`, `stored_name`, `file_size`, `mime_type`, `upload_date`).
7. **`audit_logs`**: Security audit records (`id`, `user_id` [nullable FK], `event_type`, `outcome`, `ip_address`, `details`, `created_at`).

---

## 4. Technology Stack & Justification

| Technology | Role | Justification |
| :--- | :--- | :--- |
| **Python 3.11** | Backend Language | Strong standard library cryptography support (`secrets`, `hashlib`), high readability, and robust unit testing tooling. |
| **Flask 3.x** | Web Framework | Lightweight micro-framework enabling granular control over request lifecycle, headers, cookie flags, and middleware without hidden magic. |
| **MySQL 8.x** | Relational Database | ACID-compliant relational storage supporting foreign key integrity, parameterized driver execution, and production-grade concurrency. |
| **`mysql-connector-python`** | Database Driver | Native Oracle driver enabling strict parameterized queries (`%s`), preventing driver-level query concatenation. |
| **Werkzeug Security** | Cryptographic Hashing | Industry-standard PBKDF2:SHA256 password hashing with random per-user salt and constant-time comparison to defeat timing attacks. |
| **Bootstrap 5.3 + Vanilla CSS** | Frontend Framework | Accessible, modern, professional healthcare interface with zero external CSS framework vulnerabilities and responsive layout. |
| **Jinja2** | Template Engine | Automatic context-aware HTML escaping enabled by default, mitigating Cross-Site Scripting (XSS). |

---

## 5. Security Controls & Threat Model

### Threat Model (STRIDE Alignment)

| STRIDE Threat | Attack Vector | SecureMed Defense | Implementation Location |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Credential guessing, timing attacks | PBKDF2:SHA256 hashing, constant-time `check_password_hash`, sliding-window rate limit (5 attempts / 60s), generic errors | `routes/auth.py` |
| **Tampering** | Parameterized SQL injection, CSRF | 100% parameterized queries; constant-time CSRF verification on all POST requests (`check_csrf`) | `routes/*.py`, `database/db.py` |
| **Repudiation** | Denying clinical actions or logins | Persistent audit logging in `audit_logs` table recording timestamp, actor, IP, event type, and outcome | `database/audit.py` |
| **Information Disclosure** | IDOR, path traversal, verbose error leaks | Ownership checks on records/reports; canonical path containment (`os.path.abspath`); clinical notes excluded from audit | `routes/reports.py`, `database/audit.py` |
| **Denial of Service** | Gigantic file uploads, login flooding | 16 MB request cap, 5 MB file size limit, 60-second IP lockout on repeated failures | `config.py`, `routes/auth.py` |
| **Elevation of Privilege** | Cross-role URL tampering, deactivated session reuse | `@role_required` decorator on all protected routes; mid-session `_is_account_active` verification on every request | `routes/auth.py` |

---

## 6. Test Results & Verification Evidence

All 40 automated tests pass with zero failures:
- **`test_phase2_suite.py`** (12 Tests): Verifies blueprint registrations, session invalidation on logout, unauthenticated redirection, CSRF token validation, error resilience, and asset loading.
- **`test_phase3_suite.py`** (12 Tests): Verifies account hashing, admin user creation/status toggling, doctor appointment progression, doctor-patient boundary enforcement, patient booking/cancellation, and empty state rendering.
- **`test_security_harness.py`** (16 Tests): Verifies SQLi resilience, XSS escaping, CSRF rejection, cross-patient IDOR prevention, session fixation clearing, deactivated session revocation, magic-byte inspection, rate limiting lockout, clinical audit privacy, and SIEM event export.

### Automated Verification Command:
```powershell
.\.venv\Scripts\python.exe -m unittest discover -p "test_*.py" -v
```
*Result: `Ran 40 tests in ~7.5s ... OK (100% PASS)`*

---

## 7. Limitations & Future Scope

### Limitations
1. **Development Server**: The application runs under Flask's development WSGI server. In enterprise production, it should be deployed behind an Nginx reverse proxy with Gunicorn/Waitress and TLS termination (`https://`).
2. **In-Memory Rate Limiting**: The current rate limiter uses process memory (`collections.defaultdict`). If scaled across multiple server processes, an in-memory cache such as Redis should manage attempt state.
3. **Antivirus Scanning**: File uploads are verified for magic bytes and extensions, but embedded PDF exploit scripts are not scanned with a dedicated antivirus engine (e.g., ClamAV).

### Future Scope
1. **Multi-Factor Authentication (MFA/TOTP)**: Integrate time-based one-time passwords for administrative and medical staff.
2. **Encrypted Storage at Rest**: Encrypt uploaded medical files using AES-256-GCM before writing to the filesystem.
3. **Automated ClamAV Daemon Scanning**: Inspect uploaded file streams through a ClamAV socket before accepting them into `uploads/`.
4. **Native SIEM Webhook Integration**: Stream real-time events over HTTPS to Wazuh or Elasticsearch.

---

## 8. Live Demonstration Script (5–7 Minutes)

| Time | Stage | Action | Expected Output |
| :--- | :--- | :--- | :--- |
| **0:00 - 1:00** | **System Architecture & Admin** | Log in as `demo_admin` (or `admin`). View dashboard metrics, user directory (`demo_doctor`, `demo_patient`), and filtered audit logs (`LOGIN_SUCCESS`, `DENIED`). | Proves governance and audit visibility. |
| **1:00 - 2:00** | **Patient Workflow** | Log in as `demo_patient`. Book consultation with `Dr. Alexander Wright` for a future date. Show appointment in `Scheduled` status. | Proves patient self-service and validation. |
| **2:00 - 3:30** | **Doctor Clinical Encounter** | Log in as `demo_doctor`. View Eleanor Vance under authorized patients. Update appointment to `Completed`. Author EMR record and view/upload diagnostic PDF report. | Proves clinical lifecycle and file verification. |
| **3:30 - 4:30** | **Patient Verification** | Log in as `demo_patient`. Inspect updated status, view clinical diagnosis & prescription, download medical report. | Proves complete patient encounter loop. |
| **4:30 - 6:00** | **Defensive Attack Simulations** | Run `python demonstrate_security_controls.py`: demonstrate SQLi bypass failure, IDOR report access block, brute-force rate limit lockout, and mid-session deactivation. | Proves offensive resilience and audit evidence. |
| **6:00 - 7:00** | **Monitoring & Event Export** | Run `python export_security_events.py --limit 5`. Show sanitized SIEM JSON with Wazuh-aligned severity scores. | Proves monitoring readiness without credential leakage. |

---

## 9. Likely Viva Voce Questions & Answers

### Q1: How does SecureMed defend against Insecure Direct Object References (IDOR)?
> **Answer:** SecureMed never trusts client-supplied IDs for authorization. When a patient requests an appointment cancellation or report download, their identity is resolved strictly from their authenticated server-side session (`session['user_id']`), and the query asserts `patient_id = %s`. For doctors, the system verifies an active appointment relationship (`SELECT 1 FROM appointments WHERE doctor_id = %s AND patient_id = %s`) before granting access to patient records or reports.

### Q2: Why are parameterized queries immune to SQL Injection?
> **Answer:** Parameterized queries separate SQL code structure from user data. When using `%s` placeholders with `mysql-connector-python`, the database engine compiles the SQL command syntax first, then treats the parameters strictly as literal scalar values during execution. Even if an attacker passes `' OR '1'='1`, the engine treats the entire payload as a literal string to match against `users.username`, never altering the query syntax.

### Q3: How is CSRF mitigated in state-changing requests?
> **Answer:** SecureMed employs a two-layer defense. First, a cryptographically secure token (`secrets.token_hex(16)`) is bound to the user's session and rendered in every HTML form. On POST submission, `check_csrf()` verifies the token using `secrets.compare_digest`, which runs in constant time to prevent timing attacks. Second, session cookies are configured with `SameSite="Lax"`, preventing cross-site requests initiated by third-party origins from sending the authentication cookie.

### Q4: Why is file extension validation insufficient for uploads, and how does SecureMed solve this?
> **Answer:** Attackers can rename malicious executables to innocuous extensions (e.g., `malware.exe` to `report.pdf`). SecureMed reads the initial bytes of the uploaded file stream and matches them against binary magic signatures (`%PDF-` for PDFs, `\x89PNG\r\n\x1a\n` for PNGs, `\xff\xd8\xff` for JPEGs). If the magic signature does not match the extension, the file is rejected immediately. Furthermore, stored files are assigned server-generated UUID4 names and stored outside the public directory to prevent direct execution.

### Q5: How does SecureMed handle account deactivation for an actively logged-in user?
> **Answer:** Traditional web apps only check account status during login, leaving active sessions valid until logout. SecureMed's `@login_required` and `@role_required` decorators query the database on every authenticated request via `_is_account_active(uid)`. If an administrator deactivates an account (`is_active = 0`), the user's active session is immediately purged (`session.clear()`), an audit event is logged as `UNAUTHORIZED_ACCESS` / `DENIED`, and the user is redirected to the login page with a deactivation alert.

### Q6: How does the audit logging subsystem protect patient privacy?
> **Answer:** Under healthcare privacy standards, audit trails must record security events without becoming a vector for data leakage. SecureMed's audit subsystem (`database/audit.py`) strictly sanitizes details before database insertion: it records metadata such as actor ID, event category, timestamp, IP address, and object ID, but explicitly excludes sensitive clinical diagnoses, prescriptions, physician notes, passwords, and tokens.

### Q7: What is the purpose of constant-time password comparison?
> **Answer:** Standard string comparison operators (`==`) exit on the first mismatched byte, creating measurable variations in execution time. Attackers can analyze these timing differences to deduce characters of a password or hash. `check_password_hash` compares hashes in constant time, ensuring execution duration remains identical regardless of where a mismatch occurs.
