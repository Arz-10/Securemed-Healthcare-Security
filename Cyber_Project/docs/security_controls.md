# SecureMed — Cybersecurity Controls & Threat Defenses

This document provides a comprehensive technical index of all implemented security controls, their code locations, defenses against OWASP Top 10 vulnerabilities, and operational boundaries.

---

## 1. Security Control Matrix

| Control Category | Implemented Defense | Implementation File | Verification Test |
| :--- | :--- | :--- | :--- |
| **Authentication** | Werkzeug PBKDF2:SHA256 password hashing with random salt | `seed_dev_accounts.py`, `routes/admin.py` | `test_01_account_provisioner_hashing` |
| **Authentication** | Constant-time password verification (`check_password_hash`) | `routes/auth.py` | `test_05_valid_login_establishes_session` |
| **Authentication** | Generic authentication failure messages (Enumeration prevention) | `routes/auth.py` | `test_04_invalid_credentials_generic_error` |
| **Brute-Force Defense** | Failed login rate limiting & IP lockout (5 attempts / 60s) | `routes/auth.py`, `config.py` | `test_sec_brute_01_login_rate_limiting` |
| **Session Security** | Session fixation mitigation (purging prior tokens on login) | `routes/auth.py` | `test_sec_session_01_session_fixation_clearing` |
| **Session Security** | Immediate revocation of active sessions for deactivated accounts | `routes/auth.py` | `test_sec_session_02_immediate_revocation_on_deactivation` |
| **Session Security** | `HttpOnly=True`, `SameSite="Lax"`, 30-min lifetime | `config.py` | `test_08_logout_invalidates_session` |
| **Injection Defense** | 100% Parameterized SQL (`%s` placeholders) across all queries | `routes/*.py`, `database/*.py` | `test_sec_sqli_01_login_sqli_payloads` |
| **XSS Defense** | Context-aware Jinja2 autoescaping; zero usage of `\| safe` | `templates/**/*.html` | `test_sec_xss_01_script_injection_escaped` |
| **CSRF Defense** | Constant-time session-bound CSRF validation on all POST requests | `routes/reports.py`, `app.py` | `test_sec_csrf_01_missing_token_rejection` |
| **Access Control** | Role-based authorization decorators (`@login_required`, `@role_required`) | `routes/auth.py` | `test_03_role_restrictions_enforced` |
| **IDOR Defense** | Doctor-patient consultation relationship validation | `routes/doctor.py` | `test_06_doctor_patient_record_authorization` |
| **IDOR Defense** | Patient ownership verification for appointments & medical records | `routes/patient.py` | `test_08_patient_appointment_cancellation` |
| **IDOR Defense** | Report download authorization check (Admin/Doctor/Patient) | `routes/reports.py` | `test_sec_idor_02_report_access_authorization_matrix` |
| **File Upload Defense** | Strict binary magic-byte inspection (PDF, PNG, JPG) | `routes/reports.py` | `test_09_report_upload_validation` |
| **File Upload Defense** | File extension allowlist & null-byte rejection | `routes/reports.py` | `test_sec_upload_01_null_byte_and_extension_spoof` |
| **File Upload Defense** | Unguessable UUID4 server-side filename generation | `routes/reports.py` | `test_phase2_suite.py` |
| **Path Traversal** | Canonical path containment checks (`os.path.abspath`) | `routes/reports.py` | `test_phase2_suite.py` |
| **Privacy / Logging** | Clinical diagnosis & prescription omission from audit logs | `database/audit.py`, `routes/doctor.py` | `test_sec_priv_01_no_clinical_text_in_audit_logs` |

---

## 2. Threat Mitigation Deep Dives

### A. SQL Injection (A03:2021-Injection)
- **Mechanisms**: No query uses string interpolation (`%`, `f""`, or `.format()`). Every dynamic parameter is passed as a tuple parameter to `cursor.execute(sql, tuple(params))`.
- **Database Connector**: Utilizes native `mysql.connector` parameter escaping at the driver protocol layer.

### B. Broken Object-Level Authorization / IDOR (A01:2021-Broken Access Control)
- **Mechanisms**:
  - Patient identities are resolved exclusively from `session['user_id']`. No patient ID passed in request parameters is trusted for access grant.
  - Doctors are restricted to patients with whom they have an existing appointment record (`SELECT 1 FROM appointments WHERE doctor_id = %s AND patient_id = %s`).
  - Report downloads verify ownership in database before invoking `send_from_directory`.

### C. Cross-Site Request Forgery (A01:2021-Broken Access Control)
- **Mechanisms**:
  - `secrets.token_hex(16)` generates a cryptographically secure token on initial request.
  - Every form includes `<input type="hidden" name="csrf_token" value="{{ csrf_token }}"/>`.
  - State-changing handlers invoke `check_csrf()`, which compares submitted tokens with `secrets.compare_digest` in constant time.
  - Session cookies carry `SameSite="Lax"`, providing browser-enforced CSRF protection.

### D. Malicious File Upload & Execution (A04:2021-Insecure Design)
- **Mechanisms**:
  - Files are stored in a dedicated `uploads/` directory located strictly outside the publicly served web static tree.
  - Magic byte headers (`%PDF-`, `\x89PNG\r\n\x1a\n`, `\xff\xd8\xff`) are verified from the raw file stream, preventing executable renaming attacks (e.g. `malware.exe` renamed to `scan.pdf`).
  - Uploaded filenames are stripped, and stored on disk under `uuid.uuid4().hex + ext`.

### E. Account Deactivation & Session Invalidation
- **Mechanisms**:
  - Soft deactivation sets `is_active = 0` in `users` table without destroying clinical audit records.
  - `@login_required` queries the database on every authenticated request to verify `is_active`. Deactivated users have their sessions purged immediately and are redirected to login.

---

## 3. Defensive Limitations & Security Boundaries

1. **Development Server Context**: Currently served via Flask's built-in WSGI server intended for local development. In production, run behind an enterprise reverse proxy (e.g., Nginx) and WSGI runner (Gunicorn/Waitress) with TLS/HTTPS.
2. **In-Memory Rate Limiting**: The sliding-window rate limiter stores state in process memory. If scaled to multiple server workers, an external cache (e.g., Redis) should store attempt counters.
3. **Antivirus Scanning**: Magic byte inspection validates file types, but does not scan for malicious embedded payloads within valid PDFs. Integrating an antivirus scanner (such as ClamAV) is recommended for production healthcare pipelines.
