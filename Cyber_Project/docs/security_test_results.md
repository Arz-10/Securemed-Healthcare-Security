# SecureMed — Security Test Results & Verification Matrix

This document records the automated verification, security regression, and offensive simulation test results across all project test suites.

**Test Run Execution Date:** 2026-10-21  
**Total Tests Executed:** 40  
**Passed:** 40  
**Failed:** 0  
**Status:** **100% PASS**

---

## 1. Summary of Test Suites

| Suite File | Scope | Tests Run | Pass | Fail | Execution Time |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `test_phase2_suite.py` | Security regressions, RBAC, path traversal, session hygiene | 12 | 12 | 0 | 1.63s |
| `test_phase3_suite.py` | Admin, Doctor, Patient functional healthcare workflows | 12 | 12 | 0 | 2.58s |
| `test_security_harness.py` | Offensive simulations (SQLi, XSS, CSRF, IDOR, Brute-Force, SIEM) | 16 | 16 | 0 | 3.35s |
| **Total** | **End-to-End System & Security Verification** | **40** | **40** | **0** | **~7.5s** |

---

## 2. Detailed Test Matrix

### A. Offensive Security Harness (`test_security_harness.py`)

| Test ID | Scenario | Expected Behavior | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **SEC-SQLI-01** | SQLi login bypass using `' OR '1'='1`, `admin' --`, and `UNION SELECT` | Parameterized execution treats input as literal username; rejects login | Rejected with generic invalid credentials message; query preserved `%s` | **PASS** |
| **SEC-SQLI-02** | SQLi in audit log filter (`UNION SELECT ...`) | Parameterized query isolates filter parameter; returns empty/safe records | Query executed safely with parameter binding; no SQL error | **PASS** |
| **SEC-XSS-01** | Script tags injected in appointment consultation reason and patient fields | Jinja2 escapes HTML characters (`<`, `>`, `&`, `"`) | Raw `<script>` and `<img>` tags were escaped in rendered HTML | **PASS** |
| **SEC-CSRF-01** | State-changing POST to `/admin/user/create` omitting CSRF token | Rejects request; logs `UNAUTHORIZED_ACCESS` event | Rejected with security token validation failure; no user created | **PASS** |
| **SEC-CSRF-02** | State-changing POST with forged/mismatched CSRF token | Constant-time token comparison fails; rejects request | Rejected in constant time with CSRF validation failure | **PASS** |
| **SEC-IDOR-01** | Patient A attempts to cancel Patient B's appointment by changing ID | Database ownership check fails; cancellation blocked | Blocked with "Appointment not found or not registered under your profile" | **PASS** |
| **SEC-IDOR-02** | Report access matrix (Admin, Patient Owner, Unrelated Patient) | Admin/Owner granted; unrelated patient blocked (IDOR defense) | Authorization check accurately returned `False` for unrelated patient | **PASS** |
| **SEC-SESSION-01** | Session fixation attempt with attacker pre-seeded session keys | Successful login clears pre-existing session before populating new tokens | Stale session keys purged; fresh session established | **PASS** |
| **SEC-SESSION-02** | Authenticated request from a deactivated user account (`is_active=0`) | Session immediately revoked; user redirected to login | Session cleared; redirected with account deactivation notice | **PASS** |
| **SEC-UPLOAD-01** | File upload with null-byte (`%00`) and executable disguised as `.pdf` | File inspection identifies null bytes and mismatched magic bytes | Upload rejected with descriptive security validation error | **PASS** |
| **SEC-BRUTE-01** | 5 consecutive failed login attempts from same client IP | 6th attempt triggers rate limiting lockout | Rate limit lockout triggered; login blocked with rate limit notice | **PASS** |
| **SEC-PRIV-01** | Doctor records diagnosis and prescription | Diagnosis text, prescription, and notes omitted from audit log | Audit log details only contain metadata (`record_id`, `patient_id`) | **PASS** |
| **SEC-AUTH-01** | Deactivated account (`is_active=0`) attempts login with valid credentials | Login blocked; denied event audited; no session established | Rejected with "Account is deactivated"; audited as `LOGIN_FAILED/DENIED` | **PASS** |
| **SEC-RBAC-01** | Doctor or patient attempts to execute admin report deletion | Intercepted by role check; denied with insufficient privileges | Redirected to login with privileges warning; action rejected | **PASS** |
| **SEC-PATH-01** | Download request with path traversal sequence in stored name (`../../`) | Path containment check verifies storage boundary; aborts 404 | Traversal path outside upload folder rejected with HTTP 404 | **PASS** |
| **SEC-MONITOR-01** | Security event exporter sanitization and severity scoring | Formats SIEM JSON document; assigns severity 1-10; strips sensitive whitespace | Produced sanitized JSON document matching Wazuh schema | **PASS** |

---

### B. Phase 3: Healthcare Workflows (`test_phase3_suite.py`)

| Test ID | Scenario | Expected Behavior | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **WF-ACC-01** | Safe account setup utility with Werkzeug password hashing | Hashes password with PBKDF2; rejects duplicates and invalid roles | Werkzeug hash generated (`check_password_hash` verified); duplicates blocked | **PASS** |
| **WF-CSRF-01** | State-changing request with invalid CSRF token | Request rejected with security error | Rejected with CSRF error message | **PASS** |
| **WF-ADM-01** | Admin provisions new Doctor account | Inserts user into `users` and doctor profile into `doctors` | Account and linked doctor profile created successfully | **PASS** |
| **WF-ADM-02** | Admin toggles user active status (soft-deactivation) | Updates `is_active`; prevents self-deactivation of admin | User deactivated; admin self-deactivation blocked | **PASS** |
| **WF-DOC-01** | Doctor updates appointment status (`scheduled` $\rightarrow$ `completed`) | Updates status for assigned appointment; rejects unassigned | Status updated for assigned appointment; unassigned blocked | **PASS** |
| **WF-DOC-02** | Doctor creates medical record for authorized vs unauthorized patient | Verified relationship allowed; unassigned patient rejected | Authorized record created; unauthorized attempt blocked | **PASS** |
| **WF-PAT-01** | Patient requests consultation appointment with active doctor | Validates doctor, date, and reason; creates appointment | Appointment scheduled with status `scheduled` | **PASS** |
| **WF-PAT-02** | Patient cancels own scheduled appointment | Cancels appointment; blocks cancellation of other patients' visits | Appointment cancelled; IDOR cancellation blocked | **PASS** |
| **WF-REP-01** | Report upload validation against signature allowlist | Rejects `.exe` and spoofed PDF; accepts valid binary PDF | Validated magic bytes and MIME types accurately | **PASS** |
| **WF-UI-01** | Admin dashboard empty database state rendering | Renders clean empty table state without uncaught exceptions | Empty state rendered cleanly | **PASS** |
| **WF-UI-02** | Doctor dashboard empty appointments rendering | Renders clean empty table state | Empty state rendered cleanly | **PASS** |
| **WF-UI-03** | Patient dashboard empty history rendering | Renders clean empty table state | Empty state rendered cleanly | **PASS** |

---

### C. Phase 2: Security Regressions (`test_phase2_suite.py`)

| Test ID | Scenario | Expected Behavior | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **REG-01** | App creation and blueprint registration | 5 expected blueprints registered (`auth`, `admin`, `doctor`, `patient`, `reports`) | All 5 blueprints verified | **PASS** |
| **REG-02** | Unauthenticated access to `/admin`, `/doctor`, `/patient` dashboards | Redirects to `/login` with 302 | All protected routes redirected to `/login` | **PASS** |
| **REG-03** | Role restrictions enforced (Patient $\rightarrow$ Admin dashboard) | Cross-role request blocked with 302 / error message | Blocked with insufficient privileges notice | **PASS** |
| **REG-04** | Invalid login credentials | Returns uniform generic error; prevents user enumeration | Returned "Invalid username or password" | **PASS** |
| **REG-05** | Valid login credential verification | Creates authenticated session; clears previous session data | Authenticated session created with role | **PASS** |
| **REG-06** | Logout session invalidation | Session cleared entirely; redirect to `/login` | Session completely invalidated | **PASS** |
| **REG-07** | Audit logging write and DB failure resilience | Successful events logged; DB errors handled without crash | Handled gracefully without leaking credentials | **PASS** |
| **REG-08** | File extension allowlist enforcement | Accepts `.pdf`, `.png`, `.jpg`; rejects unlisted extensions | Enforced extension allowlist | **PASS** |
| **REG-09** | Magic byte validation for PNG and JPEG files | Validates binary headers; rejects spoofed extensions | Enforced binary magic bytes | **PASS** |
| **REG-10** | Path traversal defense in report downloads | Rejects `../../` traversal; canonical containment check | Traversal attempts blocked | **PASS** |
| **REG-11** | Report download authorization check | Enforces patient ownership and doctor relationship | Authorization matrix enforced | **PASS** |
| **REG-12** | Static asset loading (CSS and JS) | Returns HTTP 200 for `/static/css/style.css` and `/static/js/main.js` | HTTP 200 returned for static assets | **PASS** |

---

## 3. Confirmed Defects Remediated During Phase 4

1. **Mid-Session Account Deactivation Gap**:
   - *Defect:* If an administrator deactivated an account (`is_active = 0`), an existing active session cookie remained valid on subsequent requests.
   - *Fix:* Added `_is_account_active(uid)` checks to `@login_required` and `@role_required` in `routes/auth.py`. Deactivated accounts have their sessions immediately purged and are redirected to login.
2. **Missing Brute-Force Rate Limiting**:
   - *Defect:* The authentication endpoint permitted unlimited consecutive failed login attempts.
   - *Fix:* Implemented a configurable, in-memory sliding-window rate limiter in `routes/auth.py` (`AUTH_MAX_FAILED_ATTEMPTS=5`, `AUTH_LOCKOUT_SECONDS=60`). Client IPs exceeding the threshold are locked out and logged.
3. **Past Appointment Date Acceptance**:
   - *Defect:* Patient consultation booking did not reject dates in the past.
   - *Fix:* Added validation in `routes/patient.py` verifying that `appointment_dt >= datetime.now()`.
4. **Appointment Status Transition Finalization**:
   - *Defect:* Finalized appointments (`completed` or `cancelled`) could theoretically be reverted or mutated.
   - *Fix:* Added transition guards in `routes/doctor.py` preventing changes to finalized consultations.
5. **Testing Bypass in CSRF Validator**:
   - *Defect:* `routes/reports.py` bypassed CSRF checks when `request.form.get("csrf_token")` was empty in test mode.
   - *Fix:* Removed the bypass to enforce strict CSRF validation across all execution environments.

---

## 4. Attack Prevention & Audit Evidence Matrix (Demonstration Results)

The following 10 attack scenarios were executed and validated via `demonstrate_security_controls.py`:

| # | Scenario | Test Input | Expected Defense | HTTP Result | Audit Evidence |
| :- | :--- | :--- | :--- | :--- | :--- |
| **1** | Invalid Login | `username='unknown_user'`, `password='***'` | Generic error; prevent user enumeration | HTTP 200 (`Invalid username or password`) | `LOGIN_FAILED` / `FAILED` |
| **2** | Rate Limiting / Brute-Force | 6 consecutive failed logins from `127.0.0.1` | Sliding-window throttle blocks 6th attempt | HTTP 200 (`Too many failed login attempts`) | `LOGIN_FAILED` / `DENIED` |
| **3** | Unauthenticated Access | `GET /admin/dashboard` (no session) | `@login_required` decorator redirects to login | HTTP 302 (Redirect to `/login`) | `UNAUTHORIZED_ACCESS` / `DENIED` |
| **4** | Cross-Role Access (RBAC) | Patient session accessing `/admin/dashboard` | `@role_required("admin")` blocks role mismatch | HTTP 302 (Redirect to `/login`) | `UNAUTHORIZED_ACCESS` / `DENIED` |
| **5** | Cross-Patient IDOR Download | Patient 111 requesting Report 55 of Patient 999 | Ownership check fails | HTTP 403 Forbidden | `UNAUTHORIZED_ACCESS` / `DENIED` |
| **6** | CSRF Rejection | `POST /admin/user/create` with forged token | Constant-time CSRF check fails | HTTP 200 (`Security token validation failed`) | `UNAUTHORIZED_ACCESS` / `DENIED` |
| **7** | SQL Injection Bypass | `username="' OR '1'='1"`, `password='pwd'` | Parameterized query `%s` treats payload literally | HTTP 200 (`Invalid username or password`) | `LOGIN_FAILED` / `FAILED` |
| **8** | XSS Script Tag Escaping | `reason='<script>alert("pwned")</script>'` | Jinja2 auto-escapes HTML characters | HTTP 200 (No raw `<script>` in DOM) | Sanitized safely in context |
| **9** | Spoofed File-Type Upload | `invoice.pdf` containing `MZ` header (Windows PE) | Magic byte validator detects signature mismatch | Validator error (`Malformed file`) | `UPLOAD_REJECTED` / `FAILED` |
| **10** | Deactivated Session Revocation | Active cookie for user with `is_active=0` | Session purged immediately on next request | HTTP 200 (`Account has been deactivated`) | `UNAUTHORIZED_ACCESS` / `DENIED` |
