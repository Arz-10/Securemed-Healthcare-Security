# SecureMed — Secure Healthcare Patient Information Management System

SecureMed is a modular, defense-in-depth healthcare web application built with Python (Flask) and MySQL. It provides role-segregated clinical workflows for Hospital Administrators, Attending Physicians, and Registered Patients while enforcing robust cybersecurity controls across the application, database, and storage tiers.

> **Notice:** This application is developed as an educational cybersecurity engineering project. It implements defense-in-depth principles (RBAC, constant-time authentication, CSRF mitigation, IDOR defense, upload validation, and audit logging) for demonstration and local testing, and does not claim production regulatory compliance (e.g., formal HIPAA/HITECH certification).

---

## 1. System Features & Workflows

### Role-Based Portals
- **Administrator Console (`/admin/dashboard`)**:
  - Live database metrics (users, doctors, patients, appointments, reports, audit events).
  - Secure user provisioning with role profile creation (`doctors` / `patients`).
  - Account status toggling (soft activation/deactivation with self-deactivation guard).
  - System-wide directory oversight and medical report metadata management.
  - Comprehensive, paginated security audit log inspector with event-type and outcome filtering.
- **Physician Clinical Workspace (`/doctor/dashboard`)**:
  - Consultation appointment schedule and encounter status progression (`scheduled` $\rightarrow$ `completed` / `cancelled`).
  - Strictly isolated patient directory restricted only to authorized patients who have appointments with the physician.
  - Electronic Medical Record (EMR) authoring with doctor-patient relationship validation.
  - Diagnostic report uploading with binary magic-byte inspection and secure file delivery.
- **Patient Health Portal (`/patient/dashboard`)**:
  - Personal demographic and emergency contact profile review.
  - Online consultation appointment booking with active physicians (future date validation).
  - Self-service cancellation of pending scheduled appointments.
  - Personal medical history and verified diagnostic reports review.

---

## 2. Core Security Architecture

- **Authentication & Sessions**:
  - Werkzeug password hashing (`pbkdf2:sha256`) with salted keys.
  - Parameterized SQL authentication queries preventing SQL injection.
  - Constant-time password comparison (`check_password_hash`) defeating timing attacks.
  - Session fixation mitigation (session dictionary purged prior to session establishment).
  - Immediate session termination for deactivated accounts on every request.
  - In-memory sliding-window failed login rate limiting (lockout after 5 failed attempts per client).
- **Access Control & IDOR Defense**:
  - Server-side authorization decorators (`@login_required`, `@role_required`).
  - Strict database relationship validation preventing unauthorized cross-patient record access.
- **State-Changing Protection**:
  - CSRF protection via constant-time token comparison (`secrets.compare_digest`) on all POST requests.
- **File & Storage Security**:
  - Binary magic-byte signature verification (PDF, PNG, JPG/JPEG).
  - 5 MB individual file size cap and 16 MB request limit.
  - Anti-traversal defenses: canonical storage path containment verification outside public static directories.
  - Unguessable UUID4 server-side stored filenames.
- **Security Audit Logging**:
  - Structured, persistent audit logging into `audit_logs` table.
  - Sensitive data exclusion: clinical diagnosis text, prescriptions, passwords, and tokens are never logged.

---

## 3. Technology Stack & Prerequisites

- **Language & Runtime**: Python 3.11+
- **Web Framework**: Flask 3.x, Jinja2, Werkzeug
- **Database**: MySQL 8.x (accessed via `mysql-connector-python`)
- **Frontend**: Bootstrap 5.3, Bootstrap Icons, Inter font, Vanilla CSS
- **Configuration**: `python-dotenv` reading `.env`

---

## 4. Installation & Local Setup

### 1. Clone & Navigate to Project Root
```powershell
cd "C:\Users\Aarushi Sontakke\Downloads\Cyber_Project"
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` if not already present and configure database parameters:
```ini
FLASK_SECRET_KEY=secure-random-secret-key-change-in-production
FLASK_DEBUG=1
DB_HOST=localhost
DB_PORT=3306
DB_NAME=securemed_db
DB_USER=root
DB_PASSWORD=your_mysql_password
```

### 3. Virtual Environment
```powershell
# Activate existing virtual environment
.\.venv\Scripts\Activate.ps1

# Verify dependencies
pip install -r requirements.txt
```

### 4. Interactive Development Account Setup
Run the safe account provisioning utility to configure passwords interactively without echoing credentials:
```powershell
.\.venv\Scripts\python.exe seed_dev_accounts.py
```
- **Option 1**: Configure/update the default `admin` account password.
- **Option 2**: Provision or update a Doctor account (e.g., `demo_doctor` - Dr. Alexander Wright).
- **Option 3**: Provision or update a Patient account (e.g., `demo_patient` - Eleanor Vance).
- **Option 4**: Provision a custom account (e.g., `demo_admin`).

---

## 5. Running the Application

Start the local development server:
```powershell
.\.venv\Scripts\python.exe app.py
```
Access the application in your browser at:
**`http://127.0.0.1:5000`**

---

## 6. Running Automated Tests & Demonstration Tools

SecureMed includes 3 automated test suites (40 tests total, 100% PASS), a standalone offensive demonstration runner, and a modular SIEM event exporter:

```powershell
# 1. Run all 40 automated test cases across the entire project
.\.venv\Scripts\python.exe -m unittest discover -s . -p "test_*.py" -v

# 2. Run the 10 repeatable attack prevention demonstration scenarios
.\.venv\Scripts\python.exe demonstrate_security_controls.py

# 3. Export sanitized security events for SIEM/Wazuh
.\.venv\Scripts\python.exe export_security_events.py --limit 20
```

---

## 7. Documentation Index

Comprehensive project, academic, and cybersecurity documentation is located in the [`docs/`](file:///c:/Users/Aarushi%20Sontakke/Downloads/Cyber_Project/docs) directory:
- [docs/project_submission.md](file:///c:/Users/Aarushi%20Sontakke/Downloads/Cyber_Project/docs/project_submission.md) — **Complete College Submission Dossier**: Abstract, problem statement, threat model, live demo script, and Viva Voce Q&A.
- [docs/architecture.md](file:///c:/Users/Aarushi%20Sontakke/Downloads/Cyber_Project/docs/architecture.md) — System components, role boundaries, database schema relationships, and request lifecycle.
- [docs/security_controls.md](file:///c:/Users/Aarushi%20Sontakke/Downloads/Cyber_Project/docs/security_controls.md) — Comprehensive technical index of security controls, OWASP Top 10 defenses, and code locations.
- [docs/security_test_results.md](file:///c:/Users/Aarushi%20Sontakke/Downloads/Cyber_Project/docs/security_test_results.md) — Complete 40-test verification matrix and attack demonstration evidence.
- [docs/demo_script.md](file:///c:/Users/Aarushi%20Sontakke/Downloads/Cyber_Project/docs/demo_script.md) — Step-by-step role demonstration walkthrough for live presentation.
- [docs/monitoring_setup.md](file:///c:/Users/Aarushi%20Sontakke/Downloads/Cyber_Project/docs/monitoring_setup.md) — Security monitoring integration guide for Nmap, Wireshark, Suricata, OpenVAS, and Wazuh.
