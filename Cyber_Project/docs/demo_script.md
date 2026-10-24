# SecureMed — Live Cybersecurity Demonstration Script

This script provides an interactive, step-by-step demonstration plan for evaluating SecureMed's healthcare workflows, role boundaries, defensive controls, and audit trails.

---

## 1. Pre-Flight Setup & Environment Check

1. Open PowerShell in the project directory:
   ```powershell
   cd "C:\Users\Aarushi Sontakke\Downloads\Cyber_Project"
   ```
2. Ensure the local application server is running:
   ```powershell
   .\.venv\Scripts\python.exe app.py
   ```
   Confirm the application is accessible at **`http://127.0.0.1:5000`**.
3. Demonstration Accounts & Local Setup:
   The application uses dedicated local demonstration accounts provisioned with salted PBKDF2:SHA256 password hashes:

   | Role | Account Username | Full Name / Profile | Password Configuration |
   | :--- | :--- | :--- | :--- |
   | **Administrator** | `demo_admin` (or `admin`) | System Administrator | Set manually via `seed_dev_accounts.py` |
   | **Physician** | `demo_doctor` | Dr. Alexander Wright (Cardiology) | Set via local setup utility |
   | **Patient** | `demo_patient` | Eleanor Vance (Blood: O+) | Set via local setup utility |

   > **Security Note:** In accordance with security best practices, plaintext passwords are never committed to version control. Set or update passwords locally using:
   > ```powershell
   > .\.venv\Scripts\python.exe seed_dev_accounts.py
   > ```

---

## 2. Demonstration Flow

### Scene 1: Administrator Operations & Governance
1. Open browser at `http://127.0.0.1:5000/login`.
2. Sign in as `demo_admin` (or `admin`) using your configured administrative password.
3. Highlight the **Administration Console**:
   - Live metrics summary (Total Users, Active Doctors, Patients, Appointments, Reports, Audit Events).
   - Click **Users Directory** tab: view active user accounts (`demo_doctor`, `demo_patient`).
   - Click **Doctors Directory** tab: view physician licensing (`MD-DEMO-01`) and Cardiology department.
   - Click **Patients Directory** tab: view patient demographics and emergency contacts.
4. Click the **Audit Logs** tab:
   - Demonstrate the multi-criteria filter (e.g., filter by `LOGIN_SUCCESS` or `USER_MANAGEMENT`).
   - Demonstrate outcome filtering (`SUCCESS`, `DENIED`, `FAILED`).
   - Show that context details record only metadata without passwords or clinical notes.
5. Click **Logout** in the top navbar.

---

### Scene 2: Patient Consultation Booking (Health Portal)
1. Sign in as `demo_patient` with your configured patient password.
2. Notice the navbar badge updates to **Patient** and lands on the **Patient Health Portal** (`Eleanor Vance`).
3. In **Personal Profile** tab, review demographic isolation.
4. Under **My Appointments**, observe the scheduled future consultation with `Dr. Alexander Wright` (`Cardiology`).
5. Click **Request Consultation**:
   - Select `Dr. Alexander Wright` from active physicians.
   - Choose a future date and time.
   - Enter consultation reason: `"Cardiovascular follow-up and resting ECG assessment"`.
   - Submit request and confirm new appointment appears in `Scheduled` status.
6. Click **Logout**.

---

### Scene 3: Physician Clinical Workflow & EMR Authoring
1. Sign in as `demo_doctor` with your configured doctor password.
2. Land on **Physician Clinical Workspace** (`Dr. Alexander Wright`):
   - Observe live metrics reflecting clinical encounters.
   - Under **Appointments**, inspect `Eleanor Vance`'s consultation appointments.
   - Under **My Patients**, notice `Eleanor Vance` is listed as an authorized patient because an appointment relationship exists.
3. Advance Consultation:
   - Click **Update** on a scheduled appointment.
   - Change status to `Completed` with clinical notes: `"Vitals stable; ECG completed"`.
   - Submit status change.
4. Review & Author Electronic Medical Record (EMR):
   - Click **Medical Records** tab.
   - View the existing verified clinical diagnosis: `"Mild Essential Hypertension"`.
   - To author a new record: Click **New Record**, select `Eleanor Vance`, input clinical assessment, and save.
5. Deliver Diagnostic Report:
   - Click **Diagnostic Reports** tab.
   - Observe the verified PDF report (`cardiac_ecg_report_demo.pdf`).
   - Click **Upload Report** to demonstrate file upload with binary magic-byte validation.
6. Click **Logout**.

---

### Scene 4: Patient Record Verification & Report Download
1. Sign in as `demo_patient`.
2. Under **Medical History**, inspect the verified clinical diagnosis and prescription documented by `Dr. Alexander Wright`.
3. Under **Diagnostic Reports**, click **Download** on `cardiac_ecg_report_demo.pdf` and verify successful retrieval.
4. Click **Logout**.

---

### Scene 5: Cybersecurity Attack Simulations & Defenses

#### 1. SQL Injection Authentication Bypass
- On the login page, submit username: `' OR '1'='1` with password `anything`.
- **Result:** Parameterized query handles input literally; access is rejected with `"Invalid username or password."`

#### 2. Cross-Role Privilege Escalation (RBAC)
- Log in as `demo_patient` (Patient).
- Directly navigate to `http://127.0.0.1:5000/admin/dashboard`.
- **Result:** Intercepted by `@role_required("admin")`; redirected with `"Unauthorized access: insufficient privileges."`

#### 3. Insecure Direct Object Reference (IDOR)
- While logged in as `demo_patient`, attempt to issue a POST request to cancel another patient's appointment ID (e.g. ID `999`):
- **Result:** Blocked with `"Appointment not found or not registered under your profile."`

#### 4. Brute-Force Rate Limiting
- Attempt 5 rapid failed logins using bad passwords for an account.
- On the 6th attempt, notice immediate lockout:
- **Result:** `"Too many failed login attempts. Please wait 60 seconds before trying again."` and logged as `DENIED`.

#### 5. Malicious File Upload Defense
- Log in as `demo_doctor`. Attempt to upload an executable renamed to `.pdf` (e.g., `calc.exe` renamed to `scan.pdf`).
- **Result:** Magic-byte inspection detects signature mismatch; upload rejected with `"Malformed file: file content does not match valid PDF format."`

#### 6. Deactivated Account Session Revocation
- Log in as `demo_admin` (or `admin`).
- In **Users Directory**, click **Deactivate** next to `demo_patient`.
- Switch to `demo_patient`'s active browser tab and refresh.
- **Result:** Immediate session revocation; redirected to login with `"Your account has been deactivated. Please contact an administrator."`

---

## 3. Concise 5–7 Minute Presentation Sequence

| Time | Segment | Presenter Action | Target Audience Focus |
| :--- | :--- | :--- | :--- |
| **0:00 - 1:00** | **Governance & RBAC** | Sign in as `demo_admin` (or `admin`). View dashboard metrics, user directory (`demo_doctor`, `demo_patient`), and filtered audit log entries (`LOGIN_SUCCESS`, `DENIED`). | Hospital oversight, multi-dimensional audit trail, non-sensitive logging. |
| **1:00 - 2:00** | **Patient Portal** | Sign in as `demo_patient`. Book a future consultation with `Dr. Alexander Wright`. Show appointment in `Scheduled` status. | Patient self-service, future-date validation, ownership isolation. |
| **2:00 - 3:30** | **Doctor Clinical Flow** | Sign in as `demo_doctor`. Mark appointment `Completed`. Author EMR record with diagnosis & prescription. View/upload lab PDF report. | Clinical lifecycle, relationship-based patient directory, magic-byte upload inspection. |
| **3:30 - 4:30** | **Patient Review** | Sign in as `demo_patient`. View completed consultation, read verified EMR prescription, download lab report. | Complete healthcare loop, IDOR protection on downloads. |
| **4:30 - 6:00** | **Live Security Proof** | Run `python demonstrate_security_controls.py` in terminal: demonstrate SQLi bypass failure, IDOR report access block, brute-force rate limit lockout, and mid-session deactivation. | Automated offensive defense proof and verified HTTP/audit results. |
| **6:00 - 7:00** | **SIEM & Monitoring** | Run `python export_security_events.py --limit 5`. Highlight sanitized Wazuh-aligned JSON and severity scoring (1-10). | Monitoring readiness without clinical data or credential leaks. |

---

## 4. Automated Demonstration Runner

To execute all 10 defensive scenarios non-destructively in automated sequence:
```powershell
.\.venv\Scripts\python.exe demonstrate_security_controls.py
```

*For likely Viva Voce technical questions and model answers, refer to [docs/project_submission.md](file:///c:/Users/Aarushi%20Sontakke/Downloads/Cyber_Project/docs/project_submission.md#9-likely-viva-voce-questions--answers).*
