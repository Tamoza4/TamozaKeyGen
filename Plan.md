Act as a Senior Full-Stack Developer and Cyber Security Architect. I need you to build a complete, secure License Key Management System.

### 1. Technical Stack Requirements
- **Backend:** Python (using FastAPI or Flask for performance).
- **Database:** MySQL (relational, robust storage).
- **ORM:** SQLAlchemy or Tortoise ORM.
- **Frontend:** HTML, CSS (Tailwind CSS suggested), and vanilla JavaScript. Must support Dark Mode.
- **Authentication:** Secure Admin Login (hashed passwords, JWT tokens).

### 2. Comprehensive Database Schema (MySQL)
Design the database to store the following granular details for each `LicenseKey`:
- **Key Details:** Cryptographically secure `key_string`, `application_name`, `owner_name`.
- **Time Controls:** `start_date` and `end_date` stored with second-precision (DATETIME). `is_paused` boolean.
- **Hardware Locking:** `hwid_lock_enabled` (boolean), `locked_hwid` (string), `max_devices` (integer, default 1), `current_devices_count` (integer).
- **Forensic & Activity Logs:**
    - `created_at`, `first_login_at`, `last_login_at`.
    - `is_online` (boolean, based on last ping).
    - `last_ip_address`, `last_region` (derived from IP).
    - `hwid_reset_count` (integer).
    - `logins_last_24h` (integer, resets daily).
    - `total_usage_time_seconds` (integer).
- **Security Flag:** `is_suspicious` (boolean, flagged by analysis logic).

### 3. Core Features & User Stories

#### A. Admin Dashboard (Protected by Login with Dark Mode)
- **Home Page:** Display general stats: Total Keys, Active Keys, Expired Keys, Online Users. Show "Important Alerts" (e.g., "5 keys flagged as suspicious", "10 keys expiring in 24h").
- **Add New Key Form:** Fields for App Name, Owner Name, Duration (dropdown/datepicker), HWID Lock Enable/Disable toggle, Max Devices count.
- **Key Management Table:** A comprehensive table with search/filter. Each row has an **Actions Menu**:
    - **Extend Duration:** Add days/hours to `end_date`.
    - **Pause/Resume:** Toggle `is_paused` status.
    - **Delete Key:** Remove permanently.
    - **Reset HWID:** Clear `locked_hwid` and increment `hwid_reset_count`.
    - **Toggle HWID Lock:** Enable/disable HWID checking for this specific key.
    - **Update Max Devices:** Change allowed simultaneous devices.
- **Detailed Key View:** A dedicated page per key showing *all* forensic data from Section 2.
    - **Suspicious Activity Analysis:** An automated logic that flags the key (`is_suspicious = true`) if:
        - The same key connects from 3 different regions within 1 hour.
        - The logins in the last 24h exceed a threshold (e.g., > 50).
        - HWID resets exceed 3 in a week.
        The Admin sees a red warning: "Suspicious Activity Detected: [Reason]".

#### B. The Universal API (For Clients: Python, C#, PHP)
Create a secure endpoint `/api/v1/validate` (POST).
- **Inputs:** `key_string`, `hwid`, `device_name`.
- **Validation Logic:**
    1. If Key not found -> Return "Invalid Key".
    2. If `is_paused` is true -> Return "License Suspended".
    3. If `Now < start_date` -> Return "License Not Yet Active".
    4. If `Now > end_date` -> Return "License Expired".
    5. If `hwid_lock_enabled` is true:
        - If `locked_hwid` is empty -> Bind incoming `hwid` to key, update database, allow access.
        - If `locked_hwid` doesn't match incoming `hwid` -> Return "Hardware ID Mismatch".
    6. If all checks pass: Update `last_login_at`, `last_ip_address`, `is_online = true`. Return "Success" + Encrypted Token.

### 4. Special Deliverable: `tree.md`
Before writing the code, generate a `tree.md` file that lists the entire project structure. For every file and function, provide a concise explanation of its purpose. Example:
```markdown
# Project Structure

- `backend/`
  - `main.py`: Entry point, initializes FastAPI.
  - `models.py`: Defines SQLAlchemy models (User, LicenseKey).
  - `auth.py`: Handles JWT generation and password hashing.
  - `api_v1.py`: Contains the `/validate` endpoint and forensic logic.
- `frontend/`
  - `dashboard.html`: Main admin interface.
  - `js/app.js`: Handles frontend logic and Dark Mode toggle.