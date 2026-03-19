# TamozaKeyGen — License Key Management System
## Project Directory Structure

```
TamozaKeyGen/
├── backend/
│   ├── __init__.py
│   ├── api_v1.py
│   ├── auth.py
│   ├── database.py
│   ├── main.py
│   ├── models.py
│   └── schemas.py
├── frontend/
│   ├── app.js
│   ├── dashboard.html
│   └── index.html
├── scripts/
│   ├── client_integration.cs
│   ├── client_integration.py
│   └── run_client.bat
├── API_Documentation.md
├── README.md
├── requirements.txt
├── SETUP.md
└── tree.md
```

---

## File Descriptions

### `/backend`

| File | Description |
|------|-------------|
| `__init__.py` | Marks the `backend/` directory as a Python package, enabling relative imports between modules. |
| `api_v1.py` | Public versioned API router — exposes `POST /api/v1/validate` (full license validation pipeline: existence, validity window, app binding, HWID, suspicious-activity detection) and `POST /api/v1/heartbeat` (keep-alive signal that marks a key as online). |
| `auth.py` | JWT authentication — implements `hash_password()`, `verify_password()`, `create_access_token()`, `get_current_user()` dependency, `require_superadmin()` dependency, and the `POST /api/v1/auth/token` login endpoint. |
| `database.py` | SQLAlchemy engine and session factory — reads `DATABASE_URL` from the environment, configures connection pooling, and exposes the `get_db()` FastAPI dependency for per-request sessions. |
| `main.py` | FastAPI application entry point — registers routers, configures CORS, runs startup migrations (`ALTER TABLE` guards), seeds the default admin account, mounts the frontend as static files, and defines all admin endpoints under `/api/v1/admin/`. |
| `models.py` | SQLAlchemy ORM table definitions — declares `LicenseKey` (identity, classification, validity window, HWID binding, usage tracking, analytics), `LoginEvent` (per-validation audit record), and `User` (admin accounts). |
| `schemas.py` | Pydantic request/response schemas — defines `LicenseKeyCreate`, `LicenseKeyResponse`, `UpdateKeyDetails`, `UpdateAdminNote`, `UpdateMaxDevices`, `LicenseKeyExtend`, `StatsResponse`, `AlertsResponse`, `Token`, and `LoginEventResponse`. |

---

### `/frontend`

| File | Description |
|------|-------------|
| `app.js` | Dashboard JavaScript — handles JWT-authenticated `apiFetch()` calls, client-side filtering and search, table rendering via DOM methods, key action handlers (pause, extend, reset HWID, delete), the Forensic View modal including Safe Edit Mode (`enterForensicEditMode()`, `saveForensicEdit()`, `cancelForensicEdit()`), and the admin note save flow. |
| `dashboard.html` | Admin dashboard UI — Tailwind CSS (Play CDN) single-page app containing the stats bar, alerts panel, add-key form (with key class and permission level selectors), filterable/searchable key table with a "Class / Perm" column, and the Forensic View modal with inline edit form, activity metrics, and login history table. |
| `index.html` | Admin login page — JWT login form that posts credentials to `/api/v1/auth/token`, stores the returned token in `localStorage`, and redirects to `dashboard.html`. |

---

### `/scripts`

| File | Description |
|------|-------------|
| `client_integration.cs` | C# / .NET 6+ SDK — provides `LicenseValidator` with `ValidateAsync()` and synchronous `Validate()`, WMI-based HWID fingerprinting via `HardwareIdProvider`, a `ValidateResponse` JSON DTO (including `KeyClass` and `PermissionLevel`), full `ValidationStatus` enum, and a console entry-point for standalone testing. |
| `client_integration.py` | Python SDK — provides `LicenseValidator` with a `validate()` method, cross-platform HWID collection (`get_hardware_id()` for Windows/Linux/macOS), a frozen `ValidationResult` dataclass (including `key_class` and `permission_level`), full `ValidationStatus` enum with human-readable messages, and a CLI entry-point for standalone testing. |
| `run_client.bat` | Windows batch helper — activates the `.venv` virtual environment and launches the Python SDK CLI (`client_integration.py`) for quick local testing without manually activating the environment. |

---

### Root-level files

| File | Description |
|------|-------------|
| `API_Documentation.md` | Client SDK integration guide — explains the validation lifecycle, all `ValidationStatus` values, the success response fields (`key_class`, `permission_level`), error mapping, the SDK result object contract, and the implementation checklist for new SDK targets. |
| `README.md` | GitHub project overview — features list, tech stack, quick-start commands, project structure, API overview table, SDK usage examples, data model summary, environment variables, and security notes. |
| `requirements.txt` | Python dependency manifest — pins FastAPI, Uvicorn, SQLAlchemy, PyMySQL, python-jose, passlib, bcrypt 4.0.1, pydantic, and requests. |
| `SETUP.md` | Full installation and configuration guide — step-by-step setup for Windows and Linux, environment variable reference, first-run walkthrough, production hardening (workers, systemd service, nginx reverse proxy, CORS restriction), and a troubleshooting section. |
| `tree.md` | This file — project directory structure and file descriptions. |
