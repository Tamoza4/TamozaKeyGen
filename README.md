# TamozaKeyGen — License Key Management System

A self-hosted, full-stack license key management system built with **FastAPI**, **MySQL**, and a **Tailwind CSS** admin dashboard. Generate, validate, and monitor software license keys with hardware-binding, real-time analytics, and a forensic audit view.

---


## Features

### Admin Dashboard
- **Key generation** — create `XXXX-XXXX-XXXX-XXXX` keys with configurable app name, owner, duration, max devices, key class, and permission level
- **Live status** — online/offline indicator (5-minute heartbeat window), active/expired/suspended badge per key
- **Filters & search** — filter by status, application, key class; full-text search across key string, app, owner, IP, region
- **Safe Edit Mode** — inline editing of app name, owner, classification, permission level, end date, and admin note from the Forensic View
- **Forensic View** — per-key drill-down showing all metadata, device/HWID info, activity metrics, login history, and a private admin note field
- **Extend time** — add days / hours / minutes to any key's expiry without resetting its start date
- **HWID management** — enable/disable hardware binding; reset the locked HWID with one click
- **Dark mode** — system-preference aware, persisted in `localStorage`

### Backend / API
- `POST /api/v1/validate` — full validation pipeline (existence → validity window → app binding → HWID → suspicious-activity detection)
- `POST /api/v1/heartbeat` — lightweight keep-alive; marks key as online in the dashboard
- Complete admin REST API under `/api/v1/admin/` — CRUD, forensic endpoint, all key actions
- **JWT authentication** — 60-minute tokens, auto-redirect on expiry
- **Suspicious-activity detection** — flags keys with >3 unique region changes within 1 hour
- **Auto schema migrations** — new columns applied at startup with per-column `ALTER TABLE` guards

### Client SDKs
| SDK | File | Language |
|-----|------|----------|
| Python | `scripts/client_integration.py` | Python 3.9+ |
| C# / .NET | `scripts/client_integration.cs` | .NET 6+ / Unity |

Both SDKs expose `ValidationResult` with `status`, `granted`, `key_class`, `permission_level`, `owner_name`, `end_date`, HWID fingerprinting, and a full `ValidationStatus` enum for all server-side error cases.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/) |
| Database ORM | [SQLAlchemy 2.x](https://www.sqlalchemy.org/) |
| Database | MySQL 8 / MariaDB 10.6+ |
| Auth | JWT via [python-jose](https://github.com/mpdavis/python-jose), bcrypt 4.0.1 |
| Frontend | Tailwind CSS (Play CDN), Vanilla JS, Inter font |
| Python HTTP | [requests](https://docs.python-requests.org/) (SDK only) |

---

## Quick Start

### Prerequisites

- Python 3.11+
- MySQL 8+ (or XAMPP for local dev)
- `uv` or `pip`

### 1. Clone

```bash
git clone https://github.com/Tamoza4/TamozaKeyGen.git
cd TamozaKeyGen
```

### 2. Create Virtual Environment & Install Dependencies

```bash
# With uv (recommended)
uv venv .venv
uv pip install -r requirements.txt

# Or with pip
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.\.venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

### 3. Create the Database

```sql
CREATE DATABASE tamozakeygen CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 4. Run

```bash
# Linux / macOS
export DATABASE_URL="mysql+pymysql://root:@localhost:3306/tamozakeygen"
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
.venv/bin/uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Windows (PowerShell)
$env:DATABASE_URL = "mysql+pymysql://root:@localhost:3306/tamozakeygen"
$env:SECRET_KEY   = "replace-with-a-256-bit-random-string"
.\.venv\Scripts\uvicorn.exe backend.main:app --reload --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000** and log in with the default credentials (`admin` / `admin`). Change them immediately.

> For a full walkthrough covering Linux, Windows, production hardening, systemd service setup, and nginx reverse proxy, see **[SETUP.md](SETUP.md)**.

---

## Project Structure

```
TamozaKeyGen/
├── backend/
│   ├── main.py          # FastAPI app, admin router, all key endpoints
│   ├── models.py        # SQLAlchemy ORM — LicenseKey, LoginEvent, User
│   ├── schemas.py       # Pydantic request/response schemas
│   ├── auth.py          # JWT creation, bcrypt, get_current_user dependency
│   └── api_v1.py        # Public validate + heartbeat endpoints
├── frontend/
│   ├── index.html       # Admin login page
│   ├── dashboard.html   # Admin dashboard UI
│   ├── styles.css       # Global stylesheet
│   └── app.js           # Dashboard JS — API calls, table rendering, modals
├── scripts/
│   ├── client_integration.py   # Python SDK
│   └── client_integration.cs  # C# / .NET SDK
├── API.md               # Complete admin API reference
├── API_Documentation.md # SDK integration guide
├── SETUP.md             # Full setup guide (Windows + Linux)
└── requirements.txt
```

---

## Admin API Overview

All admin routes require a JWT bearer token (`Authorization: Bearer <token>`).

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/api/v1/auth/token` | Login — returns JWT |
| `POST` | `/api/v1/validate` | Validate a license key (public) |
| `POST` | `/api/v1/heartbeat` | Keep-alive ping (public) |
| `GET` | `/api/v1/admin/stats` | Dashboard statistics |
| `GET` | `/api/v1/admin/alerts` | Active system alerts |
| `GET` | `/api/v1/admin/keys` | List all license keys |
| `POST` | `/api/v1/admin/keys` | Create a new key |
| `PATCH` | `/api/v1/admin/keys/{id}` | Update key details (Safe Edit) |
| `GET` | `/api/v1/admin/keys/{id}/forensic` | Full forensic view for one key |
| `POST` | `/api/v1/admin/keys/{id}/toggle-pause` | Suspend / resume a key |
| `POST` | `/api/v1/admin/keys/{id}/extend` | Extend expiry by days/hours/minutes |
| `POST` | `/api/v1/admin/keys/{id}/reset-hwid` | Clear the bound HWID |
| `POST` | `/api/v1/admin/keys/{id}/toggle-hwid-lock` | Enable / disable HWID binding |
| `POST` | `/api/v1/admin/keys/{id}/update-max-devices` | Change the device limit |
| `POST` | `/api/v1/admin/keys/{id}/update-note` | Save the internal admin note |
| `DELETE` | `/api/v1/admin/keys/{id}` | Permanently delete a key (superadmin) |

Full request/response documentation: [API.md](API.md)  
SDK integration guide: [API_Documentation.md](API_Documentation.md)

---

## SDK Usage

### Python

```python
from scripts.client_integration import LicenseValidator

validator = LicenseValidator(
    api_url  = "https://your-server.com",
    app_name = "MyApp",
)

result = validator.validate("XXXX-XXXX-XXXX-XXXX")

if result.granted:
    print(f"Welcome, {result.owner_name}!")
    print(f"Class: {result.key_class}  |  Permission: {result.permission_level}")
    print(f"Expires: {result.end_date}")
else:
    print(result.message)   # user-friendly error
```

### C# / .NET

```csharp
using TamozaKeyGen;

using var validator = new LicenseValidator("https://your-server.com", appName: "MyApp");

ValidationResult result = await validator.ValidateAsync("XXXX-XXXX-XXXX-XXXX");

if (result.Granted)
{
    Console.WriteLine($"Welcome, {result.OwnerName}!");
    Console.WriteLine($"Class: {result.KeyClass}  |  Permission: {result.PermissionLevel}");
    Console.WriteLine($"Expires: {result.EndDate}");
}
else
{
    MessageBox.Show(result.Message);
}
```

---

## License Data Model

| Field | Type | Description |
|-------|------|-------------|
| `key_string` | `VARCHAR(64)` | Unique `XXXX-XXXX-XXXX-XXXX` key |
| `app_name` | `VARCHAR(128)` | Application the key is bound to |
| `owner_name` | `VARCHAR(128)` | License holder name |
| `key_class` | `VARCHAR(32)` | `Subscription`, `Trial`, or `Demo` |
| `permission_level` | `VARCHAR(32)` | `User`, `Admin`, or `Support` |
| `admin_note` | `VARCHAR(1024)` | Internal admin note (never sent to clients) |
| `start_date` / `end_date` | `DATETIME` | Validity window (UTC) |
| `is_paused` | `BOOLEAN` | Suspended flag |
| `hwid_lock_enabled` | `BOOLEAN` | Whether HWID binding is enforced |
| `locked_hwid` | `VARCHAR(256)` | SHA-256 hardware fingerprint |
| `max_devices` | `INTEGER` | Maximum concurrent devices |
| `is_suspicious` | `BOOLEAN` | Auto-flagged by region-change detector |
| `logins_last_24h` | `INTEGER` | Rolling 24-hour login count |
| `total_usage_seconds` | `BIGINT` | Cumulative usage time |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `mysql+pymysql://root:password@localhost:3306/tamozakeygen` | SQLAlchemy connection string |
| `SECRET_KEY` | `CHANGE_ME_IN_PRODUCTION_USE_256BIT_RANDOM` | JWT signing secret — **change before deploying** |
| `ADMIN_USERNAME` | `admin` | Seeded on first startup |
| `ADMIN_PASSWORD` | `admin` | Seeded on first startup — **change immediately** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT lifetime |
| `CORS_ORIGINS` | `http://localhost,http://127.0.0.1` | Comma-separated allowed origins |

---

## Security Notes

- `SECRET_KEY` **must** be replaced with a cryptographically random value before any public deployment.  
  Generate one: `python -c "import secrets; print(secrets.token_hex(32))"`
- `admin_note` is stored in the database but is **never included** in any client-facing API response.
- All admin routes require JWT authentication. The delete endpoint additionally requires superadmin privilege.
- HWID fingerprints are SHA-256 hashes — raw hardware identifiers are never transmitted or stored.
- The suspicious-activity detector flags but does not auto-revoke keys; the admin decides how to respond.

---

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss what you would like to change.

---

## License

[MIT](LICENSE)
