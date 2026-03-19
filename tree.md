# TamozaKeyGen — License Key Management System
## Project Directory Structure

```
TamozaKeyGen/
├── backend/
│   ├── main.py
│   ├── models.py
│   ├── schemas.py
│   ├── auth.py
│   └── api_v1.py
├── frontend/
│   ├── index.html
│   ├── dashboard.html
│   ├── styles.css
│   └── app.js
├── scripts/
│   ├── client_integration.py
│   └── client_integration.cs
└── tree.md
```

---

## File Descriptions

### `/backend`

| File | Description |
|------|-------------|
| `main.py` | FastAPI application entry point — initializes the app instance, registers routers, configures CORS middleware, and starts the Uvicorn server. |
| `models.py` | SQLAlchemy ORM model definitions — declares `User`, `License`, and `Product` database table classes with their column types, constraints, and relationships. |
| `schemas.py` | Pydantic request/response schemas — defines `LicenseCreate`, `LicenseResponse`, `UserCreate`, and `Token` data-transfer objects used for input validation and serialization. |
| `auth.py` | Authentication and authorization logic — implements `create_access_token()`, `verify_password()`, `get_current_user()`, and JWT-based OAuth2 bearer token validation. |
| `api_v1.py` | Versioned REST API router — exposes all `/api/v1/` endpoints including `generate_key()`, `validate_key()`, `revoke_key()`, `list_licenses()`, and `activate_license()`. |

---

### `/frontend`

| File | Description |
|------|-------------|
| `index.html` | Public-facing login and registration page — contains the HTML structure for the auth forms that submit credentials to the `/api/v1/auth/token` endpoint. |
| `dashboard.html` | Admin dashboard page — renders the license management UI including tables for active/revoked keys, product selectors, and key generation controls. |
| `styles.css` | Global stylesheet — defines layout, color themes, typography, table styling, button states, and responsive breakpoints for all frontend pages. |
| `app.js` | Frontend JavaScript logic — handles API calls via `fetch()`, manages JWT storage in `localStorage`, populates the dashboard tables, and drives the key generation and revocation workflows. |

---

### `/scripts`

| File | Description |
|------|-------------|
| `client_integration.py` | Python client integration example — provides a `LicenseValidator` class with `check_license()` and `activate()` methods that call the validation API, intended for embedding in Python-based software products. |
| `client_integration.cs` | C# client integration example — provides a `LicenseClient` class with `ValidateKey()` and `ActivateKey()` methods using `HttpClient`, intended for embedding in .NET/Unity-based software products. |
