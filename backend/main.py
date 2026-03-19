"""
main.py — TamozaKeyGen FastAPI application entry point.

Registers all routers, configures CORS, creates DB tables on startup,
and seeds a default admin account if none exists.

Run with:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
"""

import os
import secrets
import string
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .auth import get_current_user, hash_password, require_superadmin, router as auth_router
from .api_v1 import router as validate_router
from .database import engine, get_db
from .models import Base, LicenseKey, LoginEvent, User
from .schemas import (
    AlertItem,
    AlertsResponse,
    LicenseKeyCreate,
    LicenseKeyExtend,
    LicenseKeyResponse,
    LoginEventResponse,
    StatsResponse,
    UpdateAdminNote,
    UpdateKeyDetails,
    UpdateMaxDevices,
)

# ─────────────────────────────────────────────────────────────────────────────
# Startup / Shutdown lifecycle
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables if they don't exist yet
    Base.metadata.create_all(bind=engine)
    _run_migrations()
    _seed_default_admin()
    yield
    # (shutdown logic goes here if needed)


def _run_migrations():
    """Applies lightweight schema changes for new columns on existing tables."""
    from sqlalchemy import text
    migrations = [
        "ALTER TABLE license_keys ADD COLUMN first_region VARCHAR(128) NULL",
        "ALTER TABLE license_keys ADD COLUMN key_class VARCHAR(32) NOT NULL DEFAULT 'Subscription'",
        "ALTER TABLE license_keys ADD COLUMN permission_level VARCHAR(32) NOT NULL DEFAULT 'User'",
        "ALTER TABLE license_keys ADD COLUMN admin_note VARCHAR(1024) NULL",
    ]
    for stmt in migrations:
        try:
            with engine.connect() as conn:
                conn.execute(text(stmt))
                conn.commit()
        except Exception:
            pass  # column already exists — ignore


def _seed_default_admin():
    """Creates a default admin account if no users exist in the database."""
    from .database import SessionLocal
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            default_password = os.getenv("ADMIN_PASSWORD", "admin")
            admin = User(
                username         = os.getenv("ADMIN_USERNAME", "admin"),
                hashed_password  = hash_password(default_password),
                is_active        = True,
                is_superadmin    = True,
            )
            db.add(admin)
            db.commit()
            print(
                f"\n  [TamozaKeyGen] Default admin created — "
                f"username: '{admin.username}'  password: '{default_password}'\n"
                f"  Change this immediately via the ADMIN_PASSWORD env variable.\n"
            )
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# App instance
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "TamozaKeyGen — License Key Management",
    description = "Admin API for managing software license keys.",
    version     = "1.0.0",
    lifespan    = lifespan,
)

# ─────────────────────────────────────────────────────────────────────────────
# CORS — allow all origins so any browser-based or SDK client can reach the API.
# Admin endpoints are still protected by JWT; opening CORS here does not weaken
# security because Bearer-token auth is enforced at the route level.
# Override via CORS_ORIGINS env-var (comma-separated) if you need to restrict.
# ─────────────────────────────────────────────────────────────────────────────

_origins_env = os.getenv("CORS_ORIGINS", "*")
if _origins_env == "*":
    origins = ["*"]
else:
    origins = [o.strip() for o in _origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins     = origins,
    # credentials (cookies) cannot be used with allow_origins=["*"];
    # the admin panel uses Authorization: Bearer (localStorage), so this is fine.
    allow_credentials = False,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# Routers
# ─────────────────────────────────────────────────────────────────────────────

# Public — license validation (used by client software)
app.include_router(validate_router)

# Auth — admin login
app.include_router(auth_router)

# ─────────────────────────────────────────────────────────────────────────────
# Admin API  —  /api/v1/admin/*
# ─────────────────────────────────────────────────────────────────────────────

admin_router = APIRouter(
    prefix       = "/api/v1/admin",
    tags         = ["Admin"],
    dependencies = [Depends(get_current_user)],  # all admin routes require auth
)


def _generate_key() -> str:
    """Generates a random XXXX-XXXX-XXXX-XXXX license key."""
    alphabet = string.ascii_uppercase + string.digits
    segments = ["".join(secrets.choice(alphabet) for _ in range(8)) for _ in range(4)]
    return "-".join(segments)


# ── Stats ──────────────────────────────────────────────────────────────────

@admin_router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    now        = datetime.utcnow()
    soon       = now + timedelta(hours=24)
    all_keys   = db.query(LicenseKey).all()
    total        = len(all_keys)
    active       = sum(1 for k in all_keys if not k.is_paused and k.start_date <= now <= k.end_date)
    expired      = sum(1 for k in all_keys if k.end_date < now)
    suspended    = sum(1 for k in all_keys if k.is_paused)
    suspicious   = sum(1 for k in all_keys if k.is_suspicious)
    # Key is "online" only if it sent a heartbeat / validated within the last 5 minutes
    online       = sum(1 for k in all_keys if k.last_login_at and (now - k.last_login_at).total_seconds() < 300)
    expiring_soon= sum(1 for k in all_keys if now <= k.end_date <= soon and not k.is_paused)
    return StatsResponse(
        total=total, active=active, expired=expired,
        suspended=suspended, suspicious=suspicious,
        online=online, expiring_soon=expiring_soon,
    )


# ── Alerts ─────────────────────────────────────────────────────────────────

@admin_router.get("/alerts", response_model=AlertsResponse)
def get_alerts(db: Session = Depends(get_db)):
    now   = datetime.utcnow()
    soon  = now + timedelta(hours=24)
    keys  = db.query(LicenseKey).all()
    alerts: list[AlertItem] = []

    suspicious_count   = sum(1 for k in keys if k.is_suspicious)
    expiring_count     = sum(1 for k in keys if now <= k.end_date <= soon and not k.is_paused)
    high_login_count   = sum(1 for k in keys if (k.logins_last_24h or 0) > 50)
    hwid_reset_count   = sum(1 for k in keys if (k.hwid_reset_count or 0) > 3)

    if suspicious_count:
        alerts.append(AlertItem(level="danger",
            message=f"{suspicious_count} key{'s' if suspicious_count != 1 else ''} flagged as suspicious."))
    if expiring_count:
        alerts.append(AlertItem(level="warning",
            message=f"{expiring_count} key{'s' if expiring_count != 1 else ''} expiring within 24 hours."))
    if high_login_count:
        alerts.append(AlertItem(level="warning",
            message=f"{high_login_count} key{'s' if high_login_count != 1 else ''} exceeded 50 logins in the last 24 h."))
    if hwid_reset_count:
        alerts.append(AlertItem(level="warning",
            message=f"{hwid_reset_count} key{'s' if hwid_reset_count != 1 else ''} had more than 3 HWID resets."))
    if not alerts:
        alerts.append(AlertItem(level="info", message="No active alerts. All systems normal."))

    return AlertsResponse(alerts=alerts)


# ── List keys ──────────────────────────────────────────────────────────────

@admin_router.get("/keys", response_model=list[LicenseKeyResponse])
def list_keys(db: Session = Depends(get_db)):
    return db.query(LicenseKey).order_by(LicenseKey.created_at.desc()).all()


# ── Create key ─────────────────────────────────────────────────────────────

@admin_router.post("/keys", response_model=LicenseKeyResponse, status_code=status.HTTP_201_CREATED)
def create_key(payload: LicenseKeyCreate, db: Session = Depends(get_db)):
    start = payload.start_date or datetime.utcnow()
    key = LicenseKey(
        key_string        = _generate_key(),
        app_name          = payload.app_name,
        owner_name        = payload.owner_name or '',
        start_date        = start,
        end_date          = start + timedelta(days=payload.duration_days),
        max_devices       = payload.max_devices,
        hwid_lock_enabled = payload.hwid_lock_enabled,
        key_class         = payload.key_class,
        permission_level  = payload.permission_level,
        admin_note        = payload.admin_note,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


# ── Reset HWID ─────────────────────────────────────────────────────────────

@admin_router.post("/keys/{key_id}/reset-hwid", response_model=LicenseKeyResponse)
def reset_hwid(key_id: int, db: Session = Depends(get_db)):
    key = _get_key_or_404(key_id, db)
    key.locked_hwid      = None
    key.current_devices  = 0
    key.hwid_reset_count = (key.hwid_reset_count or 0) + 1
    db.commit()
    db.refresh(key)
    return key


# ── Toggle HWID lock ────────────────────────────────────────────────────────

@admin_router.post("/keys/{key_id}/toggle-hwid-lock", response_model=LicenseKeyResponse)
def toggle_hwid_lock(key_id: int, db: Session = Depends(get_db)):
    key = _get_key_or_404(key_id, db)
    key.hwid_lock_enabled = not key.hwid_lock_enabled
    db.commit()
    db.refresh(key)
    return key


# ── Toggle pause ────────────────────────────────────────────────────────────

@admin_router.post("/keys/{key_id}/toggle-pause", response_model=LicenseKeyResponse)
def toggle_pause(key_id: int, db: Session = Depends(get_db)):
    key = _get_key_or_404(key_id, db)
    key.is_paused = not key.is_paused
    db.commit()
    db.refresh(key)
    return key


# ── Extend time ─────────────────────────────────────────────────────────────

@admin_router.post("/keys/{key_id}/extend", response_model=LicenseKeyResponse)
def extend_key(key_id: int, payload: LicenseKeyExtend, db: Session = Depends(get_db)):
    key = _get_key_or_404(key_id, db)
    key.end_date = key.end_date + timedelta(
        days=payload.days, hours=payload.hours, minutes=payload.minutes
    )
    db.commit()
    db.refresh(key)
    return key


# ── Forensic view ───────────────────────────────────────────────────────────

@admin_router.get("/keys/{key_id}/forensic")
def forensic_view(key_id: int, db: Session = Depends(get_db)):
    key = _get_key_or_404(key_id, db)
    now = datetime.utcnow()
    currently_online = (
        key.last_login_at is not None
        and (now - key.last_login_at).total_seconds() < 300
    )
    logins = (
        db.query(LoginEvent)
        .filter(LoginEvent.license_key_id == key_id)
        .order_by(LoginEvent.logged_at.desc())
        .limit(100)
        .all()
    )
    return {
        "key":             LicenseKeyResponse.model_validate(key),
        "currently_online": currently_online,
        "login_history":   [LoginEventResponse.model_validate(e) for e in logins],
    }


# ── Update max devices ─────────────────────────────────────────────────────

@admin_router.post("/keys/{key_id}/update-max-devices", response_model=LicenseKeyResponse)
def update_max_devices(key_id: int, payload: UpdateMaxDevices, db: Session = Depends(get_db)):
    key = _get_key_or_404(key_id, db)
    key.max_devices = payload.max_devices
    db.commit()
    db.refresh(key)
    return key


# ── Update admin note ──────────────────────────────────────────────────────

@admin_router.post("/keys/{key_id}/update-note", response_model=LicenseKeyResponse)
def update_note(key_id: int, payload: UpdateAdminNote, db: Session = Depends(get_db)):
    key = _get_key_or_404(key_id, db)
    key.admin_note = payload.admin_note
    db.commit()
    db.refresh(key)
    return key


# ── Safe Edit — update key details ──────────────────────────────────────────────────

@admin_router.patch("/keys/{key_id}", response_model=LicenseKeyResponse)
def update_key_details(key_id: int, payload: UpdateKeyDetails, db: Session = Depends(get_db)):
    key = _get_key_or_404(key_id, db)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(key, field, value)
    db.commit()
    db.refresh(key)
    return key


# ── Delete key (superadmin only) ────────────────────────────────────────────────

@admin_router.delete(
    "/keys/{key_id}",
    status_code = status.HTTP_204_NO_CONTENT,
    dependencies = [Depends(require_superadmin)],
)
def delete_key(key_id: int, db: Session = Depends(get_db)):
    key = _get_key_or_404(key_id, db)
    db.delete(key)
    db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_key_or_404(key_id: int, db: Session) -> LicenseKey:
    key = db.query(LicenseKey).filter(LicenseKey.id == key_id).first()
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="License key not found.")
    return key


# Register admin router
app.include_router(admin_router)


# ─────────────────────────────────────────────────────────────────────────────
# Serve frontend static files
# ─────────────────────────────────────────────────────────────────────────────

_frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(_frontend_dir):
    app.mount("/", StaticFiles(directory=_frontend_dir, html=True), name="frontend")


# ─────────────────────────────────────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"], include_in_schema=False)
def health():
    return {"status": "ok"}
