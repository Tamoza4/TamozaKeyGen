"""
api_v1.py — Versioned REST API router for TamozaKeyGen.

POST /api/v1/validate
    Full license-key validation pipeline:
      1. Key existence + paused guard
      2. Validity window (start_date / end_date)
      3. HWID binding / verification
      4. Session field updates (last_login_at, last_ip, is_online)
      5. Suspicious-activity detection (region changes > 3 in 1 hour)
"""

import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .database import get_db
from .models import LicenseKey, LoginEvent

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REGION_CHANGE_LIMIT = 3          # max unique region changes within window
_REGION_CHANGE_WINDOW = timedelta(hours=1)

# ---------------------------------------------------------------------------
# In-memory region-change tracker
# Structure: { key_string: [datetime_of_change, ...] }
# Each entry records a UTC timestamp when a *new* region was observed.
# ---------------------------------------------------------------------------

_region_changes: dict[str, list[datetime]] = defaultdict(list)
_region_lock = threading.Lock()


def _record_region_change(key_string: str, now: datetime) -> int:
    """
    Append a region-change event for *key_string* and return the count of
    distinct change events within the last hour (after pruning stale ones).
    Thread-safe.
    """
    cutoff = now - _REGION_CHANGE_WINDOW
    with _region_lock:
        history = _region_changes[key_string]
        # Prune events outside the rolling window
        history = [ts for ts in history if ts > cutoff]
        history.append(now)
        _region_changes[key_string] = history
        return len(history)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ValidateRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=64, description="License key string")
    app_name: str = Field(..., min_length=1, max_length=128, description="Application name — must match the value stored for this key")
    hwid: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Hardware ID of the requesting device (required when HWID lock is enabled)",
    )
    region: Optional[str] = Field(
        default=None,
        max_length=128,
        description="ISO country/region code reported by the client (e.g. 'US', 'DE')",
    )
    device_name: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Human-readable device name reported by the client (e.g. 'DESKTOP-ABC123')",
    )


class ValidateResponse(BaseModel):
    valid: bool
    message: str
    is_suspicious: bool = False
    app_name: Optional[str] = None
    owner_name: Optional[str] = None
    end_date: Optional[datetime] = None
    key_class: Optional[str] = None
    permission_level: Optional[str] = None


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1", tags=["License Validation"])


@router.post(
    "/validate",
    response_model=ValidateResponse,
    summary="Validate a license key",
    status_code=status.HTTP_200_OK,
)
def validate_license(
    payload: ValidateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ValidateResponse:
    """
    Validates a license key through a sequential chain of security checks.
    Returns 200 with `valid=True` on success, or raises an appropriate
    HTTP error on any failed check.
    """

    # ------------------------------------------------------------------
    # 1. Key existence check + paused guard
    # ------------------------------------------------------------------
    license_key: Optional[LicenseKey] = (
        db.query(LicenseKey)
        .filter(LicenseKey.key_string == payload.key)
        .first()
    )

    if license_key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="License key not found.",
        )

    if license_key.is_paused:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="License key is currently paused.",
        )

    # ------------------------------------------------------------------
    # 1.5 App-name binding check
    # ------------------------------------------------------------------
    if license_key.app_name.lower() != payload.app_name.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="License key is not valid for this application.",
        )

    # ------------------------------------------------------------------
    # 2. Validity window check
    # ------------------------------------------------------------------
    now: datetime = datetime.now(timezone.utc).replace(tzinfo=None)  # naive UTC

    if now < license_key.start_date:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="License key is not yet active.",
        )

    if now > license_key.end_date:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="License key has expired.",
        )

    # ------------------------------------------------------------------
    # 3. HWID lock verification / binding
    # ------------------------------------------------------------------
    if license_key.hwid_lock_enabled:
        incoming_hwid = payload.hwid

        if not incoming_hwid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="HWID is required for this license key.",
            )

        if not license_key.locked_hwid:
            # First use — bind the HWID now
            license_key.locked_hwid = incoming_hwid
        elif license_key.locked_hwid != incoming_hwid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Hardware ID mismatch. This key is locked to a different device.",
            )

    # ------------------------------------------------------------------
    # 4. Update session/usage fields
    # ------------------------------------------------------------------
    # Resolve real client IP — honour X-Forwarded-For set by a trusted proxy
    client_ip: str = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )

    if license_key.first_login_at is None:
        license_key.first_login_at = now
        # Capture the region on the very first login
        if payload.region and license_key.first_region is None:
            license_key.first_region = payload.region

    license_key.last_login_at = now
    license_key.last_ip = client_ip
    license_key.is_online = True
    license_key.logins_last_24h = (license_key.logins_last_24h or 0) + 1

    # Record login event
    event = LoginEvent(
        license_key_id = license_key.id,
        logged_at      = now,
        ip_address     = client_ip,
        hwid           = payload.hwid,
        region         = payload.region,
        device_name    = payload.device_name,
    )
    db.add(event)

    # ------------------------------------------------------------------
    # 5. Suspicious-activity analysis (multi-rule)
    # ------------------------------------------------------------------
    incoming_region: Optional[str] = payload.region

    # Rule A: Same key connecting from 3+ different regions within 1 hour
    if incoming_region and incoming_region != license_key.last_region:
        change_count = _record_region_change(payload.key, now)
        license_key.last_region = incoming_region
        if change_count > _REGION_CHANGE_LIMIT:
            license_key.is_suspicious = True

    # Rule B: More than 50 logins in the last 24 hours
    if (license_key.logins_last_24h or 0) > 50:
        license_key.is_suspicious = True

    # Rule C: HWID resets exceed 3 (tracked cumulatively — weekly check
    # requires a reset_at timestamp; using cumulative count as a safe proxy)
    if (license_key.hwid_reset_count or 0) > 3:
        license_key.is_suspicious = True

    # ------------------------------------------------------------------
    # Persist all mutations in a single commit
    # ------------------------------------------------------------------
    try:
        db.commit()
        db.refresh(license_key)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist session update. Please try again.",
        )

    return ValidateResponse(
        valid=True,
        message="License key is valid.",
        is_suspicious=license_key.is_suspicious,
        app_name=license_key.app_name,
        owner_name=license_key.owner_name,
        end_date=license_key.end_date,
        key_class=license_key.key_class,
        permission_level=license_key.permission_level,
    )


# ---------------------------------------------------------------------------
# Heartbeat  — client calls this periodically to signal the app is still running
# ---------------------------------------------------------------------------

class HeartbeatRequest(BaseModel):
    key: str      = Field(..., min_length=1, max_length=64)
    app_name: str = Field(..., min_length=1, max_length=128)


@router.post("/heartbeat", status_code=200, summary="Keep-alive heartbeat")
def heartbeat(
    payload: HeartbeatRequest,
    db: Session = Depends(get_db),
) -> dict:
    """
    Called by the client application on a regular interval (e.g. every 60 s)
    to signal it is still running. Updates last_login_at so the dashboard
    shows the key as currently online.
    """
    key = (
        db.query(LicenseKey)
        .filter(LicenseKey.key_string == payload.key)
        .first()
    )
    if not key or key.is_paused:
        return {"ok": False}
    if key.app_name.lower() != payload.app_name.lower():
        return {"ok": False}
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    key.last_login_at = now
    key.is_online = True
    db.commit()
    return {"ok": True}
