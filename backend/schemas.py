"""
schemas.py — Pydantic request/response models for TamozaKeyGen.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, model_validator


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# License Key — Create / Update
# ─────────────────────────────────────────────────────────────────────────────

class LicenseKeyCreate(BaseModel):
    app_name: str                  = Field(..., max_length=128)
    owner_name: Optional[str]      = Field(default=None, max_length=128)
    duration_days: int             = Field(..., ge=1, le=36500)
    start_date: Optional[datetime] = None   # defaults to now() on the server
    max_devices: int               = Field(default=1, ge=1)
    hwid_lock_enabled: bool        = False
    key_class: str                 = Field(default="Subscription", max_length=32)
    permission_level: str          = Field(default="User", max_length=32)
    admin_note: Optional[str]      = Field(default=None, max_length=1024)


class LicenseKeyExtend(BaseModel):
    days: int    = Field(default=0, ge=0)
    hours: int   = Field(default=0, ge=0)
    minutes: int = Field(default=0, ge=0)

    @model_validator(mode='after')
    def check_nonzero(self) -> 'LicenseKeyExtend':
        if self.days == 0 and self.hours == 0 and self.minutes == 0:
            raise ValueError('At least one of days, hours, or minutes must be > 0.')
        return self


# ─────────────────────────────────────────────────────────────────────────────
# License Key — Response
# ─────────────────────────────────────────────────────────────────────────────

class LicenseKeyResponse(BaseModel):
    id: int
    key_string: str
    app_name: str
    owner_name: str
    key_class: str
    permission_level: str
    admin_note: Optional[str]
    start_date: datetime
    end_date: datetime
    is_paused: bool
    hwid_lock_enabled: bool
    locked_hwid: Optional[str]
    max_devices: int
    current_devices: int
    first_login_at: Optional[datetime]
    last_login_at: Optional[datetime]
    last_ip: Optional[str]
    first_region: Optional[str]
    last_region: Optional[str]
    hwid_reset_count: int
    logins_last_24h: int
    total_usage_seconds: int
    is_suspicious: bool
    is_online: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# License Key — Update Max Devices
# ─────────────────────────────────────────────────────────────────────────────

class UpdateMaxDevices(BaseModel):
    max_devices: int = Field(..., ge=1, le=999)


class UpdateAdminNote(BaseModel):
    admin_note: Optional[str] = Field(default=None, max_length=1024)


class UpdateKeyDetails(BaseModel):
    """Partial-update schema for the Safe Edit Mode in the Forensic View."""
    app_name:         Optional[str]      = Field(default=None, min_length=1, max_length=128)
    owner_name:       Optional[str]      = Field(default=None, max_length=128)
    end_date:         Optional[datetime] = None
    key_class:        Optional[str]      = Field(default=None, max_length=32)
    permission_level: Optional[str]      = Field(default=None, max_length=32)
    admin_note:       Optional[str]      = Field(default=None, max_length=1024)


# ─────────────────────────────────────────────────────────────────────────────
# Stats
# ─────────────────────────────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    total: int
    active: int
    expired: int
    suspended: int
    suspicious: int
    online: int
    expiring_soon: int    # expires within 24 h


# ─────────────────────────────────────────────────────────────────────────────
# Alerts
# ─────────────────────────────────────────────────────────────────────────────

class AlertItem(BaseModel):
    level: str   # 'danger' | 'warning' | 'info'
    message: str


class AlertsResponse(BaseModel):
    alerts: list[AlertItem]


# ─────────────────────────────────────────────────────────────────────────────
# Login Event
# ─────────────────────────────────────────────────────────────────────────────

class LoginEventResponse(BaseModel):
    id: int
    logged_at: datetime
    ip_address: Optional[str]
    hwid: Optional[str]
    region: Optional[str]
    device_name: Optional[str]

    model_config = {"from_attributes": True}
