from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class LicenseKey(Base):
    __tablename__ = "license_keys"

    # --- Identity ---
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    key_string = Column(String(64), unique=True, nullable=False, index=True)
    app_name = Column(String(128), nullable=False)
    owner_name = Column(String(128), nullable=False)

    # --- Classification & Permissions ---
    key_class        = Column(String(32),   nullable=False, default="Subscription")
    permission_level = Column(String(32),   nullable=False, default="User")
    admin_note       = Column(String(1024), nullable=True)

    # --- Validity window ---
    # DateTime stores seconds precision in MySQL DATETIME(0) by default
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    is_paused = Column(Boolean, nullable=False, default=False)

    # --- HWID / device binding ---
    hwid_lock_enabled = Column(Boolean, nullable=False, default=False)
    locked_hwid = Column(String(256), nullable=True)
    max_devices = Column(Integer, nullable=False, default=1)
    current_devices = Column(Integer, nullable=False, default=0)

    # --- Usage tracking ---
    first_login_at = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    last_ip = Column(String(45), nullable=True)       # supports IPv6
    first_region = Column(String(128), nullable=True)  # region on first ever login
    last_region = Column(String(128), nullable=True)
    hwid_reset_count = Column(Integer, nullable=False, default=0)
    is_online = Column(Boolean, nullable=False, default=False)

    # --- Analytics ---
    logins_last_24h = Column(Integer, nullable=False, default=0)
    total_usage_seconds = Column(BigInteger, nullable=False, default=0)
    is_suspicious = Column(Boolean, nullable=False, default=False)

    # --- Audit timestamps ---
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    def __repr__(self) -> str:
        return (
            f"<LicenseKey id={self.id} key='{self.key_string}' "
            f"app='{self.app_name}' owner='{self.owner_name}' "
            f"paused={self.is_paused}>"
        )

    # --- Computed helpers (not persisted) ---
    @property
    def is_expired(self) -> bool:
        """Returns True if the current UTC time is past end_date."""
        return datetime.utcnow() > self.end_date

    @property
    def is_active(self) -> bool:
        """Returns True if the key is within its validity window and not paused."""
        now = datetime.utcnow()
        return (
            not self.is_paused
            and self.start_date <= now <= self.end_date
        )


# ─────────────────────────────────────────────────────────────────────────────
# Login Event — one record per validate/heartbeat call
# ─────────────────────────────────────────────────────────────────────────────

class LoginEvent(Base):
    __tablename__ = "login_events"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    license_key_id = Column(Integer, index=True, nullable=False)
    logged_at      = Column(DateTime, nullable=False)
    ip_address     = Column(String(45),  nullable=True)
    hwid           = Column(String(256), nullable=True)
    region         = Column(String(128), nullable=True)
    device_name    = Column(String(256), nullable=True)


class User(Base):
    """Admin user account — used exclusively for dashboard authentication."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)

    # bcrypt / argon2 hash stored here — never the plaintext password
    hashed_password = Column(String(256), nullable=False)

    is_active = Column(Boolean, nullable=False, default=True)
    is_superadmin = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<User id={self.id} username='{self.username}' "
            f"active={self.is_active} superadmin={self.is_superadmin}>"
        )
