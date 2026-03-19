"""
client_integration.py — TamozaKeyGen License Validator (Python Client)

Drop this file into any Python application to add license validation.
Requires: pip install requests

Usage:
    from client_integration import LicenseValidator
    validator = LicenseValidator(api_url="https://your-server.com", app_name="MyApp")
    result = validator.validate("XXXX-XXXX-XXXX-XXXX")
    print(result.message)
    if result.granted:
        # start your application logic
        ...
"""

import hashlib
import platform
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

import requests

# ─────────────────────────────────────────────────────────────────────────────
# Configuration — override per application
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_API_URL = "http://localhost/8000"  # change to your server URL in production
VALIDATE_ENDPOINT = "/api/v1/validate"
REQUEST_TIMEOUT_SECONDS = 10


# ─────────────────────────────────────────────────────────────────────────────
# Result
# ─────────────────────────────────────────────────────────────────────────────

class ValidationStatus(Enum):
    GRANTED          = auto()
    EXPIRED          = auto()
    NOT_YET_ACTIVE   = auto()
    PAUSED           = auto()
    HWID_MISMATCH    = auto()
    KEY_NOT_FOUND    = auto()
    APP_MISMATCH     = auto()   # key is not registered for this application name
    SUSPICIOUS       = auto()   # valid but flagged — application decides how to handle
    NETWORK_ERROR    = auto()
    SERVER_ERROR     = auto()
    UNKNOWN          = auto()


# Human-readable messages shown to the end user
_STATUS_MESSAGES: dict[ValidationStatus, str] = {
    ValidationStatus.GRANTED:        "Access Granted.",
    ValidationStatus.EXPIRED:        "License Expired. Please renew your license to continue.",
    ValidationStatus.NOT_YET_ACTIVE: "License Not Yet Active. Your license period has not started.",
    ValidationStatus.PAUSED:         "License Suspended. Contact support to reinstate your license.",
    ValidationStatus.HWID_MISMATCH:  "Hardware ID Mismatch. This license is bound to a different device.",
    ValidationStatus.APP_MISMATCH:   "Invalid Application. This license key is not registered for this application.",
    ValidationStatus.KEY_NOT_FOUND:  "Invalid License Key. The key you entered does not exist.",
    ValidationStatus.SUSPICIOUS:     "Access Granted (activity flagged for review).",
    ValidationStatus.NETWORK_ERROR:  "Network Error. Could not reach the license server. Check your connection.",
    ValidationStatus.SERVER_ERROR:   "Server Error. The license server returned an unexpected response.",
    ValidationStatus.UNKNOWN:        "Unknown Error. Please try again or contact support.",
}


@dataclass(frozen=True)
class ValidationResult:
    status: ValidationStatus
    message: str
    granted: bool
    app_name: Optional[str] = None
    owner_name: Optional[str] = None
    end_date: Optional[str] = None
    key_class: Optional[str] = None
    permission_level: Optional[str] = None
    is_suspicious: bool = False

    def __str__(self) -> str:
        return self.message


# ─────────────────────────────────────────────────────────────────────────────
# HWID Collection
# ─────────────────────────────────────────────────────────────────────────────

def _run_wmic(query: str) -> str:
    """Runs a WMIC command and returns the first non-header output line."""
    try:
        result = subprocess.run(
            ["wmic"] + query.split(),
            capture_output=True,
            text=True,
            timeout=8,
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        # WMIC output: first line is the header, second is the value
        return lines[1] if len(lines) >= 2 else ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _get_hwid_windows() -> str:
    """
    Derives a stable hardware fingerprint from CPU ProcessorId and
    Motherboard SerialNumber, hashed with SHA-256.
    """
    cpu_id       = _run_wmic("cpu get ProcessorId")
    board_serial = _run_wmic("baseboard get SerialNumber")

    # Some OEMs ship boards with placeholder serials — fall back to UUID
    if not board_serial or board_serial.lower() in ("to be filled by o.e.m.", "default string", ""):
        board_serial = _run_wmic("csproduct get UUID")

    raw = f"{cpu_id}::{board_serial}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _get_hwid_linux() -> str:
    """
    On Linux, derives a fingerprint from /etc/machine-id (systemd-generated,
    unique per installation) combined with the CPU model from /proc/cpuinfo.
    """
    machine_id = ""
    try:
        with open("/etc/machine-id", "r") as f:
            machine_id = f.read().strip()
    except OSError:
        pass

    cpu_model = ""
    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_model = line.split(":", 1)[-1].strip()
                    break
    except OSError:
        pass

    raw = f"{machine_id}::{cpu_model}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _get_hwid_macos() -> str:
    """
    On macOS, derives a fingerprint from the IOPlatformSerialNumber
    reported by system_profiler.
    """
    serial = ""
    try:
        result = subprocess.run(
            ["ioreg", "-l", "-d1", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True, timeout=8,
        )
        for line in result.stdout.splitlines():
            if "IOPlatformSerialNumber" in line:
                serial = line.split('"')[-2]
                break
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    raw = f"macos::{serial}"
    return hashlib.sha256(raw.encode()).hexdigest()


def get_hardware_id() -> str:
    """
    Returns the current device's hardware fingerprint as a 64-character
    hex digest (SHA-256). Dispatches by OS. Falls back to a hostname-based
    hash only if OS-specific collection fails entirely.
    """
    system = platform.system()

    if system == "Windows":
        hwid = _get_hwid_windows()
    elif system == "Linux":
        hwid = _get_hwid_linux()
    elif system == "Darwin":
        hwid = _get_hwid_macos()
    else:
        hwid = ""

    if not hwid or len(hwid) < 10:
        # Last-resort fallback: hash the hostname (low uniqueness — warn)
        hwid = hashlib.sha256(f"fallback::{platform.node()}".encode()).hexdigest()

    return hwid


# ─────────────────────────────────────────────────────────────────────────────
# Validator
# ─────────────────────────────────────────────────────────────────────────────

class LicenseValidator:
    """
    High-level license validator.

    Parameters
    ----------
    api_url  : Base URL of the TamozaKeyGen server (no trailing slash).
    app_name : Name of the application — sent as context in the request.
    timeout  : HTTP request timeout in seconds.
    """

    def __init__(
        self,
        api_url: str = DEFAULT_API_URL,
        app_name: str = "App",
        timeout: int = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self._url     = api_url.rstrip("/") + VALIDATE_ENDPOINT
        self._app     = app_name
        self._timeout = timeout

        # Collect HWID once at initialisation — it doesn't change at runtime
        self._hwid = get_hardware_id()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, key: str, region: Optional[str] = None) -> ValidationResult:
        """
        Validates *key* against the server and returns a ValidationResult.

        Parameters
        ----------
        key    : The license key string entered by the user.
        region : Optional ISO country/region code (e.g. "US") for analytics.
        """
        if not key or not isinstance(key, str):
            return self._make(ValidationStatus.KEY_NOT_FOUND)

        payload: dict = {
            "key":      key.strip(),
            "hwid":     self._hwid,
            "app_name": self._app,
        }
        if region:
            payload["region"] = region

        try:
            response = requests.post(
                self._url,
                json=payload,
                timeout=self._timeout,
                headers={"Content-Type": "application/json"},
            )
            return self._parse_response(response)

        except requests.exceptions.ConnectionError:
            return self._make(ValidationStatus.NETWORK_ERROR)
        except requests.exceptions.Timeout:
            return self._make(ValidationStatus.NETWORK_ERROR)
        except requests.exceptions.RequestException:
            return self._make(ValidationStatus.NETWORK_ERROR)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_response(self, response: requests.Response) -> ValidationResult:
        status_code = response.status_code

        # ── 200 OK — may still be suspicious ──
        if status_code == 200:
            try:
                body = response.json()
            except ValueError:
                return self._make(ValidationStatus.SERVER_ERROR)

            if not body.get("valid", False):
                return self._make(ValidationStatus.SERVER_ERROR)

            is_suspicious = body.get("is_suspicious", False)
            vstatus = ValidationStatus.SUSPICIOUS if is_suspicious else ValidationStatus.GRANTED

            return ValidationResult(
                status        = vstatus,
                message       = _STATUS_MESSAGES[vstatus],
                granted       = True,
                app_name      = body.get("app_name"),
                owner_name    = body.get("owner_name"),
                end_date      = body.get("end_date"),
                key_class     = body.get("key_class"),
                permission_level = body.get("permission_level"),
                is_suspicious = is_suspicious,
            )

        # ── Map HTTP error codes to user-friendly statuses ──
        detail = ""
        try:
            detail = response.json().get("detail", "").lower()
        except ValueError:
            pass

        if status_code == 404:
            return self._make(ValidationStatus.KEY_NOT_FOUND)

        if status_code == 403:
            if "expired" in detail:
                return self._make(ValidationStatus.EXPIRED)
            if "not yet active" in detail:
                return self._make(ValidationStatus.NOT_YET_ACTIVE)
            if "paused" in detail:
                return self._make(ValidationStatus.PAUSED)
            if "hardware id" in detail or "hwid" in detail:
                return self._make(ValidationStatus.HWID_MISMATCH)
            if "application" in detail:
                return self._make(ValidationStatus.APP_MISMATCH)
            return self._make(ValidationStatus.PAUSED)  # safe default for 403

        if status_code == 400:
            if "hwid" in detail:
                return self._make(ValidationStatus.HWID_MISMATCH)
            return self._make(ValidationStatus.UNKNOWN)

        if status_code >= 500:
            return self._make(ValidationStatus.SERVER_ERROR)

        return self._make(ValidationStatus.UNKNOWN)

    @staticmethod
    def _make(vstatus: ValidationStatus) -> ValidationResult:
        granted = vstatus in (ValidationStatus.GRANTED, ValidationStatus.SUSPICIOUS)
        return ValidationResult(
            status  = vstatus,
            message = _STATUS_MESSAGES[vstatus],
            granted = granted,
        )


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry-point — for testing without embedding
# ─────────────────────────────────────────────────────────────────────────────

def _cli() -> None:
    import getpass

    api_url  = input("Server URL [https://your-server.com]: ").strip() or DEFAULT_API_URL
    app_name = input("App name [App]: ").strip() or "App"
    key      = getpass.getpass("License key: ").strip()

    if not key:
        print("No key entered. Exiting.")
        sys.exit(1)

    validator = LicenseValidator(api_url=api_url, app_name=app_name)

    print(f"\n  Detected HWID : {validator._hwid[:16]}…")
    print("  Contacting license server…\n")

    result = validator.validate(key)

    border = "─" * 44
    print(border)
    print(f"  Status  : {result.status.name}")
    print(f"  Message : {result.message}")
    if result.granted:
        print(f"  App      : {result.app_name or '—'}")
        print(f"  Owner    : {result.owner_name or '—'}")
        print(f"  Class    : {result.key_class or '—'}")
        print(f"  Perm     : {result.permission_level or '—'}")
        print(f"  Expires  : {result.end_date or '—'}")
    print(border)

    sys.exit(0 if result.granted else 1)


if __name__ == "__main__":
    _cli()
