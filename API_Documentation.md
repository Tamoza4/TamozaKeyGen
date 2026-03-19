# TamozaKeyGen — SDK Developer Documentation

> **Purpose:** This document is a complete technical blueprint for building a TamozaKeyGen-compatible license validation SDK in any programming language. Every section maps directly to the reference implementation in `scripts/client_integration.py`.

---

## Table of Contents

1. [API Overview](#1-api-overview)
2. [Request Schema](#2-request-schema)
3. [Hardware ID (HWID) Generation](#3-hardware-id-hwid-generation)
   - 3.1 [Windows](#31-windows)
   - 3.2 [Linux](#32-linux)
   - 3.3 [macOS](#33-macos)
   - 3.4 [Fallback Strategy](#34-fallback-strategy)
   - 3.5 [HWID Reference Table](#35-hwid-reference-table)
4. [Response Handling](#4-response-handling)
   - 4.1 [Success Response (HTTP 200)](#41-success-response-http-200)
   - 4.2 [Error Response Structure](#42-error-response-structure)
   - 4.3 [Status Code Mapping](#43-status-code-mapping)
   - 4.4 [403 Detail String Parsing](#44-403-detail-string-parsing)
5. [ValidationResult Object](#5-validationresult-object)
6. [SDK Implementation Checklist](#6-sdk-implementation-checklist)
   - 6.1 [Required Enums](#61-required-enums)
   - 6.2 [Default Messages](#62-default-messages)
   - 6.3 [Implementation Steps](#63-implementation-steps)
7. [Security Best Practices](#7-security-best-practices)
8. [Complete Response Flow Diagram](#8-complete-response-flow-diagram)
9. [Language-Specific Notes](#9-language-specific-notes)

---

## 1. API Overview

| Property | Value |
|----------|-------|
| **Endpoint** | `/api/v1/validate` |
| **Method** | `POST` |
| **Content-Type** | `application/json` |
| **Auth Required** | No (public endpoint) |
| **Timeout (recommended)** | 10 seconds |

**Full URL construction:**

```
{SERVER_BASE_URL}/api/v1/validate
```

- Strip any trailing slash from the base URL before appending the path.
- Example: `https://license.myapp.com` → `https://license.myapp.com/api/v1/validate`

---

## 2. Request Schema

Send a JSON body with the following fields:

```json
{
  "key":         "ABCD1234-EFGH5678-IJKL9012-MNOP3456",
  "hwid":        "a3f8c2e1d4b7...f0e1d2c3b4a5f6e7d8c9b0a1",
  "app_name":    "MyApp",
  "region":      "US",
  "device_name": "DESKTOP-ABC123"
}
```

### Field Definitions

| Field | Type | Required | Max Length | Description |
|-------|------|----------|------------|-------------|
| `key` | String | **Yes** | 64 | The license key string entered by the user. Trim whitespace before sending. |
| `hwid` | String | Conditional | 256 | SHA-256 hex digest of hardware fingerprint. Required when the key has HWID lock enabled; always recommended. |
| `app_name` | String | **Yes** | 128 | Application identifier. Must **exactly match** (case-insensitive) the name used when the key was created. Mismatch returns `403`. |
| `region` | String | No | 128 | ISO 3166-1 alpha-2 country code (e.g. `"US"`, `"DE"`, `"GB"`). Used for analytics and fraud detection. |
| `device_name` | String | No | 256 | Human-readable device label (e.g. `"DESKTOP-ABC123"`). Displayed in the admin forensic view. |

### Important Rules

- **`key`** — call `.strip()` / `.Trim()` before including. Never send an empty key; validate locally and return `KEY_NOT_FOUND` immediately.
- **`hwid`** — compute once at startup and cache. HWID changes mid-session are not expected and will cause mismatches.
- **`app_name`** — the comparison on the server is **case-insensitive** (`lower()` on both sides), but send it consistently to avoid confusion in logs.
- **`region`** — omit the field entirely if unknown rather than sending `null` or an empty string.

---

## 3. Hardware ID (HWID) Generation

The HWID is a **64-character lowercase SHA-256 hex digest** that uniquely identifies a device. Its generation algorithm is **platform-specific** but the final output format is always identical.

> **Critical:** Every SDK implementation must produce the **exact same HWID** on the same device to avoid spurious `HWID_MISMATCH` errors. The raw string concatenation format `"{part1}::{part2}"` and SHA-256 encoding must be followed exactly.

### Hash Function

```
HWID = lowercase_hex( SHA-256( UTF-8_bytes( raw_string ) ) )
```

The `raw_string` format differs per OS, but the hashing step is always identical.

---

### 3.1 Windows

**Data sources (via WMI):**

| WMI Class | Property | WQL Query |
|-----------|----------|-----------|
| `Win32_Processor` | `ProcessorId` | `SELECT ProcessorId FROM Win32_Processor` |
| `Win32_BaseBoard` | `SerialNumber` | `SELECT SerialNumber FROM Win32_BaseBoard` |
| `Win32_ComputerSystemProduct` | `UUID` | `SELECT UUID FROM Win32_ComputerSystemProduct` *(fallback only)* |

**Algorithm:**

```
cpu_id       = WMI( Win32_Processor.ProcessorId ).trim()
board_serial = WMI( Win32_BaseBoard.SerialNumber ).trim()

// OEM placeholder check — use UUID if serial is invalid
if board_serial is empty
   OR board_serial.lower() == "to be filled by o.e.m."
   OR board_serial.lower() == "default string":
    board_serial = WMI( Win32_ComputerSystemProduct.UUID ).trim()

raw  = cpu_id + "::" + board_serial
hwid = sha256_hex( utf8(raw) )
```

**CLI equivalent (for testing):**

```cmd
wmic cpu get ProcessorId
wmic baseboard get SerialNumber
wmic csproduct get UUID
```

**Python reference:**

```python
import subprocess, hashlib

def _run_wmic(query: str) -> str:
    result = subprocess.run(["wmic"] + query.split(),
                            capture_output=True, text=True, timeout=8)
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    return lines[1] if len(lines) >= 2 else ""   # line 0 = header, line 1 = value

cpu_id       = _run_wmic("cpu get ProcessorId")
board_serial = _run_wmic("baseboard get SerialNumber")

if not board_serial or board_serial.lower() in ("to be filled by o.e.m.", "default string", ""):
    board_serial = _run_wmic("csproduct get UUID")

raw  = f"{cpu_id}::{board_serial}"
hwid = hashlib.sha256(raw.encode()).hexdigest()
```

**C# / WMI equivalent:**

```csharp
string QueryWmi(string wql, string property) {
    using var s = new ManagementObjectSearcher(wql);
    foreach (ManagementObject o in s.Get())
        return o[property]?.ToString()?.Trim() ?? "";
    return "";
}

string cpuId      = QueryWmi("SELECT ProcessorId FROM Win32_Processor",   "ProcessorId");
string boardSerial = QueryWmi("SELECT SerialNumber FROM Win32_BaseBoard", "SerialNumber");

if (string.IsNullOrWhiteSpace(boardSerial) ||
    boardSerial.Equals("To Be Filled By O.E.M.", StringComparison.OrdinalIgnoreCase) ||
    boardSerial.Equals("Default string",          StringComparison.OrdinalIgnoreCase))
    boardSerial = QueryWmi("SELECT UUID FROM Win32_ComputerSystemProduct", "UUID");

string raw  = $"{cpuId}::{boardSerial}";
string hwid = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
```

---

### 3.2 Linux

**Data sources:**

| Source | Path | Description |
|--------|------|-------------|
| Machine ID | `/etc/machine-id` | Unique per-installation ID generated by systemd |
| CPU Model | `/proc/cpuinfo` | First `model name` line |

**Algorithm:**

```
machine_id = read_file("/etc/machine-id").strip()
cpu_model  = first line starting with "model name" in /proc/cpuinfo,
             split on ":", take the right side, strip whitespace

raw  = machine_id + "::" + cpu_model
hwid = sha256_hex( utf8(raw) )
```

**Python reference:**

```python
import hashlib

machine_id = ""
with open("/etc/machine-id") as f:
    machine_id = f.read().strip()

cpu_model = ""
with open("/proc/cpuinfo") as f:
    for line in f:
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[-1].strip()
            break

raw  = f"{machine_id}::{cpu_model}"
hwid = hashlib.sha256(raw.encode()).hexdigest()
```

**C equivalent (pseudocode):**

```c
// read /etc/machine-id → machine_id (trim newline)
// read /proc/cpuinfo → find "model name" line → extract value after ":"
// snprintf(raw, sizeof(raw), "%s::%s", machine_id, cpu_model);
// sha256(raw) → hwid (hex, lowercase)
```

---

### 3.3 macOS

**Data source:** `IOPlatformSerialNumber` from the I/O Registry.

**Command:**

```bash
ioreg -l -d1 -c IOPlatformExpertDevice
```

**Parsing:** Find the line containing `IOPlatformSerialNumber` and extract the value between the last pair of double-quotes.

**Algorithm:**

```
serial = extract IOPlatformSerialNumber from ioreg output

raw  = "macos::" + serial
hwid = sha256_hex( utf8(raw) )
```

**Python reference:**

```python
import subprocess, hashlib

result = subprocess.run(
    ["ioreg", "-l", "-d1", "-c", "IOPlatformExpertDevice"],
    capture_output=True, text=True, timeout=8
)
serial = ""
for line in result.stdout.splitlines():
    if "IOPlatformSerialNumber" in line:
        serial = line.split('"')[-2]
        break

raw  = f"macos::{serial}"
hwid = hashlib.sha256(raw.encode()).hexdigest()
```

> **Note the prefix:** macOS uses `"macos::"` as the prefix, unlike Windows and Linux which use `"{value1}::{value2}"`. This is intentional — it avoids accidental collisions across platforms.

---

### 3.4 Fallback Strategy

If the OS-specific collection fails entirely (empty result, command not found, permission denied, or unsupported OS), fall back to a hostname-based hash:

```
raw  = "fallback::" + hostname()
hwid = sha256_hex( utf8(raw) )
```

> **Warning:** Hostname-based HWIDs have **low uniqueness** — hostnames can be changed by the user. This fallback should only be used when all other methods fail. Log a warning in your SDK when the fallback is triggered.

**Validity check before using any HWID:**

```python
if not hwid or len(hwid) < 10:
    hwid = sha256_hex(f"fallback::{hostname}")
```

---

### 3.5 HWID Reference Table

| OS | Data Sources | Raw String Format | Fallback |
|----|-------------|-------------------|---------|
| Windows | `Win32_Processor.ProcessorId` + `Win32_BaseBoard.SerialNumber` (or UUID) | `"{cpu_id}::{board_serial}"` | `"fallback::{hostname}"` |
| Linux | `/etc/machine-id` + `model name` from `/proc/cpuinfo` | `"{machine_id}::{cpu_model}"` | `"fallback::{hostname}"` |
| macOS | `IOPlatformSerialNumber` via `ioreg` | `"macos::{serial}"` | `"fallback::{hostname}"` |
| Other | — | — | `"fallback::{hostname}"` |

**Output for all platforms:** 64-character lowercase hex string (SHA-256 digest of UTF-8 encoded raw string).

---

## 4. Response Handling

### 4.1 Success Response (HTTP 200)

A `200 OK` response means the key passed all validation checks but **always verify the `valid` field** — a `200` with `"valid": false` must be treated as a server error.

```json
{
  "valid":            true,
  "message":          "License key is valid.",
  "is_suspicious":    false,
  "app_name":         "MyApp",
  "owner_name":       "John Doe",
  "end_date":         "2027-03-18T00:00:00",
  "key_class":        "Subscription",
  "permission_level": "User"
}
```

| Field | Type | Description |
|-------|------|--------------|
| `valid` | Boolean | Always `true` on a genuine success. If `false` on a 200, treat as `SERVER_ERROR`. |
| `message` | String | Server-side message (for logging; use your SDK's own messages for display). |
| `is_suspicious` | Boolean | `true` if the key triggered a fraud detection rule. **The key is still granted.** Your application decides how to handle this. |
| `app_name` | String | Application name registered on the key. |
| `owner_name` | String | License holder name. |
| `end_date` | String (ISO 8601 UTC) | Key expiry timestamp. Parse and store for offline grace-period logic. |
| `key_class` | String | Key classification: `Subscription`, `Trial`, or `Demo`. Use to adjust feature access or display trial banners. |
| `permission_level` | String | Permission tier: `User`, `Admin`, or `Support`. Use to gate privileged features within the application. |

**Success mapping logic:**

```
if status_code == 200:
    body = parse_json(response)
    if not body.valid:
        return SERVER_ERROR          ← malformed server response
    if body.is_suspicious:
        return SUSPICIOUS            ← granted=true, but flag to application
    else:
        return GRANTED               ← fully clean grant
```

---

### 4.2 Error Response Structure

All non-200 responses return a JSON body with exactly one field:

```json
{ "detail": "Human-readable error message." }
```

**Parsing steps:**
1. Attempt to parse the response body as JSON.
2. Extract `detail` as a string.
3. **Lowercase the entire `detail` string** before keyword matching.
4. If JSON parsing fails, treat the error as `UNKNOWN` (or `SERVER_ERROR` for 5xx).

---

### 4.3 Status Code Mapping

The following table defines the **complete decision tree** for mapping HTTP responses to SDK status values:

| HTTP Status | Condition | SDK Status | `granted` |
|-------------|-----------|------------|-----------|
| `200` | `valid == true` AND `is_suspicious == false` | `GRANTED` | `true` |
| `200` | `valid == true` AND `is_suspicious == true` | `SUSPICIOUS` | `true` |
| `200` | `valid == false` | `SERVER_ERROR` | `false` |
| `200` | JSON parse failure | `SERVER_ERROR` | `false` |
| `400` | `"hwid"` in detail | `HWID_MISMATCH` | `false` |
| `400` | any other detail | `UNKNOWN` | `false` |
| `403` | `"expired"` in detail | `EXPIRED` | `false` |
| `403` | `"not yet"` in detail | `NOT_YET_ACTIVE` | `false` |
| `403` | `"paused"` in detail | `PAUSED` | `false` |
| `403` | `"hardware id"` OR `"hwid"` in detail | `HWID_MISMATCH` | `false` |
| `403` | `"application"` in detail | `APP_MISMATCH` | `false` |
| `403` | no keyword matched | `PAUSED` *(safe fallback)* | `false` |
| `404` | any | `KEY_NOT_FOUND` | `false` |
| `422` | any | `UNKNOWN` | `false` |
| `5xx` | any | `SERVER_ERROR` | `false` |
| Network error / timeout | connection refused, DNS failure, timeout | `NETWORK_ERROR` | `false` |
| Any other code | — | `UNKNOWN` | `false` |

---

### 4.4 403 Detail String Parsing

The `403` status is the most nuanced. The server includes a short English description in the `detail` field. Your SDK must perform **case-insensitive substring matching** in the **exact evaluation order** shown below:

```
detail = response.json()["detail"].lower()

if   "expired"     in detail  →  EXPIRED
elif "not yet"     in detail  →  NOT_YET_ACTIVE
elif "paused"      in detail  →  PAUSED
elif "hardware id" in detail  →  HWID_MISMATCH
elif "hwid"        in detail  →  HWID_MISMATCH
elif "application" in detail  →  APP_MISMATCH
else                          →  PAUSED          ← default fallback
```

> **Order matters.** Evaluate from top to bottom. The `PAUSED` fallback at the bottom catches any future 403 error types that your SDK doesn't yet recognize, keeping the user experience safe rather than showing a confusing generic error.

**Reference `detail` strings from the server** (exact values as of API v1):

| Server `detail` string | Matched By | Maps To |
|------------------------|------------|---------|
| `"License key has expired."` | `"expired"` | `EXPIRED` |
| `"License key is not yet active."` | `"not yet"` | `NOT_YET_ACTIVE` |
| `"License key is currently paused."` | `"paused"` | `PAUSED` |
| `"Hardware ID mismatch. This key is locked to a different device."` | `"hardware id"` | `HWID_MISMATCH` |
| `"License key is not valid for this application."` | `"application"` | `APP_MISMATCH` |
| `"HWID is required for this license key."` *(400)* | `"hwid"` | `HWID_MISMATCH` |

---

## 5. ValidationResult Object

Every SDK must expose a result object (struct/class/record) with the following fields after a validate call:

| Field | Type | Description |
|-------|------|--------------|
| `status` | `ValidationStatus` enum | Machine-readable outcome — use for all branching logic |
| `message` | String | Localizable human-readable message for display to the end user |
| `granted` | Boolean | `true` only for `GRANTED` and `SUSPICIOUS` — use this as the gate for your application logic |
| `app_name` | String? | Application name from the server response (populated on success only) |
| `owner_name` | String? | License holder name from the server response (populated on success only) |
| `end_date` | String? | ISO 8601 UTC expiry timestamp from the server (populated on success only) |
| `key_class` | String? | Key classification (`Subscription`, `Trial`, `Demo`) — use to tailor feature set or show trial banners |
| `permission_level` | String? | Permission tier (`User`, `Admin`, `Support`) — use to unlock privileged in-app features |
| `is_suspicious` | Boolean | `true` when status is `SUSPICIOUS` |

**`granted` computation rule:**

```
granted = (status == GRANTED || status == SUSPICIOUS)
```

Only these two statuses mean the user is allowed to proceed.

**Immutability:** Make this object immutable/frozen after construction. It should not be modified after the validate call returns.

---

## 6. SDK Implementation Checklist

### 6.1 Required Enums

Implement all eleven status values. Do not merge or omit any — downstream applications depend on the exact enum values for their own business logic.

| Enum Value | `granted` | Description |
|------------|-----------|-------------|
| `GRANTED` | `true` | License is fully valid and clean |
| `SUSPICIOUS` | `true` | Valid, but flagged for potential abuse — allow but optionally warn |
| `EXPIRED` | `false` | Key has passed its `end_date` |
| `NOT_YET_ACTIVE` | `false` | Key's `start_date` is still in the future |
| `PAUSED` | `false` | Key was manually suspended by an admin |
| `HWID_MISMATCH` | `false` | Request came from a different device than the one the key is bound to |
| `APP_MISMATCH` | `false` | `app_name` in the request doesn't match the key's registered application |
| `KEY_NOT_FOUND` | `false` | The key string does not exist on the server |
| `NETWORK_ERROR` | `false` | Could not reach the server (connection refused, DNS failure, timeout) |
| `SERVER_ERROR` | `false` | Server returned an unexpected or malformed response |
| `UNKNOWN` | `false` | Unclassified error; should be rare |

---

### 6.2 Default Messages

These are the **canonical user-facing messages** to ship with your SDK. They must be overridable by the caller (e.g. for localization).

| Status | Default Message |
|--------|----------------|
| `GRANTED` | `"Access Granted."` |
| `SUSPICIOUS` | `"Access Granted (activity flagged for review)."` |
| `EXPIRED` | `"License Expired. Please renew your license to continue."` |
| `NOT_YET_ACTIVE` | `"License Not Yet Active. Your license period has not started."` |
| `PAUSED` | `"License Suspended. Contact support to reinstate your license."` |
| `HWID_MISMATCH` | `"Hardware ID Mismatch. This license is bound to a different device."` |
| `APP_MISMATCH` | `"Invalid Application. This license key is not registered for this application."` |
| `KEY_NOT_FOUND` | `"Invalid License Key. The key you entered does not exist."` |
| `NETWORK_ERROR` | `"Network Error. Could not reach the license server. Check your connection."` |
| `SERVER_ERROR` | `"Server Error. The license server returned an unexpected response."` |
| `UNKNOWN` | `"Unknown Error. Please try again or contact support."` |

---

### 6.3 Implementation Steps

Use this checklist when building a new SDK:

- [ ] **HWID generation** — implement all three OS paths + fallback
- [ ] **HWID caching** — compute once at startup, reuse for lifetime of the validator object
- [ ] **Input validation** — return `KEY_NOT_FOUND` immediately for empty/null/non-string keys (do not make a network call)
- [ ] **Key trimming** — strip leading/trailing whitespace from the key before sending
- [ ] **HTTP client** — set a **10-second timeout** for all requests
- [ ] **JSON body** — set `Content-Type: application/json`
- [ ] **200 handler** — check `valid` field, then `is_suspicious`, return appropriate status
- [ ] **403 handler** — lowercase the `detail` field, apply keyword checks in the documented order
- [ ] **404 handler** — return `KEY_NOT_FOUND`
- [ ] **400 handler** — check for `"hwid"` in detail, otherwise return `UNKNOWN`
- [ ] **5xx handler** — return `SERVER_ERROR`
- [ ] **Network exception handler** — catch connection errors, timeouts → return `NETWORK_ERROR`
- [ ] **Other status codes** — return `UNKNOWN`
- [ ] **`ValidationResult` object** — expose all 7 fields, make immutable
- [ ] **`granted` boolean** — compute as `status == GRANTED || status == SUSPICIOUS`
- [ ] **Default messages** — ship all 11 messages, allow override for localization
- [ ] **`ValidationStatus` enum** — implement all 11 values
- [ ] **Heartbeat support** — optionally implement periodic `POST /api/v1/heartbeat` calls

---

## 7. Security Best Practices

### Network Timeout — Always Set One

Never make an HTTP request without a timeout. An unresponsive server will otherwise hang your application indefinitely.

```
Recommended: 10 seconds
Minimum:      5 seconds
Maximum:     30 seconds (for poor-connectivity environments)
```

If the request times out, return `NETWORK_ERROR` — do **not** retry automatically, as a blocked/slow server is often a sign of an outage.

---

### Protecting the Server URL

The API base URL is embedded in your compiled application. Consider:

- **Obfuscate** the string in compiled binaries to make extraction harder (string splitting, XOR encoding before concatenation, etc.)
- **Environment variables or config files** for desktop tools used internally
- **Certificate pinning** (for mobile/desktop apps) to prevent MITM attacks redirecting validation calls to a fake server

---

### Protecting the License Key at Rest

- Do **not** store the raw license key in a plain-text config file.
- Consider encrypting it with a machine-specific key (e.g. DPAPI on Windows, Keychain on macOS).
- Never log the full key string — use only the first 8 characters for debug logs.

---

### Handling the `SUSPICIOUS` Flag

When `is_suspicious` is `true`, the license is **still valid** — `granted` is `true`. Your application should decide based on its sensitivity:

| Application Type | Recommended Action |
|------------------|--------------------|
| Low-risk (games, utilities) | Log it silently; allow full access |
| Medium-risk (creative tools, business software) | Show an in-app warning to the user |
| High-risk (financial, security tools) | Restrict to read-only mode; prompt user to contact support |

The suspicious flag is sticky on the server — it is set by fraud detection and only cleared by an admin.

---

### Offline Grace Period (Advanced)

If your use case requires offline support:

1. On every successful validate, **persist** `end_date`, `app_name`, and the current timestamp to encrypted local storage.
2. On startup, if the server is unreachable (`NETWORK_ERROR`), compare the current system time against the stored `end_date`.
3. Grant access within a configurable grace window (e.g. 72 hours).
4. Display a clear warning that the license could not be verified online.

> **Important:** Always verify the `end_date` comparison is done in UTC, not local time.

---

### Anti-Tampering

- **Never** branch on the `message` string — always branch on the `status` enum. Message strings may change; enum values are stable.
- Do not expose detailed error messages in production UIs — `HWID_MISMATCH`, `KEY_NOT_FOUND`, etc. should be shown to the user only through your default messages, not raw server output.

---

## 8. Complete Response Flow Diagram

```
validate(key, region?)
        │
        ├── key is null/empty?
        │       └── return KEY_NOT_FOUND (no network call)
        │
        ├── Build JSON payload { key, hwid, app_name, region? }
        │
        ├── POST /api/v1/validate  (timeout: 10s)
        │
        ├── Connection error / timeout?
        │       └── return NETWORK_ERROR
        │
        ├── HTTP 200?
        │       ├── Parse JSON body
        │       │       └── Parse fails?  → return SERVER_ERROR
        │       ├── body.valid == false?  → return SERVER_ERROR
        │       ├── body.is_suspicious == true?  → return SUSPICIOUS (granted=true)
        │       └── else  → return GRANTED (granted=true)
        │
        ├── HTTP 400?
        │       ├── "hwid" in detail?  → return HWID_MISMATCH
        │       └── else  → return UNKNOWN
        │
        ├── HTTP 403?
        │       ├── "expired"      in detail?  → return EXPIRED
        │       ├── "not yet"      in detail?  → return NOT_YET_ACTIVE
        │       ├── "paused"       in detail?  → return PAUSED
        │       ├── "hardware id"  in detail?  → return HWID_MISMATCH
        │       ├── "hwid"         in detail?  → return HWID_MISMATCH
        │       ├── "application"  in detail?  → return APP_MISMATCH
        │       └── no match                   → return PAUSED (safe fallback)
        │
        ├── HTTP 404?
        │       └── return KEY_NOT_FOUND
        │
        ├── HTTP 5xx?
        │       └── return SERVER_ERROR
        │
        └── Any other status?
                └── return UNKNOWN
```

---

## 9. Language-Specific Notes

### PHP

- Use `curl` or Guzzle for HTTP. Set `CURLOPT_TIMEOUT` to `10`.
- Use `hash('sha256', $raw)` for HWID generation.
- On Windows-based PHP hosts, use `exec('wmic cpu get ProcessorId')` — parse the second line of stdout.
- Use `json_decode($response, true)` and check `$body['valid']` before `$body['is_suspicious']`.

### C++

- Use `libcurl` for HTTP with `CURLOPT_TIMEOUT_MS` set to `10000`.
- Use OpenSSL's `EVP_DigestUpdate` / SHA-256 API for HWID hashing.
- On Windows, use `IWbemServices` (COM/WMI) to query `Win32_Processor` and `Win32_BaseBoard`.
- Use `nlohmann/json` or `rapidjson` for JSON parsing.

### Java / Kotlin

- Use `HttpClient` (Java 11+) or OkHttp. Set a `connectTimeout` and `readTimeout` of 10 seconds.
- Use `MessageDigest.getInstance("SHA-256")` for HWID.
- On Windows, use `ProcessBuilder` to execute `wmic` commands and parse stdout.
- Use Gson or Jackson for JSON deserialization.

### Go

- Use `net/http` with a `http.Client{Timeout: 10 * time.Second}`.
- Use `crypto/sha256` for HWID generation.
- On Windows, use `exec.Command("wmic", ...)` and parse stdout lines.
- Use `encoding/json` for response parsing.

### Unity (C#)

- The provided `client_integration.cs` is compatible with Unity .NET Standard 2.1+.
- Replace `System.Management` WMI calls with `UnityEngine.SystemInfo.deviceUniqueIdentifier` for the HWID (it is a stable per-device ID on all Unity platforms).
- Use `UnityEngine.Networking.UnityWebRequest` instead of `HttpClient` if required by the build target.

---

*This document reflects the TamozaKeyGen API as implemented in `scripts/client_integration.py` (reference SDK). For the admin management API, see `API.md`.*
