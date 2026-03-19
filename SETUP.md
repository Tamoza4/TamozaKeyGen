# TamozaKeyGen — Setup Guide

Complete installation and configuration instructions for **Windows** and **Linux**.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Windows Setup](#2-windows-setup)
3. [Linux Setup](#3-linux-setup)
4. [Environment Variables](#4-environment-variables)
5. [First Run](#5-first-run)
6. [Production Hardening](#6-production-hardening)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Python | 3.11+ | 3.12 or 3.14 recommended |
| MySQL | 8.0+ | MariaDB 10.6+ also works |
| pip / uv | latest | `uv` is preferred (faster) |

> **Note:** The project uses `uv` for virtual environment and package management. If you prefer plain `pip + venv`, see the alternative commands marked with 📦.

---

## 2. Windows Setup

### 2.1 Install Python

Download and install Python 3.11+ from [python.org](https://www.python.org/downloads/).  
During setup, check **"Add Python to PATH"**.

Verify:
```powershell
python --version
```

### 2.2 Install uv (recommended)

```powershell
pip install uv
```

### 2.3 Install MySQL

**Option A — XAMPP (easiest for local dev):**
1. Download XAMPP from [apachefriends.org](https://www.apachefriends.org/).
2. Install and launch the XAMPP Control Panel.
3. Start the **MySQL** module (Apache is not required).

**Option B — MySQL Community Server:**
Download from [dev.mysql.com](https://dev.mysql.com/downloads/mysql/) and follow the installer wizard.

### 2.4 Create the Database

Open MySQL (via phpMyAdmin at `http://localhost/phpmyadmin` or the `mysql` CLI):

```sql
CREATE DATABASE tamozakeygen CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

If your MySQL user requires a password, note the credentials — you will need them for the `DATABASE_URL` environment variable.

### 2.5 Clone / Download the Project

```powershell
git clone https://github.com/your-org/TamozaKeyGen.git
cd TamozaKeyGen
```

Or extract the ZIP into a folder of your choice and `cd` into it.

### 2.6 Create a Virtual Environment and Install Dependencies

**With uv (recommended):**
```powershell
uv venv .venv
uv pip install -r requirements.txt
```

📦 **With plain pip:**
```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

### 2.7 Set Environment Variables and Run

Set the required variables for your current PowerShell session, then start the server:

```powershell
$env:DATABASE_URL          = "mysql+pymysql://root:@localhost:3306/tamozakeygen"
$env:SECRET_KEY            = "replace-with-a-long-random-string"
$env:ADMIN_USERNAME        = "admin"
$env:ADMIN_PASSWORD        = "change-me"

.\.venv\Scripts\uvicorn.exe backend.main:app --reload --host 0.0.0.0 --port 8000
```

> Adjust `root:@localhost` to `user:password@host` to match your MySQL credentials.

**To persist variables across sessions**, add them to your System Environment Variables via  
*Settings → System → About → Advanced system settings → Environment Variables*.

---

## 3. Linux Setup

### 3.1 Install Python

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
```

**Fedora / RHEL:**
```bash
sudo dnf install -y python3 python3-pip
```

**Arch:**
```bash
sudo pacman -S python python-pip
```

Verify:
```bash
python3 --version
```

### 3.2 Install uv (recommended)

```bash
pip3 install uv
# or via the official installer:
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 3.3 Install MySQL

**Ubuntu / Debian:**
```bash
sudo apt install -y mysql-server
sudo systemctl enable --now mysql
sudo mysql_secure_installation   # recommended for production
```

**Fedora / RHEL:**
```bash
sudo dnf install -y mysql-server
sudo systemctl enable --now mysqld
sudo mysql_secure_installation
```

**Arch:**
```bash
sudo pacman -S mysql
sudo mysqld --initialize --user=mysql
sudo systemctl enable --now mysqld
```

### 3.4 Create the Database

```bash
sudo mysql -u root -p
```

```sql
CREATE DATABASE tamozakeygen CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- If you want a dedicated user (recommended):
CREATE USER 'tamoza'@'localhost' IDENTIFIED BY 'strong-password';
GRANT ALL PRIVILEGES ON tamozakeygen.* TO 'tamoza'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### 3.5 Clone / Download the Project

```bash
git clone https://github.com/your-org/TamozaKeyGen.git
cd TamozaKeyGen
```

### 3.6 Create a Virtual Environment and Install Dependencies

**With uv (recommended):**
```bash
uv venv .venv
uv pip install -r requirements.txt
```

📦 **With plain pip:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3.7 Set Environment Variables and Run

```bash
export DATABASE_URL="mysql+pymysql://tamoza:strong-password@localhost:3306/tamozakeygen"
export SECRET_KEY="replace-with-a-long-random-string"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="change-me"

.venv/bin/uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

**To persist variables**, add the `export` lines to your `~/.bashrc` or `~/.zshrc`, then `source` the file.

---

## 4. Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | ✅ Yes | `mysql+pymysql://root:password@localhost:3306/tamozakeygen` | Full SQLAlchemy MySQL connection string |
| `SECRET_KEY` | ✅ Yes (prod) | `CHANGE_ME_IN_PRODUCTION_USE_256BIT_RANDOM` | JWT signing secret — **must be changed before deployment** |
| `ADMIN_USERNAME` | No | `admin` | Username for the default admin account (only used on first startup) |
| `ADMIN_PASSWORD` | No | `admin` | Password for the default admin account (only used on first startup) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | `60` | JWT token lifetime in minutes |
| `CORS_ORIGINS` | No | `http://localhost,http://127.0.0.1` | Comma-separated list of allowed CORS origins |

> **Security:** `SECRET_KEY` should be a cryptographically random 256-bit (32-byte) string.  
> Generate one with: `python -c "import secrets; print(secrets.token_hex(32))"`

---

## 5. First Run

1. Start the server using the command from §2.7 (Windows) or §3.7 (Linux).
2. On first startup the server will:
   - Create all database tables automatically.
   - Run schema migrations for new columns.
   - Seed the default admin account if no users exist.
3. Open the admin dashboard in your browser:
   ```
   http://localhost:8000
   ```
4. Log in with your `ADMIN_USERNAME` / `ADMIN_PASSWORD` credentials.
5. **Change the default password immediately** via the dashboard or by restarting with updated env variables.

---

## 6. Production Hardening

### 6.1 Generate a Strong Secret Key

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Set the output as `SECRET_KEY`.

### 6.2 Run Without `--reload`

`--reload` is for development only. In production:

```bash
# Linux (with multiple workers)
.venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 4

# Windows
.\.venv\Scripts\uvicorn.exe backend.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 6.3 Run as a systemd Service (Linux)

Create `/etc/systemd/system/tamozakeygen.service`:

```ini
[Unit]
Description=TamozaKeyGen License Server
After=network.target mysql.service

[Service]
Type=exec
User=www-data
WorkingDirectory=/opt/TamozaKeyGen
Environment="DATABASE_URL=mysql+pymysql://tamoza:strong-password@localhost:3306/tamozakeygen"
Environment="SECRET_KEY=your-256-bit-secret"
Environment="ADMIN_PASSWORD=your-admin-password"
ExecStart=/opt/TamozaKeyGen/.venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tamozakeygen
sudo systemctl status tamozakeygen
```

### 6.4 Restrict CORS

Set `CORS_ORIGINS` to only your frontend domain:

```bash
export CORS_ORIGINS="https://your-domain.com"
```

### 6.5 Use a Reverse Proxy (Recommended)

Place nginx or Caddy in front of uvicorn for TLS termination, compression, and rate limiting.

**nginx minimal config example:**
```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

---

## 7. Troubleshooting

### `ModuleNotFoundError: No module named 'backend'`

Run uvicorn from the **project root** (the folder containing the `backend/` directory), not from inside `backend/` itself.

### `Access denied for user 'root'@'localhost'`

Your `DATABASE_URL` password does not match your MySQL root password.  
On a fresh XAMPP install with no password, use: `mysql+pymysql://root:@localhost:3306/tamozakeygen`  
Note the empty password between `:` and `@`.

### `sqlalchemy.exc.OperationalError: Can't connect to MySQL server`

- Confirm MySQL is running (`sudo systemctl status mysql` / check XAMPP Control Panel).
- Confirm the host, port, and database name in `DATABASE_URL` are correct.
- Check that the `tamozakeygen` database has been created.

### `bcrypt` version conflict warning

The project pins `bcrypt==4.0.1` for passlib compatibility. Do not upgrade bcrypt unless you also update the passlib integration.

### Port 8000 already in use

Change the port in the run command:
```powershell
# Windows
.\.venv\Scripts\uvicorn.exe backend.main:app --reload --host 0.0.0.0 --port 8080
```
```bash
# Linux
.venv/bin/uvicorn backend.main:app --reload --host 0.0.0.0 --port 8080
```

### JWT token errors / auto-logout on dashboard

Ensure `SECRET_KEY` is set and consistent across restarts. Changing `SECRET_KEY` invalidates all existing tokens.
