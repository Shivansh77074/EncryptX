# 🌍 Environment Variables Setup Guide

## Understanding Environment Variables

Environment variables are configuration values that:
- ✅ **Local Development**: Set each session (temporary)
- ✅ **Production Server**: Set once and persist (permanent)
- ✅ **Security**: Never commit to Git

---

## 📋 Required Environment Variables

### **APP_ENV** (Application Environment)
- **Purpose**: Determines which configuration to use
- **Values**: `development` or `production`
- **Default**: `production` (if not set)
- **Required**: Optional (defaults to production)

### **SECRET_KEY** (Session Encryption Key)
- **Purpose**: Encrypts session cookies
- **Required**: 
  - ❌ **NOT required** in development (auto-generated)
  - ✅ **REQUIRED** in production (must be set)
- **Format**: 64-character random hex string

---

## 💻 Local Development Setup (Windows PowerShell)

### Option 1: Set for Current Session Only (Temporary)

**Each time you open PowerShell, run these commands:**

```powershell
# Set to development mode (allows HTTP, relaxed security)
$env:APP_ENV = "development"

# Optional: Set custom SECRET_KEY (or let it auto-generate)
# $env:SECRET_KEY = "your-secret-key-here"

# Run the application
python main.py
```

**Characteristics:**
- ✅ Easy and quick
- ✅ Safe for testing
- ❌ Must set every new terminal session
- ❌ Lost when you close PowerShell

---

### Option 2: Create a Startup Script (Recommended for Development)

Create a file named `run_dev.ps1`:

```powershell
# run_dev.ps1
Write-Host "🚀 Starting SecureCrypt in Development Mode..." -ForegroundColor Green

# Set environment
$env:APP_ENV = "development"

# Activate virtual environment (if using venv)
if (Test-Path "venv\Scripts\Activate.ps1") {
    .\venv\Scripts\Activate.ps1
}

# Run application
python main.py
```

**Usage:**
```powershell
.\run_dev.ps1
```

---

### Option 3: Use .env File (Most Convenient)

**Step 1:** Install python-dotenv
```powershell
pip install python-dotenv
```

**Step 2:** Create `.env` file in project root:
```bash
# .env file
APP_ENV=development
# SECRET_KEY will auto-generate in dev mode
```

**Step 3:** Add to `.gitignore`:
```
.env
venv/
__pycache__/
*.pyc
```

**Step 4:** Modify `main.py` to load .env:
```python
# Add at the very top of main.py
from dotenv import load_dotenv
load_dotenv()  # Load .env file

import os
from flask import Flask, request
# ... rest of imports
```

**Characteristics:**
- ✅ Set once, works forever
- ✅ Different configs per developer
- ✅ Never committed to Git
- ✅ Industry standard

---

## 🚀 Production Server Setup (Linux/Cloud)

### For Linux Servers (Ubuntu/Debian/CentOS)

**Step 1:** Generate a secure SECRET_KEY
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# Example output: a1b2c3d4e5f6...64-character-hex-string
```

**Step 2:** Set environment variables permanently

**Option A: Using systemd service file** (Recommended)

Create `/etc/systemd/system/securecrypt.service`:
```ini
[Unit]
Description=SecureCrypt Web Application
After=network.target

[Service]
Type=notify
User=www-data
WorkingDirectory=/var/www/securecrypt
Environment="APP_ENV=production"
Environment="SECRET_KEY=YOUR_64_CHAR_SECRET_KEY_HERE"
Environment="CORS_ORIGINS=https://yourdomain.com"
ExecStart=/var/www/securecrypt/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 'main:create_app()'
Restart=always

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl enable securecrypt
sudo systemctl start securecrypt
sudo systemctl status securecrypt
```

**Option B: Using .bashrc or .profile**
```bash
# Add to ~/.bashrc or ~/.profile
export APP_ENV=production
export SECRET_KEY="your-64-char-secret-key-here"
export CORS_ORIGINS="https://yourdomain.com,https://www.yourdomain.com"
```

**Option C: Using environment file**

Create `/var/www/securecrypt/.env.production`:
```bash
APP_ENV=production
SECRET_KEY=your-64-char-secret-key-here
CORS_ORIGINS=https://yourdomain.com
```

Load in startup script:
```bash
set -a
source /var/www/securecrypt/.env.production
set +a
```

---

### For Cloud Platforms

#### **Heroku**
```bash
heroku config:set APP_ENV=production
heroku config:set SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
heroku config:set CORS_ORIGINS=https://yourapp.herokuapp.com
```

#### **AWS Elastic Beanstalk**
In `.ebextensions/environment.config`:
```yaml
option_settings:
  aws:elasticbeanstalk:application:environment:
    APP_ENV: production
    SECRET_KEY: your-secret-key
    CORS_ORIGINS: https://yourdomain.com
```

#### **Google Cloud Platform (App Engine)**
In `app.yaml`:
```yaml
env_variables:
  APP_ENV: 'production'
  SECRET_KEY: 'your-secret-key'
  CORS_ORIGINS: 'https://yourdomain.com'
```

#### **Docker / Docker Compose**

`docker-compose.yml`:
```yaml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - APP_ENV=production
      - SECRET_KEY=${SECRET_KEY}
      - CORS_ORIGINS=${CORS_ORIGINS}
    env_file:
      - .env.production
```

`.env.production` (NOT committed to Git):
```bash
SECRET_KEY=your-64-char-secret-key-here
CORS_ORIGINS=https://yourdomain.com
```

---

## 🔐 Generating Secure SECRET_KEY

### Windows PowerShell
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

### Linux/Mac
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Online (use with caution)
```python
# Run in Python interpreter
import secrets
print(secrets.token_hex(32))
```

**⚠️ Important:**
- Generate a NEW key for each environment
- NEVER reuse keys
- NEVER commit keys to Git
- Store securely (password manager, secrets vault)

---

## 📝 Complete Startup Commands

### Local Development (Windows)

**PowerShell (every session):**
```powershell
# Set environment
$env:APP_ENV = "development"

# Activate venv
.\venv\Scripts\Activate

# Run app
python main.py
```

**Or use startup script:**
```powershell
.\run_dev.ps1
```

---

### Production (Linux with systemd)

```bash
# Start service
sudo systemctl start securecrypt

# Check status
sudo systemctl status securecrypt

# View logs
sudo journalctl -u securecrypt -f

# Restart after changes
sudo systemctl restart securecrypt
```

---

### Production (Manual with gunicorn)

```bash
# Set environment
export APP_ENV=production
export SECRET_KEY="your-secret-key"

# Run with gunicorn
gunicorn -w 4 -b 127.0.0.1:8000 'main:create_app()' \
  --access-logfile /var/log/securecrypt/access.log \
  --error-logfile /var/log/securecrypt/error.log \
  --daemon
```

---

## ✅ Verification

### Check Current Environment Variables

**Windows PowerShell:**
```powershell
Write-Host "APP_ENV: $env:APP_ENV"
Write-Host "SECRET_KEY: $env:SECRET_KEY"
```

**Linux/Mac:**
```bash
echo "APP_ENV: $APP_ENV"
echo "SECRET_KEY: $SECRET_KEY"
```

### Test Configuration in Python

```python
import os
from config import get_config

print(f"APP_ENV: {os.environ.get('APP_ENV', 'not set')}")
print(f"SECRET_KEY set: {'Yes' if os.environ.get('SECRET_KEY') else 'No'}")
print(f"Config class: {get_config()}")
```

---

## 🎯 Summary Table

| Scenario | APP_ENV | SECRET_KEY | Where to Set |
|----------|---------|------------|--------------|
| **Local Development** | `development` | Auto-generated (optional) | PowerShell session or .env file |
| **Testing** | `development` | Auto-generated | CI/CD environment vars |
| **Staging Server** | `production` | **REQUIRED** (unique) | Server .env or systemd |
| **Production Server** | `production` | **REQUIRED** (unique) | Server .env or systemd |

---

## 🚨 Security Checklist

- [ ] Never commit SECRET_KEY to Git
- [ ] Use different SECRET_KEY for each environment
- [ ] Generate SECRET_KEY with `secrets.token_hex(32)`
- [ ] Add `.env` to `.gitignore`
- [ ] Use HTTPS in production (APP_ENV=production)
- [ ] Rotate SECRET_KEY periodically (forces re-login)
- [ ] Store production SECRET_KEY in secure vault
- [ ] Use environment-specific CORS_ORIGINS
- [ ] Set restrictive file permissions on .env files

---

## 📌 Quick Reference

**Development (local):**
```powershell
$env:APP_ENV = "development"
python main.py
```

**Production (server):**
```bash
export APP_ENV=production
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
gunicorn -w 4 -b 127.0.0.1:8000 'main:create_app()'
```

---

**You are correct:** 
- ✅ Local dev: Set each session (temporary)
- ✅ Production: Set once and remember (permanent in server config)
- ✅ Best practice: Use .env file or systemd service file