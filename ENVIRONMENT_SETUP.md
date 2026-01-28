# 🌍 Environment Variables Setup Guide

## Understanding Environment Variables

Environment variables are configuration values that:
-  **Local Development**: Set each session (temporary)
-  **Production Server**: Set once and persist (permanent)
-  **Security**: Never commit to Git

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

## 📌 Quick Reference

**Development (local):**
```powershell
$env:APP_ENV = "development"
python main.py
```
---

**You are correct:** 
- Local dev: Set each session (temporary)
