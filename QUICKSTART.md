# ⚡ Quick Start Guide - SecureCrypt

## 🚀 Get Running in 3 Minutes

### Prerequisites
- Python 3.9+ installed
- PowerShell (Windows) or Terminal (Mac/Linux)

---

## Step-by-Step Setup

### 1. Open PowerShell in Project Directory
```powershell
cd C:\Users\shivu\Desktop\Projects\Encypter
```

### 2. Create Virtual Environment (First Time Only)
```powershell
python -m venv venv
```

### 3. Activate Virtual Environment
```powershell
.\venv\Scripts\Activate
```

**You should see `(venv)` in your prompt:**
```
(venv) PS C:\Users\shivu\Desktop\Projects\Encypter>
```

### 4. Install Dependencies (First Time Only)
```powershell
pip install Flask==3.0.0 Flask-Cors==4.0.0 cryptography==42.0.0 pycryptodome==3.19.0
```

### 5. Set Environment Variable (Every Session)
```powershell
$env:APP_ENV = "development"
```

### 6. Run Application
```powershell
python main.py
```

### 7. Open Browser
```
http://localhost:5000
```

---

## 🎯 One-Command Startup (After First Setup)

**Every time you want to run the app:**

```powershell
.\venv\Scripts\Activate; $env:APP_ENV = "development"; python main.py
```

**Or create `run.ps1` file with this content:**
```powershell
.\venv\Scripts\Activate
$env:APP_ENV = "development"
python main.py
```

**Then just run:**
```powershell
.\run.ps1
```

---

## ✅ Verify It's Working

### Test 1: Health Check
Open: `http://localhost:5000/health`

**Should see:**
```json
{"status": "healthy", "service": "SecureCrypt"}
```

### Test 2: Main Page
Open: `http://localhost:5000`

**Should see:**
- Purple gradient background
- "🔒 SecureCrypt" title
- Login/Register tabs

### Test 3: Register a User
1. Click "Register" tab
2. Username: `testuser`
3. Password: `TestPassword123!@#`
4. Confirm password
5. Click "Register"
6. Should auto-login and see the main interface

### Test 4: Encrypt Something
1. Select algorithm: "AES-256-GCM"
2. Enter key: `MySecretKey123`
3. Enter plaintext: `Hello, World!`
4. Click "🔒 Encrypt"
5. Should see encrypted text in output box

---

## 🐛 Common Issues

### Issue 1: "python: command not found"
**Solution:** Use `py` instead of `python`:
```powershell
py main.py
```

### Issue 2: "Cannot be loaded because running scripts is disabled"
**Solution:** Allow scripts in PowerShell:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Issue 3: "ImportError: cannot import name..."
**Solution:** Make sure all files are in correct locations:
```powershell
python verify_setup.py
```

### Issue 4: "Port 5000 is already in use"
**Solution:** Kill existing process or use different port:
```powershell
# Find and kill process
Get-Process -Name python | Where-Object {$_.Path -like "*venv*"} | Stop-Process

# Or change port in main.py (line with app.run)
```

### Issue 5: Browser shows "Not found"
**Solution:** 
1. Make sure app started without errors
2. Check you're going to `http://localhost:5000` (not 5001 or other port)
3. Try `http://127.0.0.1:5000`
4. Clear browser cache (Ctrl+F5)

---

## 📁 Required File Structure

Make sure you have ALL these files:

```
Encypter/
├── main.py                    ✅
├── config.py                  ✅
├── requirements.txt           ✅
├── models/
│   ├── __init__.py           ✅
│   └── user.py               ✅
├── routes/
│   ├── __init__.py           ✅
│   ├── auth_routes.py        ✅
│   └── crypto_routes.py      ✅
├── services/
│   ├── __init__.py           ✅
│   ├── auth_service.py       ✅
│   └── crypto_service.py     ✅
├── utils/
│   ├── __init__.py           ✅
│   ├── decorators.py         ✅
│   └── validators.py         ✅
└── templates/
    ├── __init__.py           ✅
    └── html_template.py      ✅
```

**Check with:**
```powershell
python verify_setup.py
```

---

## 🎓 Understanding Environment Variables

### Local Development (Your Case)

**Every time you open PowerShell:**
```powershell
$env:APP_ENV = "development"
```

**Why?**
- Allows HTTP (no HTTPS required)
- Relaxed security for testing
- Auto-generates SECRET_KEY
- Easier debugging

**Characteristics:**
- ✅ Easy to use
- ✅ Safe for testing
- ❌ Lost when you close PowerShell
- ❌ Must set each session

### Production Server (Later)

**Set ONCE on server, remember forever:**
```bash
export APP_ENV=production
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

**Why?**
- Enforces HTTPS
- Maximum security
- Requires SECRET_KEY
- Production-ready

**Characteristics:**
- ✅ Set once, works forever
- ✅ Survives restarts
- ✅ Secure by default
- ❌ Requires HTTPS setup

---

## 📋 Daily Workflow

**Morning (Start Work):**
```powershell
cd C:\Users\shivu\Desktop\Projects\Encypter
.\venv\Scripts\Activate
$env:APP_ENV = "development"
python main.py
```

**During Day (Making Changes):**
1. Edit code
2. Press `Ctrl+C` to stop server
3. Run `python main.py` again
4. Refresh browser

**Evening (Done Working):**
1. Press `Ctrl+C` to stop server
2. Type `deactivate` to exit venv
3. Close PowerShell

---

## 🎯 Success Indicators

**✅ You're good if you see:**

**In PowerShell:**
```
======================================================================
  SECURECRYPT - PRODUCTION-GRADE CRYPTOGRAPHIC WEB APPLICATION
======================================================================

🔒 Security Features Enabled:
  ✓ AES-256-GCM Encryption (Recommended)
  ...

⚠️  DEVELOPMENT MODE
  • HTTPS not enforced
  • Use HTTPS proxy in production

🌐 Server: http://localhost:5000
======================================================================

 * Running on http://127.0.0.1:5000
```

**In Browser (http://localhost:5000):**
- Purple gradient background
- Login/Register interface
- No error messages

**In Browser Console (F12):**
- No red errors
- No 404 errors

---

## 🆘 Need Help?

1. **Run diagnostic:**
   ```powershell
   python verify_setup.py
   ```

2. **Check specific file:**
   ```powershell
   python -c "from models import user_manager; print('OK')"
   ```

3. **Test imports:**
   ```powershell
   python -c "from config import get_config; print(get_config())"
   ```

4. **Check port:**
   ```powershell
   netstat -ano | findstr :5000
   ```

---

## 📚 Next Steps

After basic setup works:

1. ✅ **Read Security Report:** `SECURITY_AUDIT_REPORT.md`
2. ✅ **Production Setup:** `ENVIRONMENT_SETUP.md`
3. ✅ **Full Documentation:** `README.md`
4. ✅ **Deploy to Production:** Follow production guide

---

## 💡 Pro Tips

1. **Use the startup script** - Create `run.ps1` for one-command startup
2. **Use .env file** - Install python-dotenv and create .env file
3. **Enable script execution** - Run PowerShell as admin, execute `Set-ExecutionPolicy RemoteSigned`
4. **Use VS Code** - Better terminal integration and debugging
5. **Keep venv active** - Don't deactivate between runs during development

---

**You're all set! 🎉**

Open `http://localhost:5000` and start encrypting!