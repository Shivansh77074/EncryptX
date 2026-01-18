# 🔧 Troubleshooting "Not found" Error

## Problem
Browser shows: `{"error": "Not found"}`

## Common Causes & Solutions

### 1. ✅ **Root Route Not Registered**

**Symptom:** Accessing `http://localhost:5000` shows "Not found"

**Cause:** The root route `/` is in `auth_routes.py` but blueprint is registered with `/api` prefix

**Solution:** The root route should work correctly. Check:

```python
# In routes/auth_routes.py - verify this exists:
@auth_bp.route('/')
def index():
    """Serve the frontend"""
    from templates.html_template import HTML_TEMPLATE
    return render_template_string(HTML_TEMPLATE)
```

**The route will be accessible at:**
- ❌ NOT at `http://localhost:5000` (because blueprint has `/api` prefix)
- ✅ Actually at `http://localhost:5000/api/`

**FIX:** Remove the `/api` prefix for the index route, or register a separate route.

---

### 2. ✅ **FIXED: Add Root Route to Main App**

Add this to `main.py` inside `create_app()` function, AFTER blueprint registration:

```python
def create_app(config_name=None):
    # ... existing code ...
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(crypto_bp, url_prefix='/api')
    
    # ===== ADD THIS: Root route for serving frontend =====
    @app.route('/')
    def index():
        """Serve the main application page"""
        from templates.html_template import HTML_TEMPLATE
        from flask import render_template_string
        return render_template_string(HTML_TEMPLATE)
    
    # ===== Security Headers =====
    # ... rest of code ...
```

---

### 3. ✅ **Browser Cache Issue**

**Symptom:** Made changes but still see old error

**Solution:** Hard refresh browser
- **Windows:** `Ctrl + F5` or `Ctrl + Shift + R`
- **Mac:** `Cmd + Shift + R`
- Or use Incognito/Private mode

---

### 4. ✅ **Wrong Port or URL**

**Check:**
```powershell
# What port is the app running on?
netstat -ano | findstr :5000
```

**Try accessing:**
- `http://127.0.0.1:5000`
- `http://localhost:5000`

---

### 5. ✅ **Before Request Hook Blocking**

**Cause:** Security check blocking legitimate requests

**Fixed in updated main.py** - now skips checks for `/` and `/health`

---

### 6. ✅ **Template Import Error**

**Check if template loads correctly:**

```python
# Test in Python console
from templates.html_template import HTML_TEMPLATE
print(len(HTML_TEMPLATE))  # Should print a large number
print(HTML_TEMPLATE[:100])  # Should show HTML
```

---

## 🔍 Debugging Steps

### Step 1: Check Application Startup

**Look for errors in console when running `python main.py`**

✅ **Should see:**
```
======================================================================
  SECURECRYPT - PRODUCTION-GRADE CRYPTOGRAPHIC WEB APPLICATION
======================================================================
...
🌐 Server: http://localhost:5000
======================================================================

 * Running on http://127.0.0.1:5000
```

❌ **If you see errors, fix them first**

---

### Step 2: Test Health Endpoint

```powershell
# Using curl (if installed)
curl http://localhost:5000/health

# Or using PowerShell
Invoke-WebRequest http://localhost:5000/health
```

**Should return:**
```json
{"status": "healthy", "service": "SecureCrypt"}
```

---

### Step 3: Check All Routes

**Add this temporary debugging endpoint to `main.py`:**

```python
@app.route('/debug/routes')
def list_routes():
    """Debug: List all registered routes"""
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(sorted(rule.methods))
        output.append(f"{rule.endpoint}: {rule.rule} [{methods}]")
    return {'routes': output}
```

**Access:** `http://localhost:5000/debug/routes`

---

### Step 4: Check Browser Console

**Open browser Developer Tools (F12)**

**Console tab - look for:**
- JavaScript errors
- CORS errors
- Network errors

**Network tab - check:**
- Status code (should be 200, not 404)
- Response headers
- Response body

---

## 🛠️ Complete Fix

### Updated main.py (add root route)

```python
def create_app(config_name=None):
    """Application factory pattern with security hardening"""
    app = Flask(__name__)
    
    # Load configuration
    if config_name:
        app.config.from_object(config_name)
    else:
        config_class = get_config()
        app.config.from_object(config_class)
    
    # Enable CORS
    CORS(
        app,
        supports_credentials=True,
        origins=app.config['CORS_ORIGINS'],
        max_age=app.config.get('CORS_MAX_AGE', 3600),
        allow_headers=['Content-Type', 'X-CSRF-Token'],
        methods=['GET', 'POST', 'OPTIONS']
    )
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(crypto_bp, url_prefix='/api')
    
    # ===== ROOT ROUTE FOR FRONTEND =====
    @app.route('/')
    def index():
        """Serve the main application page"""
        from templates.html_template import HTML_TEMPLATE
        from flask import render_template_string
        return render_template_string(HTML_TEMPLATE)
    
    # ===== Security Headers =====
    @app.after_request
    def add_security_headers(response):
        """Add comprehensive security headers to all responses"""
        headers = app.config.get('SECURITY_HEADERS', {})
        
        for header, value in headers.items():
            response.headers[header] = value
        
        response.headers.pop('Server', None)
        return response
    
    # ===== Error Handlers =====
    @app.errorhandler(404)
    def not_found(error):
        # If requesting HTML, show friendly page
        if request.accept_mimetypes.accept_html:
            return '<h1>404 - Page Not Found</h1><p><a href="/">Go to Home</a></p>', 404
        return {'error': 'Not found'}, 404
    
    # ... rest of error handlers ...
    
    # ===== Request Hooks =====
    @app.before_request
    def before_request_security():
        """Security checks before processing requests"""
        
        # Skip security checks for root route and health check
        if request.path in ['/', '/health']:
            return None
        
        # Block requests with suspicious headers
        user_agent = request.headers.get('User-Agent', '')
        if not user_agent or len(user_agent) > 500:
            return {'error': 'Invalid request'}, 400
        
        # Validate content type for POST requests to API
        if request.method == 'POST' and request.path.startswith('/api/'):
            if not request.is_json:
                return {'error': 'Content-Type must be application/json'}, 400
    
    # ===== Health Check =====
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint for monitoring"""
        return {'status': 'healthy', 'service': 'SecureCrypt'}, 200
    
    return app
```

---

## ✅ Quick Test Checklist

After applying fixes:

1. **Restart application**
   ```powershell
   python main.py
   ```

2. **Test health endpoint**
   - Visit: `http://localhost:5000/health`
   - Should see: `{"status": "healthy", "service": "SecureCrypt"}`

3. **Test root page**
   - Visit: `http://localhost:5000`
   - Should see: SecureCrypt login page with purple gradient

4. **Test API endpoint**
   - Visit: `http://localhost:5000/api/csrf-token`
   - Should see: `{"csrf_token": "..."}`

---

## 🎯 Expected Behavior

| URL | Expected Result |
|-----|-----------------|
| `http://localhost:5000` | SecureCrypt login/register page |
| `http://localhost:5000/health` | `{"status": "healthy"}` |
| `http://localhost:5000/api/csrf-token` | `{"csrf_token": "..."}` |
| `http://localhost:5000/api/status` | `{"error": "Unauthorized"}` (not logged in) |
| `http://localhost:5000/nonexistent` | `{"error": "Not found"}` |

---

## Still Having Issues?

Run the verification script:
```powershell
python verify_setup.py
```

Check console output for specific errors and share them for more targeted help.