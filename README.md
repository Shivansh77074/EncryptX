# 🔒 SecureCrypt - Production-Grade Cryptographic Web Application

Enterprise-level secure cryptographic system with zero data persistence, modern encryption algorithms, and comprehensive security controls.

## ✨ Features

### Cryptographic Algorithms
- **AES-256-GCM** (Recommended) - Authenticated encryption
- **ChaCha20-Poly1305** (Recommended) - Modern stream cipher
- **Camellia-256-CBC** - Alternative block cipher
- **RSA-2048-OAEP** - Asymmetric encryption with hybrid mode
- **Triple DES (3DES)** - Legacy support only
- **Blowfish** - Historical compatibility
- **Twofish** - Advanced symmetric encryption

### Security Features
✅ Zero persistent storage (memory-only)  
✅ PBKDF2-SHA256 with 600,000 iterations  
✅ Unique salts per encryption operation  
✅ CSRF protection on all state-changing operations  
✅ Rate limiting (IP + user-based)  
✅ Comprehensive input validation  
✅ Security headers (CSP, HSTS, X-Frame-Options)  
✅ Constant-time cryptographic operations  
✅ Session security (HTTPOnly, Secure, SameSite=Strict)  
✅ Enhanced password requirements (12+ chars, special chars)  
✅ No debug mode or information leakage  

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- pip package manager
- Virtual environment (recommended)

### Installation

1. **Clone or extract the project**
```bash
cd securecrypt
```

2. **Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set environment variables**
```bash
export FLASK_ENV=development  # Use 'production' for production
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export CORS_ORIGINS=http://localhost:5000/api
```

5. **Run application**
```bash
# Development (testing only)
python main.py

# Production (recommended)
gunicorn -w 4 -b 0.0.0.0:8000 'main:create_app()'
```

6. **Access application**
```
http://localhost:5000/api (development)
http://localhost:8000 (production with gunicorn)
```

## 🏗️ Project Structure

```
securecrypt/
├── main.py                 # Application entry point
├── config.py              # Secure configuration
├── requirements.txt       # Python dependencies
├── models/
│   ├── __init__.py
│   └── user.py           # User management (in-memory)
├── routes/
│   ├── __init__.py
│   ├── auth_routes.py    # Authentication endpoints
│   └── crypto_routes.py  # Cryptography endpoints
├── services/
│   ├── __init__.py
│   ├── auth_service.py   # Password hashing, verification
│   └── crypto_service.py # Encryption/decryption operations
├── utils/
│   ├── __init__.py
│   ├── decorators.py     # Security decorators
│   └── validators.py     # Input validation
└── templates/
    ├── __init__.py
    └── html_template.py  # Frontend UI
```

## 🔐 API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - User login
- `POST /api/logout` - User logout (requires auth + CSRF)
- `POST /api/change-password` - Change password (requires auth + CSRF)
- `GET /api/status` - Check auth status
- `GET /api/csrf-token` - Get CSRF token

### Cryptography
- `POST /api/encrypt` - Encrypt data (requires auth + CSRF)
- `POST /api/decrypt` - Decrypt data (requires auth + CSRF)
- `POST /api/generate-rsa-keys` - Generate RSA keypair (requires auth + CSRF)
- `GET /api/get-public-key` - Get user's public key
- `POST /api/import-public-key` - Import public key (requires auth + CSRF)
- `POST /api/encrypt-with-imported-key` - Encrypt with imported key (requires auth + CSRF)
- `GET /api/list-imported-keys` - List imported keys
- `POST /api/delete-imported-key` - Delete imported key (requires auth + CSRF)

### Health Check
- `GET /health` - Application health status

## 🛡️ Security Configuration

### Production Environment Setup

1. **Generate strong secret key**
```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

2. **Configure CORS origins**
```bash
export CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

3. **Use HTTPS only**
- Deploy behind nginx/Apache with SSL/TLS
- Let's Encrypt for free certificates
- Ensure `SESSION_COOKIE_SECURE=True` is set

4. **Use production WSGI server**
```bash
# DO NOT use Flask dev server in production
gunicorn -w 4 -b 127.0.0.1:8000 'main:create_app()' \
  --access-logfile /var/log/gunicorn/access.log \
  --error-logfile /var/log/gunicorn/error.log \
  --log-level info
```

### nginx Configuration Example

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # Proxy to Gunicorn
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }
    
    # Static files (if any)
    location /static {
        alias /path/to/static;
        expires 30d;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

## 📋 Usage Guide

### Registration
1. Open application in browser
2. Click "Register" tab
3. Enter username (3-50 chars, alphanumeric + underscore)
4. Enter password (12+ chars, uppercase, lowercase, number, special char)
5. Confirm password
6. Click "Register" - automatic login after success

### Password Requirements
- Minimum 12 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one number (0-9)
- At least one special character (!@#$%^&*...)
- Cannot be common weak passwords

### Encryption/Decryption
1. Log in to application
2. Select algorithm (AES-256-GCM recommended)
3. Enter encryption key (minimum 8 characters)
4. Enter plaintext in input box
5. Click "Encrypt"
6. Copy ciphertext from output box
7. To decrypt: paste ciphertext, enter same key, click "Decrypt"

### RSA Encryption
1. Click "Generate RSA Keys" button
2. For encrypting to yourself: select "Use My Keys"
3. For encrypting to others: import their public key first
4. Enter plaintext and click "Encrypt"
5. Share ciphertext with recipient (only they can decrypt with private key)

## 🧪 Testing

### Manual Security Testing
```bash
# Install testing tools
pip install pytest pytest-cov bandit safety

# Run security scanner
bandit -r . -ll

# Check for vulnerable dependencies
safety check

# Run tests (if test suite exists)
pytest tests/ -v --cov
```

### Penetration Testing Checklist
- [ ] Test rate limiting (try 10+ rapid requests)
- [ ] Test CSRF protection (requests without token)
- [ ] Test input validation (XSS payloads, SQL injection)
- [ ] Test session security (cookie flags, expiry)
- [ ] Test cryptographic operations (algorithm correctness)
- [ ] Test authentication (weak passwords, wrong credentials)
- [ ] Test error handling (generic messages, no leakage)

## 🔒 Security Best Practices

### For Users
1. Use strong, unique passwords
2. Never share your private RSA key
3. Always verify recipient's public key before importing
4. Use AES-256-GCM or ChaCha20 for maximum security
5. Avoid legacy algorithms (3DES, Blowfish) unless required
6. Log out when finished to clear keys from memory

### For Administrators
1. Always use HTTPS in production
2. Keep dependencies updated (`pip list --outdated`)
3. Monitor for security advisories
4. Regular security audits
5. Implement proper logging (no sensitive data)
6. Use Redis for rate limiting in clustered environments
7. Regular backups (though no data persists)
8. Monitor rate limit violations
9. Review error logs for attack patterns

## 🚨 Incident Response

If security issue discovered:
1. Disable affected functionality immediately
2. Notify security team and users
3. Investigate root cause
4. Deploy fix and test thoroughly
5. Document in post-mortem
6. Enhance monitoring

## 📊 Performance

- PBKDF2 (600k iterations): ~200ms per operation
- AES-256-GCM encryption: <5ms for typical payloads
- RSA-2048 generation: ~500ms
- Session validation: <1ms
- Rate limiting: <1ms overhead

## 🐛 Troubleshooting

### "CSRF token missing" error
- Ensure you're logged in
- Frontend should send `X-CSRF-Token` header
- Token obtained from `/api/csrf-token` or login/register response

### "Rate limit exceeded" error
- Wait the specified time (5 minutes for auth, 1 minute for crypto)
- Don't spam requests
- Check if IP is shared (VPN, proxy)

### "Decryption failed" error
- Verify you're using the same key used for encryption
- Check algorithm matches
- Ensure ciphertext wasn't modified or corrupted
- For RSA: ensure you have the correct private key

### "Session expired" error
- Re-login (sessions expire after 30 minutes of inactivity)
- Check system clock is correct

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/latest/security/)
- [Python Cryptography Documentation](https://cryptography.io/)

## 📄 License

This is a security-focused educational and production-ready application. Use responsibly and ensure compliance with local regulations regarding cryptography.

## 🤝 Contributing

Security improvements welcome! Please:
1. Open issue first to discuss
2. Follow existing code style
3. Add tests for new features
4. Update documentation
5. Security fixes get priority

## ⚠️ Disclaimer

This application provides cryptographic tools. While it implements industry-standard security practices:
- Always keep software updated
- Use HTTPS in production
- Follow security best practices
- Regular security audits recommended
- No warranty provided

## 📞 Support

For security issues: Report privately to security team  
For bugs: Open GitHub issue  
For questions: Check documentation first

---

**Version:** 2.0 (Security Hardened)  
**Last Updated:** January 2026  
**Status:** Production-Ready ✅