# SecureCrypt – Production-Grade Cryptographic Web Application

## Abstract / Overview
I built SecureCrypt as a security-first web application that delivers modern cryptography through a clean browser-based interface. The system focuses on strong encryption options, authenticated sessions, and zero persistent storage so that sensitive data remains in memory only. It provides both symmetric encryption (AES-256-GCM, ChaCha20, Camellia, and legacy ciphers) and asymmetric RSA key management, all wrapped in a Flask API with strict security controls and input validation.

## Problem Statement
Many lightweight encryption tools either store data or rely on outdated algorithms and weak operational safeguards. The goal here is to offer a secure, production-ready cryptographic web application that prevents common security pitfalls such as weak key derivation, insecure session handling, and lack of input validation.

## Objectives
- Deliver modern encryption and decryption capabilities with authenticated and validated endpoints.
- Enforce strong user authentication with secure password hashing and session controls.
- Avoid data persistence by keeping all user and key data in memory only.
- Provide a simple, web-based UI so encryption workflows are accessible to non-experts.
- Apply production-grade security best practices (CSRF protection, rate limiting, and security headers).

## Scope of the Project
The scope includes:
- A Flask-based API for authentication, crypto operations, and RSA key management.
- A single-page HTML UI served from the backend.
- In-memory storage for user accounts, session state, and cryptographic keys.
- Clear configuration for development vs. production security settings.

The project intentionally excludes persistent databases, file uploads, or external storage to reduce attack surface.

## Project Structure
```
EncryptX/
├── main.py                 # Application entry point
├── config.py               # Security-focused configuration
├── requirements.txt        # Python dependencies
├── models/
│   └── user.py             # In-memory user and key manager
├── routes/
│   ├── auth_routes.py      # Authentication endpoints
│   └── crypto_routes.py    # Cryptography endpoints
├── services/
│   ├── auth_service.py     # Password hashing and verification
│   └── crypto_service.py   # Encryption/decryption operations
├── utils/
│   ├── decorators.py       # Security decorators (CSRF, rate limit)
│   └── validators.py       # Input validation and sanitization
└── templates/
    └── html_template.py    # Embedded single-page UI
```

## System Architecture (text-based explanation)
1. **Client UI**: A single HTML/JS interface handles login, encryption/decryption actions, RSA key generation, and settings.
2. **Flask Application Layer**: The Flask app registers authentication and cryptography blueprints and enforces global security headers.
3. **Security Middleware**: Custom decorators handle authentication checks, rate limiting, CSRF protection, and JSON enforcement.
4. **Service Layer**: Dedicated services implement password hashing and cryptographic operations.
5. **In-Memory Data Store**: A singleton user manager keeps user data and RSA keys in memory only, clearing keys on logout.

## Technologies and Tools Used
- **Python 3.9+** for the core application logic.
- **Flask** as the web framework and routing layer.
- **Flask-CORS** for controlled cross-origin access.
- **cryptography** for modern cryptographic primitives.
- **pycryptodome** for legacy cipher support (3DES and Blowfish).
- **HTML/CSS/JavaScript** for the single-page client interface.

## Security Instructions and Cryptographic Algorithms
### Security Controls Implemented
- **No persistent storage**: all user data and keys are kept in memory and cleared on logout.
- **PBKDF2-SHA256 (600k iterations)** for password hashing and key derivation.
- **Per-operation salts** for encryption key derivation to prevent reuse attacks.
- **CSRF protection** for all state-changing endpoints.
- **Rate limiting** based on IP and user session.
- **Security headers** including CSP, HSTS, X-Frame-Options, and related policies.
- **Strict session settings** (HTTPOnly, Secure, SameSite=Strict).
- **Input validation and sanitization** on all user-provided data.

### Algorithms Used
- **AES-256-GCM** (recommended)
- **ChaCha20** (recommended)
- **Camellia-256-CBC**
- **RSA-2048 with OAEP** (hybrid encryption for larger messages)
- **Triple DES (3DES)** (legacy support)
- **Blowfish** (legacy support)
- **Twofish** (simulated with AES-CBC for compatibility)

## Methodology / Working Flow
1. User registers or logs in with strong password requirements.
2. The server creates a secure session and issues a CSRF token.
3. The client sends encryption/decryption requests with validated inputs.
4. The crypto service performs algorithm-specific operations (with PBKDF2 key derivation and per-operation salts).
5. Results are returned to the UI, with no sensitive data written to disk.

## Key Features
- Strong password rules with PBKDF2-SHA256 (600k iterations).
- AES-256-GCM and ChaCha20 as recommended encryption options.
- RSA-2048 key generation with hybrid encryption for larger payloads.
- CSRF protection on all state-changing endpoints.
- Rate limiting by IP and user session.
- Comprehensive input validation and sanitization.
- Secure session management with strict cookie settings.
- No data persistence and explicit key cleanup on logout.

## How to Use (Quick Guide)
### Setup (Development)
1. Create and activate a virtual environment.
2. Install dependencies from `requirements.txt`.
3. Set `APP_ENV=development` for local testing.
4. Run the server with `python main.py`.
5. Open `http://localhost:5000` in the browser.

### Setup and Run Steps (Detailed)
1. **Clone or open the repository**:
   ```bash
   cd /path/to/EncryptX
   ```
2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Windows: venv\\Scripts\\activate
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Set environment variables (development)**:
   ```bash
   export APP_ENV=development  # Windows PowerShell: $env:APP_ENV="development"
   ```
5. **Run the application**:
   ```bash
   python main.py
   ```
6. **Open in browser**:
   - http://localhost:5000/api

### Basic Usage
1. **Register or Login** with a strong password (12+ chars, mixed case, number, special char).
2. **Encrypt**: Select an algorithm, provide a key (except RSA), enter plaintext, and click Encrypt.
3. **Decrypt**: Paste ciphertext, keep the same algorithm/key, and click Decrypt.
4. **RSA Flow**: Generate keys, share the public key, and use RSA encryption for secure exchange.
5. **Logout**: Clears in-memory keys and session data.

## Implementation Details (high-level)
- **Application Factory**: The Flask app is created via a factory function and loads configuration based on environment variables.
- **Auth & Crypto Blueprints**: Authentication and encryption endpoints are separated for clarity and security boundaries.
- **Security Decorators**: Rate limiting, CSRF checks, and login validation are enforced as decorators around API routes.
- **Key Management**: RSA keys and imported public keys are stored only in memory and cleared on logout.
- **Frontend UI**: The HTML template is embedded in the backend and includes a JS client for API calls and UI state.

## Challenges Faced and Solutions
- **Secure key derivation**: Addressed by using PBKDF2-SHA256 with high iteration counts and per-operation salts.
- **Avoiding data persistence**: Solved by implementing a memory-only user manager and clearing keys on logout.
- **Balancing usability with security**: Implemented a web UI that still enforces strict validation, CSRF tokens, and rate limits.

## Troubleshooting
### 404 Not Found
- Confirm the server is running without errors in the terminal.
- Use the correct URL:
  - Main UI: `http://localhost:5000/api`
  - Health check: `http://localhost:5000/health`
- If you started the app on a different port, update the URL accordingly.
- Clear the browser cache or open a private window if the UI does not load.
- Ensure no proxy or firewall is blocking localhost traffic.

## Results / Outcomes
The project delivers a production-ready cryptographic web application with modern encryption algorithms, hardened security controls, and zero data persistence. Users can securely register, authenticate, generate keys, encrypt/decrypt data, and manage imported RSA keys without any sensitive information being stored on disk.

## Why Use SecureCrypt (Advantages)
- **Security-first defaults**: strong KDF, CSRF protection, rate limiting, and strict headers.
- **Zero persistence**: sensitive keys and user data never touch disk.
- **Modern crypto options**: AES-256-GCM and ChaCha20 for recommended usage, RSA for key exchange.
- **Clear UX**: a single-page UI reduces workflow friction without lowering security.
- **Production-ready posture**: environment-based config, strict session settings, and safe error handling.

## Future Enhancements
- Add audit logging with strict redaction to avoid sensitive data exposure.
- Introduce optional multi-factor authentication for higher-assurance environments.
- Integrate external rate limiting (Redis) for distributed deployments.
- Expand test coverage for cryptographic edge cases and security regressions.
- Add a modular UI build pipeline instead of embedded HTML.

## Conclusion
SecureCrypt meets the goal of providing a secure, production-grade cryptographic web application that prioritizes strong security defaults, modern encryption, and no persistent storage. The design balances usability with strict security controls, making it suitable for secure workflows where confidentiality is critical.
