import secrets
import os
from datetime import timedelta

class Config:
    """Secure application configuration"""
    
    # Security Keys
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    
    # Session Security (Production-Ready)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True  # Enforce HTTPS in production
    SESSION_COOKIE_SAMESITE = 'Strict'  # Prevent CSRF
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # Reduced from 1 hour
    SESSION_REFRESH_EACH_REQUEST = True
    
    # Request Security
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1MB (reduced from 16MB)
    
    # CORS Configuration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:5000/api').split(',')
    CORS_SUPPORTS_CREDENTIALS = True
    CORS_MAX_AGE = 3600
    
    # Rate Limiting (Per User/IP)
    RATE_LIMIT_AUTH_ATTEMPTS = 5  # Login/register attempts
    RATE_LIMIT_AUTH_WINDOW = 300  # 5 minutes
    RATE_LIMIT_CRYPTO_ATTEMPTS = 100  # Crypto operations
    RATE_LIMIT_CRYPTO_WINDOW = 60  # 1 minute
    
    # Input Validation Limits
    MAX_USERNAME_LENGTH = 50
    MAX_PASSWORD_LENGTH = 128
    MIN_PASSWORD_LENGTH = 12  # Increased from 8
    MAX_PLAINTEXT_LENGTH = 100000  # 100KB
    MAX_KEY_NAME_LENGTH = 100
    
    # Cryptography Settings
    ALLOWED_ALGORITHMS = [
        'AES',          # AES-256-GCM (Recommended)
        'ChaCha20',     # ChaCha20-Poly1305 (Recommended)
        'Camellia',     # Camellia-256-CBC
        'RSA',          # RSA-2048-OAEP
        '3DES',         # Triple DES (Legacy)
        'Blowfish',     # Blowfish
        'Twofish'       # Twofish
    ]
    # DES and RC4 REMOVED - insecure and deprecated
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    # Environment
    ENV = os.environ.get('APP_ENV', 'production')
    DEBUG = False  # NEVER True in production
    TESTING = False


class DevelopmentConfig(Config):
    """Development-specific configuration"""
    DEBUG = False  # Still False for security
    SESSION_COOKIE_SECURE = False  # Allow HTTP in dev
    CORS_ORIGINS = ['http://localhost:5000/api', 'http://127.0.0.1:5000/api']


class ProductionConfig(Config):
    """Production-specific configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True

    # Must be set in production (validated later)
    SECRET_KEY = os.environ.get('SECRET_KEY')


# Configuration selector
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': ProductionConfig
}


def get_config():
    """Get configuration based on environment (secure & correct)"""
    env = os.environ.get('APP_ENV', 'production').strip().lower()

    if env == 'development':
        return DevelopmentConfig

    # Production safety check (runtime, not import-time)
    if not os.environ.get('SECRET_KEY'):
        raise RuntimeError(
            "SECURITY ERROR: SECRET_KEY must be set when APP_ENV=production"
        )

    return ProductionConfig
