import secrets
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class AuthService:
    """Handles secure authentication operations"""
    
    # Security constants
    PBKDF2_ITERATIONS = 600000  # Increased from 100000 (OWASP recommendation 2024)
    SALT_LENGTH = 32  # 256 bits
    HASH_LENGTH = 64  # 512 bits
    
    @staticmethod
    def generate_salt():
        """Generate cryptographically secure random salt"""
        return secrets.token_hex(AuthService.SALT_LENGTH)
    
    @staticmethod
    def hash_password(password, salt):
        """
        Hash password with salt using PBKDF2-SHA256
        
        Args:
            password: Plain text password
            salt: Hex-encoded salt string
        
        Returns:
            Base64-encoded password hash
        """
        if not password or not salt:
            raise ValueError("Password and salt are required")
        
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=AuthService.HASH_LENGTH,
                salt=bytes.fromhex(salt),  # Use actual salt, not static
                iterations=AuthService.PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            password_hash = kdf.derive(password.encode('utf-8'))
            return base64.b64encode(password_hash).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Password hashing failed: {str(e)}")
    
    @staticmethod
    def verify_password(password, salt, password_hash):
        """
        Verify password against hash using constant-time comparison
        
        Args:
            password: Plain text password to verify
            salt: Hex-encoded salt
            password_hash: Base64-encoded expected hash
        
        Returns:
            Boolean indicating if password is correct
        """
        if not password or not salt or not password_hash:
            return False
        
        try:
            computed_hash = AuthService.hash_password(password, salt)
            # Use constant-time comparison to prevent timing attacks
            return secrets.compare_digest(computed_hash, password_hash)
        except Exception:
            # Don't leak information about what went wrong
            return False
    
    @staticmethod
    def generate_session_token():
        """Generate secure session token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_api_key():
        """Generate API key (if needed for future use)"""
        return secrets.token_urlsafe(48)
    
    @staticmethod
    def constant_time_compare(val1, val2):
        """
        Constant-time string comparison to prevent timing attacks
        Wrapper around secrets.compare_digest with type checking
        """
        if not isinstance(val1, str) or not isinstance(val2, str):
            return False
        
        return secrets.compare_digest(val1, val2)
    
    @staticmethod
    def secure_random_bytes(length):
        """Generate cryptographically secure random bytes"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def secure_random_string(length=32):
        """Generate cryptographically secure random string"""
        return secrets.token_hex(length)