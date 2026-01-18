import re
import html
from config import Config

class ValidationError(Exception):
    """Custom validation exception"""
    pass


def validate_password_strength(password):
    """
    Validate password meets enhanced security requirements
    
    Requirements:
    - Minimum 12 characters (increased from 8)
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if not isinstance(password, str):
        return False, "Password must be a string"
    
    if len(password) < Config.MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters"
    
    if len(password) > Config.MAX_PASSWORD_LENGTH:
        return False, f"Password must not exceed {Config.MAX_PASSWORD_LENGTH} characters"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Password must contain at least one special character"
    
    # Check for common weak passwords
    common_weak = ['password', '12345678', 'qwerty', 'abc123', 'letmein']
    if password.lower() in common_weak:
        return False, "Password is too common. Please choose a stronger password"
    
    return True, "Valid"


def sanitize_input(text, max_length=None):
    """
    Sanitize user input against XSS and injection attacks
    
    Args:
        text: Input string to sanitize
        max_length: Maximum allowed length (None for no limit)
    
    Returns:
        Sanitized string
    """
    if not isinstance(text, str):
        return ""
    
    # Apply length limit if specified
    if max_length and len(text) > max_length:
        text = text[:max_length]
    
    # HTML escape to prevent XSS
    text = html.escape(text, quote=True)
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Remove control characters except newlines and tabs
    text = ''.join(char for char in text if char.isprintable() or char in '\n\t')
    
    # Remove script tags (defense in depth)
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<iframe[^>]*>.*?</iframe>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
    
    return text.strip()


def validate_username(username):
    """
    Validate username format and length
    
    Requirements:
    - 3-50 characters
    - Alphanumeric and underscores only
    - Must start with letter
    """
    if not isinstance(username, str):
        raise ValidationError("Username must be a string")
    
    username = username.strip()
    
    if len(username) < 3:
        raise ValidationError("Username must be at least 3 characters")
    
    if len(username) > Config.MAX_USERNAME_LENGTH:
        raise ValidationError(f"Username must not exceed {Config.MAX_USERNAME_LENGTH} characters")
    
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', username):
        raise ValidationError("Username must start with a letter and contain only letters, numbers, and underscores")
    
    # Block potentially problematic usernames
    blocked = ['admin', 'root', 'system', 'administrator', 'test', 'guest']
    if username.lower() in blocked:
        raise ValidationError("This username is reserved")
    
    return username


def validate_plaintext(plaintext):
    """Validate plaintext for encryption"""
    if not isinstance(plaintext, str):
        raise ValidationError("Plaintext must be a string")
    
    if not plaintext or not plaintext.strip():
        raise ValidationError("Plaintext cannot be empty")
    
    if len(plaintext) > Config.MAX_PLAINTEXT_LENGTH:
        raise ValidationError(f"Plaintext exceeds maximum length of {Config.MAX_PLAINTEXT_LENGTH} characters")
    
    return plaintext


def validate_ciphertext(ciphertext):
    """Validate ciphertext for decryption"""
    if not isinstance(ciphertext, str):
        raise ValidationError("Ciphertext must be a string")
    
    if not ciphertext or not ciphertext.strip():
        raise ValidationError("Ciphertext cannot be empty")
    
    # Check if it looks like base64
    if not re.match(r'^[A-Za-z0-9+/]+=*$', ciphertext):
        raise ValidationError("Ciphertext format is invalid")
    
    return ciphertext


def validate_algorithm(algorithm):
    """Validate cryptographic algorithm"""
    if algorithm not in Config.ALLOWED_ALGORITHMS:
        raise ValidationError(f"Invalid algorithm. Allowed: {', '.join(Config.ALLOWED_ALGORITHMS)}")
    
    return algorithm


def validate_key(key, algorithm):
    """Validate encryption key"""
    if not isinstance(key, str):
        raise ValidationError("Key must be a string")
    
    if algorithm == 'RSA':
        return key  # RSA doesn't use password-based keys
    
    if len(key) < 8:
        raise ValidationError("Key must be at least 8 characters")
    
    if len(key) > 256:
        raise ValidationError("Key must not exceed 256 characters")
    
    return key


def validate_key_name(key_name):
    """Validate imported key name"""
    if not isinstance(key_name, str):
        raise ValidationError("Key name must be a string")
    
    key_name = key_name.strip()
    
    if not key_name:
        raise ValidationError("Key name cannot be empty")
    
    if len(key_name) > Config.MAX_KEY_NAME_LENGTH:
        raise ValidationError(f"Key name must not exceed {Config.MAX_KEY_NAME_LENGTH} characters")
    
    if not re.match(r'^[a-zA-Z0-9\s\-_]+$', key_name):
        raise ValidationError("Key name can only contain letters, numbers, spaces, hyphens, and underscores")
    
    return key_name


def validate_public_key_format(public_key_b64):
    """Validate RSA public key format"""
    if not isinstance(public_key_b64, str):
        raise ValidationError("Public key must be a string")
    
    if not re.match(r'^[A-Za-z0-9+/]+=*$', public_key_b64):
        raise ValidationError("Invalid public key format")
    
    # Check reasonable length (RSA-2048 public key ~400-450 bytes base64)
    if len(public_key_b64) < 200 or len(public_key_b64) > 2000:
        raise ValidationError("Public key length is suspicious")
    
    return public_key_b64