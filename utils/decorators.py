from functools import wraps
from flask import session, jsonify, request
from datetime import datetime, timedelta
import secrets
from config import Config

# In-memory rate limiting storage (use Redis in production)
_rate_limit_store = {}
_csrf_tokens = {}


def login_required(f):
    """
    Decorator to require authentication
    Includes session timeout validation
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Validate session is not expired
        login_time_str = session.get('login_time')
        if not login_time_str:
            session.clear()
            return jsonify({'error': 'Session expired'}), 401
        
        try:
            login_time = datetime.fromisoformat(login_time_str)
            if datetime.now() - login_time > Config.PERMANENT_SESSION_LIFETIME:
                session.clear()
                return jsonify({'error': 'Session expired'}), 401
        except (ValueError, TypeError):
            session.clear()
            return jsonify({'error': 'Invalid session'}), 401
        
        # Refresh session timestamp
        session['last_activity'] = datetime.now().isoformat()
        
        return f(*args, **kwargs)
    
    return decorated_function


def rate_limit(max_attempts=None, window=None, limit_type='auth'):
    """
    Enhanced rate limiting decorator with proper storage
    
    Args:
        max_attempts: Maximum attempts allowed
        window: Time window in seconds
        limit_type: 'auth' or 'crypto' for different limits
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get limits from config if not specified
            if limit_type == 'auth':
                attempts = max_attempts or Config.RATE_LIMIT_AUTH_ATTEMPTS
                time_window = window or Config.RATE_LIMIT_AUTH_WINDOW
            else:  # crypto
                attempts = max_attempts or Config.RATE_LIMIT_CRYPTO_ATTEMPTS
                time_window = window or Config.RATE_LIMIT_CRYPTO_WINDOW
            
            # Use IP + username for authenticated requests, just IP otherwise
            identifier = request.remote_addr
            if 'username' in session:
                identifier = f"{session['username']}:{request.remote_addr}"
            
            # Create key for this endpoint
            key = f"{limit_type}:{identifier}:{f.__name__}"
            current_time = datetime.now()
            
            # Initialize if not exists
            if key not in _rate_limit_store:
                _rate_limit_store[key] = []
            
            # Clean old attempts
            _rate_limit_store[key] = [
                timestamp for timestamp in _rate_limit_store[key]
                if (current_time - timestamp).total_seconds() < time_window
            ]
            
            # Check if limit exceeded
            if len(_rate_limit_store[key]) >= attempts:
                oldest = min(_rate_limit_store[key])
                wait_time = int(time_window - (current_time - oldest).total_seconds())
                return jsonify({
                    'error': f'Rate limit exceeded. Try again in {wait_time} seconds.'
                }), 429
            
            # Record this attempt
            _rate_limit_store[key].append(current_time)
            
            # Clean up old keys periodically (keep only last 1000 entries)
            if len(_rate_limit_store) > 1000:
                # Remove entries older than 1 hour
                cutoff = current_time - timedelta(hours=1)
                keys_to_remove = []
                for k, timestamps in _rate_limit_store.items():
                    if not timestamps or max(timestamps) < cutoff:
                        keys_to_remove.append(k)
                for k in keys_to_remove:
                    del _rate_limit_store[k]
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def csrf_protected(f):
    """
    CSRF protection for state-changing operations
    Validates token from request header
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # CSRF protection only for authenticated users
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get token from request header
        token_from_request = request.headers.get('X-CSRF-Token')
        token_from_session = session.get('csrf_token')
        
        if not token_from_request or not token_from_session:
            return jsonify({'error': 'CSRF token missing'}), 403
        
        # Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(token_from_request, token_from_session):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


def generate_csrf_token():
    """Generate a new CSRF token for the session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def require_json(f):
    """Require request to have JSON content type"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        return f(*args, **kwargs)
    return decorated_function


def clean_rate_limit_store():
    """Utility to clean rate limit store (call periodically)"""
    current_time = datetime.now()
    cutoff = current_time - timedelta(hours=1)
    
    keys_to_remove = []
    for key, timestamps in _rate_limit_store.items():
        if not timestamps or max(timestamps) < cutoff:
            keys_to_remove.append(key)
    
    for key in keys_to_remove:
        del _rate_limit_store[key]