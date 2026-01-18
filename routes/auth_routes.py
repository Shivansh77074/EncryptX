from flask import Blueprint, request, jsonify, session, render_template_string
from datetime import datetime
from models.user import user_manager
from services.auth_service import AuthService
from utils.decorators import login_required, rate_limit, csrf_protected, require_json, generate_csrf_token
from utils.validators import (
    validate_password_strength, 
    sanitize_input, 
    validate_username,
    ValidationError
)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/')
def index():
    """Serve the secure frontend"""
    from templates.html_template import HTML_TEMPLATE
    return render_template_string(HTML_TEMPLATE)


@auth_bp.route('/csrf-token', methods=['GET'])
def get_csrf_token():
    """Get CSRF token for authenticated session"""
    token = generate_csrf_token()
    return jsonify({'csrf_token': token}), 200


@auth_bp.route('/register', methods=['POST'])
@require_json
@rate_limit(limit_type='auth')
def register():
    """Secure user registration with auto-login"""
    try:
        data = request.get_json()
        
        # Extract and validate inputs
        username_raw = data.get('username', '')
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        # Validate required fields
        if not username_raw or not password or not confirm_password:
            return jsonify({'error': 'All fields are required'}), 400
        
        # Validate username
        try:
            username = validate_username(username_raw)
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        
        # Validate password match
        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Check if user already exists
        if user_manager.user_exists(username):
            return jsonify({'error': 'Username already exists'}), 400
        
        # Create user with secure password hashing
        salt = AuthService.generate_salt()
        password_hash = AuthService.hash_password(password, salt)
        
        user_manager.create_user(username, password_hash, salt)
        
        # Auto-login after successful registration
        session.permanent = True
        session['username'] = username
        session['login_time'] = datetime.now().isoformat()
        session['last_activity'] = datetime.now().isoformat()
        
        # Generate CSRF token
        csrf_token = generate_csrf_token()
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'username': username,
            'csrf_token': csrf_token,
            'auto_login': True
        }), 201
    
    except Exception as e:
        # Generic error message to prevent information leakage
        return jsonify({'error': 'Registration failed. Please try again.'}), 500


@auth_bp.route('/login', methods=['POST'])
@require_json
@rate_limit(limit_type='auth')
def login():
    """Secure user login"""
    try:
        data = request.get_json()
        
        username_raw = data.get('username', '')
        password = data.get('password', '')
        
        # Validate required fields
        if not username_raw or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Sanitize username
        try:
            username = validate_username(username_raw)
        except ValidationError:
            # Don't reveal if username format is invalid
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Get user
        user = user_manager.get_user(username)
        if not user:
            # Generic error to prevent user enumeration
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verify password (constant-time comparison)
        if not AuthService.verify_password(password, user['salt'], user['password_hash']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create secure session
        session.permanent = True
        session['username'] = username
        session['login_time'] = datetime.now().isoformat()
        session['last_activity'] = datetime.now().isoformat()
        
        # Generate CSRF token
        csrf_token = generate_csrf_token()
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'username': username,
            'csrf_token': csrf_token
        }), 200
    
    except Exception as e:
        return jsonify({'error': 'Login failed. Please try again.'}), 500


@auth_bp.route('/logout', methods=['POST'])
@login_required
@csrf_protected
def logout():
    """Secure logout with cleanup"""
    try:
        username = session.get('username')
        
        # Clear user's RSA keys from memory
        if username:
            user_manager.clear_rsa_keys(username)
        
        # Clear session completely
        session.clear()
        
        return jsonify({
            'success': True, 
            'message': 'Logged out successfully'
        }), 200
    
    except Exception:
        session.clear()
        return jsonify({
            'success': True, 
            'message': 'Logged out successfully'
        }), 200


@auth_bp.route('/change-password', methods=['POST'])
@login_required
@csrf_protected
@require_json
@rate_limit(max_attempts=3, window=300, limit_type='auth')
def change_password():
    """Secure password change"""
    try:
        data = request.get_json()
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        # Validate all fields present
        if not current_password or not new_password or not confirm_password:
            return jsonify({'error': 'All fields are required'}), 400
        
        # Validate new passwords match
        if new_password != confirm_password:
            return jsonify({'error': 'New passwords do not match'}), 400
        
        # Validate new password is different
        if current_password == new_password:
            return jsonify({'error': 'New password must be different from current password'}), 400
        
        # Get user
        username = session.get('username')
        user = user_manager.get_user(username)
        
        if not user:
            session.clear()
            return jsonify({'error': 'User not found'}), 404
        
        # Verify current password
        if not AuthService.verify_password(current_password, user['salt'], user['password_hash']):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password strength
        is_valid, message = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Update password with new salt
        new_salt = AuthService.generate_salt()
        new_hash = AuthService.hash_password(new_password, new_salt)
        
        user_manager.update_password(username, new_hash, new_salt)
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        }), 200
    
    except Exception as e:
        return jsonify({'error': 'Password change failed. Please try again.'}), 500


@auth_bp.route('/status', methods=['GET'])
@login_required
def status():
    """Check authentication status"""
    try:
        username = session.get('username')
        has_keys = user_manager.has_rsa_keys(username)
        
        return jsonify({
            'authenticated': True,
            'username': username,
            'has_rsa_keys': has_keys,
            'csrf_token': session.get('csrf_token')
        }), 200
    
    except Exception:
        return jsonify({'error': 'Status check failed'}), 500