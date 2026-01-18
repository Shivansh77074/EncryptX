from flask import Blueprint, request, jsonify, session
import base64
from models.user import user_manager
from services.crypto_service import CryptoService
from utils.decorators import login_required, rate_limit, csrf_protected, require_json
from utils.validators import (
    sanitize_input, 
    validate_algorithm, 
    validate_plaintext,
    validate_ciphertext,
    validate_key,
    validate_key_name,
    validate_public_key_format,
    ValidationError
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

crypto_bp = Blueprint('crypto', __name__)


@crypto_bp.route('/encrypt', methods=['POST'])
@login_required
@csrf_protected
@require_json
@rate_limit(limit_type='crypto')
def encrypt():
    """Secure encryption endpoint with validation"""
    try:
        data = request.get_json()
        
        plaintext_raw = data.get('plaintext', '')
        algorithm_raw = data.get('algorithm', 'AES')
        key = data.get('key', '')
        
        # Validate inputs
        try:
            plaintext = validate_plaintext(plaintext_raw)
            algorithm = validate_algorithm(algorithm_raw)
            key = validate_key(key, algorithm)
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        
        username = session.get('username')
        
        # Encryption method dispatcher
        encryption_methods = {
            'AES': CryptoService.aes_encrypt,
            '3DES': CryptoService.des3_encrypt,
            'Blowfish': CryptoService.blowfish_encrypt,
            'ChaCha20': CryptoService.chacha20_encrypt,
            'Camellia': CryptoService.camellia_encrypt,
            'Twofish': CryptoService.twofish_encrypt,
        }
        
        if algorithm in encryption_methods:
            ciphertext = encryption_methods[algorithm](plaintext, key)
        
        elif algorithm == 'RSA':
            if not user_manager.has_rsa_keys(username):
                return jsonify({'error': 'RSA keys not generated. Please generate keys first.'}), 400
            
            keys = user_manager.get_rsa_keys(username)
            public_key = keys['public_key']
            ciphertext = CryptoService.rsa_encrypt(plaintext, public_key)
        
        else:
            return jsonify({'error': 'Invalid algorithm'}), 400
        
        return jsonify({
            'success': True,
            'ciphertext': ciphertext,
            'algorithm': algorithm
        }), 200
    
    except ValueError as e:
        # Crypto-specific errors
        return jsonify({'error': str(e)}), 400
    
    except Exception as e:
        # Generic error for unexpected issues
        return jsonify({'error': 'Encryption failed. Please try again.'}), 500


@crypto_bp.route('/decrypt', methods=['POST'])
@login_required
@csrf_protected
@require_json
@rate_limit(limit_type='crypto')
def decrypt():
    """Secure decryption endpoint with validation"""
    try:
        data = request.get_json()
        
        ciphertext_raw = data.get('ciphertext', '')
        algorithm_raw = data.get('algorithm', 'AES')
        key = data.get('key', '')
        
        # Validate inputs
        try:
            ciphertext = validate_ciphertext(ciphertext_raw)
            algorithm = validate_algorithm(algorithm_raw)
            key = validate_key(key, algorithm)
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        
        username = session.get('username')
        
        # Decryption method dispatcher
        decryption_methods = {
            'AES': CryptoService.aes_decrypt,
            '3DES': CryptoService.des3_decrypt,
            'Blowfish': CryptoService.blowfish_decrypt,
            'ChaCha20': CryptoService.chacha20_decrypt,
            'Camellia': CryptoService.camellia_decrypt,
            'Twofish': CryptoService.twofish_decrypt,
        }
        
        if algorithm in decryption_methods:
            plaintext = decryption_methods[algorithm](ciphertext, key)
        
        elif algorithm == 'RSA':
            if not user_manager.has_rsa_keys(username):
                return jsonify({'error': 'RSA keys not found. Cannot decrypt.'}), 400
            
            keys = user_manager.get_rsa_keys(username)
            private_key = keys['private_key']
            plaintext = CryptoService.rsa_decrypt(ciphertext, private_key)
        
        else:
            return jsonify({'error': 'Invalid algorithm'}), 400
        
        return jsonify({
            'success': True,
            'plaintext': plaintext,
            'algorithm': algorithm
        }), 200
    
    except ValueError as e:
        # Crypto-specific errors (wrong key, corrupted data, etc.)
        return jsonify({'error': 'Decryption failed. Check your key and ciphertext.'}), 400
    
    except Exception as e:
        return jsonify({'error': 'Decryption failed. Please try again.'}), 500


@crypto_bp.route('/generate-rsa-keys', methods=['POST'])
@login_required
@csrf_protected
@rate_limit(max_attempts=10, window=3600, limit_type='crypto')
def generate_rsa_keys():
    """Generate RSA key pair for authenticated user"""
    try:
        username = session.get('username')
        
        # Generate keys
        keys = CryptoService.generate_rsa_keypair()
        
        # Store in memory (cleared on logout)
        user_manager.store_rsa_keys(username, keys)
        
        # Return preview of public key
        public_key_preview = keys['public_key'][:80] + '...'
        
        return jsonify({
            'success': True,
            'message': 'RSA-2048 keys generated successfully',
            'public_key_preview': public_key_preview,
            'public_key_full': keys['public_key']
        }), 200
    
    except Exception as e:
        return jsonify({'error': 'Key generation failed. Please try again.'}), 500


@crypto_bp.route('/get-public-key', methods=['GET'])
@login_required
def get_public_key():
    """Get current user's public key for sharing"""
    try:
        username = session.get('username')
        
        if not user_manager.has_rsa_keys(username):
            return jsonify({'error': 'RSA keys not generated. Please generate keys first.'}), 400
        
        keys = user_manager.get_rsa_keys(username)
        
        return jsonify({
            'success': True,
            'public_key': keys['public_key'],
            'username': username
        }), 200
    
    except Exception as e:
        return jsonify({'error': 'Failed to retrieve public key'}), 500


@crypto_bp.route('/import-public-key', methods=['POST'])
@login_required
@csrf_protected
@require_json
@rate_limit(max_attempts=20, window=3600, limit_type='crypto')
def import_public_key():
    """Import someone else's public key for encryption"""
    try:
        data = request.get_json()
        
        public_key_raw = data.get('public_key', '')
        key_name_raw = data.get('key_name', 'Imported Key')
        
        # Validate inputs
        try:
            key_name = validate_key_name(key_name_raw)
            public_key = validate_public_key_format(public_key_raw)
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        
        # Validate it's actually a valid RSA public key
        try:
            public_pem = base64.b64decode(public_key.encode('utf-8'))
            serialization.load_pem_public_key(public_pem, backend=default_backend())
        except Exception:
            return jsonify({'error': 'Invalid RSA public key format'}), 400
        
        # Store imported key
        username = session.get('username')
        user_manager.store_imported_key(username, key_name, public_key)
        
        return jsonify({
            'success': True,
            'message': f'Public key "{key_name}" imported successfully'
        }), 200
    
    except Exception as e:
        return jsonify({'error': 'Failed to import public key'}), 500


@crypto_bp.route('/encrypt-with-imported-key', methods=['POST'])
@login_required
@csrf_protected
@require_json
@rate_limit(limit_type='crypto')
def encrypt_with_imported_key():
    """Encrypt using an imported public key"""
    try:
        data = request.get_json()
        
        plaintext_raw = data.get('plaintext', '')
        key_name_raw = data.get('key_name', '')
        
        # Validate inputs
        try:
            plaintext = validate_plaintext(plaintext_raw)
            key_name = validate_key_name(key_name_raw)
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        
        # Get imported key
        username = session.get('username')
        public_key = user_manager.get_imported_key(username, key_name)
        
        if not public_key:
            return jsonify({'error': 'Imported key not found'}), 404
        
        # Encrypt with imported public key
        ciphertext = CryptoService.rsa_encrypt(plaintext, public_key)
        
        return jsonify({
            'success': True,
            'ciphertext': ciphertext
        }), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
    except Exception as e:
        return jsonify({'error': 'Encryption failed'}), 500


@crypto_bp.route('/list-imported-keys', methods=['GET'])
@login_required
def list_imported_keys():
    """List all imported public keys for current user"""
    try:
        username = session.get('username')
        keys = user_manager.list_imported_keys(username)
        
        return jsonify({
            'success': True,
            'keys': keys
        }), 200
    
    except Exception as e:
        return jsonify({'error': 'Failed to list keys'}), 500


@crypto_bp.route('/delete-imported-key', methods=['POST'])
@login_required
@csrf_protected
@require_json
def delete_imported_key():
    """Delete an imported public key"""
    try:
        data = request.get_json()
        key_name_raw = data.get('key_name', '')
        
        try:
            key_name = validate_key_name(key_name_raw)
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        
        username = session.get('username')
        success = user_manager.delete_imported_key(username, key_name)
        
        if not success:
            return jsonify({'error': 'Key not found'}), 404
        
        return jsonify({
            'success': True,
            'message': f'Key "{key_name}" deleted successfully'
        }), 200
    
    except Exception as e:
        return jsonify({'error': 'Failed to delete key'}), 500