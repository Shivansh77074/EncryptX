from datetime import datetime
import secrets

class UserManager:
    """
    Manages user data in secure in-memory storage
    
    Security Features:
    - No persistent storage
    - Memory-only session data
    - Automatic cleanup on logout
    - No logging of sensitive data
    """
    
    def __init__(self):
        self.users_db = {}  # username -> user data
        self.rsa_keys = {}  # username -> RSA keys
    
    def create_user(self, username, password_hash, salt):
        """
        Create a new user with secure password storage
        
        Args:
            username: Username (already validated)
            password_hash: Hashed password
            salt: Unique salt for password
        """
        username_lower = username.lower()
        
        self.users_db[username_lower] = {
            'username': username,  # Original case preserved
            'password_hash': password_hash,
            'salt': salt,
            'created_at': datetime.now().isoformat(),
            'user_id': secrets.token_hex(16)
        }
    
    def get_user(self, username):
        """
        Get user by username (case-insensitive)
        
        Returns:
            User dict or None
        """
        return self.users_db.get(username.lower())
    
    def user_exists(self, username):
        """Check if user exists (case-insensitive)"""
        return username.lower() in self.users_db
    
    def update_password(self, username, new_hash, new_salt):
        """
        Update user password with new hash and salt
        
        Returns:
            Boolean indicating success
        """
        username_lower = username.lower()
        
        if username_lower in self.users_db:
            self.users_db[username_lower]['password_hash'] = new_hash
            self.users_db[username_lower]['salt'] = new_salt
            self.users_db[username_lower]['password_updated_at'] = datetime.now().isoformat()
            return True
        
        return False
    
    # ===== RSA Key Management =====
    
    def store_rsa_keys(self, username, keys):
        """
        Store RSA key pair for user (in memory only)
        
        Args:
            username: Username
            keys: Dict with 'private_key' and 'public_key' (base64-encoded)
        """
        if username not in self.rsa_keys:
            self.rsa_keys[username] = {}
        
        self.rsa_keys[username]['private_key'] = keys['private_key']
        self.rsa_keys[username]['public_key'] = keys['public_key']
        self.rsa_keys[username]['generated_at'] = datetime.now().isoformat()
    
    def get_rsa_keys(self, username):
        """
        Get RSA keys for user
        
        Returns:
            Dict with keys or None
        """
        if username in self.rsa_keys:
            return {
                'private_key': self.rsa_keys[username].get('private_key'),
                'public_key': self.rsa_keys[username].get('public_key')
            }
        return None
    
    def has_rsa_keys(self, username):
        """Check if user has generated RSA keys"""
        return (username in self.rsa_keys and 
                'private_key' in self.rsa_keys[username] and
                'public_key' in self.rsa_keys[username])
    
    def clear_rsa_keys(self, username):
        """
        Clear RSA keys for user (called on logout)
        Ensures no key material persists after logout
        """
        if username in self.rsa_keys:
            # Overwrite with random data before deletion (defense in depth)
            if 'private_key' in self.rsa_keys[username]:
                self.rsa_keys[username]['private_key'] = secrets.token_hex(256)
            if 'public_key' in self.rsa_keys[username]:
                self.rsa_keys[username]['public_key'] = secrets.token_hex(256)
            
            # Delete the entry
            del self.rsa_keys[username]
    
    # ===== Imported Key Management =====
    
    def store_imported_key(self, username, key_name, public_key):
        """
        Store an imported public key
        
        Args:
            username: Username
            key_name: Friendly name for the key
            public_key: Base64-encoded public key
        """
        if username not in self.rsa_keys:
            self.rsa_keys[username] = {}
        
        if 'imported_keys' not in self.rsa_keys[username]:
            self.rsa_keys[username]['imported_keys'] = {}
        
        self.rsa_keys[username]['imported_keys'][key_name] = {
            'public_key': public_key,
            'imported_at': datetime.now().isoformat()
        }
    
    def get_imported_key(self, username, key_name):
        """
        Get an imported public key
        
        Returns:
            Public key string or None
        """
        if (username in self.rsa_keys and 
            'imported_keys' in self.rsa_keys[username] and
            key_name in self.rsa_keys[username]['imported_keys']):
            return self.rsa_keys[username]['imported_keys'][key_name]['public_key']
        
        return None
    
    def list_imported_keys(self, username):
        """
        List all imported key names for a user
        
        Returns:
            List of key names
        """
        if (username in self.rsa_keys and 
            'imported_keys' in self.rsa_keys[username]):
            return list(self.rsa_keys[username]['imported_keys'].keys())
        
        return []
    
    def delete_imported_key(self, username, key_name):
        """
        Delete an imported public key
        
        Returns:
            Boolean indicating success
        """
        if (username in self.rsa_keys and 
            'imported_keys' in self.rsa_keys[username] and
            key_name in self.rsa_keys[username]['imported_keys']):
            
            # Overwrite before deletion
            self.rsa_keys[username]['imported_keys'][key_name]['public_key'] = secrets.token_hex(128)
            
            # Delete
            del self.rsa_keys[username]['imported_keys'][key_name]
            return True
        
        return False
    
    # ===== Utility Methods =====
    
    def get_user_count(self):
        """Get total number of registered users (for monitoring)"""
        return len(self.users_db)
    
    def cleanup_expired_sessions(self):
        """
        Utility method to clean up old session data
        (Call periodically if implementing session expiry)
        """
        # Placeholder for future implementation
        pass


# Global singleton instance
user_manager = UserManager()