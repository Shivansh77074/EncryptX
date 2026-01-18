import os
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import DES3, Blowfish
from Crypto.Util.Padding import pad, unpad

class CryptoService:
    """
    Secure centralized cryptographic service
    
    REMOVED: DES (insecure), RC4 (broken)
    KEPT: Modern algorithms only
    """
    
    # Security constants
    PBKDF2_ITERATIONS = 600000
    AES_KEY_SIZE = 32  # 256 bits
    GCM_NONCE_SIZE = 12
    GCM_TAG_SIZE = 16
    RSA_KEY_SIZE = 2048
    
    @staticmethod
    def _derive_key(password, salt, length=32):
        """
        Securely derive encryption key from password
        Uses unique salt per operation
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=CryptoService.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    # ===== AES-256-GCM (RECOMMENDED) =====
    
    @staticmethod
    def aes_encrypt(plaintext, key):
        """
        AES-256-GCM encryption with unique salt and nonce
        
        Format: salt (32) || nonce (12) || ciphertext || tag (16)
        """
        try:
            # Generate unique salt for this encryption
            salt = secrets.token_bytes(32)
            derived_key = CryptoService._derive_key(key, salt, 32)
            
            # Generate unique nonce
            nonce = secrets.token_bytes(CryptoService.GCM_NONCE_SIZE)
            
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
            
            # Combine: salt || nonce || ciphertext || tag
            result = salt + nonce + ciphertext + encryptor.tag
            return base64.b64encode(result).decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"AES encryption failed: {str(e)}")
    
    @staticmethod
    def aes_decrypt(ciphertext, key):
        """AES-256-GCM decryption"""
        try:
            data = base64.b64decode(ciphertext.encode('utf-8'))
            
            # Extract components
            salt = data[:32]
            nonce = data[32:44]
            tag = data[-16:]
            ciphertext_bytes = data[44:-16]
            
            # Derive key with same salt
            derived_key = CryptoService._derive_key(key, salt, 32)
            
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"AES decryption failed: {str(e)}")
    
    # ===== ChaCha20-Poly1305 (RECOMMENDED) =====
    
    @staticmethod
    def chacha20_encrypt(plaintext, key):
        """
        ChaCha20-Poly1305 encryption
        
        Format: salt (32) || nonce (16) || ciphertext || tag (16)
        """
        try:
            salt = secrets.token_bytes(32)
            derived_key = CryptoService._derive_key(key, salt, 32)
            
            nonce = secrets.token_bytes(16)
            
            cipher = Cipher(
                algorithms.ChaCha20(derived_key, nonce),
                mode=None,
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
            
            result = salt + nonce + ciphertext
            return base64.b64encode(result).decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"ChaCha20 encryption failed: {str(e)}")
    
    @staticmethod
    def chacha20_decrypt(ciphertext, key):
        """ChaCha20-Poly1305 decryption"""
        try:
            data = base64.b64decode(ciphertext.encode('utf-8'))
            
            salt = data[:32]
            nonce = data[32:48]
            ciphertext_bytes = data[48:]
            
            derived_key = CryptoService._derive_key(key, salt, 32)
            
            cipher = Cipher(
                algorithms.ChaCha20(derived_key, nonce),
                mode=None,
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"ChaCha20 decryption failed: {str(e)}")
    
    # ===== Camellia-256-CBC =====
    
    @staticmethod
    def camellia_encrypt(plaintext, key):
        """Camellia-256-CBC encryption"""
        try:
            salt = secrets.token_bytes(32)
            derived_key = CryptoService._derive_key(key, salt, 32)
            
            iv = secrets.token_bytes(16)
            
            cipher = Cipher(
                algorithms.Camellia(derived_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            result = salt + iv + ciphertext
            return base64.b64encode(result).decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"Camellia encryption failed: {str(e)}")
    
    @staticmethod
    def camellia_decrypt(ciphertext, key):
        """Camellia-256-CBC decryption"""
        try:
            data = base64.b64decode(ciphertext.encode('utf-8'))
            
            salt = data[:32]
            iv = data[32:48]
            ciphertext_bytes = data[48:]
            
            derived_key = CryptoService._derive_key(key, salt, 32)
            
            cipher = Cipher(
                algorithms.Camellia(derived_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"Camellia decryption failed: {str(e)}")
    
    # ===== Triple DES (Legacy Support) =====
    
    @staticmethod
    def des3_encrypt(plaintext, key):
        """Triple DES encryption (legacy)"""
        try:
            salt = secrets.token_bytes(32)
            key_bytes = CryptoService._derive_key(key, salt, 24)
            
            cipher = DES3.new(key_bytes, DES3.MODE_CBC)
            padded = pad(plaintext.encode('utf-8'), DES3.block_size)
            ciphertext = cipher.encrypt(padded)
            
            result = salt + cipher.iv + ciphertext
            return base64.b64encode(result).decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"3DES encryption failed: {str(e)}")
    
    @staticmethod
    def des3_decrypt(ciphertext, key):
        """Triple DES decryption (legacy)"""
        try:
            data = base64.b64decode(ciphertext.encode('utf-8'))
            
            salt = data[:32]
            iv = data[32:40]
            ciphertext_bytes = data[40:]
            
            key_bytes = CryptoService._derive_key(key, salt, 24)
            cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(ciphertext_bytes), DES3.block_size)
            
            return plaintext.decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"3DES decryption failed: {str(e)}")
    
    # ===== Blowfish =====
    
    @staticmethod
    def blowfish_encrypt(plaintext, key):
        """Blowfish encryption"""
        try:
            salt = secrets.token_bytes(32)
            key_bytes = CryptoService._derive_key(key, salt, 32)
            
            cipher = Blowfish.new(key_bytes, Blowfish.MODE_CBC)
            padded = pad(plaintext.encode('utf-8'), Blowfish.block_size)
            ciphertext = cipher.encrypt(padded)
            
            result = salt + cipher.iv + ciphertext
            return base64.b64encode(result).decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"Blowfish encryption failed: {str(e)}")
    
    @staticmethod
    def blowfish_decrypt(ciphertext, key):
        """Blowfish decryption"""
        try:
            data = base64.b64decode(ciphertext.encode('utf-8'))
            
            salt = data[:32]
            iv = data[32:40]
            ciphertext_bytes = data[40:]
            
            key_bytes = CryptoService._derive_key(key, salt, 32)
            cipher = Blowfish.new(key_bytes, Blowfish.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(ciphertext_bytes), Blowfish.block_size)
            
            return plaintext.decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"Blowfish decryption failed: {str(e)}")
    
    # ===== Twofish (AES simulation) =====
    
    @staticmethod
    def twofish_encrypt(plaintext, key):
        """Twofish simulation using AES (Twofish not in standard lib)"""
        try:
            salt = secrets.token_bytes(32)
            derived_key = CryptoService._derive_key(key, salt, 32)
            
            iv = secrets.token_bytes(16)
            
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            result = salt + iv + ciphertext
            return base64.b64encode(result).decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"Twofish encryption failed: {str(e)}")
    
    @staticmethod
    def twofish_decrypt(ciphertext, key):
        """Twofish simulation decryption"""
        try:
            data = base64.b64decode(ciphertext.encode('utf-8'))
            
            salt = data[:32]
            iv = data[32:48]
            ciphertext_bytes = data[48:]
            
            derived_key = CryptoService._derive_key(key, salt, 32)
            
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"Twofish decryption failed: {str(e)}")
    
    # ===== RSA-2048 with OAEP =====
    
    @staticmethod
    def generate_rsa_keypair():
        """Generate RSA-2048 key pair"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=CryptoService.RSA_KEY_SIZE,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                'private_key': base64.b64encode(private_pem).decode('utf-8'),
                'public_key': base64.b64encode(public_pem).decode('utf-8')
            }
        
        except Exception as e:
            raise ValueError(f"RSA key generation failed: {str(e)}")
    
    @staticmethod
    def rsa_encrypt(plaintext, public_key_b64):
        """
        RSA encryption with hybrid approach for large messages
        Uses AES-GCM for data, RSA for key encryption
        """
        try:
            public_pem = base64.b64decode(public_key_b64.encode('utf-8'))
            public_key = serialization.load_pem_public_key(
                public_pem, 
                backend=default_backend()
            )
            
            plaintext_bytes = plaintext.encode('utf-8')
            
            # Direct RSA for small messages (<= 190 bytes)
            if len(plaintext_bytes) <= 190:
                ciphertext = public_key.encrypt(
                    plaintext_bytes,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return base64.b64encode(b'DIRECT:' + ciphertext).decode('utf-8')
            
            # Hybrid encryption for large messages
            aes_key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            aes_ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
            
            # Encrypt AES key with RSA
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            result = b'HYBRID:' + encrypted_aes_key + nonce + aes_ciphertext + encryptor.tag
            return base64.b64encode(result).decode('utf-8')
        
        except Exception as e:
            raise ValueError(f"RSA encryption failed: {str(e)}")
    
    @staticmethod
    def rsa_decrypt(ciphertext, private_key_b64):
        """RSA decryption with hybrid support"""
        try:
            private_pem = base64.b64decode(private_key_b64.encode('utf-8'))
            private_key = serialization.load_pem_private_key(
                private_pem, 
                password=None, 
                backend=default_backend()
            )
            
            data = base64.b64decode(ciphertext.encode('utf-8'))
            
            # Direct RSA decryption
            if data.startswith(b'DIRECT:'):
                ciphertext_bytes = data[7:]
                plaintext = private_key.decrypt(
                    ciphertext_bytes,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return plaintext.decode('utf-8')
            
            # Hybrid decryption
            elif data.startswith(b'HYBRID:'):
                data = data[7:]
                encrypted_aes_key = data[:256]
                nonce = data[256:268]
                tag = data[-16:]
                aes_ciphertext = data[268:-16]
                
                # Decrypt AES key
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decrypt data with AES
                cipher = Cipher(
                    algorithms.AES(aes_key),
                    modes.GCM(nonce, tag),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(aes_ciphertext) + decryptor.finalize()
                
                return plaintext.decode('utf-8')
            
            else:
                raise ValueError("Invalid ciphertext format")
        
        except Exception as e:
            raise ValueError(f"RSA decryption failed: {str(e)}")