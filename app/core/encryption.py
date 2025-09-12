"""
Data Encryption and Key Management
Provides AES-256 encryption for sensitive database fields and secure key management.
"""

import os
import base64
import hashlib
import logging
from typing import Optional, Union, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from sqlalchemy import TypeDecorator, String, Text
import secrets

from app.core.config import get_settings

logger = logging.getLogger(__name__)

class EncryptionManager:
    """
    Manages encryption keys and provides encryption/decryption services.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self._master_key = None
        self._field_keys = {}
        self._initialize_keys()
    
    def _initialize_keys(self):
        """Initialize encryption keys from environment or generate new ones"""
        try:
            # Get master key from environment or generate
            master_key_b64 = os.environ.get('PHISHNET_MASTER_KEY')
            if master_key_b64:
                self._master_key = base64.b64decode(master_key_b64)
            else:
                # Generate new master key (32 bytes for AES-256)
                self._master_key = secrets.token_bytes(32)
                logger.warning("Generated new master key - store PHISHNET_MASTER_KEY in production")
                logger.info(f"Master key (base64): {base64.b64encode(self._master_key).decode()}")
            
            # Derive field-specific keys from master key
            self._derive_field_keys()
            
        except Exception as e:
            logger.error(f"Error initializing encryption keys: {e}")
            raise
    
    def _derive_field_keys(self):
        """Derive field-specific encryption keys from master key"""
        fields = [
            'oauth_tokens',
            'email_content', 
            'user_pii',
            'audit_data',
            'session_data'
        ]
        
        for field in fields:
            # Use PBKDF2 to derive field-specific key
            salt = hashlib.sha256(f"phishnet_{field}_salt".encode()).digest()[:16]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            field_key = kdf.derive(self._master_key)
            self._field_keys[field] = Fernet(base64.urlsafe_b64encode(field_key))
    
    def encrypt_token(self, token: str) -> str:
        """Encrypt OAuth token"""
        if not token:
            return ""
        try:
            encrypted = self._field_keys['oauth_tokens'].encrypt(token.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Error encrypting token: {e}")
            raise
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt OAuth token"""
        if not encrypted_token:
            return ""
        try:
            encrypted_data = base64.b64decode(encrypted_token.encode())
            decrypted = self._field_keys['oauth_tokens'].decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Error decrypting token: {e}")
            raise
    
    def encrypt_email_content(self, content: str) -> str:
        """Encrypt email content"""
        if not content:
            return ""
        try:
            encrypted = self._field_keys['email_content'].encrypt(content.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Error encrypting email content: {e}")
            raise
    
    def decrypt_email_content(self, encrypted_content: str) -> str:
        """Decrypt email content"""
        if not encrypted_content:
            return ""
        try:
            encrypted_data = base64.b64decode(encrypted_content.encode())
            decrypted = self._field_keys['email_content'].decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Error decrypting email content: {e}")
            raise
    
    def encrypt_pii(self, pii_data: str) -> str:
        """Encrypt PII data"""
        if not pii_data:
            return ""
        try:
            encrypted = self._field_keys['user_pii'].encrypt(pii_data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Error encrypting PII: {e}")
            raise
    
    def decrypt_pii(self, encrypted_pii: str) -> str:
        """Decrypt PII data"""
        if not encrypted_pii:
            return ""
        try:
            encrypted_data = base64.b64decode(encrypted_pii.encode())
            decrypted = self._field_keys['user_pii'].decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Error decrypting PII: {e}")
            raise
    
    def encrypt_audit_data(self, audit_data: str) -> str:
        """Encrypt audit log data"""
        if not audit_data:
            return ""
        try:
            encrypted = self._field_keys['audit_data'].encrypt(audit_data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Error encrypting audit data: {e}")
            raise
    
    def decrypt_audit_data(self, encrypted_audit: str) -> str:
        """Decrypt audit log data"""
        if not encrypted_audit:
            return ""
        try:
            encrypted_data = base64.b64decode(encrypted_audit.encode())
            decrypted = self._field_keys['audit_data'].decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Error decrypting audit data: {e}")
            raise
    
    def hash_for_indexing(self, data: str, salt: str = "") -> str:
        """Create deterministic hash for database indexing"""
        if not data:
            return ""
        
        # Use HMAC with master key for consistent hashing
        import hmac
        key = self._master_key + salt.encode()
        return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()
    
    def create_data_fingerprint(self, data: str) -> str:
        """Create fingerprint for duplicate detection"""
        return hashlib.sha256(data.encode()).hexdigest()[:16]

# SQLAlchemy custom types for encrypted fields

class EncryptedType(TypeDecorator):
    """Base class for encrypted database fields"""
    
    impl = Text
    cache_ok = True
    
    def __init__(self, encryption_type='user_pii', *args, **kwargs):
        self.encryption_type = encryption_type
        super().__init__(*args, **kwargs)
    
    def process_bind_param(self, value, dialect):
        """Encrypt value before storing in database"""
        if value is None:
            return value
        
        encryption_manager = get_encryption_manager()
        
        if self.encryption_type == 'oauth_tokens':
            return encryption_manager.encrypt_token(str(value))
        elif self.encryption_type == 'email_content':
            return encryption_manager.encrypt_email_content(str(value))
        elif self.encryption_type == 'user_pii':
            return encryption_manager.encrypt_pii(str(value))
        elif self.encryption_type == 'audit_data':
            return encryption_manager.encrypt_audit_data(str(value))
        else:
            raise ValueError(f"Unknown encryption type: {self.encryption_type}")
    
    def process_result_value(self, value, dialect):
        """Decrypt value when loading from database"""
        if value is None:
            return value
        
        encryption_manager = get_encryption_manager()
        
        if self.encryption_type == 'oauth_tokens':
            return encryption_manager.decrypt_token(value)
        elif self.encryption_type == 'email_content':
            return encryption_manager.decrypt_email_content(value)
        elif self.encryption_type == 'user_pii':
            return encryption_manager.decrypt_pii(value)
        elif self.encryption_type == 'audit_data':
            return encryption_manager.decrypt_audit_data(value)
        else:
            raise ValueError(f"Unknown encryption type: {self.encryption_type}")

class EncryptedToken(EncryptedType):
    """Encrypted OAuth token field"""
    def __init__(self, *args, **kwargs):
        super().__init__(encryption_type='oauth_tokens', *args, **kwargs)

class EncryptedEmail(EncryptedType):
    """Encrypted email content field"""
    def __init__(self, *args, **kwargs):
        super().__init__(encryption_type='email_content', *args, **kwargs)

class EncryptedPII(EncryptedType):
    """Encrypted PII field"""
    def __init__(self, *args, **kwargs):
        super().__init__(encryption_type='user_pii', *args, **kwargs)

class EncryptedAudit(EncryptedType):
    """Encrypted audit data field"""
    def __init__(self, *args, **kwargs):
        super().__init__(encryption_type='audit_data', *args, **kwargs)

# Global encryption manager instance
_encryption_manager = None

def get_encryption_manager() -> EncryptionManager:
    """Get global encryption manager instance"""
    global _encryption_manager
    if _encryption_manager is None:
        _encryption_manager = EncryptionManager()
    return _encryption_manager

def rotate_encryption_keys():
    """Rotate encryption keys (for maintenance/security)"""
    logger.warning("Key rotation initiated - this requires database migration")
    # Implementation for key rotation would go here
    # This is a complex operation requiring careful planning
    raise NotImplementedError("Key rotation requires careful database migration")

def validate_encryption_setup() -> Dict[str, Any]:
    """Validate encryption configuration"""
    try:
        encryption_manager = get_encryption_manager()
        
        # Test encryption/decryption
        test_data = "test_encryption_data_123"
        
        # Test token encryption
        encrypted_token = encryption_manager.encrypt_token(test_data)
        decrypted_token = encryption_manager.decrypt_token(encrypted_token)
        
        # Test PII encryption
        encrypted_pii = encryption_manager.encrypt_pii(test_data)
        decrypted_pii = encryption_manager.decrypt_pii(encrypted_pii)
        
        # Test email encryption
        encrypted_email = encryption_manager.encrypt_email_content(test_data)
        decrypted_email = encryption_manager.decrypt_email_content(encrypted_email)
        
        # Validate decryption matches original
        if decrypted_token != test_data or decrypted_pii != test_data or decrypted_email != test_data:
            return {
                "valid": False,
                "error": "Encryption/decryption mismatch",
                "details": "Decrypted data does not match original"
            }
        
        return {
            "valid": True,
            "master_key_present": bool(encryption_manager._master_key),
            "field_keys_count": len(encryption_manager._field_keys),
            "test_passed": True
        }
        
    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
            "details": "Encryption validation failed"
        }

# Key management utilities

def export_master_key_for_backup() -> str:
    """Export master key for secure backup (admin only)"""
    encryption_manager = get_encryption_manager()
    if not encryption_manager._master_key:
        raise ValueError("No master key available")
    
    logger.warning("Master key exported for backup - handle securely")
    return base64.b64encode(encryption_manager._master_key).decode()

def generate_new_master_key() -> str:
    """Generate new master key for initial setup"""
    new_key = secrets.token_bytes(32)
    return base64.b64encode(new_key).decode()
