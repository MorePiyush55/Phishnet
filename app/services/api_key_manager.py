"""
Secure API Key Management System

This module provides secure storage, encryption, and management of API keys
with proper environment variable handling and key rotation support.
"""

import os
import base64
import hashlib
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import logging
from pathlib import Path

from app.config.logging import get_logger

logger = get_logger(__name__)


class APIKeyManager:
    """
    Secure API key management with encryption and environment variable support.
    
    Features:
    - Environment variable loading with validation
    - Key encryption using Fernet (AES 128)
    - Key rotation and validation
    - Secure key derivation from master password
    - Audit logging for key access
    """
    
    def __init__(self):
        self.master_key = self._get_or_create_master_key()
        self.cipher_suite = Fernet(self.master_key)
        self.encrypted_keys: Dict[str, bytes] = {}
        self._load_api_keys()
    
    def _get_or_create_master_key(self) -> bytes:
        """Get or create master encryption key from environment."""
        # Check for existing master key in environment
        master_key_env = os.getenv('PHISHNET_MASTER_KEY')
        
        if master_key_env:
            try:
                return base64.urlsafe_b64decode(master_key_env.encode())
            except Exception as e:
                logger.warning(f"Invalid master key in environment, generating new one: {e}")
        
        # Generate new master key
        salt = os.getenv('PHISHNET_SALT', secrets.token_hex(32)).encode()
        password = os.getenv('PHISHNET_PASSWORD', 'default_password_change_me').encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        
        logger.info("Generated new master encryption key")
        return key
    
    def _load_api_keys(self) -> None:
        """Load and encrypt API keys from environment variables."""
        # Define API key mappings with validation
        api_key_mappings = {
            'virustotal': {
                'env_var': 'VIRUSTOTAL_API_KEY',
                'required': True,
                'min_length': 64,
                'description': 'VirusTotal API key for malware analysis'
            },
            'abuseipdb': {
                'env_var': 'ABUSEIPDB_API_KEY', 
                'required': True,
                'min_length': 80,
                'description': 'AbuseIPDB API key for IP reputation analysis'
            },
            'google_api': {
                'env_var': 'GOOGLE_API_KEY',
                'required': True,
                'min_length': 39,
                'description': 'Google API key for AI analysis services'
            },
            'redis_password': {
                'env_var': 'REDIS_PASSWORD',
                'required': False,
                'min_length': 8,
                'description': 'Redis database password'
            },
            'database_password': {
                'env_var': 'DATABASE_PASSWORD',
                'required': False,
                'min_length': 8,
                'description': 'Database connection password'
            }
        }
        
        for key_name, config in api_key_mappings.items():
            env_value = os.getenv(config['env_var'])
            
            if env_value:
                if len(env_value) < config['min_length']:
                    logger.warning(f"API key {key_name} may be too short (expected >={config['min_length']} chars)")
                
                # Encrypt and store the key
                encrypted_key = self.cipher_suite.encrypt(env_value.encode())
                self.encrypted_keys[key_name] = encrypted_key
                
                logger.info(f"Loaded and encrypted {config['description']}")
            elif config['required']:
                logger.error(f"Required API key {config['env_var']} not found in environment")
            else:
                logger.info(f"Optional API key {config['env_var']} not provided")
    
    def get_api_key(self, key_name: str) -> Optional[str]:
        """
        Securely retrieve and decrypt an API key.
        
        Args:
            key_name: The name of the API key (virustotal, abuseipdb, google_api, etc.)
            
        Returns:
            Decrypted API key string or None if not found
        """
        try:
            if key_name not in self.encrypted_keys:
                logger.warning(f"API key '{key_name}' not found")
                return None
            
            encrypted_key = self.encrypted_keys[key_name]
            decrypted_key = self.cipher_suite.decrypt(encrypted_key).decode()
            
            # Log access (without exposing the key)
            logger.debug(f"API key '{key_name}' accessed successfully")
            
            return decrypted_key
            
        except Exception as e:
            logger.error(f"Failed to decrypt API key '{key_name}': {e}")
            return None
    
    def validate_key(self, key_name: str) -> bool:
        """Validate that an API key exists and can be decrypted."""
        try:
            key = self.get_api_key(key_name)
            return key is not None and len(key) > 0
        except Exception:
            return False
    
    def rotate_master_key(self, new_password: str) -> bool:
        """
        Rotate the master encryption key with a new password.
        This re-encrypts all stored API keys.
        """
        try:
            # Decrypt all keys with old master key
            decrypted_keys = {}
            for key_name in self.encrypted_keys:
                decrypted_keys[key_name] = self.get_api_key(key_name)
            
            # Generate new master key
            salt = secrets.token_hex(32).encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            new_master_key = base64.urlsafe_b64encode(kdf.derive(new_password.encode()))
            
            # Create new cipher suite
            new_cipher_suite = Fernet(new_master_key)
            
            # Re-encrypt all keys
            new_encrypted_keys = {}
            for key_name, key_value in decrypted_keys.items():
                if key_value:
                    new_encrypted_keys[key_name] = new_cipher_suite.encrypt(key_value.encode())
            
            # Update instance
            self.master_key = new_master_key
            self.cipher_suite = new_cipher_suite
            self.encrypted_keys = new_encrypted_keys
            
            logger.info("Master key rotated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rotate master key: {e}")
            return False
    
    def get_key_status(self) -> Dict[str, Any]:
        """Get status of all configured API keys."""
        status = {
            'total_keys': len(self.encrypted_keys),
            'keys': {}
        }
        
        for key_name in self.encrypted_keys:
            is_valid = self.validate_key(key_name)
            status['keys'][key_name] = {
                'configured': True,
                'valid': is_valid,
                'last_accessed': 'N/A'  # Could add timestamp tracking
            }
        
        return status


# Global API key manager instance
_api_key_manager: Optional[APIKeyManager] = None


def get_api_key_manager() -> APIKeyManager:
    """Get the global API key manager instance."""
    global _api_key_manager
    if _api_key_manager is None:
        _api_key_manager = APIKeyManager()
    return _api_key_manager


def get_virustotal_api_key() -> Optional[str]:
    """Get VirusTotal API key securely."""
    return get_api_key_manager().get_api_key('virustotal')


def get_abuseipdb_api_key() -> Optional[str]:
    """Get AbuseIPDB API key securely."""
    return get_api_key_manager().get_api_key('abuseipdb')


def get_google_api_key() -> Optional[str]:
    """Get Google API key securely."""
    return get_api_key_manager().get_api_key('google_api')


def get_redis_password() -> Optional[str]:
    """Get Redis password securely."""
    return get_api_key_manager().get_api_key('redis_password')


def get_database_password() -> Optional[str]:
    """Get database password securely."""
    return get_api_key_manager().get_api_key('database_password')


# Security audit function
def audit_api_key_access(key_name: str, requester: str = "unknown") -> None:
    """Log API key access for security auditing."""
    logger.info(f"API key '{key_name}' accessed by {requester}")


# Key validation for health checks
def validate_all_api_keys() -> Dict[str, bool]:
    """Validate all configured API keys for health monitoring."""
    manager = get_api_key_manager()
    return {
        'virustotal': manager.validate_key('virustotal'),
        'abuseipdb': manager.validate_key('abuseipdb'), 
        'google_api': manager.validate_key('google_api'),
        'redis': manager.validate_key('redis_password'),
        'database': manager.validate_key('database_password')
    }
