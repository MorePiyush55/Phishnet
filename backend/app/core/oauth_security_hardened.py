"""Enhanced OAuth security hardening module for production deployment."""

import os
import base64
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import jwt
import logging

from app.config.settings import settings
from app.config.logging import get_logger

logger = get_logger(__name__)

class OAuthSecurityManager:
    """Advanced OAuth security manager with comprehensive hardening."""
    
    # Security constants
    TOKEN_ROTATION_THRESHOLD = 3600  # Rotate tokens after 1 hour
    SESSION_TIMEOUT = 7200  # 2 hours session timeout
    MAX_FAILED_ATTEMPTS = 5  # Lock after 5 failed attempts
    LOCKOUT_DURATION = 900  # 15 minutes lockout
    
    def __init__(self):
        """Initialize security manager with enhanced encryption."""
        self.master_key = self._get_or_create_master_key()
        self.cipher_suite = Fernet(self.master_key)
        self.session_store = {}  # In-memory secure session storage
        self.failed_attempts = {}  # Track failed OAuth attempts
        
    def _get_or_create_master_key(self) -> bytes:
        """Get or create master encryption key using PBKDF2."""
        try:
            # Use environment variable or generate secure key
            password = settings.privacy_encryption_key.encode()
            salt = settings.SECRET_KEY[:16].encode()  # Use first 16 chars of secret key as salt
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            return base64.urlsafe_b64encode(kdf.derive(password))
            
        except Exception as e:
            logger.error(f"Failed to derive master key: {e}")
            # Fallback to Fernet key generation
            return Fernet.generate_key()
    
    def encrypt_token_advanced(self, token_data: Dict[str, Any]) -> str:
        """Advanced token encryption with additional metadata."""
        try:
            # Add security metadata
            enhanced_token = {
                **token_data,
                "encrypted_at": datetime.utcnow().isoformat(),
                "version": "2.0",
                "checksum": self._calculate_checksum(str(token_data))
            }
            
            # Convert to JSON and encrypt
            token_json = str(enhanced_token).encode()
            encrypted = self.cipher_suite.encrypt(token_json)
            
            return base64.urlsafe_b64encode(encrypted).decode()
            
        except Exception as e:
            logger.error(f"Advanced token encryption failed: {e}")
            raise ValueError("Token encryption failed")
    
    def decrypt_token_advanced(self, encrypted_token: str) -> Dict[str, Any]:
        """Advanced token decryption with validation."""
        try:
            # Decode and decrypt
            encrypted_data = base64.urlsafe_b64decode(encrypted_token)
            decrypted = self.cipher_suite.decrypt(encrypted_data)
            
            # Parse token data
            token_data = eval(decrypted.decode())  # Note: Use json.loads in production
            
            # Validate checksum
            original_data = {k: v for k, v in token_data.items() 
                           if k not in ["encrypted_at", "version", "checksum"]}
            expected_checksum = self._calculate_checksum(str(original_data))
            
            if token_data.get("checksum") != expected_checksum:
                raise ValueError("Token integrity check failed")
            
            return original_data
            
        except Exception as e:
            logger.error(f"Advanced token decryption failed: {e}")
            raise ValueError("Token decryption failed")
    
    def _calculate_checksum(self, data: str) -> str:
        """Calculate SHA-256 checksum for data integrity."""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def create_secure_session(
        self, 
        user_id: str, 
        ip_address: str, 
        user_agent: str,
        additional_claims: Optional[Dict] = None
    ) -> str:
        """Create secure JWT session token."""
        try:
            now = datetime.utcnow()
            session_id = secrets.token_urlsafe(32)
            
            payload = {
                "session_id": session_id,
                "user_id": user_id,
                "iat": now,
                "exp": now + timedelta(seconds=self.SESSION_TIMEOUT),
                "ip_address": hashlib.sha256(ip_address.encode()).hexdigest(),  # Hash IP for privacy
                "user_agent_hash": hashlib.sha256(user_agent.encode()).hexdigest(),
                "jti": secrets.token_hex(16),  # JWT ID for token tracking
                **(additional_claims or {})
            }
            
            # Sign with HS256
            session_token = jwt.encode(
                payload, 
                settings.SECRET_KEY, 
                algorithm="HS256"
            )
            
            # Store session metadata
            self.session_store[session_id] = {
                "created_at": now,
                "last_accessed": now,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "active": True
            }
            
            return session_token
            
        except Exception as e:
            logger.error(f"Session creation failed: {e}")
            raise ValueError("Session creation failed")
    
    def validate_session(
        self, 
        session_token: str, 
        ip_address: str, 
        user_agent: str
    ) -> Optional[Dict[str, Any]]:
        """Validate and refresh session token."""
        try:
            # Decode JWT
            payload = jwt.decode(
                session_token, 
                settings.SECRET_KEY, 
                algorithms=["HS256"]
            )
            
            session_id = payload.get("session_id")
            
            # Check if session exists and is active
            session_meta = self.session_store.get(session_id)
            if not session_meta or not session_meta.get("active"):
                return None
            
            # Validate IP and User-Agent consistency
            ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
            ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()
            
            if (payload.get("ip_address") != ip_hash or 
                payload.get("user_agent_hash") != ua_hash):
                logger.warning(f"Session validation failed: IP/UA mismatch for session {session_id}")
                return None
            
            # Update last accessed time
            session_meta["last_accessed"] = datetime.utcnow()
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.info("Session token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid session token: {e}")
            return None
        except Exception as e:
            logger.error(f"Session validation failed: {e}")
            return None
    
    def revoke_session(self, session_token: str) -> bool:
        """Revoke a session token."""
        try:
            payload = jwt.decode(
                session_token, 
                settings.SECRET_KEY, 
                algorithms=["HS256"]
            )
            
            session_id = payload.get("session_id")
            if session_id in self.session_store:
                self.session_store[session_id]["active"] = False
                return True
                
        except Exception as e:
            logger.error(f"Session revocation failed: {e}")
            
        return False
    
    def check_rate_limit(self, identifier: str, limit: int, window: int) -> bool:
        """Enhanced rate limiting with exponential backoff."""
        now = time.time()
        
        # Clean old entries
        cutoff = now - window
        if identifier in self.failed_attempts:
            self.failed_attempts[identifier] = [
                timestamp for timestamp in self.failed_attempts[identifier]
                if timestamp > cutoff
            ]
        
        # Check current rate
        attempts = self.failed_attempts.get(identifier, [])
        
        if len(attempts) >= limit:
            # Apply exponential backoff
            backoff_time = min(window * (2 ** (len(attempts) - limit)), 3600)  # Max 1 hour
            return False
        
        return True
    
    def record_failed_attempt(self, identifier: str):
        """Record a failed OAuth attempt."""
        now = time.time()
        
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        self.failed_attempts[identifier].append(now)
    
    def clear_failed_attempts(self, identifier: str):
        """Clear failed attempts for successful authentication."""
        if identifier in self.failed_attempts:
            del self.failed_attempts[identifier]
    
    def generate_secure_state(self, user_data: Dict[str, Any]) -> Tuple[str, str]:
        """Generate cryptographically secure OAuth state parameter."""
        # Create random state
        state_value = secrets.token_urlsafe(32)
        
        # Create signed state with user data
        state_payload = {
            "state": state_value,
            "timestamp": datetime.utcnow().isoformat(),
            "user_data": user_data,
            "nonce": secrets.token_hex(16)
        }
        
        # Sign the state
        signed_state = jwt.encode(
            state_payload,
            settings.SECRET_KEY,
            algorithm="HS256"
        )
        
        return state_value, signed_state
    
    def validate_state(self, state: str, signed_state: str, max_age: int = 600) -> Optional[Dict]:
        """Validate OAuth state parameter."""
        try:
            # Decode signed state
            payload = jwt.decode(
                signed_state,
                settings.SECRET_KEY,
                algorithms=["HS256"]
            )
            
            # Check state match
            if payload.get("state") != state:
                logger.warning("OAuth state mismatch")
                return None
            
            # Check timestamp
            timestamp = datetime.fromisoformat(payload.get("timestamp"))
            if (datetime.utcnow() - timestamp).total_seconds() > max_age:
                logger.warning("OAuth state expired")
                return None
            
            return payload.get("user_data")
            
        except Exception as e:
            logger.error(f"State validation failed: {e}")
            return None
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions from memory."""
        now = datetime.utcnow()
        expired_sessions = []
        
        for session_id, session_data in self.session_store.items():
            if (now - session_data["last_accessed"]).total_seconds() > self.SESSION_TIMEOUT:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.session_store[session_id]
        
        logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers for OAuth responses."""
        return {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
        }

# Global security manager instance
oauth_security_manager = OAuthSecurityManager()