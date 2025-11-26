"""Enhanced OAuth security manager with MongoDB persistence for production."""

import os
import base64
import secrets
import hashlib
import time
from datetime import datetime, timedelta, timezone
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

class ProductionOAuthSecurityManager:
    """Production OAuth security manager with MongoDB persistence and enhanced security."""
    
    # Security constants
    TOKEN_ROTATION_THRESHOLD = 3600  # Rotate tokens after 1 hour
    SESSION_TIMEOUT = 7200  # 2 hours session timeout
    MAX_FAILED_ATTEMPTS = 5  # Lock after 5 failed attempts
    LOCKOUT_DURATION = 900  # 15 minutes lockout
    
    def __init__(self, use_mongodb: bool = True):
        """Initialize production security manager."""
        self.master_key = self._get_or_create_master_key()
        self.cipher_suite = Fernet(self.master_key)
        self.failed_attempts = {}  # IP-based rate limiting (can be moved to Redis)
        self.use_mongodb = use_mongodb
        self._persistent_session_manager = None
        
        # Initialize MongoDB session manager if available
        if self.use_mongodb:
            self._initialize_mongodb_persistence()
        else:
            # Fallback to in-memory storage
            self.session_store = {}
            logger.warning("Using in-memory session storage - not recommended for production")
    
    def _initialize_mongodb_persistence(self):
        """Initialize MongoDB persistence for sessions."""
        try:
            from app.db.production_persistence import persistent_session_manager
            self._persistent_session_manager = persistent_session_manager
            logger.info("MongoDB session persistence initialized")
        except ImportError as e:
            logger.error(f"Failed to initialize MongoDB persistence: {e}")
            self.use_mongodb = False
            self.session_store = {}
    
    def _get_or_create_master_key(self) -> bytes:
        """Get or create master encryption key using PBKDF2."""
        try:
            # Use configured encryption key or generate one
            encryption_password = getattr(settings, 'privacy_encryption_key', None)
            if not encryption_password:
                encryption_password = settings.SECRET_KEY
            
            # Generate a stable salt from the password for consistency
            salt = hashlib.sha256(encryption_password.encode()).digest()[:16]
            
            # Derive key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            key = base64.urlsafe_b64encode(kdf.derive(encryption_password.encode()))
            logger.info("Master encryption key derived successfully")
            return key
            
        except Exception as e:
            logger.error(f"Failed to derive master key: {e}")
            # Fallback to a generated key
            return Fernet.generate_key()
    
    async def encrypt_token_advanced(self, token_data: Dict[str, Any]) -> str:
        """Encrypt OAuth token with advanced security."""
        try:
            # Add integrity metadata
            token_with_metadata = {
                **token_data,
                "encrypted_at": datetime.now(timezone.utc).isoformat(),
                "checksum": hashlib.sha256(str(token_data).encode()).hexdigest()
            }
            
            # Serialize and encrypt
            token_json = json.dumps(token_with_metadata, default=str)
            encrypted_token = self.cipher_suite.encrypt(token_json.encode())
            encrypted_b64 = base64.urlsafe_b64encode(encrypted_token).decode()
            
            logger.info("Token encrypted with integrity verification")
            return encrypted_b64
            
        except Exception as e:
            logger.error(f"Token encryption failed: {e}")
            raise
    
    async def decrypt_token_advanced(self, encrypted_token: str) -> Dict[str, Any]:
        """Decrypt OAuth token with integrity verification."""
        try:
            # Decode and decrypt
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_token.encode())
            decrypted_json = self.cipher_suite.decrypt(encrypted_bytes).decode()
            token_data = json.loads(decrypted_json)
            
            # Verify integrity
            checksum = token_data.pop("checksum", None)
            encrypted_at = token_data.pop("encrypted_at", None)
            
            # Recreate checksum without metadata
            token_without_metadata = {k: v for k, v in token_data.items() 
                                    if k not in ["checksum", "encrypted_at"]}
            expected_checksum = hashlib.sha256(str(token_without_metadata).encode()).hexdigest()
            
            if checksum != expected_checksum:
                raise ValueError("Token integrity verification failed")
            
            logger.info("Token decrypted and integrity verified")
            return token_data
            
        except Exception as e:
            logger.error(f"Token decryption failed: {e}")
            raise
    
    async def create_secure_session(self, user_id: str, ip_address: str, user_agent: str) -> str:
        """Create secure session with MongoDB persistence."""
        try:
            session_id = secrets.token_urlsafe(32)
            current_time = datetime.now(timezone.utc)
            
            # Create JWT payload
            jwt_payload = {
                "session_id": session_id,
                "user_id": user_id,
                "ip_address": ip_address,
                "user_agent_hash": hashlib.sha256(user_agent.encode()).hexdigest()[:16],
                "iat": int(current_time.timestamp()),
                "exp": int((current_time + timedelta(seconds=self.SESSION_TIMEOUT)).timestamp())
            }
            
            # Sign JWT
            session_token = jwt.encode(
                jwt_payload,
                settings.SECRET_KEY,
                algorithm="HS256"
            )
            
            # Session metadata for persistence
            session_metadata = {
                "session_id": session_id,
                "user_id": user_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": current_time,
                "last_accessed": current_time,
                "expires_at": current_time + timedelta(seconds=self.SESSION_TIMEOUT),
                "active": True
            }
            
            # Store in MongoDB or memory
            if self.use_mongodb and self._persistent_session_manager:
                await self._persistent_session_manager.store_session(session_metadata)
            else:
                self.session_store[session_id] = session_metadata
            
            logger.info(f"Secure session created for user {user_id}")
            return session_token
            
        except Exception as e:
            logger.error(f"Failed to create secure session: {e}")
            raise
    
    async def validate_session(self, session_token: str, ip_address: str, user_agent: str) -> Optional[Dict[str, Any]]:
        """Validate session with IP/User-Agent consistency checks."""
        try:
            # Decode JWT
            payload = jwt.decode(
                session_token,
                settings.SECRET_KEY,
                algorithms=["HS256"]
            )
            
            session_id = payload.get("session_id")
            if not session_id:
                return None
            
            # Get session metadata
            if self.use_mongodb and self._persistent_session_manager:
                session_meta = await self._persistent_session_manager.get_session(session_id)
            else:
                session_meta = self.session_store.get(session_id)
            
            if not session_meta or not session_meta.get("active"):
                return None
            
            # Validate IP consistency
            if session_meta.get("ip_address") != ip_address:
                logger.warning(f"IP mismatch for session {session_id}")
                return None
            
            # Validate User-Agent consistency
            current_ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]
            expected_ua_hash = payload.get("user_agent_hash")
            
            if current_ua_hash != expected_ua_hash:
                logger.warning(f"User-Agent mismatch for session {session_id}")
                return None
            
            # Update last accessed time
            if self.use_mongodb and self._persistent_session_manager:
                await self._persistent_session_manager.update_session(
                    session_id, 
                    {"last_accessed": datetime.now(timezone.utc)}
                )
            else:
                session_meta["last_accessed"] = datetime.now(timezone.utc)
            
            logger.info(f"Session validated for user {payload.get('user_id')}")
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
    
    async def revoke_session(self, session_token: str) -> bool:
        """Revoke a session."""
        try:
            payload = jwt.decode(
                session_token,
                settings.SECRET_KEY,
                algorithms=["HS256"]
            )
            
            session_id = payload.get("session_id")
            if not session_id:
                return False
            
            # Deactivate session
            if self.use_mongodb and self._persistent_session_manager:
                return await self._persistent_session_manager.update_session(
                    session_id, 
                    {"active": False, "revoked_at": datetime.now(timezone.utc)}
                )
            else:
                if session_id in self.session_store:
                    self.session_store[session_id]["active"] = False
                    return True
                return False
            
        except Exception as e:
            logger.error(f"Failed to revoke session: {e}")
            return False
    
    def check_rate_limit(self, identifier: str, max_attempts: int, window_seconds: int) -> bool:
        """Check rate limiting for OAuth operations."""
        current_time = time.time()
        
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        # Clean old attempts
        self.failed_attempts[identifier] = [
            attempt_time for attempt_time in self.failed_attempts[identifier]
            if current_time - attempt_time < window_seconds
        ]
        
        # Check if under limit
        return len(self.failed_attempts[identifier]) < max_attempts
    
    def record_failed_attempt(self, identifier: str):
        """Record a failed OAuth attempt."""
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        self.failed_attempts[identifier].append(time.time())
        logger.warning(f"Failed OAuth attempt recorded for {identifier}")
    
    def clear_failed_attempts(self, identifier: str):
        """Clear failed attempts for an identifier."""
        if identifier in self.failed_attempts:
            del self.failed_attempts[identifier]
            logger.info(f"Failed attempts cleared for {identifier}")
    
    def generate_secure_state(self, user_data: Dict[str, Any]) -> Tuple[str, str]:
        """Generate cryptographically secure OAuth state parameter."""
        try:
            # Add timestamp and nonce for uniqueness
            state_data = {
                **user_data,
                "timestamp": int(time.time()),
                "nonce": secrets.token_urlsafe(32)
            }
            
            # Encode state data
            state_value = base64.urlsafe_b64encode(
                json.dumps(state_data).encode()
            ).decode()
            
            # Create HMAC signature
            signature = hmac.new(
                settings.SECRET_KEY.encode(),
                state_value.encode(),
                hashlib.sha256
            ).hexdigest()
            
            signed_state = f"{state_value}.{signature}"
            
            logger.info("Secure OAuth state generated")
            return state_value, signed_state
            
        except Exception as e:
            logger.error(f"State generation failed: {e}")
            raise
    
    def validate_state(self, state_value: str, signed_state: str) -> Optional[Dict[str, Any]]:
        """Validate OAuth state parameter with signature verification."""
        try:
            # Split state and signature
            received_state, received_signature = signed_state.split('.', 1)
            
            # Verify signature
            expected_signature = hmac.new(
                settings.SECRET_KEY.encode(),
                received_state.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(received_signature, expected_signature):
                logger.warning("OAuth state signature verification failed")
                return None
            
            # Verify state value matches
            if received_state != state_value:
                logger.warning("OAuth state value mismatch")
                return None
            
            # Decode and validate state data
            state_data = json.loads(
                base64.urlsafe_b64decode(state_value.encode()).decode()
            )
            
            # Check timestamp (5 minute window)
            if time.time() - state_data.get("timestamp", 0) > 300:
                logger.warning("OAuth state expired")
                return None
            
            logger.info("OAuth state validated successfully")
            return state_data
            
        except Exception as e:
            logger.error(f"State validation failed: {e}")
            return None
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        try:
            if self.use_mongodb and self._persistent_session_manager:
                return await self._persistent_session_manager.cleanup_expired_sessions()
            else:
                # Clean up in-memory sessions
                current_time = datetime.now(timezone.utc)
                expired_sessions = []
                
                for session_id, session_data in self.session_store.items():
                    expires_at = session_data.get("expires_at")
                    if expires_at and expires_at < current_time:
                        expired_sessions.append(session_id)
                
                for session_id in expired_sessions:
                    del self.session_store[session_id]
                
                if expired_sessions:
                    logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
                
                return len(expired_sessions)
                
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")
            return 0
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get comprehensive security headers for OAuth responses."""
        return {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache"
        }

# Global instance for production use
production_oauth_security_manager = ProductionOAuthSecurityManager(use_mongodb=True)

# Backward compatibility - use the new manager
oauth_security_manager = production_oauth_security_manager