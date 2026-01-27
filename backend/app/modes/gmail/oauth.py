"""
Gmail OAuth Handler - Mode 2 (On-Demand Check)
===============================================
Handles OAuth 2.0 authentication flow for Gmail API access.

Privacy-First Design:
- Minimal scope (gmail.readonly only)
- Short-lived tokens (no refresh tokens by default)
- State token verification for CSRF protection
- Token encryption for secure storage
"""

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet
import hashlib

from app.config.settings import get_settings
from app.config.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)


class GmailOAuthHandler:
    """
    Handles OAuth 2.0 flow for Gmail API access.
    
    This handler implements incremental OAuth with minimal scope
    and short-lived tokens for privacy-first operation.
    """
    
    GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
    REQUIRED_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
    STATE_EXPIRY_MINUTES = 10
    
    def __init__(self):
        """Initialize OAuth handler."""
        self.client_id = getattr(settings, 'GMAIL_CLIENT_ID', None)
        self.client_secret = getattr(settings, 'GMAIL_CLIENT_SECRET', None)
        self.base_url = getattr(settings, 'BASE_URL', 'http://localhost:8002')
        self.redirect_uri = f"{self.base_url}/api/v2/gmail/oauth/callback"
        
        # Encryption for token storage
        self._cipher = self._init_cipher()
        
        if not self.client_id or not self.client_secret:
            logger.warning("Gmail OAuth credentials not configured")
    
    @property
    def is_configured(self) -> bool:
        """Check if OAuth is properly configured."""
        return bool(self.client_id and self.client_secret)
    
    def _init_cipher(self) -> Optional[Fernet]:
        """Initialize Fernet cipher for token encryption."""
        try:
            key = getattr(settings, 'ENCRYPTION_KEY', None)
            if not key:
                # Generate a key from a secret
                secret = getattr(settings, 'SECRET_KEY', 'phishnet-default-secret')
                key = base64.urlsafe_b64encode(
                    hashlib.sha256(secret.encode()).digest()
                )
            elif isinstance(key, str):
                if len(key) == 44:  # Valid Fernet key
                    key = key.encode()
                else:
                    key = base64.urlsafe_b64encode(
                        hashlib.sha256(key.encode()).digest()
                    )
            
            return Fernet(key)
        except Exception as e:
            logger.warning(f"Failed to initialize cipher: {e}")
            return None
    
    def build_auth_url(
        self,
        user_id: str,
        redirect_uri: str = None,
        include_refresh: bool = False
    ) -> Tuple[str, str]:
        """
        Build OAuth authorization URL.
        
        Args:
            user_id: User ID to include in state
            redirect_uri: Optional custom redirect URI
            include_refresh: Whether to request offline access (refresh token)
            
        Returns:
            Tuple of (authorization_url, state_token)
        """
        if not self.is_configured:
            raise ValueError("OAuth credentials not configured")
        
        # Generate state token with embedded data
        state_data = {
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": secrets.token_urlsafe(16),
        }
        state_token = base64.urlsafe_b64encode(
            json.dumps(state_data).encode()
        ).decode()
        
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri or self.redirect_uri,
            "scope": self.REQUIRED_SCOPE,
            "response_type": "code",
            "state": state_token,
            "access_type": "offline" if include_refresh else "online",
            "prompt": "consent",
        }
        
        auth_url = f"{self.GOOGLE_AUTH_URL}?{urlencode(params)}"
        
        logger.info(f"Generated OAuth URL for user {user_id}")
        return auth_url, state_token
    
    def verify_state(
        self,
        state_token: str,
        expected_user_id: str = None
    ) -> Dict[str, Any]:
        """
        Verify state token from OAuth callback.
        
        Args:
            state_token: State token from callback
            expected_user_id: Optional user ID to verify
            
        Returns:
            Decoded state data
            
        Raises:
            ValueError: If state is invalid or expired
        """
        try:
            decoded = base64.urlsafe_b64decode(state_token.encode())
            state_data = json.loads(decoded.decode())
            
            # Check expiry
            timestamp = datetime.fromisoformat(state_data["timestamp"])
            if datetime.now(timezone.utc) - timestamp > timedelta(minutes=self.STATE_EXPIRY_MINUTES):
                raise ValueError("State token expired")
            
            # Verify user ID if provided
            if expected_user_id and state_data["user_id"] != expected_user_id:
                raise ValueError("State token user mismatch")
            
            return state_data
            
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Invalid state token format: {e}")
        except Exception as e:
            logger.error(f"State verification failed: {e}")
            raise ValueError(f"State verification failed: {e}")
    
    async def exchange_code(
        self,
        code: str,
        redirect_uri: str = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token.
        
        Args:
            code: Authorization code from callback
            redirect_uri: Redirect URI used in auth request
            
        Returns:
            Dict with access_token, expires_in, etc.
        """
        if not self.is_configured:
            raise ValueError("OAuth credentials not configured")
        
        token_data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri or self.redirect_uri,
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.GOOGLE_TOKEN_URL,
                data=token_data,
                timeout=30.0
            )
            
            if response.status_code != 200:
                logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
                raise ValueError(f"Token exchange failed: {response.status_code}")
            
            tokens = response.json()
            
            # Verify we got the required scope
            granted_scopes = tokens.get("scope", "").split()
            if self.REQUIRED_SCOPE not in granted_scopes:
                logger.warning(f"Required scope not granted: {granted_scopes}")
            
            logger.info("Successfully exchanged code for access token")
            return tokens
    
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh an access token using a refresh token.
        
        Args:
            refresh_token: Refresh token from previous auth
            
        Returns:
            Dict with new access_token, expires_in, etc.
        """
        if not self.is_configured:
            raise ValueError("OAuth credentials not configured")
        
        token_data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.GOOGLE_TOKEN_URL,
                data=token_data,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise ValueError(f"Token refresh failed: {response.status_code}")
            
            return response.json()
    
    def encrypt_token(self, token: str) -> str:
        """Encrypt a token for secure storage."""
        if not self._cipher:
            raise ValueError("Encryption not available")
        
        encrypted = self._cipher.encrypt(token.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt a stored token."""
        if not self._cipher:
            raise ValueError("Encryption not available")
        
        encrypted = base64.b64decode(encrypted_token.encode())
        decrypted = self._cipher.decrypt(encrypted)
        return decrypted.decode()
    
    async def revoke_token(self, token: str) -> bool:
        """
        Revoke an access or refresh token.
        
        Args:
            token: Token to revoke
            
        Returns:
            True if revocation succeeded
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://oauth2.googleapis.com/revoke",
                params={"token": token},
                timeout=15.0
            )
            
            if response.status_code == 200:
                logger.info("Token revoked successfully")
                return True
            else:
                logger.warning(f"Token revocation failed: {response.status_code}")
                return False


# Singleton instance
_handler: Optional[GmailOAuthHandler] = None

def get_gmail_oauth_handler() -> GmailOAuthHandler:
    """Get singleton OAuth handler instance."""
    global _handler
    if _handler is None:
        _handler = GmailOAuthHandler()
    return _handler
