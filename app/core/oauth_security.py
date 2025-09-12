"""Secure OAuth flow with CSRF protection and encrypted token storage."""

import base64
import hashlib
import secrets
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode, urlparse

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.config.settings import Settings
from app.core.secrets import get_secret_manager

logger = logging.getLogger(__name__)


class OAuthSecurityError(Exception):
    """Base OAuth security error."""
    pass


class CSRFTokenError(OAuthSecurityError):
    """CSRF token validation error."""
    pass


class InvalidRedirectURIError(OAuthSecurityError):
    """Invalid redirect URI error."""
    pass


class TokenEncryptionError(OAuthSecurityError):
    """Token encryption/decryption error."""
    pass


class CSRFProtection:
    """CSRF protection for OAuth flow."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._secret_key = None
    
    async def _get_secret_key(self) -> bytes:
        """Get secret key for CSRF token signing."""
        if self._secret_key is None:
            secret_manager = get_secret_manager(self.settings)
            jwt_secret = await secret_manager.get_jwt_secret()
            # Derive CSRF key from JWT secret
            self._secret_key = hashlib.sha256(f"csrf_{jwt_secret}".encode()).digest()
        return self._secret_key
    
    async def generate_csrf_token(self, user_id: str, expiry_minutes: int = 30) -> str:
        """Generate CSRF token with expiry."""
        secret_key = await self._get_secret_key()
        
        # Create token data
        token_data = {
            "user_id": user_id,
            "expires_at": (datetime.utcnow() + timedelta(minutes=expiry_minutes)).isoformat(),
            "nonce": secrets.token_urlsafe(16)
        }
        
        # Encode and sign
        token_json = json.dumps(token_data, sort_keys=True)
        token_b64 = base64.urlsafe_b64encode(token_json.encode()).decode()
        
        # Create signature
        signature = hashlib.hmac.new(
            secret_key, 
            token_b64.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        return f"{token_b64}.{signature}"
    
    async def validate_csrf_token(self, token: str, user_id: str) -> bool:
        """Validate CSRF token."""
        try:
            if not token or "." not in token:
                return False
            
            token_b64, signature = token.rsplit(".", 1)
            
            # Verify signature
            secret_key = await self._get_secret_key()
            expected_signature = hashlib.hmac.new(
                secret_key,
                token_b64.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not secrets.compare_digest(signature, expected_signature):
                return False
            
            # Decode token data
            token_json = base64.urlsafe_b64decode(token_b64.encode()).decode()
            token_data = json.loads(token_json)
            
            # Validate user ID
            if token_data.get("user_id") != user_id:
                return False
            
            # Check expiry
            expires_at = datetime.fromisoformat(token_data["expires_at"])
            if datetime.utcnow() > expires_at:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"CSRF token validation error: {e}")
            return False


class RedirectURIValidator:
    """Validates OAuth redirect URIs for security."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        
        # Allowed domains for redirect URIs
        self.allowed_domains = self._get_allowed_domains()
    
    def _get_allowed_domains(self) -> set:
        """Get allowed domains from settings."""
        domains = set()
        
        # Add base URL domain
        base_url = urlparse(self.settings.BASE_URL)
        if base_url.netloc:
            domains.add(base_url.netloc.lower())
        
        # Add localhost for development
        if self.settings.is_development():
            domains.update({
                "localhost:3000",
                "localhost:8000", 
                "localhost:8080",
                "127.0.0.1:3000",
                "127.0.0.1:8000",
                "127.0.0.1:8080"
            })
        
        return domains
    
    def validate_redirect_uri(self, redirect_uri: str) -> bool:
        """Validate that redirect URI is allowed."""
        try:
            parsed = urlparse(redirect_uri)
            
            # Must use HTTPS in production
            if self.settings.is_production() and parsed.scheme != "https":
                logger.warning(f"Non-HTTPS redirect URI in production: {redirect_uri}")
                return False
            
            # Check domain
            domain = parsed.netloc.lower()
            if domain not in self.allowed_domains:
                logger.warning(f"Disallowed redirect URI domain: {domain}")
                return False
            
            # No fragments allowed
            if parsed.fragment:
                logger.warning(f"Redirect URI contains fragment: {redirect_uri}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Redirect URI validation error: {e}")
            return False


class TokenEncryption:
    """Encrypts OAuth refresh tokens for database storage."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._encryption_key = None
    
    async def _get_encryption_key(self) -> bytes:
        """Get or derive encryption key."""
        if self._encryption_key is None:
            secret_manager = get_secret_manager(self.settings)
            jwt_secret = await secret_manager.get_jwt_secret()
            
            # Derive encryption key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"phishnet_oauth_salt",  # Static salt for consistency
                iterations=100000,
            )
            self._encryption_key = base64.urlsafe_b64encode(kdf.derive(jwt_secret.encode()))
        
        return self._encryption_key
    
    async def encrypt_token(self, token: str) -> str:
        """Encrypt OAuth refresh token."""
        try:
            key = await self._get_encryption_key()
            cipher = Fernet(key)
            
            encrypted = cipher.encrypt(token.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
            
        except Exception as e:
            logger.error(f"Token encryption error: {e}")
            raise TokenEncryptionError(f"Failed to encrypt token: {e}")
    
    async def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt OAuth refresh token."""
        try:
            key = await self._get_encryption_key()
            cipher = Fernet(key)
            
            encrypted_data = base64.urlsafe_b64decode(encrypted_token.encode())
            decrypted = cipher.decrypt(encrypted_data)
            return decrypted.decode()
            
        except Exception as e:
            logger.error(f"Token decryption error: {e}")
            raise TokenEncryptionError(f"Failed to decrypt token: {e}")


class SecureOAuthService:
    """Secure OAuth service with comprehensive protection."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.csrf_protection = CSRFProtection(settings)
        self.redirect_validator = RedirectURIValidator(settings)
        self.token_encryption = TokenEncryption(settings)
        self.secret_manager = get_secret_manager(settings)
    
    async def generate_oauth_url(
        self, 
        provider: str,
        user_id: str,
        redirect_uri: str,
        scopes: list = None
    ) -> Tuple[str, str]:
        """Generate secure OAuth authorization URL with CSRF protection."""
        
        # Validate redirect URI
        if not self.redirect_validator.validate_redirect_uri(redirect_uri):
            raise InvalidRedirectURIError(f"Invalid redirect URI: {redirect_uri}")
        
        # Generate CSRF token
        csrf_token = await self.csrf_protection.generate_csrf_token(user_id)
        
        # Generate state parameter (includes CSRF token)
        state_data = {
            "csrf_token": csrf_token,
            "user_id": user_id,
            "provider": provider,
            "redirect_uri": redirect_uri
        }
        state = base64.urlsafe_b64encode(
            json.dumps(state_data).encode()
        ).decode()
        
        if provider == "gmail":
            oauth_url = await self._generate_gmail_oauth_url(
                redirect_uri, scopes or [], state
            )
        else:
            raise ValueError(f"Unsupported OAuth provider: {provider}")
        
        return oauth_url, csrf_token
    
    async def _generate_gmail_oauth_url(
        self, 
        redirect_uri: str, 
        scopes: list, 
        state: str
    ) -> str:
        """Generate Gmail OAuth URL."""
        # Get OAuth credentials from secret management
        api_keys = await self.secret_manager.get_api_keys()
        client_id = api_keys.get("gmail_client_id")
        
        if not client_id:
            raise OAuthSecurityError("Gmail client ID not configured")
        
        # Default scopes for Gmail API
        default_scopes = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.modify"
        ]
        scopes = scopes or default_scopes
        
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "response_type": "code",
            "access_type": "offline",  # Get refresh token
            "prompt": "consent",       # Force consent to get refresh token
            "state": state,
            "include_granted_scopes": "true"
        }
        
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    
    async def handle_oauth_callback(
        self, 
        code: str, 
        state: str, 
        csrf_token: str,
        db: Session
    ) -> Dict[str, any]:
        """Handle OAuth callback with security validation."""
        
        # Decode and validate state
        try:
            state_data = json.loads(
                base64.urlsafe_b64decode(state.encode()).decode()
            )
        except Exception as e:
            raise CSRFTokenError(f"Invalid state parameter: {e}")
        
        user_id = state_data.get("user_id")
        provider = state_data.get("provider")
        stored_csrf = state_data.get("csrf_token")
        redirect_uri = state_data.get("redirect_uri")
        
        # Validate CSRF token
        if not csrf_token or csrf_token != stored_csrf:
            raise CSRFTokenError("CSRF token mismatch")
        
        if not await self.csrf_protection.validate_csrf_token(csrf_token, user_id):
            raise CSRFTokenError("Invalid or expired CSRF token")
        
        # Exchange code for tokens
        if provider == "gmail":
            tokens = await self._exchange_gmail_code(code, redirect_uri)
        else:
            raise ValueError(f"Unsupported provider: {provider}")
        
        # Encrypt and store refresh token
        if tokens.get("refresh_token"):
            encrypted_token = await self.token_encryption.encrypt_token(
                tokens["refresh_token"]
            )
            
            await self._store_oauth_token(
                user_id=int(user_id),
                provider=provider,
                encrypted_refresh_token=encrypted_token,
                expires_at=tokens.get("expires_at"),
                scope=tokens.get("scope"),
                db=db
            )
        
        return {
            "user_id": user_id,
            "provider": provider,
            "access_token": tokens["access_token"],
            "expires_in": tokens.get("expires_in"),
            "scope": tokens.get("scope")
        }
    
    async def _exchange_gmail_code(self, code: str, redirect_uri: str) -> Dict[str, any]:
        """Exchange Gmail authorization code for tokens."""
        import httpx
        
        # Get OAuth credentials
        api_keys = await self.secret_manager.get_api_keys()
        client_id = api_keys.get("gmail_client_id")
        client_secret = api_keys.get("gmail_client_secret")
        
        if not client_id or not client_secret:
            raise OAuthSecurityError("Gmail OAuth credentials not configured")
        
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            
            if response.status_code != 200:
                logger.error(f"Gmail token exchange failed: {response.text}")
                raise OAuthSecurityError("Token exchange failed")
            
            tokens = response.json()
            
            # Calculate expiry time
            if tokens.get("expires_in"):
                tokens["expires_at"] = (
                    datetime.utcnow() + 
                    timedelta(seconds=tokens["expires_in"])
                ).isoformat()
            
            return tokens
    
    async def _store_oauth_token(
        self,
        user_id: int,
        provider: str,
        encrypted_refresh_token: str,
        expires_at: Optional[str],
        scope: Optional[str],
        db: Session
    ):
        """Store encrypted OAuth token in database."""
        from app.models.user import OAuthToken
        
        try:
            # Check if token already exists for this user/provider
            existing = db.query(OAuthToken).filter(
                OAuthToken.user_id == user_id,
                OAuthToken.provider == provider,
                OAuthToken.is_active == True
            ).first()
            
            if existing:
                # Update existing token
                existing.encrypted_refresh_token = encrypted_refresh_token
                existing.token_expires_at = (
                    datetime.fromisoformat(expires_at) if expires_at else None
                )
                existing.scope = scope
                existing.updated_at = datetime.utcnow()
            else:
                # Create new token
                oauth_token = OAuthToken(
                    user_id=user_id,
                    provider=provider,
                    encrypted_refresh_token=encrypted_refresh_token,
                    token_expires_at=(
                        datetime.fromisoformat(expires_at) if expires_at else None
                    ),
                    scope=scope
                )
                db.add(oauth_token)
            
            db.commit()
            logger.info(f"OAuth token stored for user {user_id}, provider {provider}")
            
        except Exception as e:
            logger.error(f"Failed to store OAuth token: {e}")
            db.rollback()
            raise OAuthSecurityError(f"Token storage failed: {e}")
    
    async def refresh_oauth_token(
        self, 
        user_id: int, 
        provider: str, 
        db: Session
    ) -> Optional[Dict[str, any]]:
        """Refresh OAuth access token using stored refresh token."""
        from app.models.user import OAuthToken
        
        try:
            # Get stored token
            oauth_token = db.query(OAuthToken).filter(
                OAuthToken.user_id == user_id,
                OAuthToken.provider == provider,
                OAuthToken.is_active == True
            ).first()
            
            if not oauth_token:
                return None
            
            # Decrypt refresh token
            refresh_token = await self.token_encryption.decrypt_token(
                oauth_token.encrypted_refresh_token
            )
            
            # Refresh based on provider
            if provider == "gmail":
                new_tokens = await self._refresh_gmail_token(refresh_token)
            else:
                raise ValueError(f"Unsupported provider: {provider}")
            
            # Update stored token if we got a new refresh token
            if new_tokens.get("refresh_token"):
                encrypted_token = await self.token_encryption.encrypt_token(
                    new_tokens["refresh_token"]
                )
                oauth_token.encrypted_refresh_token = encrypted_token
                oauth_token.updated_at = datetime.utcnow()
                db.commit()
            
            return new_tokens
            
        except Exception as e:
            logger.error(f"OAuth token refresh failed: {e}")
            return None
    
    async def _refresh_gmail_token(self, refresh_token: str) -> Dict[str, any]:
        """Refresh Gmail access token."""
        import httpx
        
        # Get OAuth credentials
        api_keys = await self.secret_manager.get_api_keys()
        client_id = api_keys.get("gmail_client_id")
        client_secret = api_keys.get("gmail_client_secret")
        
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            
            if response.status_code != 200:
                logger.error(f"Gmail token refresh failed: {response.text}")
                raise OAuthSecurityError("Token refresh failed")
            
            return response.json()
    
    async def revoke_oauth_token(self, user_id: int, provider: str, db: Session) -> bool:
        """Revoke OAuth token."""
        from app.models.user import OAuthToken
        
        try:
            oauth_token = db.query(OAuthToken).filter(
                OAuthToken.user_id == user_id,
                OAuthToken.provider == provider,
                OAuthToken.is_active == True
            ).first()
            
            if oauth_token:
                oauth_token.is_active = False
                oauth_token.updated_at = datetime.utcnow()
                db.commit()
                
                logger.info(f"OAuth token revoked for user {user_id}, provider {provider}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"OAuth token revocation failed: {e}")
            db.rollback()
            return False


# Global OAuth service instance
_oauth_service: Optional[SecureOAuthService] = None


def get_oauth_service(settings: Optional[Settings] = None) -> SecureOAuthService:
    """Get global OAuth service instance."""
    global _oauth_service
    
    if _oauth_service is None:
        from app.config.settings import get_settings
        settings = settings or get_settings()
        _oauth_service = SecureOAuthService(settings)
    
    return _oauth_service
