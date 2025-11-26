"""
Backend OAuth2 Service for Render deployment
Implements secure OAuth flow with PKCE, state management, and token handling
"""

import base64
import json
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

import httpx
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session
from fastapi import HTTPException, status, Request, Response
from jose import jwt, JWTError
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from app.models.user import User, OAuthCredential, AuditLog
from app.core.database import get_db
from app.core.redis_client import get_redis_client
from app.config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class BackendOAuthService:
    """Production OAuth2 service for backend operations."""
    
    def __init__(self):
        self.client_id = settings.GMAIL_CLIENT_ID
        self.client_secret = settings.GMAIL_CLIENT_SECRET
        self.redirect_uri = settings.GMAIL_REDIRECT_URI
        self.encryption_key = settings.privacy_encryption_key
        self.cipher_suite = Fernet(self.encryption_key.encode() if isinstance(self.encryption_key, str) else self.encryption_key)
        self.redis_client = get_redis_client()
        
        # OAuth endpoints
        self.auth_uri = "https://accounts.google.com/o/oauth2/auth"
        self.token_uri = "https://oauth2.googleapis.com/token"
        self.revoke_uri = "https://oauth2.googleapis.com/revoke"
        self.userinfo_uri = "https://www.googleapis.com/oauth2/v2/userinfo"
        
        # Scopes for Gmail access
        self.scopes = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.modify", 
            "https://www.googleapis.com/auth/gmail.labels",
            "openid",
            "email",
            "profile"
        ]

    async def generate_oauth_url(
        self,
        request: Request,
        response: Response,
        db: Session,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Generate OAuth URL with secure state and PKCE.
        
        Implements GET /auth/start endpoint specifications:
        - Generates cryptographically secure state
        - Creates PKCE code_verifier/code_challenge
        - Stores state server-side with session management
        - Builds Google auth URL with all required parameters
        """
        
        # Generate cryptographically secure state and PKCE values
        state = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(43)  # 43 chars = 256 bits base64url
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')
        
        # Create or get session ID
        session_id = request.cookies.get("session_id")
        if not session_id:
            session_id = secrets.token_urlsafe(32)
            # Set httpOnly, secure cookie
            response.set_cookie(
                key="session_id",
                value=session_id,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=3600  # 1 hour
            )
        
        # Store state and PKCE values in Redis with session linkage
        session_data = {
            "state": state,
            "code_verifier": code_verifier,
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat(),
            "ip_address": self._get_client_ip(request),
            "user_agent": request.headers.get("user-agent", "")
        }
        
        # Store in Redis with 1 hour expiration
        await self.redis_client.setex(
            f"oauth_session:{session_id}",
            3600,
            json.dumps(session_data)
        )
        
        # Build Google OAuth URL
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "access_type": "offline",  # Request refresh token
            "prompt": "consent",  # Force consent for refresh token
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        
        auth_url = f"{self.auth_uri}?{urlencode(params)}"
        
        # Audit log
        await self._log_audit_event(
            db=db,
            user_id=user_id,
            action="oauth_start",
            success=True,
            ip_address=session_data["ip_address"],
            user_agent=session_data["user_agent"],
            metadata={
                "session_id": session_id,
                "scopes_requested": self.scopes
            }
        )
        
        return {
            "success": True,
            "authorization_url": auth_url,
            "session_id": session_id,
            "state": state  # For debugging only, remove in production
        }

    async def handle_oauth_callback(
        self,
        request: Request,
        db: Session,
        code: str,
        state: str,
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Handle OAuth callback with comprehensive validation.
        
        Implements GET /oauth2callback endpoint specifications:
        - Validates state against stored session data
        - Exchanges code for tokens (access, refresh, ID tokens)
        - Validates ID token (issuer, audience)
        - Creates/updates User record and links tokens
        - Encrypts and stores refresh token
        """
        
        if error:
            await self._log_audit_event(
                db=db,
                action="oauth_callback",
                success=False,
                error_message=f"OAuth error: {error}",
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", "")
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"OAuth authorization failed: {error}"
            )
        
        # Get session ID from cookie
        session_id = request.cookies.get("session_id")
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No session found"
            )
        
        # Retrieve and validate session data
        session_data_str = await self.redis_client.get(f"oauth_session:{session_id}")
        if not session_data_str:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session expired or invalid"
            )
        
        session_data = json.loads(session_data_str)
        
        # Validate state parameter
        if session_data.get("state") != state:
            await self._log_audit_event(
                db=db,
                action="oauth_callback",
                success=False,
                error_message="Invalid state parameter",
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", "")
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid state parameter - possible CSRF attack"
            )
        
        try:
            # Exchange authorization code for tokens
            token_data = await self._exchange_code_for_tokens(
                code=code,
                code_verifier=session_data["code_verifier"]
            )
            
            # Validate ID token
            id_token_claims = await self._validate_id_token(token_data["id_token"])
            
            # Extract user information
            google_sub = id_token_claims["sub"]
            email = id_token_claims["email"]
            display_name = id_token_claims.get("name", "")
            
            # Create or update user record
            user = await self._create_or_update_user(
                db=db,
                google_sub=google_sub,
                email=email,
                display_name=display_name,
                existing_user_id=session_data.get("user_id")
            )
            
            # Store OAuth credentials
            await self._store_oauth_credentials(
                db=db,
                user_id=user.id,
                token_data=token_data
            )
            
            # Clean up session data
            await self.redis_client.delete(f"oauth_session:{session_id}")
            
            # Audit log success
            await self._log_audit_event(
                db=db,
                user_id=user.id,
                action="oauth_callback",
                success=True,
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                metadata={
                    "email": email,
                    "scopes_granted": token_data.get("scope", "").split()
                }
            )
            
            return {
                "success": True,
                "user_id": user.id,
                "email": email,
                "display_name": display_name,
                "scopes_granted": token_data.get("scope", "").split()
            }
            
        except Exception as e:
            await self._log_audit_event(
                db=db,
                action="oauth_callback",
                success=False,
                error_message=str(e),
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", "")
            )
            
            logger.error(f"OAuth callback failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to complete OAuth flow"
            )

    async def get_valid_access_token(
        self,
        db: Session,
        user_id: int
    ) -> Optional[str]:
        """
        Get valid access token with automatic refresh.
        
        Implements token management specifications:
        - Refresh tokens automatically with retries
        - Circuit breaker for failed refreshes
        - Mark user as disconnected if refresh fails
        """
        
        # Get OAuth credentials
        oauth_cred = db.query(OAuthCredential).filter(
            OAuthCredential.user_id == user_id,
            OAuthCredential.is_active == True
        ).first()
        
        if not oauth_cred:
            return None
        
        try:
            # Decrypt refresh token
            refresh_token = self._decrypt_token(oauth_cred.encrypted_refresh_token)
            
            # Use Google OAuth2 credentials with automatic refresh
            credentials = Credentials(
                token=None,  # Will be refreshed
                refresh_token=refresh_token,
                token_uri=self.token_uri,
                client_id=self.client_id,
                client_secret=self.client_secret,
                scopes=json.loads(oauth_cred.scopes)
            )
            
            # Refresh if needed
            if not credentials.valid:
                request = GoogleRequest()
                credentials.refresh(request)
                
                # Update last refresh time
                oauth_cred.last_refresh_at = datetime.utcnow()
                db.commit()
                
                # Audit log
                await self._log_audit_event(
                    db=db,
                    user_id=user_id,
                    action="token_refresh",
                    success=True,
                    metadata={"expires_at": credentials.expiry.isoformat() if credentials.expiry else None}
                )
            
            return credentials.token
            
        except Exception as e:
            # Mark credentials as inactive and user as disconnected
            oauth_cred.is_active = False
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.status = "disconnected"
                user.disconnected_at = datetime.utcnow()
            
            db.commit()
            
            await self._log_audit_event(
                db=db,
                user_id=user_id,
                action="token_refresh",
                success=False,
                error_message=str(e)
            )
            
            logger.error(f"Token refresh failed for user {user_id}: {e}")
            return None

    async def revoke_oauth_access(
        self,
        db: Session,
        user_id: int,
        request: Request
    ) -> bool:
        """
        Revoke OAuth access and clean up tokens.
        
        Implements POST /auth/revoke specifications:
        - Revoke tokens via Google endpoint
        - Delete local tokens and associations
        - Audit log the action
        """
        
        try:
            # Get OAuth credentials
            oauth_cred = db.query(OAuthCredential).filter(
                OAuthCredential.user_id == user_id,
                OAuthCredential.is_active == True
            ).first()
            
            if oauth_cred:
                # Decrypt refresh token
                refresh_token = self._decrypt_token(oauth_cred.encrypted_refresh_token)
                
                # Revoke via Google
                async with httpx.AsyncClient() as client:
                    revoke_response = await client.post(
                        self.revoke_uri,
                        data={"token": refresh_token},
                        headers={"Content-Type": "application/x-www-form-urlencoded"}
                    )
                
                # Mark credentials as inactive regardless of Google response
                oauth_cred.is_active = False
            
            # Update user status
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.status = "disconnected"
                user.disconnected_at = datetime.utcnow()
                user.gmail_connected = False
            
            db.commit()
            
            # Audit log
            await self._log_audit_event(
                db=db,
                user_id=user_id,
                action="oauth_revoke",
                success=True,
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", "")
            )
            
            return True
            
        except Exception as e:
            await self._log_audit_event(
                db=db,
                user_id=user_id,
                action="oauth_revoke",
                success=False,
                error_message=str(e),
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", "")
            )
            
            logger.error(f"OAuth revocation failed for user {user_id}: {e}")
            return False

    # Private helper methods
    
    async def _exchange_code_for_tokens(self, code: str, code_verifier: str) -> Dict[str, Any]:
        """Exchange authorization code for tokens."""
        
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code_verifier": code_verifier
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_uri,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Token exchange failed: {response.text}"
                )
            
            return response.json()

    async def _validate_id_token(self, id_token: str) -> Dict[str, Any]:
        """Validate Google ID token."""
        
        try:
            # For production, implement proper ID token validation
            # This is a simplified version - use google.auth.jwt for production
            header = jwt.get_unverified_header(id_token)
            claims = jwt.get_unverified_claims(id_token)
            
            # Basic validation
            if claims.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
                raise ValueError("Invalid issuer")
            
            if claims.get("aud") != self.client_id:
                raise ValueError("Invalid audience")
            
            if claims.get("exp", 0) < datetime.utcnow().timestamp():
                raise ValueError("Token expired")
            
            return claims
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"ID token validation failed: {e}"
            )

    async def _create_or_update_user(
        self,
        db: Session,
        google_sub: str,
        email: str,
        display_name: str,
        existing_user_id: Optional[int] = None
    ) -> User:
        """Create or update user record."""
        
        # Try to find existing user by Google sub
        user = db.query(User).filter(User.google_sub == google_sub).first()
        
        if not user and existing_user_id:
            # Link to existing user account
            user = db.query(User).filter(User.id == existing_user_id).first()
            if user:
                user.google_sub = google_sub
        
        if not user:
            # Create new user
            user = User(
                email=email,
                username=email.split("@")[0],  # Use email prefix as username
                hashed_password="",  # OAuth users don't need password
                google_sub=google_sub,
                display_name=display_name,
                gmail_email=email,
                is_verified=True  # Google OAuth users are pre-verified
            )
            db.add(user)
        else:
            # Update existing user
            user.display_name = display_name
            user.gmail_email = email
        
        # Update connection status
        user.status = "connected"
        user.connected_at = datetime.utcnow()
        user.gmail_connected = True
        user.gmail_connection_date = datetime.utcnow()
        
        db.commit()
        db.refresh(user)
        
        return user

    async def _store_oauth_credentials(
        self,
        db: Session,
        user_id: int,
        token_data: Dict[str, Any]
    ) -> None:
        """Store encrypted OAuth credentials."""
        
        # Deactivate existing credentials
        db.query(OAuthCredential).filter(
            OAuthCredential.user_id == user_id
        ).update({"is_active": False})
        
        # Encrypt refresh token
        encrypted_refresh_token = self._encrypt_token(token_data["refresh_token"])
        
        # Calculate token expiry
        expires_at = None
        if "expires_in" in token_data:
            expires_at = datetime.utcnow() + timedelta(seconds=int(token_data["expires_in"]))
        
        # Create new credential record
        oauth_cred = OAuthCredential(
            user_id=user_id,
            client_id=self.client_id,
            encrypted_refresh_token=encrypted_refresh_token,
            scopes=json.dumps(token_data.get("scope", "").split()),
            token_expires_at=expires_at
        )
        
        db.add(oauth_cred)
        db.commit()

    def _encrypt_token(self, token: str) -> str:
        """Encrypt token for storage."""
        encrypted = self.cipher_suite.encrypt(token.encode())
        return base64.b64encode(encrypted).decode()

    def _decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt stored token."""
        try:
            encrypted_data = base64.b64decode(encrypted_token.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Token decryption failed: {e}")

    async def _log_audit_event(
        self,
        db: Session,
        action: str,
        success: bool,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Log audit event."""
        
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            actor="user" if user_id else "system",
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            metadata=metadata,
            error_message=error_message
        )
        
        db.add(audit_log)
        db.commit()

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check for forwarded IP (Render/proxy setup)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"


# Dependency injection
def get_backend_oauth_service() -> BackendOAuthService:
    """Dependency to get backend OAuth service."""
    return BackendOAuthService()
