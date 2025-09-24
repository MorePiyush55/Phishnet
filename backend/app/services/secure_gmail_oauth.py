"""Enhanced OAuth service integration with hardened security."""

import asyncio
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from fastapi import HTTPException, status
import logging

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.oauth_security_hardened import oauth_security_manager

logger = get_logger(__name__)

class SecureGmailOAuthService:
    """Enhanced Gmail OAuth service with comprehensive security hardening."""
    
    # Required scopes with principle of least privilege
    MINIMAL_SCOPES = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/userinfo.email"
    ]
    
    ENHANCED_SCOPES = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",  # For quarantine
        "https://www.googleapis.com/auth/userinfo.email"
    ]
    
    def __init__(self):
        """Initialize secure OAuth service."""
        self.client_id = settings.GMAIL_CLIENT_ID
        self.client_secret = settings.GMAIL_CLIENT_SECRET
        self.redirect_uri = settings.GMAIL_REDIRECT_URI
        
        if not all([self.client_id, self.client_secret, self.redirect_uri]):
            raise ValueError("Gmail OAuth credentials not properly configured")
    
    async def create_authorization_url(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str,
        scope_level: str = "minimal"
    ) -> Tuple[str, str]:
        """Create secure authorization URL with PKCE and enhanced state management."""
        
        # Select appropriate scopes
        scopes = self.MINIMAL_SCOPES if scope_level == "minimal" else self.ENHANCED_SCOPES
        
        # Generate PKCE parameters
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')
        
        # Create secure state with additional context
        user_data = {
            "user_id": user_id,
            "ip_address": hashlib.sha256(ip_address.encode()).hexdigest(),  # Hash for privacy
            "user_agent_hash": hashlib.sha256(user_agent.encode()).hexdigest(),
            "scope_level": scope_level,
            "code_verifier": code_verifier,
            "initiated_at": datetime.utcnow().isoformat()
        }
        
        state_value, signed_state = oauth_security_manager.generate_secure_state(user_data)
        
        # Store state securely
        await self._store_oauth_state(state_value, user_data, ttl_seconds=600)  # 10 minutes
        
        # Create OAuth flow
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [self.redirect_uri]
                }
            },
            scopes=scopes
        )
        flow.redirect_uri = self.redirect_uri
        
        # Generate authorization URL with PKCE
        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            state=state_value,
            code_challenge=code_challenge,
            code_challenge_method='S256',
            prompt='consent'  # Force consent to ensure refresh token
        )
        
        return authorization_url, state_value
    
    async def handle_oauth_callback(
        self,
        code: str,
        state: str,
        ip_address: str,
        user_agent: str
    ) -> Dict[str, Any]:
        """Handle OAuth callback with enhanced security validation."""
        
        # Retrieve and validate state
        state_data = await self._get_oauth_state(state)
        if not state_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OAuth state"
            )
        
        # Validate IP and User-Agent consistency
        ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
        ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()
        
        if (state_data.get("ip_address") != ip_hash or 
            state_data.get("user_agent_hash") != ua_hash):
            logger.warning(f"OAuth callback security violation: IP/UA mismatch")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security validation failed"
            )
        
        # Validate timing
        initiated_at = datetime.fromisoformat(state_data.get("initiated_at"))
        if (datetime.utcnow() - initiated_at).total_seconds() > 600:  # 10 minutes max
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OAuth flow expired"
            )
        
        # Exchange code for tokens with PKCE
        code_verifier = state_data.get("code_verifier")
        if not code_verifier:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing PKCE code verifier"
            )
        
        # Create flow for token exchange
        scopes = (self.MINIMAL_SCOPES if state_data.get("scope_level") == "minimal" 
                 else self.ENHANCED_SCOPES)
        
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [self.redirect_uri]
                }
            },
            scopes=scopes
        )
        flow.redirect_uri = self.redirect_uri
        
        # Fetch tokens
        try:
            flow.fetch_token(
                authorization_response=f"{self.redirect_uri}?code={code}&state={state}",
                code_verifier=code_verifier
            )
        except Exception as e:
            logger.error(f"Token exchange failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to exchange authorization code"
            )
        
        credentials = flow.credentials
        
        # Get user info
        user_info = await self._get_user_info(credentials)
        
        # Encrypt and store tokens
        encrypted_tokens = oauth_security_manager.encrypt_token_advanced({
            "access_token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes,
            "expiry": credentials.expiry.isoformat() if credentials.expiry else None
        })
        
        # Clean up state
        await self._delete_oauth_state(state)
        
        return {
            "success": True,
            "user_info": user_info,
            "encrypted_tokens": encrypted_tokens,
            "scopes_granted": credentials.scopes,
            "expires_at": credentials.expiry.isoformat() if credentials.expiry else None
        }
    
    async def refresh_access_token(self, encrypted_tokens: str) -> Dict[str, Any]:
        """Refresh access token with enhanced security."""
        
        try:
            # Decrypt tokens
            token_data = oauth_security_manager.decrypt_token_advanced(encrypted_tokens)
            
            # Create credentials object
            credentials = Credentials(
                token=token_data.get("access_token"),
                refresh_token=token_data.get("refresh_token"),
                token_uri=token_data.get("token_uri"),
                client_id=token_data.get("client_id"),
                client_secret=token_data.get("client_secret"),
                scopes=token_data.get("scopes")
            )
            
            # Refresh token
            request = Request()
            credentials.refresh(request)
            
            # Re-encrypt updated tokens
            new_encrypted_tokens = oauth_security_manager.encrypt_token_advanced({
                "access_token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": credentials.scopes,
                "expiry": credentials.expiry.isoformat() if credentials.expiry else None
            })
            
            return {
                "success": True,
                "encrypted_tokens": new_encrypted_tokens,
                "expires_at": credentials.expiry.isoformat() if credentials.expiry else None
            }
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to refresh access token"
            )
    
    async def revoke_tokens(self, encrypted_tokens: str) -> bool:
        """Securely revoke OAuth tokens."""
        
        try:
            # Decrypt tokens
            token_data = oauth_security_manager.decrypt_token_advanced(encrypted_tokens)
            
            # Revoke tokens with Google
            import httpx
            
            async with httpx.AsyncClient() as client:
                # Revoke refresh token
                if token_data.get("refresh_token"):
                    revoke_response = await client.post(
                        "https://oauth2.googleapis.com/revoke",
                        params={"token": token_data["refresh_token"]}
                    )
                    
                # Revoke access token
                if token_data.get("access_token"):
                    revoke_response = await client.post(
                        "https://oauth2.googleapis.com/revoke",
                        params={"token": token_data["access_token"]}
                    )
            
            return True
            
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False
    
    async def validate_token_security(self, encrypted_tokens: str) -> Dict[str, Any]:
        """Validate token security and integrity."""
        
        try:
            # Decrypt and validate tokens
            token_data = oauth_security_manager.decrypt_token_advanced(encrypted_tokens)
            
            # Check token expiry
            expiry_str = token_data.get("expiry")
            if expiry_str:
                expiry = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                time_until_expiry = (expiry - datetime.utcnow()).total_seconds()
                
                if time_until_expiry <= 0:
                    return {"valid": False, "reason": "Token expired"}
                
                if time_until_expiry <= 300:  # 5 minutes
                    return {"valid": True, "needs_refresh": True, "expires_in": time_until_expiry}
            
            # Validate required fields
            required_fields = ["access_token", "refresh_token", "scopes"]
            missing_fields = [field for field in required_fields if not token_data.get(field)]
            
            if missing_fields:
                return {"valid": False, "reason": f"Missing fields: {missing_fields}"}
            
            return {"valid": True, "needs_refresh": False}
            
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return {"valid": False, "reason": "Token validation failed"}
    
    async def _get_user_info(self, credentials: Credentials) -> Dict[str, Any]:
        """Get user information from Google API."""
        
        try:
            service = build('oauth2', 'v2', credentials=credentials)
            user_info = service.userinfo().get().execute()
            
            return {
                "email": user_info.get("email"),
                "name": user_info.get("name"),
                "picture": user_info.get("picture"),
                "verified_email": user_info.get("verified_email", False)
            }
            
        except Exception as e:
            logger.error(f"Failed to get user info: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve user information"
            )
    
    async def _store_oauth_state(self, state_key: str, state_data: Dict, ttl_seconds: int = 600):
        """Store OAuth state securely in memory."""
        # This is simplified for demonstration
        # In production, use encrypted Redis or database storage
        oauth_security_manager.session_store[f"oauth_state:{state_key}"] = {
            "data": state_data,
            "expires_at": datetime.utcnow() + timedelta(seconds=ttl_seconds)
        }
    
    async def _get_oauth_state(self, state_key: str) -> Optional[Dict]:
        """Retrieve OAuth state from secure storage."""
        state_entry = oauth_security_manager.session_store.get(f"oauth_state:{state_key}")
        
        if not state_entry:
            return None
        
        if datetime.utcnow() > state_entry["expires_at"]:
            # Clean up expired state
            del oauth_security_manager.session_store[f"oauth_state:{state_key}"]
            return None
        
        return state_entry["data"]
    
    async def _delete_oauth_state(self, state_key: str):
        """Delete OAuth state from secure storage."""
        if f"oauth_state:{state_key}" in oauth_security_manager.session_store:
            del oauth_security_manager.session_store[f"oauth_state:{state_key}"]

# Global service instance
secure_gmail_oauth_service = SecureGmailOAuthService()