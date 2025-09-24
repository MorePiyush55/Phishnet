"""Production Gmail OAuth service with MongoDB persistence."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode

from app.config.settings import settings
from app.core.production_oauth_security import production_oauth_security_manager
from app.repositories.production_repositories import user_repository, audit_log_repository

logger = logging.getLogger(__name__)

class ProductionGmailOAuthService:
    """Production Gmail OAuth service with MongoDB persistence and enhanced security."""
    
    def __init__(self):
        self.oauth_security = production_oauth_security_manager
        self.base_auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_url = "https://oauth2.googleapis.com/token"
        self.revoke_url = "https://oauth2.googleapis.com/revoke"
        
        # Production OAuth scopes
        self.default_scopes = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ]
    
    async def generate_auth_url_production(
        self,
        user_id: str,
        scopes: Optional[List[str]] = None,
        ip_address: str = "unknown",
        user_agent: str = "unknown"
    ) -> Dict[str, Any]:
        """Generate OAuth authorization URL with production security."""
        try:
            # Log OAuth initiation
            await audit_log_repository.log_event({
                "event_type": "oauth_initiation",
                "user_id": user_id,
                "action": "generate_auth_url",
                "description": "User initiated Gmail OAuth flow",
                "ip_address": ip_address,
                "user_agent": user_agent,
                "metadata": {
                    "scopes": scopes or self.default_scopes,
                    "service": "gmail"
                }
            })
            
            # Use provided scopes or defaults
            oauth_scopes = scopes or self.default_scopes
            
            # Generate secure state with user context
            user_data = {
                "user_id": user_id,
                "ip_address": ip_address,
                "user_agent_hash": hash(user_agent),
                "scopes": oauth_scopes,
                "service": "gmail"
            }
            
            state_value, signed_state = self.oauth_security.generate_secure_state(user_data)
            
            # Store state in production persistence
            await self._store_oauth_state(
                state_value, 
                user_data, 
                ttl_seconds=600  # 10 minutes
            )
            
            # Generate PKCE challenge
            code_verifier = self._generate_code_verifier()
            code_challenge = self._generate_code_challenge(code_verifier)
            
            # Store PKCE verifier securely
            await self._store_pkce_verifier(state_value, code_verifier)
            
            # Build authorization URL
            auth_params = {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "scope": " ".join(oauth_scopes),
                "response_type": "code",
                "state": signed_state,
                "access_type": "offline",
                "prompt": "consent",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "include_granted_scopes": "true"
            }
            
            auth_url = f"{self.base_auth_url}?{urlencode(auth_params)}"
            
            logger.info(f"Production OAuth URL generated for user {user_id}")
            
            return {
                "auth_url": auth_url,
                "state": signed_state,
                "code_challenge": code_challenge,
                "expires_in": 600  # 10 minutes
            }
            
        except Exception as e:
            logger.error(f"Failed to generate production OAuth URL: {e}")
            
            # Log the error
            await audit_log_repository.log_event({
                "event_type": "oauth_error",
                "user_id": user_id,
                "action": "generate_auth_url_failed",
                "description": f"Failed to generate OAuth URL: {str(e)}",
                "ip_address": ip_address,
                "metadata": {"error": str(e)}
            })
            
            raise
    
    async def exchange_code_for_tokens_production(
        self,
        code: str,
        state: str,
        ip_address: str = "unknown",
        user_agent: str = "unknown"
    ) -> Dict[str, Any]:
        """Exchange authorization code for tokens with production security."""
        try:
            # Validate state parameter
            state_data = await self._validate_oauth_state(state, ip_address, user_agent)
            if not state_data:
                raise ValueError("Invalid or expired OAuth state")
            
            user_id = state_data["user_id"]
            
            # Get PKCE code verifier
            code_verifier = await self._get_pkce_verifier(state_data["state_value"])
            if not code_verifier:
                raise ValueError("PKCE code verifier not found or expired")
            
            # Exchange code for tokens
            import httpx
            
            token_data = {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "code_verifier": code_verifier
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(self.token_url, data=token_data)
                response.raise_for_status()
                tokens = response.json()
            
            # Validate token response
            if "access_token" not in tokens:
                raise ValueError("No access token in response")
            
            # Encrypt tokens for storage
            encrypted_tokens = await self.oauth_security.encrypt_token_advanced(tokens)
            
            # Update user with encrypted tokens
            token_expires_at = None
            if "expires_in" in tokens:
                token_expires_at = datetime.now(timezone.utc).timestamp() + tokens["expires_in"]
                token_expires_at = datetime.fromtimestamp(token_expires_at, timezone.utc)
            
            await user_repository.update_oauth_tokens(user_id, {
                "access_token": encrypted_tokens,
                "refresh_token": tokens.get("refresh_token"),
                "expires_at": token_expires_at
            })
            
            # Log successful token exchange
            await audit_log_repository.log_event({
                "event_type": "oauth_success",
                "user_id": user_id,
                "action": "tokens_exchanged",
                "description": "OAuth tokens successfully exchanged and stored",
                "ip_address": ip_address,
                "user_agent": user_agent,
                "metadata": {
                    "scopes": tokens.get("scope", "").split(),
                    "token_type": tokens.get("token_type"),
                    "expires_in": tokens.get("expires_in")
                }
            })
            
            # Clean up temporary data
            await self._cleanup_oauth_data(state_data["state_value"])
            
            logger.info(f"Production OAuth tokens exchanged for user {user_id}")
            
            return {
                "success": True,
                "user_id": user_id,
                "token_type": tokens.get("token_type", "Bearer"),
                "expires_in": tokens.get("expires_in"),
                "scope": tokens.get("scope", ""),
                "encrypted_storage": True
            }
            
        except Exception as e:
            logger.error(f"Failed to exchange OAuth code: {e}")
            
            # Log the error
            await audit_log_repository.log_event({
                "event_type": "oauth_error",
                "action": "token_exchange_failed",
                "description": f"Failed to exchange OAuth code: {str(e)}",
                "ip_address": ip_address,
                "metadata": {"error": str(e)}
            })
            
            raise
    
    async def refresh_access_token_production(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Refresh access token with production security."""
        try:
            # Get user with tokens
            user = await user_repository.get_by_id(user_id)
            if not user or not user.gmail_refresh_token:
                logger.warning(f"No refresh token found for user {user_id}")
                return None
            
            # Refresh token
            import httpx
            
            refresh_data = {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "refresh_token": user.gmail_refresh_token,
                "grant_type": "refresh_token"
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(self.token_url, data=refresh_data)
                response.raise_for_status()
                tokens = response.json()
            
            # Encrypt new tokens
            encrypted_tokens = await self.oauth_security.encrypt_token_advanced(tokens)
            
            # Update user tokens
            token_expires_at = None
            if "expires_in" in tokens:
                token_expires_at = datetime.now(timezone.utc).timestamp() + tokens["expires_in"]
                token_expires_at = datetime.fromtimestamp(token_expires_at, timezone.utc)
            
            await user_repository.update_oauth_tokens(user_id, {
                "access_token": encrypted_tokens,
                "expires_at": token_expires_at
            })
            
            # Log token refresh
            await audit_log_repository.log_event({
                "event_type": "oauth_refresh",
                "user_id": user_id,
                "action": "tokens_refreshed",
                "description": "OAuth tokens successfully refreshed",
                "metadata": {
                    "expires_in": tokens.get("expires_in"),
                    "token_type": tokens.get("token_type")
                }
            })
            
            logger.info(f"Production OAuth tokens refreshed for user {user_id}")
            
            return {
                "success": True,
                "expires_in": tokens.get("expires_in"),
                "token_type": tokens.get("token_type", "Bearer")
            }
            
        except Exception as e:
            logger.error(f"Failed to refresh OAuth tokens for user {user_id}: {e}")
            
            # Log the error
            await audit_log_repository.log_event({
                "event_type": "oauth_error",
                "user_id": user_id,
                "action": "token_refresh_failed",
                "description": f"Failed to refresh OAuth tokens: {str(e)}",
                "metadata": {"error": str(e)}
            })
            
            return None
    
    async def get_decrypted_tokens(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get decrypted OAuth tokens for API calls."""
        try:
            user = await user_repository.get_by_id(user_id)
            if not user or not user.gmail_access_token:
                return None
            
            # Check if token is expired
            if user.gmail_token_expires_at and user.gmail_token_expires_at < datetime.now(timezone.utc):
                # Try to refresh
                refresh_result = await self.refresh_access_token_production(user_id)
                if not refresh_result:
                    return None
                
                # Get updated user
                user = await user_repository.get_by_id(user_id)
            
            # Decrypt tokens
            decrypted_tokens = await self.oauth_security.decrypt_token_advanced(user.gmail_access_token)
            
            return decrypted_tokens
            
        except Exception as e:
            logger.error(f"Failed to get decrypted tokens for user {user_id}: {e}")
            return None
    
    async def revoke_tokens_production(self, user_id: str) -> bool:
        """Revoke OAuth tokens with production security."""
        try:
            # Get decrypted tokens
            tokens = await self.get_decrypted_tokens(user_id)
            if not tokens:
                return False
            
            # Revoke access token
            import httpx
            
            revoke_data = {"token": tokens["access_token"]}
            
            async with httpx.AsyncClient() as client:
                response = await client.post(self.revoke_url, data=revoke_data)
                # Google returns 200 even for already revoked tokens
            
            # Clear user tokens
            await user_repository.update_oauth_tokens(user_id, {
                "access_token": None,
                "refresh_token": None,
                "expires_at": None
            })
            
            # Log token revocation
            await audit_log_repository.log_event({
                "event_type": "oauth_revocation",
                "user_id": user_id,
                "action": "tokens_revoked",
                "description": "OAuth tokens successfully revoked",
                "metadata": {"revoked_at": datetime.now(timezone.utc).isoformat()}
            })
            
            logger.info(f"Production OAuth tokens revoked for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke OAuth tokens for user {user_id}: {e}")
            return False
    
    # Helper methods
    
    def _generate_code_verifier(self) -> str:
        """Generate PKCE code verifier."""
        import secrets
        import base64
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    def _generate_code_challenge(self, verifier: str) -> str:
        """Generate PKCE code challenge from verifier."""
        import hashlib
        import base64
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
    
    async def _store_oauth_state(self, state_key: str, state_data: Dict, ttl_seconds: int = 600):
        """Store OAuth state in production persistence."""
        try:
            from app.db.production_persistence import persistent_session_manager
            
            session_data = {
                "session_id": f"oauth_state:{state_key}",
                "user_id": state_data["user_id"],
                "data": state_data,
                "expires_at": datetime.now(timezone.utc).timestamp() + ttl_seconds,
                "type": "oauth_state"
            }
            
            await persistent_session_manager.store_session(session_data)
            
        except Exception as e:
            logger.error(f"Failed to store OAuth state: {e}")
            # Fallback to in-memory storage
            self.oauth_security.session_store[f"oauth_state:{state_key}"] = {
                "data": state_data,
                "expires_at": datetime.now(timezone.utc).timestamp() + ttl_seconds
            }
    
    async def _validate_oauth_state(self, signed_state: str, ip_address: str, user_agent: str) -> Optional[Dict]:
        """Validate OAuth state from production persistence."""
        try:
            # Split state and signature
            state_value, signature = signed_state.split('.', 1)
            
            # Validate state signature
            state_data = self.oauth_security.validate_state(state_value, signed_state)
            if not state_data:
                return None
            
            # Additional validations
            if state_data.get("ip_address") != ip_address:
                logger.warning("IP address mismatch in OAuth state validation")
                return None
            
            # Get stored state data
            try:
                from app.db.production_persistence import persistent_session_manager
                stored_data = await persistent_session_manager.get_session(f"oauth_state:{state_value}")
                
                if stored_data and stored_data.get("data"):
                    state_data.update(stored_data["data"])
                    state_data["state_value"] = state_value
                    return state_data
            except:
                # Fallback to in-memory
                stored_entry = self.oauth_security.session_store.get(f"oauth_state:{state_value}")
                if stored_entry and stored_entry.get("data"):
                    state_data.update(stored_entry["data"])
                    state_data["state_value"] = state_value
                    return state_data
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to validate OAuth state: {e}")
            return None
    
    async def _store_pkce_verifier(self, state_key: str, verifier: str):
        """Store PKCE code verifier."""
        try:
            from app.db.production_persistence import persistent_session_manager
            
            session_data = {
                "session_id": f"pkce_verifier:{state_key}",
                "data": {"verifier": verifier},
                "expires_at": datetime.now(timezone.utc).timestamp() + 600,  # 10 minutes
                "type": "pkce_verifier"
            }
            
            await persistent_session_manager.store_session(session_data)
            
        except Exception as e:
            logger.error(f"Failed to store PKCE verifier: {e}")
            # Fallback to in-memory
            self.oauth_security.session_store[f"pkce_verifier:{state_key}"] = {
                "verifier": verifier,
                "expires_at": datetime.now(timezone.utc).timestamp() + 600
            }
    
    async def _get_pkce_verifier(self, state_key: str) -> Optional[str]:
        """Get PKCE code verifier."""
        try:
            from app.db.production_persistence import persistent_session_manager
            stored_data = await persistent_session_manager.get_session(f"pkce_verifier:{state_key}")
            
            if stored_data and stored_data.get("data"):
                return stored_data["data"].get("verifier")
                
        except:
            # Fallback to in-memory
            stored_entry = self.oauth_security.session_store.get(f"pkce_verifier:{state_key}")
            if stored_entry:
                return stored_entry.get("verifier")
        
        return None
    
    async def _cleanup_oauth_data(self, state_key: str):
        """Clean up temporary OAuth data."""
        try:
            from app.db.production_persistence import persistent_session_manager
            
            # Clean up state and PKCE data
            await persistent_session_manager.delete_session(f"oauth_state:{state_key}")
            await persistent_session_manager.delete_session(f"pkce_verifier:{state_key}")
            
        except:
            # Fallback cleanup
            self.oauth_security.session_store.pop(f"oauth_state:{state_key}", None)
            self.oauth_security.session_store.pop(f"pkce_verifier:{state_key}", None)


# Global instance for production use
production_gmail_oauth_service = ProductionGmailOAuthService()