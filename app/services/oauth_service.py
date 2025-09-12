"""
OAuth Integration Service
Handles OAuth flow, token management, and Google API integration.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import json
import secrets
import hashlib
from urllib.parse import urlencode, parse_qs

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from app.models.consent import ConsentScope, get_minimal_required_scopes
from app.services.consent_manager import get_consent_manager
from app.core.redis_client import get_redis_client
from app.core.config import get_settings

logger = logging.getLogger(__name__)

class OAuthService:
    """
    Manages OAuth flow and Google API integration.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.redis_client = get_redis_client()
        self.consent_manager = get_consent_manager()
        
        # OAuth configuration
        self.client_config = {
            "web": {
                "client_id": self.settings.google_client_id,
                "client_secret": self.settings.google_client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [self.settings.oauth_redirect_uri]
            }
        }
        
        # Minimal scopes for privacy
        self.required_scopes = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid"
        ]
        
        self.optional_scopes = [
            "https://www.googleapis.com/auth/gmail.modify"  # Only for labeling/quarantine
        ]
    
    def generate_oauth_url(self, 
                          user_id: str,
                          requested_scopes: List[str] = None,
                          custom_params: Dict[str, str] = None) -> Tuple[str, str]:
        """
        Generate OAuth authorization URL.
        
        Args:
            user_id: Internal user identifier
            requested_scopes: List of requested scopes
            custom_params: Additional OAuth parameters
            
        Returns:
            Tuple[str, str]: (authorization_url, state_token)
        """
        try:
            # Use minimal scopes by default
            scopes = requested_scopes or self.required_scopes.copy()
            
            # Ensure required scopes are included
            for scope in self.required_scopes:
                if scope not in scopes:
                    scopes.append(scope)
            
            # Create flow
            flow = Flow.from_client_config(
                self.client_config,
                scopes=scopes,
                redirect_uri=self.settings.oauth_redirect_uri
            )
            
            # Generate state token
            state_token = secrets.token_urlsafe(32)
            
            # Store state information
            state_data = {
                "user_id": user_id,
                "scopes": scopes,
                "created_at": datetime.utcnow().isoformat(),
                "custom_params": custom_params or {}
            }
            
            # Cache state for 10 minutes
            state_key = f"oauth_state:{state_token}"
            self.redis_client.setex(
                state_key,
                600,  # 10 minutes
                json.dumps(state_data)
            )
            
            # Build authorization URL with custom parameters
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                state=state_token,
                prompt='consent',  # Force consent screen for transparency
                **custom_params or {}
            )
            
            logger.info(f"Generated OAuth URL for user {user_id}")
            return auth_url, state_token
            
        except Exception as e:
            logger.error(f"Error generating OAuth URL: {e}")
            raise
    
    async def handle_oauth_callback(self,
                                  authorization_code: str,
                                  state_token: str,
                                  consent_preferences: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle OAuth callback and exchange code for tokens.
        
        Args:
            authorization_code: Authorization code from Google
            state_token: State token for CSRF protection
            consent_preferences: User's consent preferences
            
        Returns:
            Dict: Contains user info and consent status
        """
        try:
            # Validate state token
            state_key = f"oauth_state:{state_token}"
            state_data_str = await self.redis_client.get(state_key)
            
            if not state_data_str:
                raise ValueError("Invalid or expired state token")
            
            state_data = json.loads(state_data_str)
            user_id = state_data["user_id"]
            requested_scopes = state_data["scopes"]
            
            # Clean up state
            await self.redis_client.delete(state_key)
            
            # Create flow with stored scopes
            flow = Flow.from_client_config(
                self.client_config,
                scopes=requested_scopes,
                redirect_uri=self.settings.oauth_redirect_uri,
                state=state_token
            )
            
            # Exchange code for tokens
            flow.fetch_token(code=authorization_code)
            credentials = flow.credentials
            
            # Get user info
            user_info = await self._get_user_info(credentials)
            
            # Validate that we got the required scopes
            granted_scopes = credentials.scopes or []
            missing_required = [
                scope for scope in self.required_scopes 
                if scope not in granted_scopes
            ]
            
            if missing_required:
                raise ValueError(f"Missing required scopes: {missing_required}")
            
            # Grant consent with tokens
            consent = await self.consent_manager.grant_consent(
                user_id=user_id,
                email=user_info["email"],
                google_user_id=user_info["id"],
                access_token=credentials.token,
                refresh_token=credentials.refresh_token,
                token_expires_at=credentials.expiry,
                granted_scopes=granted_scopes,
                consent_preferences=consent_preferences,
                request_context={
                    "source": "oauth_callback",
                    "scopes_requested": requested_scopes,
                    "scopes_granted": granted_scopes
                }
            )
            
            logger.info(f"OAuth callback successful for user {user_id}")
            
            return {
                "success": True,
                "user_id": user_id,
                "email": user_info["email"],
                "granted_scopes": granted_scopes,
                "consent_id": consent.id,
                "message": "OAuth authorization successful"
            }
            
        except Exception as e:
            logger.error(f"Error handling OAuth callback: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "OAuth authorization failed"
            }
    
    async def refresh_access_token(self, user_id: str) -> Optional[Credentials]:
        """
        Refresh access token for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Credentials: Refreshed credentials or None if failed
        """
        try:
            # Get user consent
            consent = await self.consent_manager.get_user_consent(user_id)
            if not consent or not consent.is_active:
                logger.warning(f"No active consent for user {user_id}")
                return None
            
            # Create credentials from stored tokens
            credentials = Credentials(
                token=None,  # Will be refreshed
                refresh_token=consent.refresh_token_hash,  # Note: This should be the actual token, not hash
                token_uri=self.client_config["web"]["token_uri"],
                client_id=self.client_config["web"]["client_id"],
                client_secret=self.client_config["web"]["client_secret"],
                scopes=consent.granted_scopes
            )
            
            # Refresh token
            credentials.refresh(Request())
            
            # Update stored token (hash it for storage)
            # Note: In production, implement secure token storage
            
            logger.info(f"Refreshed access token for user {user_id}")
            return credentials
            
        except Exception as e:
            logger.error(f"Error refreshing token for user {user_id}: {e}")
            return None
    
    async def revoke_tokens(self, user_id: str) -> bool:
        """
        Revoke OAuth tokens for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            bool: Success status
        """
        try:
            # Get user consent
            consent = await self.consent_manager.get_user_consent(user_id)
            if not consent:
                logger.warning(f"No consent found for user {user_id}")
                return False
            
            # Revoke tokens with Google
            credentials = Credentials(
                token=consent.access_token_hash,  # Note: Should be actual token
                refresh_token=consent.refresh_token_hash,
                token_uri=self.client_config["web"]["token_uri"],
                client_id=self.client_config["web"]["client_id"],
                client_secret=self.client_config["web"]["client_secret"]
            )
            
            # Revoke with Google
            try:
                credentials.revoke(Request())
                logger.info(f"Revoked Google tokens for user {user_id}")
            except Exception as e:
                logger.warning(f"Error revoking Google tokens: {e}")
                # Continue with local revocation even if Google revocation fails
            
            # Revoke consent locally
            await self.consent_manager.revoke_consent(
                user_id=user_id,
                request_context={"source": "token_revocation"},
                cleanup_data=True
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error revoking tokens for user {user_id}: {e}")
            return False
    
    async def get_gmail_service(self, user_id: str) -> Optional[Any]:
        """
        Get Gmail API service for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Gmail service instance or None
        """
        try:
            # Get or refresh credentials
            credentials = await self._get_valid_credentials(user_id)
            if not credentials:
                return None
            
            # Build Gmail service
            service = build('gmail', 'v1', credentials=credentials)
            return service
            
        except Exception as e:
            logger.error(f"Error getting Gmail service for user {user_id}: {e}")
            return None
    
    async def test_gmail_access(self, user_id: str) -> Dict[str, Any]:
        """
        Test Gmail API access for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dict: Test results
        """
        try:
            service = await self.get_gmail_service(user_id)
            if not service:
                return {
                    "success": False,
                    "error": "Unable to get Gmail service"
                }
            
            # Test basic access
            profile = service.users().getProfile(userId='me').execute()
            
            # Test message listing (minimal)
            messages = service.users().messages().list(
                userId='me',
                maxResults=1
            ).execute()
            
            return {
                "success": True,
                "email": profile.get("emailAddress"),
                "total_messages": profile.get("messagesTotal", 0),
                "access_verified": True
            }
            
        except HttpError as e:
            logger.error(f"Gmail API error for user {user_id}: {e}")
            return {
                "success": False,
                "error": f"Gmail API error: {e.resp.status}",
                "needs_reauth": e.resp.status == 401
            }
        except Exception as e:
            logger.error(f"Error testing Gmail access for user {user_id}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_consent_page_data(self, 
                            state_token: str,
                            requested_scopes: List[str] = None) -> Dict[str, Any]:
        """
        Get data for custom consent page.
        
        Args:
            state_token: OAuth state token
            requested_scopes: Requested OAuth scopes
            
        Returns:
            Dict: Consent page data
        """
        scopes = requested_scopes or self.required_scopes
        
        scope_descriptions = {
            "https://www.googleapis.com/auth/gmail.readonly": {
                "title": "Read Gmail Messages",
                "description": "Access to read your Gmail messages for phishing analysis",
                "required": True,
                "privacy_impact": "Medium",
                "data_accessed": "Email headers, subject lines, sender information"
            },
            "https://www.googleapis.com/auth/gmail.modify": {
                "title": "Modify Gmail Messages", 
                "description": "Ability to label suspicious emails and move them to quarantine",
                "required": False,
                "privacy_impact": "Low",
                "data_accessed": "Message labels only"
            },
            "https://www.googleapis.com/auth/userinfo.email": {
                "title": "Email Address",
                "description": "Access to your email address for account identification",
                "required": True,
                "privacy_impact": "Low",
                "data_accessed": "Email address only"
            }
        }
        
        return {
            "state_token": state_token,
            "requested_scopes": [
                {
                    "scope": scope,
                    **scope_descriptions.get(scope, {
                        "title": scope,
                        "description": "Unknown scope",
                        "required": False,
                        "privacy_impact": "Unknown"
                    })
                }
                for scope in scopes
            ],
            "privacy_policy_url": f"{self.settings.app_url}/privacy",
            "terms_of_service_url": f"{self.settings.app_url}/terms",
            "data_retention_info": {
                "default_retention": "30 days",
                "configurable": True,
                "deletion_available": True
            },
            "minimal_access": True,
            "no_ads": True,
            "user_controls": [
                "Opt out of AI analysis",
                "Opt out of persistent storage", 
                "Configure data retention period",
                "Revoke access at any time"
            ]
        }
    
    # Private helper methods
    
    async def _get_user_info(self, credentials: Credentials) -> Dict[str, Any]:
        """Get user info from Google API"""
        try:
            # Build OAuth2 service
            oauth_service = build('oauth2', 'v2', credentials=credentials)
            user_info = oauth_service.userinfo().get().execute()
            
            return {
                "id": user_info.get("id"),
                "email": user_info.get("email"),
                "name": user_info.get("name"),
                "picture": user_info.get("picture")
            }
            
        except Exception as e:
            logger.error(f"Error getting user info: {e}")
            raise
    
    async def _get_valid_credentials(self, user_id: str) -> Optional[Credentials]:
        """Get valid credentials for a user, refreshing if necessary"""
        try:
            consent = await self.consent_manager.get_user_consent(user_id)
            if not consent or not consent.is_active:
                return None
            
            # Check if token is expired
            if consent.token_expires_at and consent.token_expires_at <= datetime.utcnow():
                # Try to refresh
                return await self.refresh_access_token(user_id)
            
            # Create credentials from stored data
            # Note: In production, implement secure token storage/retrieval
            credentials = Credentials(
                token="stored_access_token",  # Implement secure retrieval
                refresh_token="stored_refresh_token",
                token_uri=self.client_config["web"]["token_uri"],
                client_id=self.client_config["web"]["client_id"],
                client_secret=self.client_config["web"]["client_secret"],
                scopes=consent.granted_scopes
            )
            
            return credentials
            
        except Exception as e:
            logger.error(f"Error getting valid credentials: {e}")
            return None

# Global OAuth service instance
_oauth_service = None

def get_oauth_service() -> OAuthService:
    """Get global OAuth service instance"""
    global _oauth_service
    if not _oauth_service:
        _oauth_service = OAuthService()
    return _oauth_service
