"""Production-grade Gmail OAuth2 service with comprehensive security and audit logging."""

import base64
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import logging
from urllib.parse import urlencode, parse_qs

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
import httpx
from google.cloud import pubsub_v1
import asyncio

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db
from app.models.user import User, OAuthToken, OAuthAuditLog
from app.core.redis_client import redis_client

logger = get_logger(__name__)


class GmailOAuth2Service:
    """Production-ready Gmail OAuth2 service with comprehensive security."""
    
    # Gmail API scopes for phishing analysis
    REQUIRED_SCOPES = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/userinfo.email"
    ]
    
    SCOPE_DESCRIPTIONS = {
        "https://www.googleapis.com/auth/gmail.readonly": "Read your email messages and metadata",
        "https://www.googleapis.com/auth/gmail.modify": "Label and quarantine suspicious emails",
        "https://www.googleapis.com/auth/userinfo.email": "Access your email address for verification"
    }
    
    def __init__(self):
        """Initialize OAuth service with encryption and security."""
        self.client_id = settings.GMAIL_CLIENT_ID
        self.client_secret = settings.GMAIL_CLIENT_SECRET
        self.redirect_uri = settings.GMAIL_REDIRECT_URI
        
        # Initialize encryption
        self.encryption_key = self._get_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
    def _get_encryption_key(self) -> bytes:
        """Get or generate encryption key for OAuth tokens."""
        key = settings.ENCRYPTION_KEY.encode()
        if len(key) != 32:
            return hashlib.sha256(key).digest()
        return key
    
    def _encrypt_token(self, token_data: str) -> str:
        """Encrypt OAuth token for secure storage."""
        try:
            encrypted = self.cipher_suite.encrypt(token_data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token encryption failed"
            )
    
    def _decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt stored OAuth token."""
        try:
            encrypted_data = base64.b64decode(encrypted_token.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token decryption failed"
            )
    
    async def _log_oauth_event(
        self,
        db: Session,
        user_id: int,
        event_type: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """Log OAuth-related events for audit trail."""
        try:
            audit_log = OAuthAuditLog(
                user_id=user_id,
                event_type=event_type,
                provider="gmail",
                details=json.dumps(details) if details else None,
                ip_address=ip_address,
                user_agent=user_agent,
                success=success,
                error_message=error_message
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            logger.error(f"Failed to log OAuth event: {e}")
            # Don't raise exception for logging failures
    
    async def generate_oauth_url(
        self,
        db: Session,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[str, str]:
        """Generate OAuth authorization URL with PKCE and state validation."""
        try:
            # Generate PKCE code verifier and challenge
            code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode('utf-8').rstrip('=')
            
            # Generate secure state parameter
            state_data = {
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat(),
                "nonce": secrets.token_urlsafe(16),
                "code_verifier": code_verifier
            }
            state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()
            
            # Store state in Redis with expiration
            await redis_client.setex(
                f"oauth_state:{user_id}:{state_data['nonce']}",
                600,  # 10 minutes
                json.dumps(state_data)
            )
            
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
                scopes=self.REQUIRED_SCOPES
            )
            flow.redirect_uri = self.redirect_uri
            
            # Generate authorization URL with PKCE
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='false',
                state=state,
                prompt='consent',  # Force consent screen
                code_challenge=code_challenge,
                code_challenge_method='S256'
            )
            
            await self._log_oauth_event(
                db, user_id, "oauth_url_generated", True,
                details={"scopes": self.REQUIRED_SCOPES},
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            logger.info(f"Generated OAuth URL for user {user_id}")
            return auth_url, state_data['nonce']
            
        except Exception as e:
            logger.error(f"Failed to generate OAuth URL: {e}")
            await self._log_oauth_event(
                db, user_id, "oauth_url_generation_failed", False,
                error_message=str(e),
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate OAuth URL"
            )
    
    async def handle_oauth_callback(
        self,
        db: Session,
        user_id: int,
        authorization_code: str,
        state: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """Handle OAuth callback with comprehensive validation."""
        try:
            # Decode and validate state
            try:
                state_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
            except Exception as e:
                logger.error(f"Invalid state parameter: {e}")
                await self._log_oauth_event(
                    db, user_id, "oauth_callback_invalid_state", False,
                    error_message="Invalid state parameter",
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid state parameter"
                )
            
            # Validate user ID
            if state_data.get("user_id") != user_id:
                logger.error(f"User ID mismatch in state: {state_data.get('user_id')} != {user_id}")
                await self._log_oauth_event(
                    db, user_id, "oauth_callback_user_mismatch", False,
                    error_message="User ID mismatch",
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid request"
                )
            
            # Validate state freshness (not older than 10 minutes)
            state_time = datetime.fromisoformat(state_data["timestamp"])
            if datetime.utcnow() - state_time > timedelta(minutes=10):
                logger.error(f"Expired state for user {user_id}")
                await self._log_oauth_event(
                    db, user_id, "oauth_callback_expired_state", False,
                    error_message="State expired",
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Authorization request expired"
                )
            
            # Validate stored state in Redis
            nonce = state_data.get("nonce")
            stored_state = await redis_client.get(f"oauth_state:{user_id}:{nonce}")
            if not stored_state:
                logger.error(f"State not found in Redis for user {user_id}")
                await self._log_oauth_event(
                    db, user_id, "oauth_callback_state_not_found", False,
                    error_message="State not found",
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired authorization request"
                )
            
            # Clean up state from Redis
            await redis_client.delete(f"oauth_state:{user_id}:{nonce}")
            
            # Exchange authorization code for tokens
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
                scopes=self.REQUIRED_SCOPES
            )
            flow.redirect_uri = self.redirect_uri
            
            # Get tokens with PKCE
            code_verifier = state_data.get("code_verifier")
            if not code_verifier:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Missing code verifier"
                )
            
            flow.fetch_token(
                code=authorization_code,
                code_verifier=code_verifier
            )
            credentials = flow.credentials
            
            # Validate token by making test API call
            user_email = await self._validate_credentials(credentials)
            
            # Store encrypted tokens
            await self._store_oauth_tokens(db, user_id, credentials, user_email, ip_address, user_agent)
            
            await self._log_oauth_event(
                db, user_id, "oauth_connection_successful", True,
                details={
                    "gmail_email": user_email,
                    "scopes": credentials.granted_scopes or self.REQUIRED_SCOPES
                },
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            logger.info(f"OAuth connection successful for user {user_id}, Gmail: {user_email}")
            
            return {
                "success": True,
                "gmail_email": user_email,
                "scopes_granted": credentials.granted_scopes or self.REQUIRED_SCOPES,
                "connection_date": datetime.utcnow().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"OAuth callback failed for user {user_id}: {e}")
            await self._log_oauth_event(
                db, user_id, "oauth_callback_failed", False,
                error_message=str(e),
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="OAuth callback processing failed"
            )
    
    async def _validate_credentials(self, credentials: Credentials) -> str:
        """Validate OAuth credentials and return user email."""
        try:
            # Build Gmail service and test connection
            service = build('gmail', 'v1', credentials=credentials)
            profile = service.users().getProfile(userId='me').execute()
            
            return profile.get('emailAddress')
            
        except Exception as e:
            logger.error(f"Failed to validate OAuth credentials: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to validate Gmail access"
            )
    
    async def _store_oauth_tokens(
        self,
        db: Session,
        user_id: int,
        credentials: Credentials,
        gmail_email: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """Store encrypted OAuth tokens and update user record."""
        try:
            # Deactivate existing tokens for this user/provider
            existing_tokens = db.query(OAuthToken).filter(
                OAuthToken.user_id == user_id,
                OAuthToken.provider == "gmail",
                OAuthToken.is_active == True
            ).all()
            
            for token in existing_tokens:
                token.is_active = False
                token.revoked_at = datetime.utcnow()
                token.revocation_reason = "Replaced by new token"
            
            # Encrypt and store new tokens
            refresh_token_encrypted = self._encrypt_token(credentials.refresh_token) if credentials.refresh_token else None
            access_token_encrypted = self._encrypt_token(credentials.token) if credentials.token else None
            
            new_token = OAuthToken(
                user_id=user_id,
                provider="gmail",
                encrypted_refresh_token=refresh_token_encrypted,
                encrypted_access_token=access_token_encrypted,
                token_expires_at=credentials.expiry,
                scope=json.dumps(credentials.granted_scopes or self.REQUIRED_SCOPES),
                creation_ip=ip_address,
                creation_user_agent=user_agent,
                is_active=True
            )
            db.add(new_token)
            
            # Update user record
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.gmail_connected = True
                user.gmail_email = gmail_email
                user.gmail_scopes_granted = json.dumps(credentials.granted_scopes or self.REQUIRED_SCOPES)
                user.gmail_connection_date = datetime.utcnow()
                user.gmail_status = "connected"
                user.email_monitoring_enabled = True
            
            db.commit()
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to store OAuth tokens: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store OAuth tokens"
            )
    
    async def get_oauth_status(self, db: Session, user_id: int) -> Dict[str, Any]:
        """Get OAuth connection status for user."""
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Get active token
            active_token = db.query(OAuthToken).filter(
                OAuthToken.user_id == user_id,
                OAuthToken.provider == "gmail",
                OAuthToken.is_active == True
            ).first()
            
            if not active_token or not user.gmail_connected:
                return {
                    "connected": False,
                    "status": "disconnected",
                    "gmail_email": None,
                    "scopes_granted": [],
                    "connection_date": None,
                    "last_scan": user.last_email_scan.isoformat() if user.last_email_scan else None
                }
            
            return {
                "connected": True,
                "status": user.gmail_status,
                "gmail_email": user.gmail_email,
                "scopes_granted": json.loads(user.gmail_scopes_granted) if user.gmail_scopes_granted else [],
                "connection_date": user.gmail_connection_date.isoformat() if user.gmail_connection_date else None,
                "last_scan": user.last_email_scan.isoformat() if user.last_email_scan else None,
                "last_token_refresh": user.gmail_last_token_refresh.isoformat() if user.gmail_last_token_refresh else None,
                "monitoring_enabled": user.email_monitoring_enabled
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to get OAuth status: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get OAuth status"
            )
    
    async def revoke_oauth_access(
        self,
        db: Session,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """Revoke OAuth access and clean up tokens."""
        try:
            # Get active tokens
            active_tokens = db.query(OAuthToken).filter(
                OAuthToken.user_id == user_id,
                OAuthToken.provider == "gmail",
                OAuthToken.is_active == True
            ).all()
            
            if not active_tokens:
                return {"success": True, "message": "No active tokens found"}
            
            # Revoke tokens with Google
            for token in active_tokens:
                try:
                    if token.encrypted_refresh_token:
                        refresh_token = self._decrypt_token(token.encrypted_refresh_token)
                        # Revoke token with Google
                        revoke_url = f"https://oauth2.googleapis.com/revoke?token={refresh_token}"
                        async with httpx.AsyncClient() as client:
                            response = await client.post(revoke_url)
                            if response.status_code != 200:
                                logger.warning(f"Failed to revoke token with Google: {response.status_code}")
                except Exception as e:
                    logger.warning(f"Failed to revoke token with Google: {e}")
                
                # Mark token as revoked
                token.is_active = False
                token.revoked_at = datetime.utcnow()
                token.revocation_reason = "User requested revocation"
            
            # Update user record
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.gmail_connected = False
                user.gmail_status = "disconnected"
                user.email_monitoring_enabled = False
                user.gmail_credentials = None  # Clear old format credentials
            
            db.commit()
            
            await self._log_oauth_event(
                db, user_id, "oauth_access_revoked", True,
                details={"tokens_revoked": len(active_tokens)},
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            logger.info(f"OAuth access revoked for user {user_id}")
            
            return {
                "success": True,
                "message": "OAuth access revoked successfully",
                "tokens_revoked": len(active_tokens)
            }
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to revoke OAuth access: {e}")
            await self._log_oauth_event(
                db, user_id, "oauth_revocation_failed", False,
                error_message=str(e),
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to revoke OAuth access"
            )
    
    async def get_valid_credentials(self, db: Session, user_id: int) -> Optional[Credentials]:
        """Get valid credentials for API calls, refreshing if necessary."""
        try:
            # Get active token
            active_token = db.query(OAuthToken).filter(
                OAuthToken.user_id == user_id,
                OAuthToken.provider == "gmail",
                OAuthToken.is_active == True
            ).first()
            
            if not active_token or not active_token.encrypted_refresh_token:
                return None
            
            # Decrypt refresh token
            refresh_token = self._decrypt_token(active_token.encrypted_refresh_token)
            
            # Create credentials object
            credentials = Credentials(
                token=self._decrypt_token(active_token.encrypted_access_token) if active_token.encrypted_access_token else None,
                refresh_token=refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=self.client_id,
                client_secret=self.client_secret,
                scopes=json.loads(active_token.scope) if active_token.scope else self.REQUIRED_SCOPES
            )
            
            # Refresh token if needed
            if not credentials.valid:
                credentials.refresh(Request())
                
                # Update stored access token
                if credentials.token:
                    active_token.encrypted_access_token = self._encrypt_token(credentials.token)
                    active_token.token_expires_at = credentials.expiry
                    active_token.last_used_at = datetime.utcnow()
                    
                    # Update user record
                    user = db.query(User).filter(User.id == user_id).first()
                    if user:
                        user.gmail_last_token_refresh = datetime.utcnow()
                    
                    db.commit()
            
            active_token.last_used_at = datetime.utcnow()
            db.commit()
            
            return credentials
            
        except Exception as e:
            logger.error(f"Failed to get valid credentials for user {user_id}: {e}")
            return None

    async def setup_gmail_watch(
        self,
        db: Session,
        user_id: int,
        topic_name: str
    ) -> Dict[str, Any]:
        """
        Set up Gmail watch for real-time notifications via Pub/Sub.
        
        Args:
            db: Database session
            user_id: User ID
            topic_name: Pub/Sub topic name (e.g., "projects/PROJECT_ID/topics/TOPIC_NAME")
        
        Returns:
            Watch response with historyId and expiration
        """
        credentials = await self.get_valid_credentials(db, user_id)
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No valid Gmail credentials found"
            )
        
        try:
            service = build('gmail', 'v1', credentials=credentials)
            
            # Set up watch request
            watch_request = {
                'labelIds': ['INBOX'],  # Monitor inbox only
                'topicName': topic_name
            }
            
            result = service.users().watch(userId='me', body=watch_request).execute()
            
            # Store watch information
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.gmail_watch_history_id = result.get('historyId')
                user.gmail_watch_expiration = datetime.fromtimestamp(
                    int(result.get('expiration', 0)) / 1000
                )
                db.commit()
            
            await self._log_oauth_event(
                db=db,
                user_id=user_id,
                event_type="gmail_watch_setup",
                success=True,
                details={
                    "history_id": result.get('historyId'),
                    "expiration": result.get('expiration'),
                    "topic": topic_name
                }
            )
            
            logger.info(f"Gmail watch set up for user {user_id}: {result}")
            return result
            
        except HttpError as e:
            error_details = json.loads(e.content.decode()) if e.content else {}
            error_message = error_details.get('error', {}).get('message', str(e))
            
            await self._log_oauth_event(
                db=db,
                user_id=user_id,
                event_type="gmail_watch_setup",
                success=False,
                error_message=error_message
            )
            
            logger.error(f"Failed to set up Gmail watch for user {user_id}: {error_message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to set up Gmail watch: {error_message}"
            )

    async def stop_gmail_watch(
        self,
        db: Session,
        user_id: int
    ) -> bool:
        """
        Stop Gmail watch for a user.
        
        Args:
            db: Database session
            user_id: User ID
            
        Returns:
            True if successful
        """
        credentials = await self.get_valid_credentials(db, user_id)
        if not credentials:
            return False
        
        try:
            service = build('gmail', 'v1', credentials=credentials)
            service.users().stop(userId='me').execute()
            
            # Clear watch information
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.gmail_watch_history_id = None
                user.gmail_watch_expiration = None
                db.commit()
            
            await self._log_oauth_event(
                db=db,
                user_id=user_id,
                event_type="gmail_watch_stop",
                success=True
            )
            
            logger.info(f"Gmail watch stopped for user {user_id}")
            return True
            
        except HttpError as e:
            error_details = json.loads(e.content.decode()) if e.content else {}
            error_message = error_details.get('error', {}).get('message', str(e))
            
            await self._log_oauth_event(
                db=db,
                user_id=user_id,
                event_type="gmail_watch_stop",
                success=False,
                error_message=error_message
            )
            
            logger.error(f"Failed to stop Gmail watch for user {user_id}: {error_message}")
            return False

    async def process_gmail_notification(
        self,
        db: Session,
        notification_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process Gmail Pub/Sub notification.
        
        Args:
            db: Database session
            notification_data: Pub/Sub notification data
            
        Returns:
            Processing result
        """
        try:
            # Decode Pub/Sub message
            message_data = base64.b64decode(notification_data.get('data', '')).decode()
            gmail_data = json.loads(message_data)
            
            email_address = gmail_data.get('emailAddress')
            history_id = gmail_data.get('historyId')
            
            logger.info(f"Processing Gmail notification for {email_address}, historyId: {history_id}")
            
            # Find user by Gmail email
            user = db.query(User).filter(User.gmail_email == email_address).first()
            if not user:
                logger.warning(f"No user found for Gmail address: {email_address}")
                return {"status": "user_not_found", "email": email_address}
            
            # Get credentials and fetch new messages
            credentials = await self.get_valid_credentials(db, user.id)
            if not credentials:
                logger.warning(f"No valid credentials for user {user.id}")
                return {"status": "no_credentials", "user_id": user.id}
            
            service = build('gmail', 'v1', credentials=credentials)
            
            # Get history since last known historyId
            start_history_id = user.gmail_watch_history_id or history_id
            
            history_response = service.users().history().list(
                userId='me',
                startHistoryId=start_history_id,
                historyTypes=['messageAdded']
            ).execute()
            
            new_messages = []
            for history_item in history_response.get('history', []):
                for message_added in history_item.get('messagesAdded', []):
                    message_id = message_added['message']['id']
                    new_messages.append(message_id)
            
            # Update user's history ID
            user.gmail_watch_history_id = history_id
            db.commit()
            
            # Log the notification processing
            await self._log_oauth_event(
                db=db,
                user_id=user.id,
                event_type="gmail_notification_processed",
                success=True,
                details={
                    "history_id": history_id,
                    "new_messages_count": len(new_messages),
                    "message_ids": new_messages[:10]  # Log first 10 IDs
                }
            )
            
            return {
                "status": "processed",
                "user_id": user.id,
                "email": email_address,
                "new_messages": new_messages,
                "history_id": history_id
            }
            
        except Exception as e:
            logger.error(f"Failed to process Gmail notification: {e}")
            return {"status": "error", "error": str(e)}

    async def get_gmail_messages(
        self,
        db: Session,
        user_id: int,
        query: Optional[str] = None,
        max_results: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get Gmail messages for analysis.
        
        Args:
            db: Database session
            user_id: User ID
            query: Gmail search query (optional)
            max_results: Maximum number of messages to return
            
        Returns:
            List of message data
        """
        credentials = await self.get_valid_credentials(db, user_id)
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No valid Gmail credentials found"
            )
        
        try:
            service = build('gmail', 'v1', credentials=credentials)
            
            # List messages
            list_params = {
                'userId': 'me',
                'maxResults': max_results
            }
            if query:
                list_params['q'] = query
            
            messages_result = service.users().messages().list(**list_params).execute()
            message_ids = [msg['id'] for msg in messages_result.get('messages', [])]
            
            # Get message details
            messages = []
            for msg_id in message_ids:
                try:
                    message = service.users().messages().get(
                        userId='me',
                        id=msg_id,
                        format='metadata',
                        metadataHeaders=['From', 'To', 'Subject', 'Date']
                    ).execute()
                    
                    # Extract headers
                    headers = {}
                    for header in message.get('payload', {}).get('headers', []):
                        headers[header['name'].lower()] = header['value']
                    
                    messages.append({
                        'id': msg_id,
                        'thread_id': message.get('threadId'),
                        'label_ids': message.get('labelIds', []),
                        'snippet': message.get('snippet', ''),
                        'headers': headers,
                        'internal_date': message.get('internalDate')
                    })
                    
                except HttpError as e:
                    logger.warning(f"Failed to get message {msg_id}: {e}")
                    continue
            
            logger.info(f"Retrieved {len(messages)} Gmail messages for user {user_id}")
            return messages
            
        except HttpError as e:
            error_details = json.loads(e.content.decode()) if e.content else {}
            error_message = error_details.get('error', {}).get('message', str(e))
            
            logger.error(f"Failed to get Gmail messages for user {user_id}: {error_message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to get Gmail messages: {error_message}"
            )


# Dependency injection
def get_gmail_oauth_service() -> GmailOAuth2Service:
    """Dependency to get Gmail OAuth service."""
    return GmailOAuth2Service()
