"""
On-Demand Gmail Message Fetching Service
Privacy-first single message analysis using Message ID
"""

import base64
import email
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
import logging
import secrets

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from cryptography.fernet import Fernet
import hashlib

from app.config.settings import settings

logger = logging.getLogger(__name__)


class GmailOnDemandService:
    """
    Privacy-first service for fetching single Gmail messages on-demand.
    
    Key Features:
    - Minimal scope (gmail.readonly only)
    - Short-lived tokens (no refresh tokens by default)
    - Incremental OAuth (request permission only when needed)
    - No storage of raw messages unless user consents
    """
    
    GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
    REQUIRED_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
    TOKEN_LIFETIME = 3600  # 1 hour
    
    def __init__(self):
        """Initialize on-demand service."""
        self.scopes = [self.REQUIRED_SCOPE]
        self.encryption_key = self._get_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
    def _get_encryption_key(self) -> bytes:
        """Get encryption key for token storage."""
        key = getattr(settings, 'privacy_encryption_key', 'Eu8zqPoxLiuy-qAGUJzEHyOfJG08pgpxrF6TRI4hbtI=')
        if len(key) == 44:
            return key.encode()
        return base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())
    
    def _encrypt_token(self, token: str) -> str:
        """Encrypt access token for secure storage."""
        try:
            encrypted = self.cipher_suite.encrypt(token.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Token encryption failed: {e}")
            raise
    
    def _decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt stored access token."""
        try:
            encrypted_data = base64.b64decode(encrypted_token.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Token decryption failed: {e}")
            raise
    
    def build_incremental_auth_url(
        self,
        user_id: str,
        redirect_uri: str = None
    ) -> Tuple[str, str]:
        """
        Build incremental OAuth URL for gmail.readonly scope.
        
        Returns:
            Tuple of (authorization_url, state_token)
        """
        from urllib.parse import urlencode
        
        # Generate state token for CSRF protection
        state_data = {
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": secrets.token_urlsafe(16)
        }
        state_token = base64.urlsafe_b64encode(
            json.dumps(state_data).encode()
        ).decode()
        
        # Build OAuth URL
        client_id = getattr(settings, 'GMAIL_CLIENT_ID', None)
        if not client_id:
            raise ValueError("GMAIL_CLIENT_ID not configured")
        
        if not redirect_uri:
            base_url = getattr(settings, 'BASE_URL', 'http://localhost:8002')
            redirect_uri = f"{base_url}/api/v2/auth/callback"
        
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.scopes),
            "response_type": "code",
            "state": state_token,
            "access_type": "online",  # No refresh token for privacy
            "prompt": "consent"  # Always show consent screen
        }
        
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
        
        logger.info(f"Generated incremental auth URL for user {user_id}")
        return auth_url, state_token
    
    def verify_state_token(self, state_token: str, expected_user_id: str = None) -> Dict[str, Any]:
        """
        Verify state token from OAuth callback.
        
        Args:
            state_token: State token from OAuth callback
            expected_user_id: Optional user ID to verify against
            
        Returns:
            Dict with decoded state data
            
        Raises:
            ValueError: If state token is invalid or expired
        """
        try:
            decoded = base64.urlsafe_b64decode(state_token.encode())
            state_data = json.loads(decoded.decode())
            
            # Check timestamp (state should be used within 10 minutes)
            timestamp = datetime.fromisoformat(state_data["timestamp"])
            if datetime.now(timezone.utc) - timestamp > timedelta(minutes=10):
                raise ValueError("State token expired")
            
            # Verify user ID if provided
            if expected_user_id and state_data["user_id"] != expected_user_id:
                raise ValueError("State token user mismatch")
            
            return state_data
            
        except Exception as e:
            logger.error(f"State token verification failed: {e}")
            raise ValueError(f"Invalid state token: {e}")
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token.
        
        Args:
            code: Authorization code from OAuth callback
            redirect_uri: Redirect URI used in OAuth flow
            
        Returns:
            Dict with access_token, expires_in, scope, etc.
        """
        client_id = getattr(settings, 'GMAIL_CLIENT_ID', None)
        client_secret = getattr(settings, 'GMAIL_CLIENT_SECRET', None)
        
        if not client_id or not client_secret:
            raise ValueError("OAuth credentials not configured")
        
        if not redirect_uri:
            base_url = getattr(settings, 'BASE_URL', 'http://localhost:8002')
            redirect_uri = f"{base_url}/api/v2/auth/callback"
        
        token_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    "https://oauth2.googleapis.com/token",
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
                    raise ValueError(f"Required scope {self.REQUIRED_SCOPE} not granted")
                
                logger.info("Successfully exchanged code for access token")
                return tokens
                
            except httpx.RequestError as e:
                logger.error(f"Token exchange request failed: {e}")
                raise ValueError(f"Token exchange request failed: {e}")
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def fetch_message_raw(
        self,
        access_token: str,
        message_id: str
    ) -> email.message.Message:
        """
        Fetch single message from Gmail using message ID.
        
        Args:
            access_token: Valid Gmail access token
            message_id: Gmail message ID
            
        Returns:
            Parsed email.message.Message object
        """
        url = f"{self.GMAIL_API_BASE}/users/me/messages/{message_id}?format=raw"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url, headers=headers, timeout=30.0)
                
                if response.status_code == 404:
                    raise ValueError(f"Message {message_id} not found")
                
                if response.status_code == 401:
                    raise ValueError("Access token expired or invalid")
                
                if response.status_code != 200:
                    logger.error(f"Message fetch failed: {response.status_code} - {response.text}")
                    raise ValueError(f"Message fetch failed: {response.status_code}")
                
                data = response.json()
                raw_message = data.get("raw")
                
                if not raw_message:
                    raise ValueError("No raw message data in response")
                
                # Decode base64
                raw_bytes = base64.urlsafe_b64decode(raw_message)
                
                # Parse MIME message
                message = email.message_from_bytes(raw_bytes)
                
                logger.info(f"Successfully fetched message {message_id}")
                return message
                
            except httpx.RequestError as e:
                logger.error(f"Message fetch request failed: {e}")
                raise ValueError(f"Message fetch request failed: {e}")
    
    def extract_email_content(self, message: email.message.Message) -> Dict[str, Any]:
        """
        Extract relevant content from parsed email message.
        
        Args:
            message: Parsed email.message.Message
            
        Returns:
            Dict with sender, subject, body, headers, etc.
        """
        # Extract headers
        sender = message.get("From", "")
        subject = message.get("Subject", "")
        to = message.get("To", "")
        date = message.get("Date", "")
        message_id_header = message.get("Message-ID", "")
        
        # Extract body (handle multipart)
        body_text = ""
        body_html = ""
        
        if message.is_multipart():
            for part in message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text += payload.decode("utf-8", errors="ignore")
                
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html += payload.decode("utf-8", errors="ignore")
        else:
            # Single part message
            payload = message.get_payload(decode=True)
            if payload:
                content_type = message.get_content_type()
                if content_type == "text/html":
                    body_html = payload.decode("utf-8", errors="ignore")
                else:
                    body_text = payload.decode("utf-8", errors="ignore")
        
        # Extract all headers for analysis
        headers_dict = {}
        for key, value in message.items():
            headers_dict[key] = value
        
        return {
            "sender": sender,
            "subject": subject,
            "to": to,
            "date": date,
            "message_id": message_id_header,
            "body_text": body_text,
            "body_html": body_html,
            "headers": headers_dict,
            "raw_size_bytes": len(str(message))
        }
    
    async def check_email_on_demand(
        self,
        user_id: str,
        message_id: str,
        access_token: str = None,
        store_consent: bool = False
    ) -> Dict[str, Any]:
        """
        Main method for on-demand email checking.
        
        Args:
            user_id: User ID requesting the check
            message_id: Gmail message ID to check
            access_token: Optional access token (if already available)
            store_consent: Whether user consented to storing the analysis
            
        Returns:
            Dict with analysis results or need_oauth flag
        """
        
        # Check if we have a valid access token
        if not access_token:
            # Check session/cache for stored token
            # For now, return need_oauth
            auth_url, state = self.build_incremental_auth_url(user_id)
            return {
                "need_oauth": True,
                "oauth_url": auth_url,
                "message": "Gmail access required. Please authenticate."
            }
        
        try:
            # Fetch message from Gmail
            message = await self.fetch_message_raw(access_token, message_id)
            
            # Extract content
            email_content = self.extract_email_content(message)
            
            # Analyze email (pass to existing pipeline)
            # Analyze email (pass to existing pipeline)
            from app.core.orchestrator import get_orchestrator
            orchestrator = get_orchestrator()
            await orchestrator.start() # Ensure orchestrator is running
            
            orchestration_result = await orchestrator.orchestrate_email_processing(email_content)
            
            if orchestration_result.success:
                analysis_result = orchestration_result.result
            else:
                logger.error(f"Orchestration failed: {orchestration_result.error}")
                analysis_result = {
                    "score": 0, 
                    "risk_level": "UNKNOWN", 
                    "error": orchestration_result.error,
                    "details": "Analysis pipeline failed"
                }
            
            # Build response
            response = {
                "success": True,
                "message_id": message_id,
                "analysis": analysis_result,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "privacy_notice": "This analysis was performed on-demand and is not stored unless you consent below."
            }
            
            # If user consented to storage, log metadata
            if store_consent:
                await self._store_analysis_with_consent(user_id, message_id, analysis_result, email_content)
                response["stored"] = True
            else:
                response["stored"] = False
            
            # Log audit event (without raw email)
            await self._log_audit_event(
                user_id=user_id,
                message_id=message_id,
                action="on_demand_check",
                stored=store_consent
            )
            
            return response
            
        except ValueError as e:
            if "expired" in str(e).lower() or "invalid" in str(e).lower():
                # Token expired, need re-auth
                auth_url, state = self.build_incremental_auth_url(user_id)
                return {
                    "need_oauth": True,
                    "oauth_url": auth_url,
                    "message": "Access token expired. Please re-authenticate."
                }
            raise
    
    async def _store_analysis_with_consent(
        self,
        user_id: str,
        message_id: str,
        analysis_result: Dict[str, Any],
        email_content: Dict[str, Any]
    ):
        """Store analysis with user consent (MongoDB)."""
        from app.models.mongodb_models import OnDemandAnalysis
        
        try:
            analysis_doc = OnDemandAnalysis(
                user_id=user_id,
                gmail_message_id=message_id,
                threat_score=analysis_result.get("score", 0.0),
                risk_level=analysis_result.get("risk_level", "UNKNOWN"),
                analysis_result=analysis_result,
                email_metadata={
                    "sender": email_content.get("sender"),
                    "subject": email_content.get("subject"),
                    "date": email_content.get("date"),
                },
                raw_email_content=email_content if True else None,  # Optional: store full content
                consent_given=True,
                retention_until=datetime.now(timezone.utc) + timedelta(days=30),
                created_at=datetime.now(timezone.utc)
            )
            
            await analysis_doc.save()
            logger.info(f"Stored on-demand analysis for user {user_id}, message {message_id}")
            
        except Exception as e:
            logger.error(f"Failed to store analysis: {e}")
            # Don't fail the request if storage fails
    
    async def _log_audit_event(
        self,
        user_id: str,
        message_id: str,
        action: str,
        stored: bool
    ):
        """Log audit event for on-demand check."""
        from app.models.mongodb_models import AuditLog
        
        try:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                resource_type="gmail_message",
                resource_id=message_id,
                metadata={
                    "stored": stored,
                    "mode": "on_demand"
                },
                timestamp=datetime.now(timezone.utc)
            )
            
            await audit_log.save()
            logger.info(f"Logged audit event: {action} for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            # Don't fail the request if logging fails


# Singleton instance
gmail_ondemand_service = GmailOnDemandService()
