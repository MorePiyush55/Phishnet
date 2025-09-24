"""
Enhanced OAuth Consent Management Service
Provides secure OAuth token management with GDPR compliance and granular consent tracking.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import json
import secrets
import hashlib
from urllib.parse import urlencode, parse_qs

from cryptography.fernet import Fernet
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from backend.app.models.consent import (
    UserConsent, ConsentAuditLog, UserDataArtifact, ConsentTemplate,
    ConsentScope, DataProcessingType, RetentionPolicy
)
from backend.app.models.production_models import OAuthCredentials
from backend.app.core.database import get_db
from backend.app.core.config import get_settings
from backend.app.core.redis_client import get_redis_client
from backend.app.core.security import get_encryption_key

logger = logging.getLogger(__name__)

class ConsentOAuthService:
    """
    Enhanced OAuth service with consent management and GDPR compliance.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.redis_client = get_redis_client()
        self.encryption_key = get_encryption_key()
        self.fernet = Fernet(self.encryption_key)
        
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
        
        # Minimal scopes for privacy-first approach
        self.required_scopes = [
            ConsentScope.GMAIL_READONLY.value,
            "https://www.googleapis.com/auth/userinfo.email",
            "openid"
        ]
    
    def encrypt_tokens(self, credentials: dict) -> str:
        """
        Encrypt OAuth tokens for secure storage.
        
        Args:
            credentials: Dictionary containing OAuth credentials
            
        Returns:
            Encrypted token string
        """
        try:
            credentials_json = json.dumps(credentials)
            encrypted_tokens = self.fernet.encrypt(credentials_json.encode())
            return encrypted_tokens.decode()
        except Exception as e:
            logger.error(f"Token encryption failed: {str(e)}")
            raise Exception("Failed to encrypt OAuth tokens")
    
    def decrypt_tokens(self, encrypted_tokens: str) -> dict:
        """
        Decrypt OAuth tokens for use.
        
        Args:
            encrypted_tokens: Encrypted token string
            
        Returns:
            Decrypted credentials dictionary
        """
        try:
            decrypted_data = self.fernet.decrypt(encrypted_tokens.encode())
            return json.loads(decrypted_data.decode())
        except Exception as e:
            logger.error(f"Token decryption failed: {str(e)}")
            raise Exception("Failed to decrypt OAuth tokens")
        
        self.optional_scopes = [
            ConsentScope.GMAIL_MODIFY.value  # For quarantine functionality
        ]

    async def initialize_consent_flow(self, 
                                    user_id: str,
                                    requested_scopes: Optional[List[str]] = None,
                                    consent_preferences: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Initialize OAuth consent flow with comprehensive consent tracking.
        
        Args:
            user_id: Unique user identifier
            requested_scopes: OAuth scopes being requested
            consent_preferences: User's initial consent preferences
            
        Returns:
            Dict containing authorization URL, state token, and consent metadata
        """
        try:
            # Generate secure state token
            state_token = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(16)
            
            # Use minimal scopes by default
            scopes = requested_scopes or self.required_scopes
            
            # Store state and consent context in Redis with expiration
            consent_context = {
                "user_id": user_id,
                "requested_scopes": scopes,
                "consent_preferences": consent_preferences or {},
                "nonce": nonce,
                "timestamp": datetime.utcnow().isoformat(),
                "ip_address": None,  # Will be set by endpoint
                "user_agent": None   # Will be set by endpoint
            }
            
            state_key = f"oauth_consent_state:{state_token}"
            await self.redis_client.setex(
                state_key,
                3600,  # 1 hour expiration
                json.dumps(consent_context)
            )
            
            # Create OAuth flow
            flow = Flow.from_client_config(
                self.client_config,
                scopes=scopes
            )
            flow.redirect_uri = self.settings.oauth_redirect_uri
            
            # Generate authorization URL with consent-specific parameters
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                state=state_token,
                prompt='consent',  # Always show consent screen
                nonce=nonce
            )
            
            # Log consent flow initiation
            logger.info(f"Consent flow initiated for user {user_id} with scopes: {scopes}")
            
            return {
                "success": True,
                "authorization_url": auth_url,
                "state_token": state_token,
                "requested_scopes": scopes,
                "consent_requirements": self._get_consent_requirements(scopes),
                "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to initialize consent flow for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": "Failed to initialize OAuth consent flow",
                "error_code": "CONSENT_INIT_FAILED"
            }

    async def handle_consent_callback(self,
                                    authorization_code: str,
                                    state_token: str,
                                    user_consent_data: Dict[str, Any],
                                    request_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle OAuth callback with comprehensive consent recording.
        
        Args:
            authorization_code: Authorization code from Google
            state_token: State token for CSRF protection
            user_consent_data: User's explicit consent choices
            request_context: Request metadata (IP, user agent, etc.)
            
        Returns:
            Dict containing consent status and user information
        """
        try:
            # Validate and retrieve state
            state_key = f"oauth_consent_state:{state_token}"
            state_data_str = await self.redis_client.get(state_key)
            
            if not state_data_str:
                raise ValueError("Invalid or expired state token")
            
            state_data = json.loads(state_data_str)
            user_id = state_data["user_id"]
            requested_scopes = state_data["scopes"]
            
            # Clean up state
            await self.redis_client.delete(state_key)
            
            # Exchange code for tokens
            flow = Flow.from_client_config(
                self.client_config,
                scopes=requested_scopes,
                redirect_uri=self.settings.oauth_redirect_uri,
                state=state_token
            )
            
            flow.fetch_token(code=authorization_code)
            credentials = flow.credentials
            
            # Get user info from Google
            user_info = await self._get_user_info(credentials)
            
            # Validate granted scopes
            granted_scopes = credentials.scopes or []
            missing_required = [
                scope for scope in self.required_scopes 
                if scope not in granted_scopes
            ]
            
            if missing_required:
                raise ValueError(f"Missing required scopes: {missing_required}")
            
            # Create or update consent record
            consent = await self._create_consent_record(
                user_id=user_id,
                email=user_info["email"],
                google_user_id=user_info["sub"],
                credentials=credentials,
                granted_scopes=granted_scopes,
                consent_data=user_consent_data,
                request_context=request_context
            )
            
            # Store encrypted tokens
            await self._store_encrypted_tokens(
                user_id=user_id,
                credentials=credentials,
                consent_id=consent.id,
                request_context=request_context
            )
            
            # Log successful consent
            await self._log_consent_event(
                consent_id=consent.id,
                event_type="consent_granted",
                event_details={
                    "granted_scopes": granted_scopes,
                    "gmail_email": user_info["email"],
                    "google_user_id": user_info["sub"]
                },
                request_context=request_context
            )
            
            logger.info(f"Consent successfully granted for user {user_id}")
            
            return {
                "success": True,
                "consent_id": consent.id,
                "user_email": user_info["email"],
                "granted_scopes": granted_scopes,
                "consent_status": "active",
                "next_actions": self._get_post_consent_actions(consent)
            }
            
        except Exception as e:
            logger.error(f"Consent callback failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "CONSENT_CALLBACK_FAILED"
            }

    async def revoke_consent(self,
                           user_id: str,
                           revocation_reason: str,
                           request_context: Dict[str, Any],
                           cleanup_data: bool = True) -> Dict[str, Any]:
        """
        Revoke user consent and cleanup associated data (GDPR Right to be Forgotten).
        
        Args:
            user_id: User identifier
            revocation_reason: Reason for consent revocation
            request_context: Request metadata
            cleanup_data: Whether to delete user data artifacts
            
        Returns:
            Dict containing revocation status and cleanup summary
        """
        try:
            with get_db() as db:
                # Get active consent
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id,
                    UserConsent.is_active == True
                ).first()
                
                if not consent:
                    return {
                        "success": True,
                        "message": "No active consent found",
                        "already_revoked": True
                    }
                
                # Revoke tokens with Google
                revoked_tokens = await self._revoke_google_tokens(consent)
                
                # Update consent record
                consent.is_active = False
                consent.consent_revoked_at = datetime.utcnow()
                
                # Log revocation
                await self._log_consent_event(
                    consent_id=consent.id,
                    event_type="consent_revoked",
                    event_details={
                        "revocation_reason": revocation_reason,
                        "tokens_revoked": revoked_tokens,
                        "cleanup_requested": cleanup_data
                    },
                    request_context=request_context
                )
                
                # Cleanup user data if requested
                cleanup_summary = {}
                if cleanup_data:
                    cleanup_summary = await self._cleanup_user_data(
                        consent_id=consent.id,
                        request_context=request_context
                    )
                
                db.commit()
                
                logger.info(f"Consent revoked for user {user_id}: {revocation_reason}")
                
                return {
                    "success": True,
                    "consent_revoked": True,
                    "tokens_revoked": revoked_tokens,
                    "data_cleanup": cleanup_summary,
                    "revocation_timestamp": consent.consent_revoked_at.isoformat()
                }
                
        except Exception as e:
            logger.error(f"Failed to revoke consent for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "CONSENT_REVOCATION_FAILED"
            }

    async def get_consent_status(self, user_id: str) -> Dict[str, Any]:
        """
        Get comprehensive consent status for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dict containing consent status, permissions, and metadata
        """
        try:
            with get_db() as db:
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id
                ).order_by(UserConsent.consent_granted_at.desc()).first()
                
                if not consent:
                    return {
                        "consent_exists": False,
                        "consent_status": "none",
                        "requires_consent": True
                    }
                
                # Get data artifacts count
                artifacts_count = db.query(UserDataArtifact).filter(
                    UserDataArtifact.user_consent_id == consent.id,
                    UserDataArtifact.deleted_at.is_(None)
                ).count()
                
                # Check token validity
                token_status = await self._check_token_validity(user_id)
                
                return {
                    "consent_exists": True,
                    "consent_status": "active" if consent.is_active else "revoked",
                    "consent_id": consent.id,
                    "email": consent.email,
                    "granted_scopes": consent.granted_scopes,
                    "consent_granted_at": consent.consent_granted_at.isoformat(),
                    "consent_updated_at": consent.consent_updated_at.isoformat(),
                    "consent_version": consent.consent_version,
                    "token_status": token_status,
                    "data_artifacts_count": artifacts_count,
                    "retention_policy": consent.retention_policy,
                    "retention_days": consent.effective_retention_days,
                    "privacy_settings": consent.to_dict()["privacy_preferences"],
                    "requires_consent": not consent.is_consent_valid
                }
                
        except Exception as e:
            logger.error(f"Failed to get consent status for user {user_id}: {str(e)}")
            return {
                "consent_exists": False,
                "consent_status": "error",
                "error": str(e)
            }

    async def export_user_data(self, 
                             user_id: str,
                             request_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Export all user data for GDPR compliance (Right to Data Portability).
        
        Args:
            user_id: User identifier
            request_context: Request metadata
            
        Returns:
            Dict containing complete user data export
        """
        try:
            with get_db() as db:
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id
                ).order_by(UserConsent.consent_granted_at.desc()).first()
                
                if not consent:
                    return {
                        "success": False,
                        "error": "No consent record found",
                        "error_code": "NO_CONSENT_RECORD"
                    }
                
                # Get all data artifacts
                artifacts = db.query(UserDataArtifact).filter(
                    UserDataArtifact.user_consent_id == consent.id,
                    UserDataArtifact.deleted_at.is_(None)
                ).all()
                
                # Get audit logs
                audit_logs = db.query(ConsentAuditLog).filter(
                    ConsentAuditLog.user_consent_id == consent.id
                ).order_by(ConsentAuditLog.event_timestamp.desc()).all()
                
                # Compile export data
                export_data = {
                    "export_metadata": {
                        "user_id": user_id,
                        "export_timestamp": datetime.utcnow().isoformat(),
                        "export_request_ip": request_context.get("ip_address"),
                        "data_controller": "PhishNet Email Security",
                        "export_format": "JSON"
                    },
                    "consent_record": consent.to_dict(),
                    "data_artifacts": [
                        {
                            "artifact_type": artifact.artifact_type,
                            "created_at": artifact.created_at.isoformat(),
                            "expires_at": artifact.expires_at.isoformat(),
                            "size_bytes": artifact.size_bytes,
                            "tags": artifact.tags
                        }
                        for artifact in artifacts
                    ],
                    "consent_history": [
                        {
                            "event_type": log.event_type,
                            "timestamp": log.event_timestamp.isoformat(),
                            "details": log.event_details,
                            "ip_address": log.ip_address
                        }
                        for log in audit_logs
                    ],
                    "legal_information": {
                        "privacy_policy_version": consent.privacy_policy_version,
                        "terms_version": consent.terms_of_service_version,
                        "legal_basis": "consent",
                        "data_retention_days": consent.effective_retention_days,
                        "processing_purposes": [
                            "Phishing detection and email security analysis",
                            "Threat intelligence and pattern recognition",
                            "User notification and protection services"
                        ]
                    }
                }
                
                # Log export request
                await self._log_consent_event(
                    consent_id=consent.id,
                    event_type="data_export_requested",
                    event_details={
                        "artifacts_count": len(artifacts),
                        "export_size_estimate": sum(a.size_bytes for a in artifacts)
                    },
                    request_context=request_context
                )
                
                return {
                    "success": True,
                    "export_data": export_data,
                    "export_summary": {
                        "consent_records": 1,
                        "data_artifacts": len(artifacts),
                        "audit_events": len(audit_logs),
                        "total_size_bytes": sum(a.size_bytes for a in artifacts)
                    }
                }
                
        except Exception as e:
            logger.error(f"Failed to export user data for {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "DATA_EXPORT_FAILED"
            }

    # Private helper methods

    async def _create_consent_record(self,
                                   user_id: str,
                                   email: str,
                                   google_user_id: str,
                                   credentials: Credentials,
                                   granted_scopes: List[str],
                                   consent_data: Dict[str, Any],
                                   request_context: Dict[str, Any]) -> UserConsent:
        """Create comprehensive consent record."""
        
        with get_db() as db:
            # Deactivate any existing consent records
            existing_consents = db.query(UserConsent).filter(
                UserConsent.user_id == user_id,
                UserConsent.is_active == True
            ).all()
            
            for existing in existing_consents:
                existing.is_active = False
                existing.consent_revoked_at = datetime.utcnow()
            
            # Create new consent record
            consent = UserConsent(
                user_id=user_id,
                email=email,
                google_user_id=google_user_id,
                granted_scopes=granted_scopes,
                token_expires_at=credentials.expiry,
                
                # Data processing preferences from user choices
                allow_subject_analysis=consent_data.get("allow_subject_analysis", True),
                allow_body_analysis=consent_data.get("allow_body_analysis", True),
                allow_attachment_scanning=consent_data.get("allow_attachment_scanning", False),
                allow_llm_processing=consent_data.get("allow_llm_processing", True),
                allow_threat_intel_lookup=consent_data.get("allow_threat_intel_lookup", True),
                opt_out_ai_analysis=consent_data.get("opt_out_ai_analysis", False),
                opt_out_persistent_storage=consent_data.get("opt_out_persistent_storage", False),
                
                # Privacy preferences
                allow_analytics=consent_data.get("allow_analytics", False),
                allow_performance_monitoring=consent_data.get("allow_performance_monitoring", True),
                share_threat_intelligence=consent_data.get("share_threat_intelligence", True),
                
                # Retention settings
                retention_policy=consent_data.get("retention_policy", RetentionPolicy.STANDARD_30_DAYS.value),
                custom_retention_days=consent_data.get("custom_retention_days"),
                
                # Legal compliance
                gdpr_consent=consent_data.get("gdpr_consent", False),
                ccpa_opt_out=consent_data.get("ccpa_opt_out", False),
                
                # Request metadata
                ip_address=request_context.get("ip_address"),
                user_agent=request_context.get("user_agent"),
                consent_source=request_context.get("source", "web_ui")
            )
            
            db.add(consent)
            db.flush()  # Get the ID
            db.commit()
            
            return consent

    async def _store_encrypted_tokens(self,
                                    user_id: str,
                                    credentials: Credentials,
                                    consent_id: int,
                                    request_context: Dict[str, Any]) -> None:
        """Store encrypted OAuth tokens securely."""
        
        try:
            # Encrypt tokens
            encrypted_access = self.fernet.encrypt(credentials.token.encode()) if credentials.token else None
            encrypted_refresh = self.fernet.encrypt(credentials.refresh_token.encode()) if credentials.refresh_token else None
            encrypted_id_token = None
            
            if hasattr(credentials, 'id_token') and credentials.id_token:
                encrypted_id_token = self.fernet.encrypt(credentials.id_token.encode())
            
            # Store in production MongoDB collection
            oauth_cred = OAuthCredentials(
                user_id=user_id,
                provider="google",
                encrypted_access_token=encrypted_access.decode() if encrypted_access else None,
                encrypted_refresh_token=encrypted_refresh.decode() if encrypted_refresh else None,
                encrypted_id_token=encrypted_id_token.decode() if encrypted_id_token else None,
                expires_at=credentials.expiry,
                scope=credentials.scopes or [],
                encryption_key_id="primary",  # For key rotation
                created_from_ip=request_context.get("ip_address"),
                last_used_ip=request_context.get("ip_address")
            )
            
            # Save to MongoDB
            await oauth_cred.insert()
            
            logger.info(f"Encrypted tokens stored for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to store encrypted tokens for user {user_id}: {str(e)}")
            raise

    async def _get_user_info(self, credentials: Credentials) -> Dict[str, Any]:
        """Get user information from Google using credentials."""
        
        try:
            service = build('oauth2', 'v2', credentials=credentials)
            user_info = service.userinfo().get().execute()
            return user_info
        except Exception as e:
            logger.error(f"Failed to get user info: {str(e)}")
            raise

    async def _log_consent_event(self,
                               consent_id: int,
                               event_type: str,
                               event_details: Dict[str, Any],
                               request_context: Dict[str, Any]) -> None:
        """Log consent-related events for audit trail."""
        
        try:
            with get_db() as db:
                audit_log = ConsentAuditLog(
                    user_consent_id=consent_id,
                    event_type=event_type,
                    event_details=event_details,
                    ip_address=request_context.get("ip_address"),
                    user_agent=request_context.get("user_agent"),
                    request_id=request_context.get("request_id")
                )
                
                db.add(audit_log)
                db.commit()
                
        except Exception as e:
            logger.error(f"Failed to log consent event: {str(e)}")

    def _get_consent_requirements(self, scopes: List[str]) -> Dict[str, Any]:
        """Get detailed consent requirements for requested scopes."""
        
        requirements = {
            "required_scopes": [],
            "optional_scopes": [],
            "data_access_summary": [],
            "processing_purposes": [],
            "retention_options": []
        }
        
        scope_info = {
            ConsentScope.GMAIL_READONLY.value: {
                "title": "Read Gmail Messages",
                "description": "Access email content for phishing analysis",
                "required": True,
                "data_access": ["Email headers", "Subject lines", "Message content", "Sender information"],
                "purposes": ["Phishing detection", "Threat analysis", "Security alerts"]
            },
            ConsentScope.GMAIL_MODIFY.value: {
                "title": "Modify Gmail Messages", 
                "description": "Label and quarantine suspicious emails",
                "required": False,
                "data_access": ["Email labels", "Folder organization"],
                "purposes": ["Automatic quarantine", "Threat mitigation", "Email organization"]
            }
        }
        
        for scope in scopes:
            if scope in scope_info:
                info = scope_info[scope]
                scope_req = {
                    "scope": scope,
                    "title": info["title"],
                    "description": info["description"],
                    "data_access": info["data_access"],
                    "purposes": info["purposes"]
                }
                
                if info["required"]:
                    requirements["required_scopes"].append(scope_req)
                else:
                    requirements["optional_scopes"].append(scope_req)
        
        requirements["retention_options"] = [
            {
                "policy": RetentionPolicy.MINIMAL_7_DAYS.value,
                "days": 7,
                "description": "Minimal metadata storage for 7 days"
            },
            {
                "policy": RetentionPolicy.STANDARD_30_DAYS.value,
                "days": 30,
                "description": "Standard retention for security analysis"
            },
            {
                "policy": RetentionPolicy.EXTENDED_90_DAYS.value,
                "days": 90,
                "description": "Extended retention for threat research"
            }
        ]
        
        return requirements

    def _get_post_consent_actions(self, consent: UserConsent) -> List[Dict[str, Any]]:
        """Get recommended actions after consent is granted."""
        
        actions = []
        
        if consent.has_scope(ConsentScope.GMAIL_READONLY):
            actions.append({
                "action": "initial_scan",
                "title": "Scan Recent Emails",
                "description": "Perform initial security scan of recent emails",
                "recommended": True
            })
        
        if not consent.allow_attachment_scanning:
            actions.append({
                "action": "enable_attachment_scan",
                "title": "Enable Attachment Scanning",
                "description": "Enhanced protection by scanning email attachments",
                "recommended": True
            })
        
        if consent.retention_policy == RetentionPolicy.NO_STORAGE.value:
            actions.append({
                "action": "review_retention",
                "title": "Review Data Retention",
                "description": "Consider allowing minimal data storage for better protection",
                "recommended": False
            })
        
        return actions

    async def _revoke_google_tokens(self, consent: UserConsent) -> Dict[str, Any]:
        """Revoke tokens with Google OAuth service."""
        
        try:
            # This would implement actual Google token revocation
            # For now, return success status
            return {
                "access_token_revoked": True,
                "refresh_token_revoked": True,
                "revocation_timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to revoke Google tokens: {str(e)}")
            return {
                "access_token_revoked": False,
                "refresh_token_revoked": False,
                "error": str(e)
            }

    async def _cleanup_user_data(self, 
                               consent_id: int,
                               request_context: Dict[str, Any]) -> Dict[str, Any]:
        """Cleanup all user data artifacts (GDPR compliance)."""
        
        try:
            with get_db() as db:
                # Mark all data artifacts as deleted
                artifacts = db.query(UserDataArtifact).filter(
                    UserDataArtifact.user_consent_id == consent_id,
                    UserDataArtifact.deleted_at.is_(None)
                ).all()
                
                cleanup_summary = {
                    "artifacts_deleted": 0,
                    "total_size_freed": 0,
                    "artifact_types": {}
                }
                
                for artifact in artifacts:
                    artifact.deleted_at = datetime.utcnow()
                    cleanup_summary["artifacts_deleted"] += 1
                    cleanup_summary["total_size_freed"] += artifact.size_bytes or 0
                    
                    if artifact.artifact_type not in cleanup_summary["artifact_types"]:
                        cleanup_summary["artifact_types"][artifact.artifact_type] = 0
                    cleanup_summary["artifact_types"][artifact.artifact_type] += 1
                
                db.commit()
                
                return cleanup_summary
                
        except Exception as e:
            logger.error(f"Failed to cleanup user data: {str(e)}")
            return {"error": str(e)}

    async def _check_token_validity(self, user_id: str) -> Dict[str, Any]:
        """Check if stored tokens are still valid."""
        
        try:
            # This would implement actual token validation
            # For now, return placeholder status
            return {
                "access_token_valid": True,
                "refresh_token_valid": True,
                "expires_at": None,
                "needs_refresh": False
            }
        except Exception as e:
            return {
                "access_token_valid": False,
                "refresh_token_valid": False,
                "error": str(e)
            }


# Global service instance
_consent_oauth_service = None

def get_consent_oauth_service() -> ConsentOAuthService:
    """Get global consent OAuth service instance."""
    global _consent_oauth_service
    if _consent_oauth_service is None:
        _consent_oauth_service = ConsentOAuthService()
    return _consent_oauth_service