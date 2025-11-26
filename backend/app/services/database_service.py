"""
Production Database Service Layer
Handles transactions, encryption, and advanced database operations
"""

import asyncio
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Union, Tuple
from contextlib import asynccontextmanager
import logging
import json

from cryptography.fernet import Fernet
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorClientSession
from pymongo.errors import DuplicateKeyError, BulkWriteError
from beanie import init_beanie
import bcrypt

from app.config.settings import get_settings
from app.db.mongodb import MongoDBManager
from .production_models import (
    User, OAuthCredentials, EmailMeta, ScanResult, AuditLog, 
    RefreshToken, ReputationCache, PRODUCTION_DOCUMENT_MODELS,
    ActionType, ScanStatus, ThreatLevel, ReputationLevel
)

logger = logging.getLogger(__name__)
settings = get_settings()


class DatabaseService:
    """Production database service with transactions and encryption."""
    
    def __init__(self):
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or generate encryption key for sensitive data."""
        key_env = getattr(settings, 'privacy_encryption_key', None)
        if key_env:
            return key_env.encode()
        
        # Generate a key - in production, store this securely!
        key = Fernet.generate_key()
        logger.warning("⚠️ Generated new encryption key. Store securely in production!")
        return key
    
    def encrypt_token(self, token: str, salt: str = None) -> Tuple[str, str]:
        """Encrypt OAuth token with salt."""
        if not salt:
            salt = secrets.token_hex(16)
        
        # Combine token with salt for encryption
        salted_token = f"{salt}:{token}"
        encrypted = self.cipher_suite.encrypt(salted_token.encode())
        return encrypted.decode(), salt
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt OAuth token."""
        try:
            decrypted = self.cipher_suite.decrypt(encrypted_token.encode())
            salted_token = decrypted.decode()
            # Remove salt prefix
            return salted_token.split(':', 1)[1]
        except Exception as e:
            logger.error(f"Token decryption failed: {e}")
            raise
    
    @asynccontextmanager
    async def transaction_context(self):
        """Provide MongoDB transaction context for atomic operations."""
        if not MongoDBManager.client:
            await MongoDBManager.connect_to_mongo()
        
        session = MongoDBManager.client.start_session()
        try:
            async with session.start_transaction():
                yield session
        except Exception as e:
            logger.error(f"Transaction failed: {e}")
            raise
        finally:
            await session.end_session()
    
    async def create_user_with_tokens(
        self, 
        user_data: Dict[str, Any],
        oauth_tokens: Optional[Dict[str, str]] = None
    ) -> User:
        """Atomically create user and OAuth credentials."""
        
        async with self.transaction_context() as session:
            # Create user
            user = User(**user_data)
            await user.insert(session=session)
            
            # Create OAuth credentials if provided
            if oauth_tokens:
                encrypted_access, salt = self.encrypt_token(oauth_tokens['access_token'])
                
                oauth_creds = OAuthCredentials(
                    user_id=str(user.id),
                    provider=oauth_tokens.get('provider', 'google'),
                    encrypted_access_token=encrypted_access,
                    salt=salt,
                    expires_at=oauth_tokens.get('expires_at'),
                    scope=oauth_tokens.get('scope', [])
                )
                
                if 'refresh_token' in oauth_tokens:
                    encrypted_refresh, _ = self.encrypt_token(oauth_tokens['refresh_token'], salt)
                    oauth_creds.encrypted_refresh_token = encrypted_refresh
                
                await oauth_creds.insert(session=session)
            
            # Log user creation
            await self.log_audit_event(
                action=ActionType.USER_LOGIN,  # First login counts as creation
                user_id=str(user.id),
                resource_type="user",
                resource_id=str(user.id),
                description=f"New user account created: {user.email}",
                session=session
            )
            
            return user
    
    async def process_email_scan(
        self,
        email_data: Dict[str, Any],
        scan_results: Dict[str, Any],
        user_id: str
    ) -> Tuple[EmailMeta, ScanResult]:
        """Atomically process email scan with metadata and results."""
        
        async with self.transaction_context() as session:
            # Create email metadata
            email_meta = EmailMeta(
                message_id=email_data['message_id'],
                user_id=user_id,
                sender=email_data['sender'],
                recipient=email_data['recipient'],
                subject=email_data['subject'],
                date_sent=email_data.get('date_sent', datetime.now(timezone.utc)),
                content_type=email_data.get('content_type', 'text/plain'),
                content_length=email_data.get('content_length', 0),
                processing_status=EmailStatus.COMPLETED,
                processing_completed_at=datetime.now(timezone.utc),
                processing_time_ms=scan_results.get('processing_time_ms', 0)
            )
            await email_meta.insert(session=session)
            
            # Create scan result
            scan_result = ScanResult(
                message_id=email_data['message_id'],
                user_id=user_id,
                scan_id=f"scan_{secrets.token_hex(16)}",
                scan_status=ScanStatus.COMPLETED,
                scan_completed_at=datetime.now(timezone.utc),
                is_phishing=scan_results.get('is_phishing', False),
                threat_level=ThreatLevel(scan_results.get('threat_level', 'low')),
                confidence_score=scan_results.get('confidence_score', 0.5),
                detected_threats=scan_results.get('detected_threats', []),
                content_analysis=scan_results.get('content_analysis', {}),
                url_analysis=scan_results.get('url_analysis', {}),
                model_predictions=scan_results.get('model_predictions', {}),
                top_features=scan_results.get('top_features', [])
            )
            await scan_result.insert(session=session)
            
            # Update user statistics
            user = await User.get(user_id, session=session)
            if user:
                user.total_emails_scanned += 1
                if scan_result.is_phishing:
                    user.threats_detected += 1
                await user.save(session=session)
            
            # Log scan completion
            await self.log_audit_event(
                action=ActionType.EMAIL_SCAN,
                user_id=user_id,
                resource_type="email",
                resource_id=email_data['message_id'],
                description=f"Email scan completed - Threat: {'Yes' if scan_result.is_phishing else 'No'}",
                details={
                    "confidence": scan_result.confidence_score,
                    "threats": scan_result.detected_threats
                },
                session=session
            )
            
            return email_meta, scan_result
    
    async def handle_analyst_feedback(
        self,
        scan_id: str,
        feedback_type: str,  # "false_positive" or "false_negative"
        analyst_id: str,
        notes: Optional[str] = None
    ) -> bool:
        """Handle analyst feedback with audit trail."""
        
        async with self.transaction_context() as session:
            # Update scan result
            scan_result = await ScanResult.find_one(
                ScanResult.scan_id == scan_id,
                session=session
            )
            
            if not scan_result:
                return False
            
            scan_result.user_feedback = feedback_type
            if notes:
                scan_result.actions_taken.append(f"Analyst feedback: {notes}")
            await scan_result.save(session=session)
            
            # Update user statistics
            user = await User.get(scan_result.user_id, session=session)
            if user:
                if feedback_type == "false_positive":
                    user.false_positives += 1
                elif feedback_type == "false_negative":
                    user.false_negatives += 1
                await user.save(session=session)
            
            # Log feedback
            action = ActionType.FALSE_POSITIVE if feedback_type == "false_positive" else ActionType.FALSE_NEGATIVE
            await self.log_audit_event(
                action=action,
                user_id=analyst_id,
                resource_type="scan",
                resource_id=scan_id,
                description=f"Analyst marked scan as {feedback_type}",
                details={"notes": notes, "original_result": scan_result.is_phishing},
                session=session
            )
            
            return True
    
    async def log_audit_event(
        self,
        action: ActionType,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        description: str = "",
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        session: Optional[AsyncIOMotorClientSession] = None
    ) -> AuditLog:
        """Create comprehensive audit log entry."""
        
        audit_log = AuditLog(
            action=action,
            resource_type=resource_type or "system",
            resource_id=resource_id,
            user_id=user_id,
            description=description,
            details=details or {},
            ip_address=ip_address,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Set retention based on compliance requirements
        if action in [ActionType.USER_LOGIN, ActionType.USER_LOGOUT]:
            audit_log.retention_until = datetime.now(timezone.utc) + timedelta(days=90)
            audit_log.compliance_tags = ["security", "access"]
        elif action in [ActionType.THREAT_DETECTED, ActionType.EMAIL_SCAN]:
            audit_log.retention_until = datetime.now(timezone.utc) + timedelta(days=365)
            audit_log.compliance_tags = ["security", "threat_intel"]
        
        if session:
            await audit_log.insert(session=session)
        else:
            await audit_log.insert()
        
        return audit_log
    
    async def update_reputation_cache(
        self,
        indicator: str,
        indicator_type: str,
        reputation_data: Dict[str, Any]
    ) -> ReputationCache:
        """Update or create reputation cache entry."""
        
        # Try to find existing entry
        existing = await ReputationCache.find_one(
            ReputationCache.indicator == indicator
        )
        
        if existing:
            # Update existing
            existing.reputation_level = ReputationLevel(reputation_data.get('level', 'neutral'))
            existing.reputation_score = reputation_data.get('score', 0.5)
            existing.confidence = reputation_data.get('confidence', 0.5)
            existing.last_seen = datetime.now(timezone.utc)
            existing.last_updated = datetime.now(timezone.utc)
            
            # Update statistics
            if 'phishing_count' in reputation_data:
                existing.phishing_emails += reputation_data['phishing_count']
            if 'total_count' in reputation_data:
                existing.total_emails += reputation_data['total_count']
            
            await existing.save()
            return existing
        else:
            # Create new entry
            cache_entry = ReputationCache(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation_level=ReputationLevel(reputation_data.get('level', 'neutral')),
                reputation_score=reputation_data.get('score', 0.5),
                confidence=reputation_data.get('confidence', 0.5),
                sources=reputation_data.get('sources', []),
                total_emails=reputation_data.get('total_count', 0),
                phishing_emails=reputation_data.get('phishing_count', 0)
            )
            await cache_entry.insert()
            return cache_entry
    
    async def create_refresh_token(
        self,
        user_id: str,
        token_value: str,
        expires_in: int = 2592000,  # 30 days
        device_info: Optional[Dict[str, Any]] = None
    ) -> RefreshToken:
        """Create secure refresh token."""
        
        # Hash the token for storage
        hashed_token = bcrypt.hashpw(token_value.encode('utf-8'), bcrypt.gensalt())
        
        refresh_token = RefreshToken(
            user_id=user_id,
            hashed_token=hashed_token.decode('utf-8'),
            token_family=f"family_{secrets.token_hex(8)}",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
            device_info=device_info or {}
        )
        
        await refresh_token.insert()
        return refresh_token
    
    async def cleanup_expired_data(self) -> Dict[str, int]:
        """Clean up expired tokens and old audit logs."""
        
        cleanup_stats = {
            "expired_refresh_tokens": 0,
            "expired_oauth_tokens": 0,
            "old_audit_logs": 0
        }
        
        now = datetime.now(timezone.utc)
        
        # Clean up expired refresh tokens
        expired_refresh = await RefreshToken.find(
            RefreshToken.expires_at < now,
            RefreshToken.revoked == False
        ).to_list()
        
        for token in expired_refresh:
            token.revoked = True
            token.revoked_at = now
            token.revoked_reason = "expired"
            await token.save()
        
        cleanup_stats["expired_refresh_tokens"] = len(expired_refresh)
        
        # Clean up expired OAuth tokens
        expired_oauth = await OAuthCredentials.find(
            OAuthCredentials.expires_at < now
        ).to_list()
        
        for creds in expired_oauth:
            await creds.delete()
        
        cleanup_stats["expired_oauth_tokens"] = len(expired_oauth)
        
        # Clean up old audit logs (based on retention policy)
        old_logs = await AuditLog.find(
            AuditLog.retention_until < now
        ).to_list()
        
        for log in old_logs:
            await log.delete()
        
        cleanup_stats["old_audit_logs"] = len(old_logs)
        
        # Log cleanup activity
        await self.log_audit_event(
            action=ActionType.CONFIG_CHANGE,
            resource_type="system",
            description="Automated data cleanup completed",
            details=cleanup_stats
        )
        
        return cleanup_stats
    
    async def get_user_analytics(self, user_id: str, days: int = 30) -> Dict[str, Any]:
        """Get user analytics for the dashboard."""
        
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Get scan statistics
        scan_results = await ScanResult.find(
            ScanResult.user_id == user_id,
            ScanResult.scan_completed_at >= start_date
        ).to_list()
        
        analytics = {
            "total_scans": len(scan_results),
            "threats_detected": sum(1 for s in scan_results if s.is_phishing),
            "avg_confidence": sum(s.confidence_score for s in scan_results) / len(scan_results) if scan_results else 0,
            "threat_distribution": {},
            "daily_scans": {},
            "top_threats": []
        }
        
        # Calculate threat distribution
        for result in scan_results:
            level = result.threat_level
            analytics["threat_distribution"][level] = analytics["threat_distribution"].get(level, 0) + 1
        
        # Calculate daily scan counts
        for result in scan_results:
            date_key = result.scan_completed_at.date().isoformat()
            analytics["daily_scans"][date_key] = analytics["daily_scans"].get(date_key, 0) + 1
        
        # Get top threat types
        threat_counts = {}
        for result in scan_results:
            for threat in result.detected_threats:
                threat_counts[threat] = threat_counts.get(threat, 0) + 1
        
        analytics["top_threats"] = sorted(
            [(threat, count) for threat, count in threat_counts.items()],
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return analytics


# Global database service instance
db_service = DatabaseService()


# Utility functions for easy access
async def init_production_database():
    """Initialize production database with all models and indexes."""
    try:
        # Connect to MongoDB
        await MongoDBManager.connect_to_mongo()
        
        # Initialize Beanie with production models
        await MongoDBManager.initialize_beanie(PRODUCTION_DOCUMENT_MODELS)
        
        # Create additional indexes
        from .production_models import create_production_indexes
        await create_production_indexes()
        
        logger.info("✅ Production database initialized successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize production database: {e}")
        raise


async def get_database_stats() -> Dict[str, Any]:
    """Get comprehensive database statistics."""
    stats = {
        "collections": {},
        "indexes": {},
        "storage": {}
    }
    
    if MongoDBManager.database:
        # Get collection stats
        for model in PRODUCTION_DOCUMENT_MODELS:
            collection_name = model.Settings.name
            count = await MongoDBManager.database[collection_name].count_documents({})
            stats["collections"][collection_name] = count
        
        # Get database stats
        db_stats = await MongoDBManager.database.command("dbStats")
        stats["storage"] = {
            "total_size": db_stats.get("dataSize", 0),
            "index_size": db_stats.get("indexSize", 0),
            "storage_size": db_stats.get("storageSize", 0)
        }
    
    return stats