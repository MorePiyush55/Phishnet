"""
Specialized repositories for PhishNet async models.
Implements business-specific queries and operations.
"""

from typing import Dict, List, Optional, Any
from uuid import UUID
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, joinedload

from app.models.async_models import (
    AsyncUser, AsyncEmail, AsyncThreatResult, AsyncAuditLog, 
    AsyncFeatureFlag, AsyncOAuthToken, AsyncRevokedToken,
    UserRole, EmailStatus, ThreatLevel, AuditAction
)
from app.repositories.base import BaseAsyncRepository, PaginatedResult


class UserRepository(BaseAsyncRepository[AsyncUser]):
    """Repository for user management with authentication features."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, AsyncUser)
    
    def _add_relationship_loads(self, query):
        """Load user relationships when requested."""
        return query.options(
            selectinload(AsyncUser.emails),
            selectinload(AsyncUser.oauth_tokens),
            selectinload(AsyncUser.audit_logs)
        )
    
    async def get_by_email(self, email: str) -> Optional[AsyncUser]:
        """Get user by email address."""
        return await self.get_by_field("email", email)
    
    async def get_by_username(self, username: str) -> Optional[AsyncUser]:
        """Get user by username."""
        return await self.get_by_field("username", username)
    
    async def create_user(
        self, 
        email: str, 
        username: str, 
        password_hash: str,
        full_name: Optional[str] = None,
        role: UserRole = UserRole.USER
    ) -> AsyncUser:
        """Create a new user with required fields."""
        return await self.create(
            email=email,
            username=username,
            password_hash=password_hash,
            full_name=full_name,
            role=role,
            is_active=True,
            is_verified=False,
            login_count=0
        )
    
    async def update_last_login(self, user_id: UUID) -> Optional[AsyncUser]:
        """Update user's last login timestamp and count."""
        user = await self.get_by_id(user_id)
        if user:
            return await self.update(
                user_id,
                last_login_at=datetime.now(timezone.utc),
                login_count=user.login_count + 1
            )
        return None
    
    async def get_active_users(self, role: Optional[UserRole] = None) -> List[AsyncUser]:
        """Get all active users, optionally filtered by role."""
        filters = {"is_active": True}
        if role:
            filters["role"] = role
        
        return await self.get_multi(filters=filters, order_by="-last_login_at")
    
    async def search_users(self, query: str, page: int = 1, per_page: int = 20) -> PaginatedResult[AsyncUser]:
        """Search users by email, username, or full name."""
        return await self.search(
            query_text=query,
            search_fields=["email", "username", "full_name"],
            page=page,
            per_page=per_page,
            filters={"is_active": True}
        )


class EmailRepository(BaseAsyncRepository[AsyncEmail]):
    """Repository for email management and analysis."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, AsyncEmail)
    
    def _add_relationship_loads(self, query):
        """Load email relationships when requested."""
        return query.options(
            joinedload(AsyncEmail.user),
            selectinload(AsyncEmail.threat_results)
        )
    
    async def create_email(
        self,
        user_id: UUID,
        subject: str,
        sender: str,
        recipients: List[str],
        body_text: Optional[str] = None,
        body_html: Optional[str] = None,
        headers: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        file_hash: Optional[str] = None,
        file_size: Optional[int] = None
    ) -> AsyncEmail:
        """Create a new email for analysis."""
        return await self.create(
            user_id=user_id,
            subject=subject,
            sender=sender,
            recipients=recipients,
            body_text=body_text,
            body_html=body_html,
            headers=headers or {},
            message_id=message_id,
            file_hash=file_hash,
            file_size=file_size,
            status=EmailStatus.PENDING,
            threat_level=ThreatLevel.UNKNOWN
        )
    
    async def get_user_emails(
        self, 
        user_id: UUID, 
        page: int = 1, 
        per_page: int = 20,
        status: Optional[EmailStatus] = None
    ) -> PaginatedResult[AsyncEmail]:
        """Get emails for a specific user with pagination."""
        filters = {"user_id": user_id}
        if status:
            filters["status"] = status
        
        return await self.paginate(
            page=page,
            per_page=per_page,
            filters=filters,
            order_by="-created_at",
            load_relationships=True
        )
    
    async def update_analysis_status(
        self, 
        email_id: UUID, 
        status: EmailStatus,
        threat_level: Optional[ThreatLevel] = None,
        confidence_score: Optional[float] = None,
        processing_time: Optional[float] = None
    ) -> Optional[AsyncEmail]:
        """Update email analysis status and results."""
        update_data = {"status": status}
        
        if threat_level:
            update_data["threat_level"] = threat_level
        if confidence_score is not None:
            update_data["confidence_score"] = confidence_score
        if processing_time is not None:
            update_data["processing_time"] = processing_time
        
        return await self.update(email_id, **update_data)
    
    async def get_pending_emails(self, limit: int = 50) -> List[AsyncEmail]:
        """Get emails pending analysis."""
        return await self.get_multi(
            filters={"status": EmailStatus.PENDING},
            limit=limit,
            order_by="created_at"
        )
    
    async def get_threat_summary(self, user_id: Optional[UUID] = None) -> Dict[str, int]:
        """Get threat level summary statistics."""
        base_query = select(
            AsyncEmail.threat_level,
            func.count(AsyncEmail.id).label('count')
        ).group_by(AsyncEmail.threat_level)
        
        if user_id:
            base_query = base_query.where(AsyncEmail.user_id == user_id)
        
        result = await self.session.execute(base_query)
        
        summary = {level.value: 0 for level in ThreatLevel}
        for threat_level, count in result:
            summary[threat_level.value] = count
        
        return summary
    
    async def search_emails(
        self,
        query: str,
        user_id: Optional[UUID] = None,
        threat_level: Optional[ThreatLevel] = None,
        page: int = 1,
        per_page: int = 20
    ) -> PaginatedResult[AsyncEmail]:
        """Search emails by subject, sender, or content."""
        filters = {}
        if user_id:
            filters["user_id"] = user_id
        if threat_level:
            filters["threat_level"] = threat_level
        
        return await self.search(
            query_text=query,
            search_fields=["subject", "sender", "body_text"],
            page=page,
            per_page=per_page,
            filters=filters
        )


class ThreatResultRepository(BaseAsyncRepository[AsyncThreatResult]):
    """Repository for threat analysis results."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, AsyncThreatResult)
    
    def _add_relationship_loads(self, query):
        """Load threat result relationships when requested."""
        return query.options(joinedload(AsyncThreatResult.email))
    
    async def create_threat_result(
        self,
        email_id: UUID,
        source: str,
        threat_level: ThreatLevel,
        confidence_score: float,
        raw_response: Dict[str, Any],
        source_id: Optional[str] = None,
        indicators: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        analysis_duration: Optional[float] = None,
        cached: bool = False
    ) -> AsyncThreatResult:
        """Create a new threat analysis result."""
        return await self.create(
            email_id=email_id,
            source=source,
            threat_level=threat_level,
            confidence_score=confidence_score,
            raw_response=raw_response,
            source_id=source_id,
            indicators=indicators or [],
            categories=categories or [],
            tags=tags or [],
            analysis_duration=analysis_duration,
            cached=cached
        )
    
    async def get_email_results(self, email_id: UUID) -> List[AsyncThreatResult]:
        """Get all threat results for an email."""
        return await self.get_multi(
            filters={"email_id": email_id},
            order_by="-created_at"
        )
    
    async def get_source_results(
        self, 
        source: str, 
        threat_level: Optional[ThreatLevel] = None
    ) -> List[AsyncThreatResult]:
        """Get results from a specific analysis source."""
        filters = {"source": source}
        if threat_level:
            filters["threat_level"] = threat_level
        
        return await self.get_multi(
            filters=filters,
            order_by="-confidence_score"
        )
    
    async def get_performance_stats(self, source: str) -> Dict[str, Any]:
        """Get performance statistics for an analysis source."""
        query = select(
            func.count(AsyncThreatResult.id).label('total_analyses'),
            func.avg(AsyncThreatResult.confidence_score).label('avg_confidence'),
            func.avg(AsyncThreatResult.analysis_duration).label('avg_duration'),
            func.sum(func.cast(AsyncThreatResult.cached, func.Integer)).label('cached_results')
        ).where(AsyncThreatResult.source == source)
        
        result = await self.session.execute(query)
        row = result.first()
        
        return {
            'total_analyses': row.total_analyses or 0,
            'avg_confidence': float(row.avg_confidence or 0),
            'avg_duration': float(row.avg_duration or 0),
            'cached_results': row.cached_results or 0,
            'cache_rate': (row.cached_results or 0) / max(row.total_analyses or 1, 1) * 100
        }


class AuditLogRepository(BaseAsyncRepository[AsyncAuditLog]):
    """Repository for audit logging and security tracking."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, AsyncAuditLog)
    
    def _add_relationship_loads(self, query):
        """Load audit log relationships when requested."""
        return query.options(joinedload(AsyncAuditLog.user))
    
    async def log_action(
        self,
        action: AuditAction,
        description: str,
        user_id: Optional[UUID] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AsyncAuditLog:
        """Create an audit log entry."""
        return await self.create(
            action=action,
            description=description,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata=metadata or {}
        )
    
    async def get_user_activity(
        self, 
        user_id: UUID, 
        page: int = 1, 
        per_page: int = 50,
        action: Optional[AuditAction] = None
    ) -> PaginatedResult[AsyncAuditLog]:
        """Get activity logs for a specific user."""
        filters = {"user_id": user_id}
        if action:
            filters["action"] = action
        
        return await self.paginate(
            page=page,
            per_page=per_page,
            filters=filters,
            order_by="-created_at"
        )
    
    async def get_security_events(
        self, 
        hours: int = 24,
        actions: Optional[List[AuditAction]] = None
    ) -> List[AsyncAuditLog]:
        """Get security-related events in the last N hours."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        query = select(AsyncAuditLog).where(AsyncAuditLog.created_at >= since)
        
        if actions:
            query = query.where(AsyncAuditLog.action.in_(actions))
        else:
            # Default security-related actions
            security_actions = [AuditAction.LOGIN, AuditAction.LOGOUT, AuditAction.THREAT_DETECTED]
            query = query.where(AsyncAuditLog.action.in_(security_actions))
        
        query = query.order_by(desc(AsyncAuditLog.created_at))
        
        result = await self.session.execute(query)
        return result.scalars().all()


class FeatureFlagRepository(BaseAsyncRepository[AsyncFeatureFlag]):
    """Repository for feature flag management."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, AsyncFeatureFlag)
    
    async def get_by_name(self, name: str) -> Optional[AsyncFeatureFlag]:
        """Get feature flag by name."""
        return await self.get_by_field("name", name)
    
    async def is_enabled(self, name: str, user_email: Optional[str] = None, user_role: Optional[UserRole] = None) -> bool:
        """Check if a feature flag is enabled for a user."""
        flag = await self.get_by_name(name)
        
        if not flag or not flag.is_enabled:
            return False
        
        # Check date constraints
        now = datetime.now(timezone.utc)
        if flag.start_date and now < flag.start_date:
            return False
        if flag.end_date and now > flag.end_date:
            return False
        
        # Check user targeting
        if user_email and flag.user_emails and user_email not in flag.user_emails:
            return False
        
        if user_role and flag.user_roles and user_role.value not in flag.user_roles:
            return False
        
        # Check percentage rollout
        if flag.percentage < 100 and user_email:
            import hashlib
            hash_input = f"{name}:{user_email}".encode()
            user_hash = int(hashlib.md5(hash_input).hexdigest(), 16)
            user_percentage = user_hash % 100
            return user_percentage < flag.percentage
        
        return flag.percentage > 0
    
    async def get_active_flags(self) -> List[AsyncFeatureFlag]:
        """Get all currently active feature flags."""
        now = datetime.now(timezone.utc)
        
        query = select(AsyncFeatureFlag).where(
            and_(
                AsyncFeatureFlag.is_enabled == True,
                or_(
                    AsyncFeatureFlag.start_date.is_(None),
                    AsyncFeatureFlag.start_date <= now
                ),
                or_(
                    AsyncFeatureFlag.end_date.is_(None),
                    AsyncFeatureFlag.end_date >= now
                )
            )
        )
        
        result = await self.session.execute(query)
        return result.scalars().all()


class OAuthTokenRepository(BaseAsyncRepository[AsyncOAuthToken]):
    """Repository for OAuth token management."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, AsyncOAuthToken)
    
    def _add_relationship_loads(self, query):
        """Load OAuth token relationships when requested."""
        return query.options(joinedload(AsyncOAuthToken.user))
    
    async def get_user_token(self, user_id: UUID, provider: str) -> Optional[AsyncOAuthToken]:
        """Get OAuth token for user and provider."""
        query = select(AsyncOAuthToken).where(
            and_(
                AsyncOAuthToken.user_id == user_id,
                AsyncOAuthToken.provider == provider
            )
        )
        
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def cleanup_expired_tokens(self) -> int:
        """Clean up expired OAuth tokens."""
        now = datetime.now(timezone.utc)
        
        query = select(AsyncOAuthToken.id).where(
            and_(
                AsyncOAuthToken.expires_at.isnot(None),
                AsyncOAuthToken.expires_at < now
            )
        )
        
        result = await self.session.execute(query)
        expired_ids = [row[0] for row in result]
        
        if expired_ids:
            delete_query = delete(AsyncOAuthToken).where(AsyncOAuthToken.id.in_(expired_ids))
            await self.session.execute(delete_query)
            await self.session.commit()
        
        return len(expired_ids)


class RevokedTokenRepository(BaseAsyncRepository[AsyncRevokedToken]):
    """Repository for revoked JWT token tracking."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, AsyncRevokedToken)
    
    async def is_revoked(self, jti: str) -> bool:
        """Check if a token JTI is revoked."""
        return await self.exists(jti=jti)
    
    async def revoke_token(
        self, 
        jti: str, 
        token_type: str, 
        user_id: UUID,
        expires_at: datetime,
        reason: Optional[str] = None
    ) -> AsyncRevokedToken:
        """Add a token to the revocation list."""
        return await self.create(
            jti=jti,
            token_type=token_type,
            user_id=user_id,
            expires_at=expires_at,
            reason=reason
        )
    
    async def cleanup_expired_tokens(self) -> int:
        """Clean up expired revoked tokens."""
        now = datetime.now(timezone.utc)
        
        query = delete(AsyncRevokedToken).where(AsyncRevokedToken.expires_at < now)
        result = await self.session.execute(query)
        await self.session.commit()
        
        return result.rowcount
