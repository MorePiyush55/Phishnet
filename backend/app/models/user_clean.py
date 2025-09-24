"""User model for authentication and user management."""

from datetime import datetime, timedelta
from typing import Optional
import enum

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, Enum, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship

from app.core.database import Base

# Define UserRole enum locally to avoid circular imports
class UserRole(enum.Enum):
    VIEWER = "viewer"
    USER = "user"
    ADMIN = "admin"
    SUPERUSER = "superuser"


class User(Base):
    """User model for authentication and user management."""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(200), nullable=True)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
    disabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Google OAuth specific fields per specifications
    google_sub = Column(String(255), unique=True, nullable=True, index=True)  # Google user ID
    display_name = Column(String(200), nullable=True)  # Google display name
    connected_at = Column(DateTime, nullable=True)  # When OAuth was completed
    disconnected_at = Column(DateTime, nullable=True)  # When OAuth was revoked
    status = Column(String(50), default="disconnected")  # connected, disconnected, error, expired
    
    # Legacy Gmail fields (keeping for backward compatibility)
    gmail_credentials = Column(Text, nullable=True)
    gmail_watch_expiration = Column(DateTime, nullable=True)
    email_monitoring_enabled = Column(Boolean, default=False)
    last_email_scan = Column(DateTime, nullable=True)
    
    # Enhanced Gmail OAuth fields
    gmail_connected = Column(Boolean, default=False)
    gmail_email = Column(String(255), nullable=True)  # Connected Gmail address
    gmail_scopes_granted = Column(Text, nullable=True)  # JSON array of granted scopes
    gmail_connection_date = Column(DateTime, nullable=True)
    gmail_last_token_refresh = Column(DateTime, nullable=True)
    gmail_consent_version = Column(String(50), nullable=True)  # Track consent version
    gmail_status = Column(String(50), default="disconnected")  # connected, disconnected, error, expired
    
    # Gmail watch/real-time monitoring fields
    gmail_watch_history_id = Column(String(100), nullable=True)  # Gmail watch history ID
    gmail_watch_expiration = Column(DateTime, nullable=True)  # Watch expiration timestamp
    gmail_realtime_enabled = Column(Boolean, default=False)  # Real-time monitoring enabled
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}')>"


class OAuthCredential(Base):
    """OAuth credentials storage with encryption."""
    
    __tablename__ = "oauth_credentials"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    provider = Column(String(50), nullable=False)  # google, microsoft, etc.
    provider_user_id = Column(String(255), nullable=False)  # OAuth provider's user ID
    access_token = Column(Text, nullable=False)  # Encrypted access token
    refresh_token = Column(Text, nullable=True)  # Encrypted refresh token
    token_expires_at = Column(DateTime, nullable=True)
    scopes = Column(Text, nullable=True)  # JSON array of granted scopes
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    user = relationship("User", back_populates="oauth_credentials")


class RevokedToken(Base):
    """Model to track revoked JWT tokens for security."""
    
    __tablename__ = "revoked_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(255), unique=True, index=True, nullable=False)  # JWT ID
    user_id = Column(String(255), nullable=True)  # For user-wide revocation
    revoked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reason = Column(String(255), nullable=True)  # Reason for revocation
    
    def __repr__(self) -> str:
        return f"<RevokedToken(jti='{self.jti}', revoked_at={self.revoked_at})>"


class OAuthToken(Base):
    """Model to store encrypted OAuth refresh tokens."""
    
    __tablename__ = "oauth_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    provider = Column(String(50), nullable=False)  # 'gmail', 'outlook', etc.
    encrypted_refresh_token = Column(Text, nullable=False)  # Encrypted token
    encrypted_access_token = Column(Text, nullable=True)  # Encrypted current access token
    token_expires_at = Column(DateTime, nullable=True)
    scope = Column(String(500), nullable=True)  # OAuth scopes granted
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Security and audit fields
    creation_ip = Column(String(45), nullable=True)  # IP when token was created
    creation_user_agent = Column(String(500), nullable=True)
    revocation_reason = Column(String(255), nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    
    def __init__(self, **kwargs):
        """Initialize OAuthToken with encryption setup."""
        super().__init__(**kwargs)
        self._token_encryptor = None
    
    @property
    def token_encryptor(self):
        """Get token encryptor instance."""
        if self._token_encryptor is None:
            from app.core.config import settings
            from app.privacy import TokenEncryption
            self._token_encryptor = TokenEncryption(settings.privacy_encryption_key)
        return self._token_encryptor
    
    def encrypt_access_token(self, access_token: str) -> None:
        """Encrypt and store access token."""
        if access_token:
            self.encrypted_access_token = self.token_encryptor.encrypt_token(access_token)
    
    def decrypt_access_token(self) -> str:
        """Decrypt and return access token."""
        if self.encrypted_access_token:
            return self.token_encryptor.decrypt_token(self.encrypted_access_token)
        return ""
    
    def encrypt_refresh_token(self, refresh_token: str) -> None:
        """Encrypt and store refresh token."""
        if refresh_token:
            self.encrypted_refresh_token = self.token_encryptor.encrypt_token(refresh_token)
    
    def decrypt_refresh_token(self) -> str:
        """Decrypt and return refresh token."""
        if self.encrypted_refresh_token:
            return self.token_encryptor.decrypt_token(self.encrypted_refresh_token)
        return ""
    
    def is_expired(self) -> bool:
        """Check if access token is expired."""
        if not self.token_expires_at:
            return True
        return datetime.utcnow() >= self.token_expires_at
    
    async def refresh_access_token(self, db_session=None) -> bool:
        """Refresh the access token using the refresh token."""
        try:
            import httpx
            from app.core.config import settings
            
            refresh_token = self.decrypt_refresh_token()
            if not refresh_token:
                return False
            
            # Make request to Google OAuth2 token endpoint
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "client_id": settings.google_client_id,
                        "client_secret": settings.google_client_secret,
                        "refresh_token": refresh_token,
                        "grant_type": "refresh_token"
                    }
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    
                    # Update access token
                    new_access_token = token_data.get("access_token")
                    expires_in = token_data.get("expires_in", 3600)
                    
                    if new_access_token:
                        self.encrypt_access_token(new_access_token)
                        self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in - 300)  # 5 min buffer
                        self.updated_at = datetime.utcnow()
                        self.last_used_at = datetime.utcnow()
                        
                        # Update refresh token if provided
                        new_refresh_token = token_data.get("refresh_token")
                        if new_refresh_token:
                            self.encrypt_refresh_token(new_refresh_token)
                        
                        # Save to database if session provided
                        if db_session:
                            db_session.commit()
                        
                        return True
                else:
                    print(f"Token refresh failed: {response.status_code} - {response.text}")
                    return False
                    
        except Exception as e:
            print(f"Error refreshing token: {e}")
            return False
    
    async def get_valid_access_token(self, db_session=None) -> str:
        """Get a valid access token, refreshing if necessary."""
        # If token is not expired, return it
        if not self.is_expired():
            return self.decrypt_access_token()
        
        # Try to refresh the token
        if await self.refresh_access_token(db_session):
            return self.decrypt_access_token()
        
        # If refresh failed, token is invalid
        return ""
    
    def __repr__(self) -> str:
        return f"<OAuthToken(user_id={self.user_id}, provider='{self.provider}', active={self.is_active})>"


class OAuthAuditLog(Base):
    """OAuth audit log for OAuth-related events."""
    
    __tablename__ = "oauth_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # connect, disconnect, token_refresh, scope_change
    provider = Column(String(50), nullable=False)
    details = Column(Text, nullable=True)  # JSON details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)
    
    def __repr__(self) -> str:
        return f"<OAuthAuditLog(user_id={self.user_id}, event='{self.event_type}', success={self.success})>"


# Add back_populates relationships
User.oauth_credentials = relationship("OAuthCredential", back_populates="user")