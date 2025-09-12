"""Comprehensive security tests for PhishNet authentication system."""

import json
import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, AsyncMock

from app.main import app
from app.core.database import Base, get_db
from app.core.auth import get_auth_service, UserRole
from app.models.user import User, RevokedToken, OAuthToken
from app.config.settings import get_settings


# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_security.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


class TestSecretManagement:
    """Test secret management and configuration security."""
    
    def test_no_hardcoded_secrets_in_settings(self):
        """Verify no hardcoded secrets in settings."""
        settings = get_settings()
        
        # Check that sensitive fields use proper defaults
        assert settings.SECRET_KEY != "your-secret-key"
        assert len(settings.SECRET_KEY) >= 32
        
        # API keys should be None by default (loaded from env/secrets)
        assert settings.GEMINI_API_KEY is None or not settings.GEMINI_API_KEY.startswith("AIza")
        assert settings.VIRUSTOTAL_API_KEY is None or len(settings.VIRUSTOTAL_API_KEY) != 64
    
    def test_environment_based_configuration(self):
        """Test that configuration properly uses environment variables."""
        with patch.dict('os.environ', {
            'SECRET_KEY': 'test-secret-key-32-characters-long',
            'DATABASE_URL': 'sqlite:///test.db'
        }):
            from app.config.settings import Settings
            test_settings = Settings()
            
            assert test_settings.SECRET_KEY == 'test-secret-key-32-characters-long'
            assert test_settings.DATABASE_URL == 'sqlite:///test.db'
    
    def test_secret_key_validation(self):
        """Test that secret key validation works."""
        with pytest.raises(ValueError, match="SECRET_KEY must be at least 32 characters"):
            from app.config.settings import Settings
            Settings(SECRET_KEY="short")


class TestJWTAuthentication:
    """Test JWT authentication system."""
    
    @pytest.fixture
    def auth_service(self):
        settings = get_settings()
        return get_auth_service(settings)
    
    @pytest.fixture
    def test_user_data(self):
        return {
            "id": "123",
            "email": "test@example.com", 
            "role": UserRole.USER,
            "permissions": ["email:read"]
        }
    
    @pytest.mark.asyncio
    async def test_token_creation_and_verification(self, auth_service, test_user_data):
        """Test JWT token creation and verification."""
        # Create tokens
        tokens = await auth_service.create_user_tokens(test_user_data)
        
        assert tokens.access_token
        assert tokens.refresh_token
        assert tokens.token_type == "bearer"
        assert tokens.expires_in > 0
        
        # Verify access token
        payload = await auth_service.jwt_service.verify_token(tokens.access_token)
        
        assert payload.sub == "123"
        assert payload.role == UserRole.USER
        assert "email:read" in payload.permissions
    
    @pytest.mark.asyncio
    async def test_token_expiration(self, auth_service, test_user_data):
        """Test token expiration handling."""
        # Create token with short expiry
        with patch.object(auth_service.jwt_service, 'access_token_expire_minutes', 0):
            tokens = await auth_service.create_user_tokens(test_user_data)
        
        # Token should be expired
        from app.core.auth import ExpiredTokenError
        with pytest.raises(ExpiredTokenError):
            await auth_service.jwt_service.verify_token(tokens.access_token)
    
    @pytest.mark.asyncio
    async def test_refresh_token_flow(self, auth_service, test_user_data):
        """Test refresh token functionality."""
        db = next(override_get_db())
        
        try:
            # Create initial tokens
            tokens = await auth_service.create_user_tokens(test_user_data)
            
            # Refresh access token
            new_tokens = await auth_service.jwt_service.refresh_access_token(
                tokens.refresh_token, db
            )
            
            assert new_tokens.access_token != tokens.access_token
            assert new_tokens.refresh_token  # Should get new refresh token if rotation enabled
            
        finally:
            db.close()
    
    @pytest.mark.asyncio
    async def test_token_revocation(self, auth_service, test_user_data):
        """Test token revocation."""
        db = next(override_get_db())
        
        try:
            tokens = await auth_service.create_user_tokens(test_user_data)
            payload = await auth_service.jwt_service.verify_token(tokens.access_token)
            
            # Revoke token
            await auth_service.jwt_service.revoke_token(payload.jti, db)
            
            # Check if revoked
            is_revoked = await auth_service.jwt_service.is_token_revoked(payload.jti, db)
            assert is_revoked
            
        finally:
            db.close()


class TestPasswordSecurity:
    """Test password security features."""
    
    @pytest.fixture
    def password_service(self):
        settings = get_settings()
        auth_service = get_auth_service(settings)
        return auth_service.password_service
    
    def test_password_hashing(self, password_service):
        """Test password hashing and verification."""
        password = "test_password_123!"
        
        # Hash password
        hashed = password_service.hash_password(password)
        
        # Should be different from original
        assert hashed != password
        assert len(hashed) > 50  # bcrypt produces long hashes
        
        # Verify correct password
        assert password_service.verify_password(password, hashed)
        
        # Verify incorrect password
        assert not password_service.verify_password("wrong_password", hashed)
    
    def test_password_validation(self, password_service):
        """Test password strength validation."""
        # Short password should fail
        with pytest.raises(ValueError, match="at least"):
            password_service.hash_password("short")
        
        # Password without special chars should fail if required
        if password_service.require_special:
            with pytest.raises(ValueError, match="special character"):
                password_service.hash_password("NoSpecialChars123")


class TestAPIAuthentication:
    """Test API endpoint authentication."""
    
    def test_public_endpoints_accessible(self):
        """Test that public endpoints don't require authentication."""
        public_endpoints = [
            "/",
            "/health", 
            "/docs",
            "/api/v1/auth/login"
        ]
        
        for endpoint in public_endpoints:
            response = client.get(endpoint)
            # Should not return 401 (may return 404 or other codes)
            assert response.status_code != 401
    
    def test_protected_endpoints_require_auth(self):
        """Test that protected endpoints require authentication."""
        protected_endpoints = [
            "/api/v1/auth/me",
            "/api/v1/auth/logout"
        ]
        
        for endpoint in protected_endpoints:
            response = client.get(endpoint)
            assert response.status_code == 401
    
    def test_login_success_flow(self):
        """Test successful login flow."""
        # Create test user first
        db = next(override_get_db())
        
        try:
            from app.core.auth import get_auth_service
            auth_service = get_auth_service()
            
            # Create test user
            hashed_password = auth_service.password_service.hash_password("testpass123!")
            test_user = User(
                email="test@example.com",
                username="testuser",
                hashed_password=hashed_password,
                role=UserRole.USER,
                is_active=True
            )
            db.add(test_user)
            db.commit()
            
            # Login
            response = client.post("/api/v1/auth/login", json={
                "email": "test@example.com",
                "password": "testpass123!"
            })
            
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"
            
        finally:
            db.close()
    
    def test_login_failure_flow(self):
        """Test failed login attempts."""
        response = client.post("/api/v1/auth/login", json={
            "email": "nonexistent@example.com", 
            "password": "wrongpassword"
        })
        
        assert response.status_code == 401
        assert "Invalid email or password" in response.json()["detail"]
    
    def test_authenticated_request_flow(self):
        """Test making authenticated requests."""
        # This would need a valid token from login
        # For now, test that invalid token is rejected
        
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/api/v1/auth/me", headers=headers)
        
        assert response.status_code == 401


class TestOAuthSecurity:
    """Test OAuth security features."""
    
    @pytest.fixture
    def oauth_service(self):
        from app.core.oauth_security import get_oauth_service
        return get_oauth_service()
    
    @pytest.mark.asyncio
    async def test_csrf_token_generation_and_validation(self, oauth_service):
        """Test CSRF token security."""
        user_id = "123"
        
        # Generate CSRF token
        csrf_token = await oauth_service.csrf_protection.generate_csrf_token(user_id)
        
        assert csrf_token
        assert "." in csrf_token  # Should have signature
        
        # Validate token
        is_valid = await oauth_service.csrf_protection.validate_csrf_token(
            csrf_token, user_id
        )
        assert is_valid
        
        # Invalid token should fail
        is_valid = await oauth_service.csrf_protection.validate_csrf_token(
            "invalid.token", user_id
        )
        assert not is_valid
        
        # Wrong user should fail
        is_valid = await oauth_service.csrf_protection.validate_csrf_token(
            csrf_token, "wrong_user"
        )
        assert not is_valid
    
    def test_redirect_uri_validation(self, oauth_service):
        """Test redirect URI validation."""
        validator = oauth_service.redirect_validator
        
        # Valid URIs (for development)
        valid_uris = [
            "http://localhost:8000/callback",
            "https://localhost:3000/callback"
        ]
        
        for uri in valid_uris:
            assert validator.validate_redirect_uri(uri)
        
        # Invalid URIs
        invalid_uris = [
            "http://evil.com/callback",
            "javascript:alert(1)",
            "https://example.com/callback#fragment"
        ]
        
        for uri in invalid_uris:
            assert not validator.validate_redirect_uri(uri)
    
    @pytest.mark.asyncio
    async def test_token_encryption_decryption(self, oauth_service):
        """Test OAuth token encryption."""
        original_token = "test_refresh_token_12345"
        
        # Encrypt token
        encrypted = await oauth_service.token_encryption.encrypt_token(original_token)
        
        assert encrypted != original_token
        assert len(encrypted) > len(original_token)  # Base64 encoding increases size
        
        # Decrypt token
        decrypted = await oauth_service.token_encryption.decrypt_token(encrypted)
        
        assert decrypted == original_token


class TestWebSocketSecurity:
    """Test WebSocket authentication."""
    
    def test_websocket_requires_token(self):
        """Test that WebSocket connections require authentication."""
        # This is a simplified test - real WebSocket testing would need more setup
        
        # Try to connect without token
        with pytest.raises(Exception):  # Would raise connection error
            with client.websocket_connect("/ws"):
                pass
        
        # Try with invalid token
        with pytest.raises(Exception):  # Would raise authentication error
            with client.websocket_connect("/ws?token=invalid_token"):
                pass


class TestRoleBasedAccess:
    """Test role-based access control."""
    
    @pytest.mark.asyncio
    async def test_role_permission_mapping(self):
        """Test that roles have correct permissions."""
        from app.models.user import User
        
        # Admin should have all permissions
        admin_user = User(role=UserRole.ADMIN)
        admin_permissions = admin_user.permissions
        
        assert "user:create" in admin_permissions
        assert "system:configure" in admin_permissions
        
        # Analyst should have analysis permissions
        analyst_user = User(role=UserRole.ANALYST)
        analyst_permissions = analyst_user.permissions
        
        assert "email:analyze" in analyst_permissions
        assert "system:configure" not in analyst_permissions  # Should not have admin perms
        
        # User should have minimal permissions
        regular_user = User(role=UserRole.USER)
        user_permissions = regular_user.permissions
        
        assert "email:read" in user_permissions
        assert "email:analyze" not in user_permissions  # Should not have analyst perms


class TestSecurityHeaders:
    """Test security headers and middleware."""
    
    def test_cors_headers(self):
        """Test CORS configuration."""
        # Test preflight request
        response = client.options("/api/v1/auth/login")
        
        # Should have CORS headers (if configured)
        # This depends on your CORS middleware setup
        # assert "Access-Control-Allow-Origin" in response.headers


class TestAuditLogging:
    """Test security audit logging."""
    
    def test_login_audit_logging(self):
        """Test that login attempts are audited."""
        # This would test audit service integration
        # For now, check that login endpoint doesn't crash
        
        response = client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "testpass"
        })
        
        # Should not crash (may return 401 for invalid creds)
        assert response.status_code in [200, 401]


class TestIntegrationSecurity:
    """Integration tests for complete security flows."""
    
    @pytest.mark.asyncio
    async def test_complete_auth_flow(self):
        """Test complete authentication flow."""
        db = next(override_get_db())
        
        try:
            # 1. Register user
            auth_service = get_auth_service()
            hashed_password = auth_service.password_service.hash_password("testpass123!")
            
            test_user = User(
                email="integration@example.com",
                username="integrationuser",
                hashed_password=hashed_password,
                role=UserRole.USER,
                is_active=True
            )
            db.add(test_user)
            db.commit()
            
            # 2. Login
            login_response = client.post("/api/v1/auth/login", json={
                "email": "integration@example.com",
                "password": "testpass123!"
            })
            
            assert login_response.status_code == 200
            tokens = login_response.json()
            
            # 3. Access protected resource
            headers = {"Authorization": f"Bearer {tokens['access_token']}"}
            me_response = client.get("/api/v1/auth/me", headers=headers)
            
            assert me_response.status_code == 200
            user_data = me_response.json()
            assert user_data["email"] == "integration@example.com"
            
            # 4. Refresh token
            refresh_response = client.post("/api/v1/auth/refresh", json={
                "refresh_token": tokens["refresh_token"]
            })
            
            assert refresh_response.status_code == 200
            new_tokens = refresh_response.json()
            assert new_tokens["access_token"] != tokens["access_token"]
            
            # 5. Logout
            logout_response = client.post("/api/v1/auth/logout", headers=headers)
            assert logout_response.status_code == 200
            
            # 6. Try to access with revoked token
            revoked_response = client.get("/api/v1/auth/me", headers=headers)
            assert revoked_response.status_code == 401
            
        finally:
            db.close()


# Test configuration
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
