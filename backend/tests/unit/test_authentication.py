"""
Unit tests for authentication and authorization systems.
Tests JWT handling, API key validation, and security middleware.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
import jwt
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer
import secrets

from app.auth.jwt_handler import JWTHandler
from app.auth.api_key_validator import APIKeyValidator
from app.auth.middleware import AuthenticationMiddleware
from app.models.user import User, UserRole


@pytest.fixture
def jwt_handler():
    """Create JWTHandler instance for testing."""
    return JWTHandler(
        secret_key="test-secret-key-for-testing-only",
        algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7
    )


@pytest.fixture
def api_key_validator():
    """Create APIKeyValidator instance for testing."""
    return APIKeyValidator()


@pytest.fixture
def sample_user():
    """Create sample user for testing."""
    return User(
        id=1,
        username="testuser",
        email="test@example.com",
        role=UserRole.USER,
        is_active=True,
        created_at=datetime.utcnow()
    )


@pytest.fixture
def sample_admin_user():
    """Create sample admin user for testing."""
    return User(
        id=2,
        username="admin",
        email="admin@example.com",
        role=UserRole.ADMIN,
        is_active=True,
        created_at=datetime.utcnow()
    )


class TestJWTHandler:
    """Test suite for JWT handling."""
    
    def test_jwt_handler_initialization(self, jwt_handler):
        """Test JWT handler initializes correctly."""
        assert jwt_handler.secret_key == "test-secret-key-for-testing-only"
        assert jwt_handler.algorithm == "HS256"
        assert jwt_handler.access_token_expire_minutes == 30
        assert jwt_handler.refresh_token_expire_days == 7
    
    def test_create_access_token(self, jwt_handler, sample_user):
        """Test access token creation."""
        token = jwt_handler.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role
        )
        
        assert token is not None
        assert isinstance(token, str)
        
        # Decode and verify token
        payload = jwt.decode(
            token,
            jwt_handler.secret_key,
            algorithms=[jwt_handler.algorithm]
        )
        
        assert payload["user_id"] == sample_user.id
        assert payload["username"] == sample_user.username
        assert payload["role"] == sample_user.role.value
        assert payload["type"] == "access"
        assert "exp" in payload
        assert "iat" in payload
    
    def test_create_refresh_token(self, jwt_handler, sample_user):
        """Test refresh token creation."""
        token = jwt_handler.create_refresh_token(
            user_id=sample_user.id,
            username=sample_user.username
        )
        
        assert token is not None
        assert isinstance(token, str)
        
        # Decode and verify token
        payload = jwt.decode(
            token,
            jwt_handler.secret_key,
            algorithms=[jwt_handler.algorithm]
        )
        
        assert payload["user_id"] == sample_user.id
        assert payload["username"] == sample_user.username
        assert payload["type"] == "refresh"
        assert "exp" in payload
        assert "iat" in payload
    
    def test_verify_token_valid(self, jwt_handler, sample_user):
        """Test verification of valid token."""
        token = jwt_handler.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role
        )
        
        payload = jwt_handler.verify_token(token)
        
        assert payload is not None
        assert payload["user_id"] == sample_user.id
        assert payload["username"] == sample_user.username
        assert payload["role"] == sample_user.role.value
    
    def test_verify_token_invalid(self, jwt_handler):
        """Test verification of invalid token."""
        invalid_token = "invalid.token.here"
        
        with pytest.raises(HTTPException) as exc_info:
            jwt_handler.verify_token(invalid_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_verify_token_expired(self, jwt_handler, sample_user):
        """Test verification of expired token."""
        # Create token with very short expiry
        expired_payload = {
            "user_id": sample_user.id,
            "username": sample_user.username,
            "role": sample_user.role.value,
            "type": "access",
            "exp": datetime.utcnow() - timedelta(minutes=1),  # Expired
            "iat": datetime.utcnow() - timedelta(minutes=2)
        }
        
        expired_token = jwt.encode(
            expired_payload,
            jwt_handler.secret_key,
            algorithm=jwt_handler.algorithm
        )
        
        with pytest.raises(HTTPException) as exc_info:
            jwt_handler.verify_token(expired_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "expired" in exc_info.value.detail.lower()
    
    def test_verify_token_wrong_type(self, jwt_handler, sample_user):
        """Test verification of token with wrong type."""
        refresh_token = jwt_handler.create_refresh_token(
            user_id=sample_user.id,
            username=sample_user.username
        )
        
        # Try to verify refresh token as access token
        with pytest.raises(HTTPException) as exc_info:
            jwt_handler.verify_token(refresh_token, expected_type="access")
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_refresh_access_token(self, jwt_handler, sample_user):
        """Test refreshing access token."""
        refresh_token = jwt_handler.create_refresh_token(
            user_id=sample_user.id,
            username=sample_user.username
        )
        
        new_access_token = jwt_handler.refresh_access_token(
            refresh_token=refresh_token,
            role=sample_user.role
        )
        
        assert new_access_token is not None
        
        # Verify new token
        payload = jwt_handler.verify_token(new_access_token)
        assert payload["user_id"] == sample_user.id
        assert payload["type"] == "access"
    
    def test_token_expiry_calculation(self, jwt_handler):
        """Test token expiry time calculations."""
        now = datetime.utcnow()
        
        # Test access token expiry
        access_expiry = jwt_handler._calculate_expiry(
            minutes=jwt_handler.access_token_expire_minutes
        )
        expected_access = now + timedelta(minutes=30)
        assert abs((access_expiry - expected_access).total_seconds()) < 60
        
        # Test refresh token expiry
        refresh_expiry = jwt_handler._calculate_expiry(
            days=jwt_handler.refresh_token_expire_days
        )
        expected_refresh = now + timedelta(days=7)
        assert abs((refresh_expiry - expected_refresh).total_seconds()) < 60
    
    def test_secret_key_validation(self):
        """Test secret key validation."""
        # Test weak secret key
        with pytest.raises(ValueError):
            JWTHandler(secret_key="weak", algorithm="HS256")
        
        # Test strong secret key
        strong_key = secrets.token_urlsafe(32)
        handler = JWTHandler(secret_key=strong_key, algorithm="HS256")
        assert handler.secret_key == strong_key
    
    def test_algorithm_validation(self):
        """Test algorithm validation."""
        valid_algorithms = ["HS256", "HS384", "HS512", "RS256"]
        
        for algo in valid_algorithms:
            handler = JWTHandler(
                secret_key="test-secret-key-for-testing-only",
                algorithm=algo
            )
            assert handler.algorithm == algo
        
        # Test invalid algorithm
        with pytest.raises(ValueError):
            JWTHandler(
                secret_key="test-secret-key-for-testing-only",
                algorithm="INVALID"
            )


class TestAPIKeyValidator:
    """Test suite for API key validation."""
    
    def test_api_key_validator_initialization(self, api_key_validator):
        """Test API key validator initializes correctly."""
        assert api_key_validator is not None
        assert hasattr(api_key_validator, 'validate_api_key')
        assert hasattr(api_key_validator, 'create_api_key')
    
    def test_create_api_key(self, api_key_validator):
        """Test API key creation."""
        api_key = api_key_validator.create_api_key(
            user_id=1,
            name="Test API Key",
            permissions=["url:analyze", "reports:read"]
        )
        
        assert api_key is not None
        assert len(api_key) >= 32  # Should be sufficiently long
        assert api_key.startswith("phishnet_")  # Should have prefix
    
    def test_validate_api_key_valid(self, api_key_validator):
        """Test validation of valid API key."""
        # Mock database lookup
        with patch.object(api_key_validator, '_get_api_key_from_db') as mock_get:
            mock_get.return_value = {
                "id": 1,
                "user_id": 1,
                "name": "Test Key",
                "permissions": ["url:analyze"],
                "is_active": True,
                "created_at": datetime.utcnow(),
                "last_used": None
            }
            
            result = api_key_validator.validate_api_key("phishnet_test123")
            
            assert result is not None
            assert result["user_id"] == 1
            assert "url:analyze" in result["permissions"]
    
    def test_validate_api_key_invalid(self, api_key_validator):
        """Test validation of invalid API key."""
        with patch.object(api_key_validator, '_get_api_key_from_db') as mock_get:
            mock_get.return_value = None
            
            with pytest.raises(HTTPException) as exc_info:
                api_key_validator.validate_api_key("invalid_key")
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_validate_api_key_inactive(self, api_key_validator):
        """Test validation of inactive API key."""
        with patch.object(api_key_validator, '_get_api_key_from_db') as mock_get:
            mock_get.return_value = {
                "id": 1,
                "user_id": 1,
                "name": "Inactive Key",
                "permissions": ["url:analyze"],
                "is_active": False,  # Inactive
                "created_at": datetime.utcnow(),
                "last_used": None
            }
            
            with pytest.raises(HTTPException) as exc_info:
                api_key_validator.validate_api_key("phishnet_inactive123")
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "inactive" in exc_info.value.detail.lower()
    
    def test_check_permission(self, api_key_validator):
        """Test permission checking."""
        permissions = ["url:analyze", "reports:read", "admin:*"]
        
        # Test exact permission match
        assert api_key_validator.check_permission(permissions, "url:analyze")
        assert api_key_validator.check_permission(permissions, "reports:read")
        
        # Test wildcard permission
        assert api_key_validator.check_permission(permissions, "admin:users")
        assert api_key_validator.check_permission(permissions, "admin:settings")
        
        # Test no permission
        assert not api_key_validator.check_permission(permissions, "reports:write")
        assert not api_key_validator.check_permission(permissions, "users:delete")
    
    def test_api_key_format_validation(self, api_key_validator):
        """Test API key format validation."""
        valid_keys = [
            "phishnet_abc123def456",
            "phishnet_0123456789abcdef",
            "phishnet_" + "a" * 32
        ]
        
        invalid_keys = [
            "invalid_prefix_123",
            "phishnet_",  # Too short
            "phishnet_abc",  # Too short
            "",  # Empty
            None,  # None
            "phishnet_abc123!@#"  # Invalid characters
        ]
        
        for key in valid_keys:
            assert api_key_validator._is_valid_format(key)
        
        for key in invalid_keys:
            assert not api_key_validator._is_valid_format(key)
    
    def test_api_key_usage_tracking(self, api_key_validator):
        """Test API key usage tracking."""
        api_key = "phishnet_test123"
        
        with patch.object(api_key_validator, '_update_last_used') as mock_update:
            with patch.object(api_key_validator, '_get_api_key_from_db') as mock_get:
                mock_get.return_value = {
                    "id": 1,
                    "user_id": 1,
                    "name": "Test Key",
                    "permissions": ["url:analyze"],
                    "is_active": True,
                    "created_at": datetime.utcnow(),
                    "last_used": None
                }
                
                api_key_validator.validate_api_key(api_key)
                
                # Should update last used timestamp
                mock_update.assert_called_once_with(1)
    
    def test_rate_limiting_by_api_key(self, api_key_validator):
        """Test rate limiting by API key."""
        api_key = "phishnet_ratelimit123"
        
        with patch.object(api_key_validator, '_check_rate_limit') as mock_rate_limit:
            mock_rate_limit.return_value = False  # Rate limit exceeded
            
            with patch.object(api_key_validator, '_get_api_key_from_db') as mock_get:
                mock_get.return_value = {
                    "id": 1,
                    "user_id": 1,
                    "name": "Rate Limited Key",
                    "permissions": ["url:analyze"],
                    "is_active": True,
                    "created_at": datetime.utcnow(),
                    "last_used": None
                }
                
                with pytest.raises(HTTPException) as exc_info:
                    api_key_validator.validate_api_key(api_key)
                
                assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS


class TestAuthenticationMiddleware:
    """Test suite for authentication middleware."""
    
    @pytest.fixture
    def auth_middleware(self, jwt_handler, api_key_validator):
        """Create authentication middleware for testing."""
        return AuthenticationMiddleware(
            jwt_handler=jwt_handler,
            api_key_validator=api_key_validator
        )
    
    @pytest.mark.asyncio
    async def test_jwt_authentication(self, auth_middleware, jwt_handler, sample_user):
        """Test JWT authentication flow."""
        token = jwt_handler.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role
        )
        
        # Mock request with JWT token
        mock_request = Mock()
        mock_request.headers = {"Authorization": f"Bearer {token}"}
        mock_request.url.path = "/api/v1/analyze"
        
        # Mock call_next
        mock_call_next = AsyncMock()
        mock_response = Mock()
        mock_call_next.return_value = mock_response
        
        result = await auth_middleware(mock_request, mock_call_next)
        
        # Should authenticate successfully
        assert result == mock_response
        assert hasattr(mock_request.state, 'user')
        assert mock_request.state.user["user_id"] == sample_user.id
        mock_call_next.assert_called_once_with(mock_request)
    
    @pytest.mark.asyncio
    async def test_api_key_authentication(self, auth_middleware, api_key_validator):
        """Test API key authentication flow."""
        # Mock request with API key
        mock_request = Mock()
        mock_request.headers = {"X-API-Key": "phishnet_test123"}
        mock_request.url.path = "/api/v1/analyze"
        
        # Mock API key validation
        with patch.object(api_key_validator, 'validate_api_key') as mock_validate:
            mock_validate.return_value = {
                "id": 1,
                "user_id": 1,
                "permissions": ["url:analyze"]
            }
            
            mock_call_next = AsyncMock()
            mock_response = Mock()
            mock_call_next.return_value = mock_response
            
            result = await auth_middleware(mock_request, mock_call_next)
            
            assert result == mock_response
            assert hasattr(mock_request.state, 'api_key')
            mock_call_next.assert_called_once_with(mock_request)
    
    @pytest.mark.asyncio
    async def test_public_endpoint_bypass(self, auth_middleware):
        """Test that public endpoints bypass authentication."""
        public_paths = [
            "/",
            "/health",
            "/docs",
            "/openapi.json",
            "/metrics"
        ]
        
        for path in public_paths:
            mock_request = Mock()
            mock_request.headers = {}
            mock_request.url.path = path
            
            mock_call_next = AsyncMock()
            mock_response = Mock()
            mock_call_next.return_value = mock_response
            
            result = await auth_middleware(mock_request, mock_call_next)
            
            assert result == mock_response
            mock_call_next.assert_called_once_with(mock_request)
            mock_call_next.reset_mock()
    
    @pytest.mark.asyncio
    async def test_missing_authentication(self, auth_middleware):
        """Test handling of missing authentication."""
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.url.path = "/api/v1/analyze"
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_middleware(mock_request, Mock())
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_invalid_token_format(self, auth_middleware):
        """Test handling of invalid token format."""
        mock_request = Mock()
        mock_request.headers = {"Authorization": "InvalidFormat token"}
        mock_request.url.path = "/api/v1/analyze"
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_middleware(mock_request, Mock())
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_role_based_authorization(self, auth_middleware, jwt_handler, sample_user, sample_admin_user):
        """Test role-based authorization."""
        # Create tokens for different roles
        user_token = jwt_handler.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role
        )
        
        admin_token = jwt_handler.create_access_token(
            user_id=sample_admin_user.id,
            username=sample_admin_user.username,
            role=sample_admin_user.role
        )
        
        # Test admin endpoint access
        admin_request = Mock()
        admin_request.headers = {"Authorization": f"Bearer {admin_token}"}
        admin_request.url.path = "/api/v1/admin/users"
        
        mock_call_next = AsyncMock()
        mock_response = Mock()
        mock_call_next.return_value = mock_response
        
        # Admin should have access
        result = await auth_middleware(admin_request, mock_call_next)
        assert result == mock_response
        
        # Regular user should be denied
        user_request = Mock()
        user_request.headers = {"Authorization": f"Bearer {user_token}"}
        user_request.url.path = "/api/v1/admin/users"
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_middleware(user_request, Mock())
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    
    @pytest.mark.asyncio
    async def test_permission_based_authorization(self, auth_middleware, api_key_validator):
        """Test permission-based authorization for API keys."""
        # Mock request requiring specific permission
        mock_request = Mock()
        mock_request.headers = {"X-API-Key": "phishnet_limited123"}
        mock_request.url.path = "/api/v1/reports"
        mock_request.method = "POST"
        
        # API key with insufficient permissions
        with patch.object(api_key_validator, 'validate_api_key') as mock_validate:
            mock_validate.return_value = {
                "id": 1,
                "user_id": 1,
                "permissions": ["url:analyze"]  # Missing reports:write
            }
            
            with pytest.raises(HTTPException) as exc_info:
                await auth_middleware(mock_request, Mock())
            
            assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    
    def test_security_headers_addition(self, auth_middleware):
        """Test addition of security headers."""
        if hasattr(auth_middleware, '_add_security_headers'):
            mock_response = Mock()
            mock_response.headers = {}
            
            auth_middleware._add_security_headers(mock_response)
            
            expected_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security"
            ]
            
            for header in expected_headers:
                assert header in mock_response.headers
    
    def test_cors_handling(self, auth_middleware):
        """Test CORS handling in middleware."""
        if hasattr(auth_middleware, '_handle_cors'):
            mock_request = Mock()
            mock_request.method = "OPTIONS"
            mock_request.headers = {
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST"
            }
            
            response = auth_middleware._handle_cors(mock_request)
            
            assert response.status_code == 200
            assert "Access-Control-Allow-Origin" in response.headers
    
    @pytest.mark.asyncio
    async def test_request_logging(self, auth_middleware):
        """Test request logging functionality."""
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.url.path = "/health"
        mock_request.method = "GET"
        mock_request.client.host = "127.0.0.1"
        
        mock_call_next = AsyncMock()
        mock_response = Mock()
        mock_call_next.return_value = mock_response
        
        with patch('app.auth.middleware.logger') as mock_logger:
            await auth_middleware(mock_request, mock_call_next)
            
            # Should log request
            mock_logger.info.assert_called()
    
    @pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "PATCH"])
    @pytest.mark.asyncio
    async def test_http_methods_handling(self, auth_middleware, jwt_handler, sample_user, method):
        """Test handling of different HTTP methods."""
        token = jwt_handler.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role
        )
        
        mock_request = Mock()
        mock_request.headers = {"Authorization": f"Bearer {token}"}
        mock_request.url.path = "/api/v1/analyze"
        mock_request.method = method
        
        mock_call_next = AsyncMock()
        mock_response = Mock()
        mock_call_next.return_value = mock_response
        
        result = await auth_middleware(mock_request, mock_call_next)
        assert result == mock_response
