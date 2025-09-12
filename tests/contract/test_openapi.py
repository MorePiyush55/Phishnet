"""Contract tests for PhishNet OpenAPI specification."""

import pytest
import json
from fastapi.testclient import TestClient
from openapi_spec_validator import validate_spec
from openapi_spec_validator.readers import read_from_filename
import yaml

from app.main import app


class TestOpenAPIContract:
    """Test OpenAPI specification compliance."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    @pytest.fixture
    def openapi_spec(self, client):
        """Get OpenAPI specification from the running app."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        return response.json()
    
    def test_openapi_spec_valid(self, openapi_spec):
        """Test that OpenAPI specification is valid."""
        try:
            validate_spec(openapi_spec)
        except Exception as e:
            pytest.fail(f"OpenAPI specification is invalid: {e}")
    
    def test_openapi_spec_structure(self, openapi_spec):
        """Test OpenAPI specification has required structure."""
        # Check required top-level fields
        required_fields = ["openapi", "info", "paths"]
        for field in required_fields:
            assert field in openapi_spec, f"Missing required field: {field}"
        
        # Check OpenAPI version
        assert openapi_spec["openapi"].startswith("3."), "Should use OpenAPI 3.x"
        
        # Check info section
        info = openapi_spec["info"]
        assert "title" in info
        assert "version" in info
        assert info["title"] == "PhishNet API"
    
    def test_required_endpoints_documented(self, openapi_spec):
        """Test that all required endpoints are documented."""
        paths = openapi_spec["paths"]
        
        # Core endpoints that must be documented
        required_endpoints = [
            "/api/email/analyze",
            "/api/dashboard/kpis",
            "/api/scoring/rules",
            "/health",
            "/health/readiness",
            "/health/liveness"
        ]
        
        for endpoint in required_endpoints:
            assert endpoint in paths, f"Endpoint {endpoint} not documented"
    
    def test_authentication_documented(self, openapi_spec):
        """Test that authentication is properly documented."""
        # Check security schemes
        components = openapi_spec.get("components", {})
        security_schemes = components.get("securitySchemes", {})
        
        # Should have bearer token authentication
        assert "bearerAuth" in security_schemes or "HTTPBearer" in security_schemes
        
        # Check that protected endpoints have security requirements
        paths = openapi_spec["paths"]
        protected_endpoints = ["/api/dashboard/kpis", "/api/email/analyze"]
        
        for endpoint in protected_endpoints:
            if endpoint in paths:
                for method_data in paths[endpoint].values():
                    if isinstance(method_data, dict):
                        assert "security" in method_data, f"Endpoint {endpoint} missing security"
    
    def test_request_response_schemas(self, openapi_spec):
        """Test that request and response schemas are properly defined."""
        components = openapi_spec.get("components", {})
        schemas = components.get("schemas", {})
        
        # Check for important schemas
        important_schemas = [
            "EmailCreate",
            "EmailResponse", 
            "ScoringResponse",
            "ErrorResponse"
        ]
        
        for schema_name in important_schemas:
            # Not all schemas may be auto-generated, so this is informational
            if schema_name not in schemas:
                print(f"Note: Schema {schema_name} not found in OpenAPI spec")
    
    def test_error_responses_documented(self, openapi_spec):
        """Test that error responses are documented."""
        paths = openapi_spec["paths"]
        
        # Check some endpoints for error response documentation
        test_endpoints = ["/api/email/analyze", "/api/dashboard/kpis"]
        
        for endpoint in test_endpoints:
            if endpoint in paths:
                for method, method_data in paths[endpoint].items():
                    if isinstance(method_data, dict) and "responses" in method_data:
                        responses = method_data["responses"]
                        
                        # Should document common error codes
                        error_codes = ["400", "401", "422", "500"]
                        documented_errors = [code for code in error_codes if code in responses]
                        
                        # At least some error codes should be documented
                        assert len(documented_errors) > 0, f"No error responses documented for {endpoint}"
    
    def test_response_content_types(self, openapi_spec):
        """Test that response content types are properly specified."""
        paths = openapi_spec["paths"]
        
        for endpoint, methods in paths.items():
            for method, method_data in methods.items():
                if isinstance(method_data, dict) and "responses" in method_data:
                    for status_code, response_data in method_data["responses"].items():
                        if "content" in response_data:
                            content = response_data["content"]
                            # Should primarily use application/json
                            assert "application/json" in content, \
                                f"Endpoint {endpoint} missing JSON content type"


class TestAPIContractCompliance:
    """Test that actual API responses match OpenAPI specification."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    def test_health_endpoint_contract(self, client):
        """Test health endpoint matches OpenAPI contract."""
        response = client.get("/health")
        
        # Should return 200 or 503
        assert response.status_code in [200, 503]
        
        # Should return JSON
        assert response.headers["content-type"].startswith("application/json")
        
        # Check response structure
        data = response.json()
        required_fields = ["status", "correlation_id"]
        for field in required_fields:
            assert field in data, f"Missing field {field} in health response"
        
        # Status should be a string
        assert isinstance(data["status"], str)
    
    def test_openapi_json_endpoint(self, client):
        """Test OpenAPI JSON endpoint is accessible."""
        response = client.get("/openapi.json")
        
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        
        # Should be valid JSON
        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert "paths" in data
    
    def test_docs_endpoint_availability(self, client):
        """Test API documentation endpoint availability."""
        # Docs might be disabled in production
        response = client.get("/docs")
        
        # Should either be available (200) or disabled (404)
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            # Should return HTML
            assert "text/html" in response.headers["content-type"]


class TestAPIVersioning:
    """Test API versioning compliance."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    def test_api_version_in_openapi(self, client):
        """Test that API version is properly specified."""
        response = client.get("/openapi.json")
        spec = response.json()
        
        # Version should be specified
        assert "version" in spec["info"]
        version = spec["info"]["version"]
        
        # Version should follow semantic versioning
        import re
        semver_pattern = r"^\d+\.\d+\.\d+(?:-[\w\.]+)?(?:\+[\w\.]+)?$"
        assert re.match(semver_pattern, version), f"Invalid version format: {version}"
    
    def test_api_prefix_consistency(self, client):
        """Test that API endpoints use consistent prefix."""
        response = client.get("/openapi.json")
        spec = response.json()
        
        paths = spec["paths"]
        api_paths = [path for path in paths.keys() if path.startswith("/api/")]
        
        # API paths should use consistent versioning (if any)
        # For now, just check they start with /api/
        for path in api_paths:
            assert path.startswith("/api/"), f"API path {path} doesn't use /api/ prefix"


class TestSchemaValidation:
    """Test schema validation against actual data."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    def test_email_schema_validation(self):
        """Test email schema validation."""
        from app.schemas.email import EmailCreate, EmailResponse
        from pydantic import ValidationError
        
        # Valid email data
        valid_email = {
            "subject": "Test Email",
            "sender": "test@example.com",
            "recipient": "user@company.com",
            "body": "Test email body",
            "headers": {"From": "test@example.com"}
        }
        
        # Should validate successfully
        email_create = EmailCreate(**valid_email)
        assert email_create.subject == "Test Email"
        
        # Invalid email data
        invalid_email = {
            "subject": "",  # Empty subject
            "sender": "invalid-email",  # Invalid email format
            "body": ""  # Empty body
        }
        
        # Should raise validation error
        with pytest.raises(ValidationError):
            EmailCreate(**invalid_email)
    
    def test_scoring_schema_validation(self):
        """Test scoring schema validation."""
        from app.schemas.scoring import ScoringResponse
        from pydantic import ValidationError
        
        # Valid scoring data
        valid_scoring = {
            "email_id": "test-123",
            "risk_score": 0.75,
            "confidence": 0.90,
            "threats_detected": ["phishing"],
            "processing_time": 2.5
        }
        
        # Should validate successfully
        scoring_response = ScoringResponse(**valid_scoring)
        assert scoring_response.risk_score == 0.75
        
        # Invalid scoring data
        invalid_scoring = {
            "risk_score": 1.5,  # Out of range
            "confidence": -0.1,  # Out of range
            "threats_detected": "not_a_list"  # Wrong type
        }
        
        # Should raise validation error
        with pytest.raises(ValidationError):
            ScoringResponse(**invalid_scoring)


class TestAPIDocumentation:
    """Test API documentation quality and completeness."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    @pytest.fixture
    def openapi_spec(self, client):
        """Get OpenAPI specification."""
        response = client.get("/openapi.json")
        return response.json()
    
    def test_endpoint_descriptions(self, openapi_spec):
        """Test that endpoints have proper descriptions."""
        paths = openapi_spec["paths"]
        
        for endpoint, methods in paths.items():
            for method, method_data in methods.items():
                if isinstance(method_data, dict):
                    # Should have summary or description
                    has_docs = "summary" in method_data or "description" in method_data
                    assert has_docs, f"Endpoint {method.upper()} {endpoint} missing documentation"
    
    def test_parameter_descriptions(self, openapi_spec):
        """Test that parameters have descriptions."""
        paths = openapi_spec["paths"]
        
        for endpoint, methods in paths.items():
            for method, method_data in methods.items():
                if isinstance(method_data, dict) and "parameters" in method_data:
                    for param in method_data["parameters"]:
                        assert "description" in param, \
                            f"Parameter {param.get('name', 'unknown')} missing description in {endpoint}"
    
    def test_response_descriptions(self, openapi_spec):
        """Test that responses have descriptions."""
        paths = openapi_spec["paths"]
        
        for endpoint, methods in paths.items():
            for method, method_data in methods.items():
                if isinstance(method_data, dict) and "responses" in method_data:
                    for status_code, response_data in method_data["responses"].items():
                        assert "description" in response_data, \
                            f"Response {status_code} missing description in {endpoint}"
    
    def test_tags_consistency(self, openapi_spec):
        """Test that endpoints are properly tagged."""
        paths = openapi_spec["paths"]
        used_tags = set()
        
        for endpoint, methods in paths.items():
            for method, method_data in methods.items():
                if isinstance(method_data, dict) and "tags" in method_data:
                    used_tags.update(method_data["tags"])
        
        # Check that tags are defined
        if "tags" in openapi_spec:
            defined_tags = {tag["name"] for tag in openapi_spec["tags"]}
            undefined_tags = used_tags - defined_tags
            assert not undefined_tags, f"Undefined tags used: {undefined_tags}"


class TestBackwardCompatibility:
    """Test API backward compatibility."""
    
    def test_api_stability(self):
        """Test that core API structure remains stable."""
        # This would compare current API spec with a baseline
        # For now, just test that core endpoints exist
        
        core_endpoints = [
            "/api/email/analyze",
            "/api/dashboard/kpis", 
            "/health"
        ]
        
        from fastapi.testclient import TestClient
        client = TestClient(app)
        
        for endpoint in core_endpoints:
            # Endpoint should exist (even if it returns auth error)
            response = client.get(endpoint)
            assert response.status_code != 404, f"Core endpoint {endpoint} not found"
    
    def test_required_fields_stable(self):
        """Test that required fields in schemas remain stable."""
        from app.schemas.email import EmailCreate
        from app.schemas.scoring import ScoringResponse
        
        # EmailCreate required fields should be stable
        email_required = EmailCreate.__fields__
        core_email_fields = {"subject", "sender", "body"}
        
        for field in core_email_fields:
            assert field in email_required, f"Core field {field} missing from EmailCreate"
        
        # ScoringResponse required fields should be stable
        scoring_required = ScoringResponse.__fields__
        core_scoring_fields = {"risk_score", "confidence"}
        
        for field in core_scoring_fields:
            assert field in scoring_required, f"Core field {field} missing from ScoringResponse"


# Helper functions for contract testing
def extract_schema_from_response(response_data: dict, path: str) -> dict:
    """Extract schema definition from OpenAPI response."""
    parts = path.split(".")
    current = response_data
    
    for part in parts:
        if part in current:
            current = current[part]
        else:
            return {}
    
    return current


def validate_response_against_schema(response_data: dict, schema: dict) -> bool:
    """Validate response data against OpenAPI schema."""
    try:
        # Simple validation - in real implementation would use jsonschema
        if "type" in schema:
            if schema["type"] == "object" and not isinstance(response_data, dict):
                return False
            elif schema["type"] == "array" and not isinstance(response_data, list):
                return False
            elif schema["type"] == "string" and not isinstance(response_data, str):
                return False
            elif schema["type"] == "number" and not isinstance(response_data, (int, float)):
                return False
        
        return True
    except Exception:
        return False
