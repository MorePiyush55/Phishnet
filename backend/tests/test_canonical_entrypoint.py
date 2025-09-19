"""Smoke test for canonical backend entrypoint consolidation."""

import pytest
from fastapi.testclient import TestClient


def test_canonical_app_import():
    """Test that backend.app.main:app can be imported without side effects."""
    try:
        from backend.app.main import app
        assert app is not None
        assert hasattr(app, 'router')
    except ImportError as e:
        pytest.fail(f"Failed to import canonical app: {e}")


def test_health_endpoint():
    """Test that /health endpoint responds correctly."""
    from backend.app.main import app
    
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"


def test_root_endpoint():
    """Test that root endpoint responds correctly."""
    from backend.app.main import app
    
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "PhishNet" in data["message"]


def test_openapi_endpoint():
    """Test that OpenAPI spec is available."""
    from backend.app.main import app
    
    with TestClient(app) as client:
        response = client.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert "paths" in data


def test_expected_routes_registered():
    """Test that expected routes are registered in the app."""
    from backend.app.main import app
    
    # Extract route paths from the app
    route_paths = set()
    for route in app.router.routes:
        if hasattr(route, 'path'):
            route_paths.add(route.path)
    
    # Check for expected endpoints
    expected_paths = {"/", "/health", "/openapi.json", "/docs"}
    
    for path in expected_paths:
        assert path in route_paths, f"Expected route {path} not found in registered routes"


def test_no_duplicate_routes():
    """Test that routes are not duplicated."""
    from backend.app.main import app
    
    route_paths = []
    for route in app.router.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            for method in route.methods:
                route_paths.append(f"{method} {route.path}")
    
    # Check for duplicates
    duplicates = []
    seen = set()
    for route in route_paths:
        if route in seen:
            duplicates.append(route)
        seen.add(route)
    
    assert len(duplicates) == 0, f"Duplicate routes found: {duplicates}"


if __name__ == "__main__":
    # Run basic smoke tests
    test_canonical_app_import()
    test_health_endpoint()
    test_root_endpoint()
    test_openapi_endpoint()
    test_expected_routes_registered()
    test_no_duplicate_routes()
    print("✅ All smoke tests passed!")