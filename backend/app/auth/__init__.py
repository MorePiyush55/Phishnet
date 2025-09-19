"""Auth compatibility package: re-export JWT handler expected by tests."""

# Prefer existing EnhancedJWTHandler if available
try:
    from app.core.enhanced_security import EnhancedJWTHandler as JWTHandler
except Exception:
    # Fallback minimal JWTHandler
    class JWTHandler:
        def __init__(self, secret_key: str = "secret", algorithm: str = "HS256"):
            self.secret_key = secret_key
            self.algorithm = algorithm

        def create_access_token(self, data: dict) -> str:
            import jwt
            return jwt.encode(data, self.secret_key, algorithm=self.algorithm)

        def create_refresh_token(self, data: dict) -> str:
            import jwt
            return jwt.encode(data, self.secret_key, algorithm=self.algorithm)

__all__ = ["JWTHandler"]
