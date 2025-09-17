"""API key validator shim used by tests expecting app.auth.api_key_validator.APIKeyValidator"""

class APIKeyValidator:
    def __init__(self, valid_keys=None):
        self.valid_keys = valid_keys or set()

    def is_valid(self, key: str) -> bool:
        return key in self.valid_keys

__all__ = ["APIKeyValidator"]
