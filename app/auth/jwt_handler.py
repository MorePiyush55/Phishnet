"""Minimal JWT handler shim used by tests.
Exposes a JWTHandler class with create/verify helpers.
"""
from typing import Dict, Any

class JWTHandler:
    def __init__(self, secret: str = "secret"):
        self.secret = secret

    def create(self, payload: Dict[str, Any]) -> str:
        return "token"

    def verify(self, token: str) -> Dict[str, Any]:
        return {}
