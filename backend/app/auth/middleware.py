"""Minimal AuthenticationMiddleware shim for tests."""
from typing import Callable


class AuthenticationMiddleware:
    def __init__(self, app, validator=None):
        self.app = app
        self.validator = validator

    async def __call__(self, scope, receive, send):
        # No-op middleware for test environment
        await self.app(scope, receive, send)

__all__ = ["AuthenticationMiddleware"]
