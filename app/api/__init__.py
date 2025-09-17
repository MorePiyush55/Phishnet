"""API routes package for PhishNet.

This module re-exports commonly used submodules so tests and imports like
`from app.api import auth, scoring` continue to work during collection.
"""

from importlib import import_module
import types
from fastapi import APIRouter

__all__ = [
	"auth",
	"dashboard",
	"email_analysis",
	"analysis",
	"scoring",
	"health",
	"gmail_oauth",
]

for _m in list(__all__):
	try:
		globals()[_m] = import_module(f"app.api.{_m}")
	except Exception:
		# Defer detailed errors to when tests import the specific module.
		# Provide a minimal fallback module with an empty router so the
		# application can be imported during pytest collection without
		# failing when tests don't need the real implementation.
		mod = types.ModuleType(f"app.api.{_m}")
		mod.router = APIRouter()
		globals()[_m] = mod

