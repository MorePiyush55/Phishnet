"""Compatibility shim: re-export ScanResult model from app.models.user.

Some tests import app.models.scan_result.ScanResult; this module re-exports the
ScanResult class defined in app.models.user to keep that import working.
"""
from app.models.user import ScanResult  # re-export

__all__ = ["ScanResult"]
