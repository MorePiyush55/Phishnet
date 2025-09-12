"""Admin API package - administrative endpoints."""

from .federated import router as federated_router
from .dashboard import router as admin_dashboard_router

__all__ = ["federated_router", "admin_dashboard_router"]
