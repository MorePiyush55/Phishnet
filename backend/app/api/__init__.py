"""API routes package for PhishNet."""

from .link_analysis import router as link_analysis_router
from .threat_intelligence import router as threat_intelligence_router
from .workers import router as workers_router

__all__ = ["link_analysis_router", "threat_intelligence_router", "workers_router"]

