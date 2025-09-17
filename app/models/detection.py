"""Compatibility shim: expose detection models at app.models.detection

This file keeps the historic import path `app.models.detection` working by
re-exporting the classes from the analysis package where they live.
"""

from app.models.analysis.detection import Detection, DetectionRule

__all__ = ["Detection", "DetectionRule"]
