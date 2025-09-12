"""Detection schemas for phishing detection results and rules."""

from datetime import datetime
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field


class DetectionRuleBase(BaseModel):
    """Base detection rule schema."""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    conditions: Dict[str, Any]
    action: str = Field(..., pattern="^(block|flag|quarantine)$")
    priority: int = Field(default=0, ge=0, le=100)


class DetectionRuleCreate(DetectionRuleBase):
    """Schema for creating detection rules."""
    pass


class DetectionRuleUpdate(BaseModel):
    """Schema for updating detection rules."""
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    action: Optional[str] = Field(None, pattern="^(block|flag|quarantine)$")
    priority: Optional[int] = Field(None, ge=0, le=100)
    is_active: Optional[bool] = None


class DetectionRule(DetectionRuleBase):
    """Schema for detection rule response."""
    id: int
    user_id: Optional[int]
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class DetectionRuleList(BaseModel):
    """Schema for detection rule list response."""
    rules: List[DetectionRule]
    total: int
    page: int
    size: int
    has_next: bool
    has_prev: bool


class DetectionStats(BaseModel):
    """Schema for detection statistics."""
    total_detections: int
    phishing_detections: int
    legitimate_detections: int
    detection_rate: float
    false_positive_rate: float
    false_negative_rate: float
    average_confidence: float
    model_accuracy: float
    
    # Time-based stats
    detections_today: int
    detections_this_week: int
    detections_this_month: int
    
    # Risk level breakdown
    risk_levels: Dict[str, int]
    
    # Model performance
    model_performance: Dict[str, float]


class DetectionAnalytics(BaseModel):
    """Schema for detection analytics."""
    time_series: List[Dict[str, Any]]
    top_senders: List[Dict[str, Any]]
    top_risk_factors: List[Dict[str, Any]]
    model_comparison: Dict[str, float]
    threat_trends: List[Dict[str, Any]]


class DetectionExport(BaseModel):
    """Schema for detection export request."""
    format: str = Field(..., pattern="^(csv|json|pdf)$")
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    risk_levels: Optional[List[str]] = None
    include_details: bool = True

