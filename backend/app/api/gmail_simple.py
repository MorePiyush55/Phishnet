"""Simple Gmail API endpoint for testing without complex dependencies."""

from fastapi import APIRouter, HTTPException, Request
from typing import Dict, Any, Optional
import datetime

router = APIRouter(prefix="/api/gmail-simple", tags=["Gmail Test"])

@router.get("/test")
async def test_endpoint():
    """Simple test endpoint."""
    return {"status": "ok", "message": "Gmail simple endpoint is working"}

@router.get("/health")
async def gmail_health():
    """Health check for Gmail simple endpoint."""
    return {"status": "ok", "service": "gmail_simple"}

@router.post("/analyze")
async def analyze_user_emails(request: Optional[Dict[str, Any]] = None):
    """
    Analyze user's Gmail emails for phishing indicators.
    
    This is a simplified test version that returns mock data.
    """
    return {
        "total_emails": 2,
        "emails": [
            {
                "id": "test-1",
                "subject": "Test Email 1", 
                "sender": "sender1@example.com",
                "received_at": "2024-01-01T10:00:00Z",
                "snippet": "This is test email 1",
                "phishing_analysis": {
                    "risk_score": 30,
                    "risk_level": "LOW",
                    "indicators": [],
                    "summary": "Safe email"
                }
            },
            {
                "id": "test-2",
                "subject": "Important: Verify Account",
                "sender": "security@fake-bank.com",
                "received_at": "2024-01-01T11:00:00Z",
                "snippet": "Click here to verify your account immediately",
                "phishing_analysis": {
                    "risk_score": 85,
                    "risk_level": "HIGH",
                    "indicators": ["Suspicious domain", "Urgent action required"],
                    "summary": "Potential phishing attempt"
                }
            }
        ]
    }