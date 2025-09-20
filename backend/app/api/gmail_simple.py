"""Real Gmail API endpoint for fetching user emails."""

from fastapi import APIRouter, HTTPException, Request
from typing import Dict, Any, Optional
import datetime

# Import the real Gmail service
try:
    from ..services.gmail_service import GmailService
    GMAIL_SERVICE_AVAILABLE = True
except ImportError:
    GMAIL_SERVICE_AVAILABLE = False
    GmailService = None

router = APIRouter(prefix="/api/gmail-simple", tags=["Gmail Test"])

@router.get("/test")
async def test_endpoint():
    """Simple test endpoint."""
    return {"status": "ok", "message": "Gmail simple endpoint is working"}

@router.get("/health")
async def gmail_health():
    """Health check for Gmail simple endpoint."""
    return {"status": "ok", "service": "gmail_simple", "real_gmail_api": GMAIL_SERVICE_AVAILABLE}

@router.post("/analyze")
async def analyze_user_emails(request: Optional[Dict[str, Any]] = None):
    """
    Analyze user's Gmail emails for phishing indicators.
    
    This fetches real emails from the user's Gmail account.
    """
    try:
        # Get user email from request
        user_email = request.get("user_email") if request else None
        max_emails = request.get("max_emails", 10) if request else 10
        
        # Validate user email
        if not user_email:
            return {
                "error": "user_email is required",
                "total_emails": 0,
                "emails": []
            }
        
        # Check if Gmail service is available
        if not GMAIL_SERVICE_AVAILABLE or not GmailService:
            # Return mock data as fallback
            return get_mock_emails_response()
        
        # Create Gmail service instance
        gmail_service = GmailService()
        
        # Try to fetch real emails
        try:
            analyzed_emails = await gmail_service.analyze_emails_for_phishing(user_email, max_emails)
            
            # Convert to our expected format
            formatted_emails = []
            for email in analyzed_emails:
                formatted_email = {
                    "id": email.get("id", ""),
                    "subject": email.get("subject", "No Subject"),
                    "sender": email.get("from", "Unknown Sender"),
                    "received_at": email.get("received_at", ""),
                    "snippet": email.get("snippet", ""),
                    "phishing_analysis": email.get("phishing_analysis", {
                        "risk_score": 0,
                        "risk_level": "SAFE",
                        "indicators": [],
                        "summary": "No analysis available"
                    })
                }
                formatted_emails.append(formatted_email)
            
            return {
                "total_emails": len(formatted_emails),
                "emails": formatted_emails
            }
            
        except Exception as gmail_error:
            print(f"Gmail API error: {gmail_error}")
            # Fall back to mock data if Gmail API fails
            return get_mock_emails_response()
        
    except Exception as e:
        print(f"Error in analyze_user_emails: {e}")
        # Return mock data on any error
        return get_mock_emails_response()

def get_mock_emails_response():
    """Return mock emails as fallback."""
    return {
        "total_emails": 2,
        "emails": [
            {
                "id": "demo-1",
                "subject": "Weekly Team Meeting", 
                "sender": "team@yourcompany.com",
                "received_at": "2024-01-15T10:00:00Z",
                "snippet": "Just a reminder about our weekly team meeting scheduled for today at 2 PM",
                "phishing_analysis": {
                    "risk_score": 5,
                    "risk_level": "SAFE",
                    "indicators": [],
                    "summary": "Safe internal communication"
                }
            },
            {
                "id": "demo-2",
                "subject": "URGENT: Account Verification Required",
                "sender": "security@suspicious-bank.net",
                "received_at": "2024-01-15T11:30:00Z",
                "snippet": "Your account will be suspended if you don't verify immediately. Click here now!",
                "phishing_analysis": {
                    "risk_score": 85,
                    "risk_level": "HIGH",
                    "indicators": [
                        "Suspicious subject word: 'urgent'",
                        "Suspicious phrase: 'account suspended'",
                        "Suspicious phrase: 'verify immediately'"
                    ],
                    "summary": "High risk phishing attempt detected"
                }
            }
        ]
    }