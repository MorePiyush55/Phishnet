"""Simple Gmail API endpoint for testing without complex dependencies."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from typing import List, Dict, Any
import random
from datetime import datetime, timedelta

router = APIRouter(prefix="/api/gmail", tags=["Gmail Test"])

class UserEmailRequest(BaseModel):
    user_email: EmailStr
    max_emails: int = 10

class EmailAnalysisResponse(BaseModel):
    id: str
    subject: str
    sender: str
    received_at: str
    snippet: str
    phishing_analysis: Dict[str, Any]

class EmailListResponse(BaseModel):
    total_emails: int
    emails: List[EmailAnalysisResponse]

def generate_mock_email(index: int, user_email: str) -> EmailAnalysisResponse:
    """Generate a mock email for testing."""
    
    # Sample email data
    subjects = [
        "Important: Verify your account immediately",
        "Your package has been delivered",
        "Meeting reminder for tomorrow",
        "Security alert: Unusual login detected",
        "Special offer just for you!",
        "Your invoice is ready",
        "Team update from Monday",
        "Password reset request"
    ]
    
    senders = [
        "security@bank-alert.com",
        "noreply@legitimate-site.com", 
        "team@yourcompany.com",
        "support@suspicious-domain.net",
        "notifications@trusted-service.com"
    ]
    
    snippets = [
        "Click here to verify your account before it gets suspended...",
        "Your package delivery was attempted but failed. Click to reschedule...",
        "Just a reminder about our team meeting scheduled for tomorrow at 2 PM...",
        "We detected an unusual login from a new device. If this wasn't you...",
        "Limited time offer! Get 90% off on premium products. Act now...",
        "Your monthly invoice is ready for download. Please review and pay...",
        "Here's a quick update on what the team accomplished this week...",
        "Someone requested a password reset for your account. If this wasn't you..."
    ]
    
    # Determine risk level based on sender and content
    sender = senders[index % len(senders)]
    subject = subjects[index % len(subjects)]
    snippet = snippets[index % len(snippets)]
    
    # Simple risk assessment
    if "security" in sender.lower() or "alert" in subject.lower() or "verify" in snippet.lower():
        risk_level = "HIGH"
        risk_score = random.randint(70, 95)
        indicators = ["Suspicious sender domain", "Urgent action required", "Account verification request"]
        summary = "High risk phishing attempt. Requests urgent account verification."
    elif "offer" in subject.lower() or "90%" in snippet.lower():
        risk_level = "MEDIUM" 
        risk_score = random.randint(40, 69)
        indicators = ["Promotional content", "Time pressure tactics"]
        summary = "Medium risk promotional email with aggressive marketing tactics."
    elif "team" in sender.lower() or "meeting" in subject.lower():
        risk_level = "SAFE"
        risk_score = random.randint(1, 25)
        indicators = []
        summary = "Safe internal communication."
    else:
        risk_level = "LOW"
        risk_score = random.randint(26, 39)
        indicators = ["External sender"]
        summary = "Low risk external email."
    
    received_time = datetime.now() - timedelta(hours=random.randint(1, 72))
    
    return EmailAnalysisResponse(
        id=f"mock-email-{index}-{hash(user_email) % 1000}",
        subject=subject,
        sender=sender,
        received_at=received_time.isoformat(),
        snippet=snippet,
        phishing_analysis={
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators,
            "summary": summary
        }
    )

@router.get("/test")
async def test_endpoint():
    """Simple test endpoint."""
    return {"status": "ok", "message": "Gmail simple endpoint is working"}

@router.get("/health")
async def gmail_health():
    """Health check for Gmail simple endpoint."""
    return {"status": "ok", "service": "gmail_simple"}

@router.post("/analyze")
async def analyze_user_emails(request: UserEmailRequest) -> EmailListResponse:
    """
    Analyze user's Gmail emails for phishing indicators.
    
    This is a simplified test version that returns mock data.
    """
    try:
        print(f"Mock Gmail analysis for {request.user_email}, max_emails: {request.max_emails}")
        
        # Create a simple mock email
        mock_email = EmailAnalysisResponse(
            id="mock-1",
            subject="Test Email",
            sender="test@example.com",
            received_at=datetime.now().isoformat(),
            snippet="This is a test email",
            phishing_analysis={
                "risk_score": 50,
                "risk_level": "MEDIUM",
                "indicators": ["Test indicator"],
                "summary": "Test analysis"
            }
        )
        
        response = EmailListResponse(
            total_emails=1,
            emails=[mock_email]
        )
        
        print(f"Returning mock email: {mock_email}")
        return response
        
    except Exception as e:
        print(f"Error in mock Gmail analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to analyze emails: {str(e)}"
        )