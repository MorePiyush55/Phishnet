"""Gmail API endpoints for email analysis."""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, EmailStr

# Import GmailService directly to avoid dependency chain issues
try:
    from ..services.gmail_service import GmailService
except ImportError:
    # If import fails, create a mock service for now
    class GmailService:
        def __init__(self):
            pass
        async def analyze_emails_for_phishing(self, email, max_emails):
            raise HTTPException(status_code=503, detail="Gmail service temporarily unavailable")

router = APIRouter(prefix="/api/gmail", tags=["Gmail Analysis"])

class EmailAnalysisResponse(BaseModel):
    """Response model for email analysis."""
    id: str
    subject: str
    sender: str
    received_at: Optional[str]
    snippet: str
    phishing_analysis: Dict[str, Any]

class EmailListResponse(BaseModel):
    """Response model for email list."""
    total_emails: int
    emails: List[EmailAnalysisResponse]
    
class UserEmailRequest(BaseModel):
    """Request model for user email operations."""
    user_email: EmailStr

@router.post("/analyze")
async def analyze_user_emails(
    request: UserEmailRequest,
    max_emails: int = Query(default=10, ge=1, le=50, description="Maximum number of emails to analyze"),
    gmail_service: GmailService = Depends(lambda: GmailService())
) -> EmailListResponse:
    """
    Analyze user's Gmail emails for phishing indicators.
    
    This endpoint:
    1. Fetches recent emails from the user's Gmail account
    2. Analyzes each email for phishing indicators
    3. Returns a list of emails with their risk assessments
    """
    try:
        # Analyze emails for phishing
        analyzed_emails = await gmail_service.analyze_emails_for_phishing(
            request.user_email, 
            max_emails
        )
        
        # Convert to response format
        email_responses = []
        for email in analyzed_emails:
            email_response = EmailAnalysisResponse(
                id=email["id"],
                subject=email["subject"],
                sender=email["from"],
                received_at=email["received_at"],
                snippet=email["snippet"],
                phishing_analysis=email["phishing_analysis"]
            )
            email_responses.append(email_response)
        
        return EmailListResponse(
            total_emails=len(email_responses),
            emails=email_responses
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to analyze emails: {str(e)}"
        )

@router.get("/email/{message_id}")
async def get_email_details(
    message_id: str,
    user_email: EmailStr = Query(..., description="User's email address"),
    gmail_service: GmailService = Depends(lambda: GmailService())
) -> Dict[str, Any]:
    """
    Get detailed information about a specific email.
    
    Returns full email content including headers, body, and phishing analysis.
    """
    try:
        # Get email details
        email_details = await gmail_service.get_email_details(user_email, message_id)
        
        # Extract and analyze email
        email_info = gmail_service.extract_email_info(email_details)
        phishing_analysis = gmail_service._analyze_phishing_indicators(email_info)
        
        return {
            **email_info,
            "phishing_analysis": phishing_analysis
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get email details: {str(e)}"
        )

@router.get("/status")
async def get_gmail_connection_status(
    user_email: EmailStr = Query(..., description="User's email address"),
    gmail_service: GmailService = Depends(lambda: GmailService())
) -> Dict[str, Any]:
    """
    Check the Gmail connection status for a user.
    
    Returns information about token validity and connection status.
    """
    try:
        # Check if user has valid tokens
        tokens = await gmail_service.get_user_tokens(user_email)
        
        if not tokens:
            return {
                "connected": False,
                "message": "User not found or no Gmail tokens available",
                "requires_oauth": True
            }
        
        # Try to get a valid access token
        access_token = await gmail_service.get_valid_access_token(user_email)
        
        if not access_token:
            return {
                "connected": False,
                "message": "Gmail tokens expired and cannot be refreshed",
                "requires_oauth": True
            }
        
        return {
            "connected": True,
            "message": "Gmail connection is active",
            "token_expires_at": tokens["expires_at"].isoformat() if tokens["expires_at"] else None,
            "requires_oauth": False
        }
        
    except Exception as e:
        return {
            "connected": False,
            "message": f"Error checking connection status: {str(e)}",
            "requires_oauth": True
        }

@router.post("/test-connection")
async def test_gmail_connection(
    request: UserEmailRequest,
    gmail_service: GmailService = Depends(lambda: GmailService())
) -> Dict[str, Any]:
    """
    Test Gmail API connection by fetching a small number of emails.
    
    This is useful for verifying that the OAuth tokens work and the user
    has granted the necessary permissions.
    """
    try:
        # Try to fetch just 1 email to test the connection
        email_list = await gmail_service.get_email_list(request.user_email, max_results=1)
        
        if not email_list:
            return {
                "success": True,
                "message": "Connection successful, but no emails found",
                "email_count": 0
            }
        
        # Get details of the first email to fully test the connection
        first_email = email_list[0]
        email_details = await gmail_service.get_email_details(
            request.user_email, 
            first_email["id"]
        )
        
        email_info = gmail_service.extract_email_info(email_details)
        
        return {
            "success": True,
            "message": "Gmail connection is working correctly",
            "email_count": len(email_list),
            "sample_email": {
                "id": email_info["id"],
                "subject": email_info["subject"][:50] + "..." if len(email_info["subject"]) > 50 else email_info["subject"],
                "from": email_info["from"],
                "received_at": email_info["received_at"]
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Gmail connection test failed: {str(e)}"
        )