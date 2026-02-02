"""
Gmail On-Demand Check Routes
============================

Endpoints for privacy-first on-demand email checking via Gmail API.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Header
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from app.modes.dependencies import get_gmail_orchestrator_dep
from app.modes.gmail.orchestrator import GmailOrchestrator
from app.modes.base import AnalysisRequest, ModeType, AnalysisStatus
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/check", tags=["Gmail Check"])


# ============================================================================
# Request/Response Models
# ============================================================================

class CheckEmailRequest(BaseModel):
    """Request to check a specific email."""
    message_id: str = Field(..., description="Gmail Message ID to analyze")
    access_token: Optional[str] = Field(None, description="Gmail Access Token (if available)")
    store_consent: bool = Field(False, description="Whether to store the analysis result")
    user_id: str = Field(..., description="User ID requesting the check")


class CheckEmailResponse(BaseModel):
    """Response from email check."""
    success: bool
    message_id: Optional[str] = None
    analysis_id: Optional[str] = None
    need_oauth: bool = False
    oauth_url: Optional[str] = None
    verdict: Optional[str] = None
    confidence: Optional[float] = None
    risk_score: Optional[float] = None
    threat_indicators: list = []
    ai_summary: Optional[str] = None
    message: Optional[str] = None


class QuickCheckRequest(BaseModel):
    """Request for quick check with minimal data."""
    message_id: str = Field(..., description="Gmail Message ID")
    user_id: str = Field(..., description="User ID")


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/request", response_model=CheckEmailResponse)
async def request_check(
    request: CheckEmailRequest,
    orchestrator: GmailOrchestrator = Depends(get_gmail_orchestrator_dep)
):
    """
    Request an on-demand check for a specific email.
    
    This is the primary endpoint for Mode 2 (consumer) email verification.
    If the access token is missing or expired, returns need_oauth=True
    with an authorization URL.
    
    Privacy Features:
    - Only reads the specific email requested (gmail.readonly scope)
    - No background inbox scanning
    - Result stored only if store_consent=True
    - Email content not persisted by default
    
    Args:
        request: Check request with message ID and optional token
        
    Returns:
        Analysis result or OAuth redirect URL
    """
    try:
        # Use convenience method on orchestrator
        result = await orchestrator.check_email_on_demand(
            user_id=request.user_id,
            message_id=request.message_id,
            access_token=request.access_token,
            store_consent=request.store_consent
        )
        
        # Handle need OAuth case
        if result.get("need_oauth"):
            return CheckEmailResponse(
                success=False,
                message_id=request.message_id,
                need_oauth=True,
                oauth_url=result.get("oauth_url"),
                message="Authorization required. Please authenticate with Gmail."
            )
        
        # Return analysis result
        return CheckEmailResponse(
            success=result.get("success", False),
            message_id=request.message_id,
            analysis_id=result.get("analysis_id"),
            verdict=result.get("verdict"),
            confidence=result.get("confidence"),
            risk_score=result.get("risk_score"),
            threat_indicators=result.get("threat_indicators", []),
            ai_summary=result.get("ai_summary"),
            message=result.get("message")
        )
        
    except Exception as e:
        logger.error(f"On-demand check failed for {request.message_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/quick")
async def quick_check(
    request: QuickCheckRequest,
    orchestrator: GmailOrchestrator = Depends(get_gmail_orchestrator_dep)
):
    """
    Quick check using stored tokens.
    
    Attempts to use existing stored tokens for the user.
    Returns OAuth URL if no valid tokens available.
    
    Args:
        request: Message ID and user ID
        
    Returns:
        Analysis result or OAuth redirect
    """
    try:
        result = await orchestrator.check_email_on_demand(
            user_id=request.user_id,
            message_id=request.message_id,
            access_token=None,  # Will try to use stored token
            store_consent=False
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Quick check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/status/{analysis_id}")
async def get_check_status(
    analysis_id: str,
    orchestrator: GmailOrchestrator = Depends(get_gmail_orchestrator_dep)
):
    """
    Get status of an on-demand check.
    
    For async processing scenarios, check if analysis is complete.
    
    Args:
        analysis_id: The analysis ID returned from check request
        
    Returns:
        Current status and result if available
    """
    try:
        status_info = await orchestrator.get_analysis_status(analysis_id)
        
        if not status_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis {analysis_id} not found"
            )
        
        return status_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get status for {analysis_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/history")
async def get_user_history(
    user_id: str,
    limit: int = 20
):
    """
    Get check history for a user.
    
    Returns past on-demand checks where user consented to storage.
    
    Args:
        user_id: The user ID
        limit: Maximum results to return
        
    Returns:
        List of past check results
    """
    try:
        from app.models.mongodb_models import OnDemandAnalysis
        
        results = await OnDemandAnalysis.find(
            OnDemandAnalysis.user_id == user_id
        ).sort(-OnDemandAnalysis.analyzed_at).limit(limit).to_list()
        
        return {
            "success": True,
            "count": len(results),
            "results": [
                {
                    "id": str(r.id),
                    "message_id": r.message_id,
                    "subject": r.subject,
                    "verdict": r.verdict,
                    "risk_score": r.risk_score,
                    "checked_at": r.analyzed_at
                }
                for r in results
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get history for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete("/history/{analysis_id}")
async def delete_check_result(
    analysis_id: str,
    user_id: str
):
    """
    Delete a stored check result.
    
    Users can remove their stored analysis results.
    
    Args:
        analysis_id: The analysis ID to delete
        user_id: The user requesting deletion (must own the result)
        
    Returns:
        Deletion confirmation
    """
    try:
        from app.models.mongodb_models import OnDemandAnalysis
        from bson import ObjectId
        
        result = await OnDemandAnalysis.find_one(
            OnDemandAnalysis.id == ObjectId(analysis_id)
        )
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Analysis not found"
            )
        
        # Verify ownership
        if result.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete your own results"
            )
        
        await result.delete()
        
        return {
            "success": True,
            "deleted_id": analysis_id,
            "message": "Check result deleted"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete {analysis_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# ============================================================================
# Helper function to extract email body from Gmail API response
# ============================================================================

def extract_email_body(payload: dict) -> str:
    """
    Extract the plain text body from a Gmail message payload.
    Handles multipart messages and base64 decoding.
    """
    import base64
    
    body = ""
    
    # Check for direct body data
    if "body" in payload and payload["body"].get("data"):
        try:
            body = base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
        except Exception:
            pass
    
    # Check for multipart content
    if "parts" in payload:
        for part in payload["parts"]:
            mime_type = part.get("mimeType", "")
            
            # Prefer plain text
            if mime_type == "text/plain" and part.get("body", {}).get("data"):
                try:
                    body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="ignore")
                    break
                except Exception:
                    pass
            
            # Fallback to HTML (strip tags)
            if mime_type == "text/html" and not body and part.get("body", {}).get("data"):
                try:
                    html_body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="ignore")
                    # Simple HTML tag stripping
                    import re
                    body = re.sub(r'<[^>]+>', ' ', html_body)
                    body = re.sub(r'\s+', ' ', body).strip()
                except Exception:
                    pass
            
            # Recursively check nested parts
            if "parts" in part:
                nested_body = extract_email_body(part)
                if nested_body:
                    body = nested_body
                    break
    
    return body.strip()


# ============================================================================
# Inbox Scan Endpoint (Mode 2 - Dashboard Display)
# ============================================================================

class InboxScanRequest(BaseModel):
    """Request to scan user's inbox."""
    user_email: str = Field(..., description="User's Gmail address")
    access_token: Optional[str] = Field(None, description="Gmail Access Token")
    limit: int = Field(50, ge=1, le=100, description="Maximum emails to scan")


class EmailWithAnalysis(BaseModel):
    """Email with phishing analysis result."""
    id: str
    subject: str
    sender: str
    received_at: Optional[str] = None
    snippet: str = ""
    verdict: str = "UNKNOWN"
    risk_level: str = "unknown"
    threat_score: float = 0.0
    confidence: float = 0.0
    threat_indicators: list = []


class InboxScanResponse(BaseModel):
    """Response from inbox scan."""
    success: bool
    count: int = 0
    emails: list = []
    need_oauth: bool = False
    oauth_url: Optional[str] = None
    message: Optional[str] = None


@router.get("/inbox/{user_email}", response_model=InboxScanResponse)
async def scan_inbox(
    user_email: str,
    limit: int = 50,
    access_token: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """
    Scan user's Gmail inbox and analyze emails for phishing.
    
    This is the main endpoint for Mode 2 dashboard display.
    It fetches emails from the user's Gmail account using their OAuth token
    and returns them with phishing analysis scores.
    
    Args:
        user_email: The user's Gmail address
        limit: Maximum number of emails to fetch (default 50)
        access_token: Gmail OAuth access token (optional, will try stored token)
        authorization: Authorization header with Bearer token
        
    Returns:
        List of emails with phishing analysis
    """
    import httpx
    import asyncio
    
    try:
        logger.info(f"Inbox scan requested for {user_email}, limit={limit}")
        
        # Try to get access token from various sources:
        # 1. Query parameter
        # 2. Authorization header (Bearer token)
        # 3. Stored in database
        gmail_access_token = access_token
        
        if not gmail_access_token and authorization:
            if authorization.startswith("Bearer "):
                gmail_access_token = authorization[7:]
                logger.info(f"Using token from Authorization header for {user_email}")
        
        if not gmail_access_token:
            try:
                from motor.motor_asyncio import AsyncIOMotorClient
                from app.config.settings import settings
                
                mongodb_uri = settings.MONGODB_URI
                # Handle potentially quoted URI from env
                if mongodb_uri:
                    mongodb_uri = mongodb_uri.strip().strip('"').strip("'")
                    
                client = AsyncIOMotorClient(mongodb_uri)
                db = client.phishnet
                
                user_doc = await db.users.find_one({"email": user_email})
                if user_doc:
                    gmail_access_token = user_doc.get("gmail_access_token")
                    logger.info(f"Found stored token for {user_email}")
                else:
                    logger.warning(f"No user document found for {user_email}")
                client.close()
            except Exception as e:
                logger.warning(f"Could not retrieve stored token: {e}")
        
        if not gmail_access_token:
            # User needs to authenticate
            logger.info(f"No access token for {user_email}, OAuth required")
            return InboxScanResponse(
                success=False,
                need_oauth=True,
                oauth_url=f"/auth/google?prompt=consent",
                message="Please connect your Gmail account first."
            )
        
        # Fetch emails from Gmail API
        headers = {
            "Authorization": f"Bearer {gmail_access_token}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get list of messages
            messages_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
            params = {"maxResults": min(limit, 100), "q": "in:inbox"}
            
            response = await client.get(messages_url, headers=headers, params=params)
            
            if response.status_code == 401:
                logger.warning(f"Token expired for {user_email}")
                return InboxScanResponse(
                    success=False,
                    need_oauth=True,
                    oauth_url=f"/auth/google?prompt=consent",
                    message="Session expired. Please reconnect your Gmail account."
                )
            
            if response.status_code != 200:
                logger.error(f"Gmail API error: {response.status_code} - {response.text}")
                return InboxScanResponse(
                    success=False,
                    message=f"Gmail API error: {response.status_code}"
                )
            
            messages_data = response.json()
            messages = messages_data.get("messages", [])
            
            if not messages:
                return InboxScanResponse(
                    success=True,
                    count=0,
                    emails=[],
                    message="No emails found in inbox."
                )
            
            logger.info(f"Found {len(messages)} messages for {user_email}")
            
            # Fetch email details in parallel (batched)
            emails_with_analysis = []
            
            async def fetch_and_analyze_email(message_id: str) -> Optional[Dict[str, Any]]:
                """Fetch a single email and analyze it."""
                try:
                    msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}"
                    # Fetch full message to get body content
                    params = {"format": "full"}
                    
                    msg_response = await client.get(msg_url, headers=headers, params=params)
                    
                    if msg_response.status_code != 200:
                        return None
                    
                    msg_data = msg_response.json()
                    
                    # Extract headers
                    headers_list = msg_data.get("payload", {}).get("headers", [])
                    subject = next((h["value"] for h in headers_list if h["name"].lower() == "subject"), "No Subject")
                    sender = next((h["value"] for h in headers_list if h["name"].lower() == "from"), "Unknown")
                    date = next((h["value"] for h in headers_list if h["name"].lower() == "date"), None)
                    snippet = msg_data.get("snippet", "")
                    
                    # Extract body content
                    body = extract_email_body(msg_data.get("payload", {}))
                    
                    # Perform quick phishing analysis
                    analysis = await analyze_email_for_phishing(sender, subject, body or snippet)
                    
                    return {
                        "id": message_id,
                        "subject": subject,
                        "sender": sender,
                        "received_at": date,
                        "snippet": snippet[:200] if snippet else "",
                        "body": body[:5000] if body else snippet,  # Limit body size
                        "verdict": analysis.get("verdict", "UNKNOWN"),
                        "risk_level": analysis.get("risk_level", "unknown"),
                        "threat_score": analysis.get("threat_score", 0.0),
                        "confidence": analysis.get("confidence", 0.0),
                        "threat_indicators": analysis.get("threat_indicators", [])
                    }
                except Exception as e:
                    logger.error(f"Error processing email {message_id}: {e}")
                    return None
            
            # Process emails in batches of 10
            batch_size = 10
            for i in range(0, min(len(messages), limit), batch_size):
                batch = messages[i:i + batch_size]
                tasks = [fetch_and_analyze_email(msg["id"]) for msg in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if result and not isinstance(result, Exception):
                        emails_with_analysis.append(result)
            
            logger.info(f"Successfully analyzed {len(emails_with_analysis)} emails for {user_email}")
            
            return InboxScanResponse(
                success=True,
                count=len(emails_with_analysis),
                emails=emails_with_analysis,
                message=f"Analyzed {len(emails_with_analysis)} emails."
            )
            
    except Exception as e:
        logger.error(f"Inbox scan failed for {user_email}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


async def analyze_email_for_phishing(sender: str, subject: str, snippet: str) -> Dict[str, Any]:
    """
    Perform quick phishing analysis on email metadata.
    
    Uses heuristics and pattern matching for fast analysis.
    """
    threat_indicators = []
    threat_score = 0.0
    
    # Check sender patterns
    sender_lower = sender.lower()
    
    # Suspicious sender patterns
    if any(term in sender_lower for term in ["noreply", "no-reply", "donotreply"]):
        threat_score += 0.1
    
    # Check for spoofed domains (homoglyphs)
    suspicious_domains = ["paypa1", "amaz0n", "goog1e", "micr0soft", "app1e", "faceb00k", "netf1ix"]
    if any(domain in sender_lower for domain in suspicious_domains):
        threat_indicators.append("Suspicious sender domain (possible spoofing)")
        threat_score += 0.4
    
    # Check subject patterns
    subject_lower = subject.lower()
    
    urgency_keywords = ["urgent", "immediate", "action required", "suspended", "verify now", 
                       "account locked", "security alert", "unusual activity", "expire",
                       "password reset", "confirm your", "update your payment"]
    
    for keyword in urgency_keywords:
        if keyword in subject_lower:
            threat_indicators.append(f"Urgency language: '{keyword}'")
            threat_score += 0.15
    
    # Check for suspicious patterns in snippet
    snippet_lower = snippet.lower()
    
    phishing_patterns = ["click here", "verify your", "confirm your identity", 
                        "log in immediately", "enter your password", "update payment",
                        "wire transfer", "bitcoin", "gift card", "lottery winner",
                        "inheritance", "prince", "million dollars"]
    
    for pattern in phishing_patterns:
        if pattern in snippet_lower:
            threat_indicators.append(f"Phishing phrase detected: '{pattern}'")
            threat_score += 0.2
    
    # Cap the score at 1.0
    threat_score = min(threat_score, 1.0)
    
    # Determine verdict based on score
    if threat_score >= 0.7:
        verdict = "PHISHING"
        risk_level = "high"
    elif threat_score >= 0.4:
        verdict = "SUSPICIOUS"
        risk_level = "medium"
    elif threat_score >= 0.2:
        verdict = "CAUTION"
        risk_level = "low"
    else:
        verdict = "SAFE"
        risk_level = "safe"
    
    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "threat_score": threat_score,
        "confidence": 0.75 if threat_indicators else 0.6,
        "threat_indicators": threat_indicators[:5]  # Limit indicators
    }
