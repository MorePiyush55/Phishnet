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

def clean_html_to_text(html: str) -> str:
    """
    Convert HTML email to clean readable text like Gmail/Outlook displays.
    Properly handles complex HTML newsletters (Reddit, LinkedIn, etc.)
    """
    import re
    from html import unescape
    
    if not html:
        return ""
    
    text = html
    
    # Remove entire script and style blocks
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<head[^>]*>.*?</head>', '', text, flags=re.DOTALL | re.IGNORECASE)
    
    # Remove HTML comments and conditional comments (<!--[if gte mso 9]> etc.)
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
    text = re.sub(r'<!\[CDATA\[.*?\]\]>', '', text, flags=re.DOTALL)
    
    # Remove DOCTYPE and XML declarations
    text = re.sub(r'<!DOCTYPE[^>]*>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'<\?xml[^>]*\?>', '', text, flags=re.IGNORECASE)
    
    # Convert common block elements to newlines
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</(p|div|tr|li|h[1-6])>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<(p|div|tr|h[1-6])[^>]*>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<li[^>]*>', '\n• ', text, flags=re.IGNORECASE)
    
    # Extract link text and URLs for important links
    def replace_link(match):
        full_tag = match.group(0)
        href_match = re.search(r'href=["\']([^"\']+)["\']', full_tag)
        # Get the text between <a> and </a>
        text_match = re.search(r'>([^<]*)</a>', full_tag, re.IGNORECASE)
        if text_match:
            link_text = text_match.group(1).strip()
            if link_text:
                return link_text + ' '
        return ''
    
    text = re.sub(r'<a[^>]*>.*?</a>', replace_link, text, flags=re.DOTALL | re.IGNORECASE)
    
    # Remove all remaining HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    
    # Decode HTML entities
    text = unescape(text)
    
    # Clean up whitespace
    text = re.sub(r'[ \t]+', ' ', text)  # Multiple spaces to single
    text = re.sub(r'\n\s*\n', '\n\n', text)  # Multiple newlines to double
    text = re.sub(r'\n{3,}', '\n\n', text)  # Max 2 newlines
    
    # Remove leading/trailing whitespace from each line
    lines = [line.strip() for line in text.split('\n')]
    text = '\n'.join(line for line in lines if line)  # Remove empty lines
    
    return text.strip()


def extract_email_body(payload: dict) -> str:
    """
    Extract the readable text body from a Gmail message payload.
    Handles multipart messages, base64 decoding, and HTML conversion.
    Returns clean text suitable for display like Gmail/Outlook.
    """
    import base64
    
    plain_text = ""
    html_text = ""
    
    def extract_from_part(part: dict):
        """Extract text from a single part."""
        nonlocal plain_text, html_text
        
        mime_type = part.get("mimeType", "")
        body_data = part.get("body", {}).get("data", "")
        
        if body_data:
            try:
                decoded = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="ignore")
                
                if mime_type == "text/plain" and not plain_text:
                    plain_text = decoded
                elif mime_type == "text/html" and not html_text:
                    html_text = decoded
            except Exception:
                pass
        
        # Recursively check nested parts
        if "parts" in part:
            for nested_part in part["parts"]:
                extract_from_part(nested_part)
    
    # Check direct body first
    if "body" in payload and payload["body"].get("data"):
        try:
            decoded = base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
            mime_type = payload.get("mimeType", "")
            if "html" in mime_type.lower():
                html_text = decoded
            else:
                plain_text = decoded
        except Exception:
            pass
    
    # Check multipart content
    if "parts" in payload:
        for part in payload["parts"]:
            extract_from_part(part)
    
    # Prefer plain text if available, otherwise convert HTML
    if plain_text and len(plain_text.strip()) > 50:
        return plain_text.strip()
    elif html_text:
        return clean_html_to_text(html_text)
    elif plain_text:
        return plain_text.strip()
    
    return ""


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
                    
                    # Gmail provides a clean text snippet - this is the best summary
                    snippet = msg_data.get("snippet", "")
                    
                    # Extract and clean body content (handles HTML conversion)
                    body = extract_email_body(msg_data.get("payload", {}))
                    
                    # Use cleaned body, but fallback to snippet if body extraction failed
                    # or if body still contains HTML artifacts
                    display_body = body if body and not body.startswith('<!DOCTYPE') and '<html' not in body.lower()[:100] else snippet
                    
                    # Perform quick phishing analysis using available content
                    analysis_text = display_body or snippet or subject
                    analysis = await analyze_email_for_phishing(sender, subject, analysis_text)
                    
                    return {
                        "id": message_id,
                        "subject": subject,
                        "sender": sender,
                        "received_at": date,
                        "snippet": snippet[:200] if snippet else "",
                        "body": display_body[:5000] if display_body else snippet,  # Clean text for display
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
    Perform phishing analysis on email metadata and content.
    
    Uses heuristics, URL analysis, sender reputation, and pattern matching.
    """
    import re
    from urllib.parse import urlparse
    
    threat_indicators = []
    threat_score = 0.0
    
    # Track signal categories for compound scoring
    has_urgency = False
    has_payment_request = False
    has_credential_request = False
    has_suspicious_url = False
    has_suspicious_sender = False
    
    # ========== SENDER ANALYSIS ==========
    sender_lower = sender.lower()
    
    # Extract sender domain
    sender_domain_match = re.search(r'@([\w.-]+)', sender_lower)
    sender_domain = sender_domain_match.group(1) if sender_domain_match else ""
    
    # Suspicious sender patterns
    if any(term in sender_lower for term in ["noreply", "no-reply", "donotreply"]):
        threat_score += 0.1
    
    # Check for spoofed domains (homoglyphs)
    spoofed_domains = ["paypa1", "amaz0n", "goog1e", "micr0soft", "app1e", "faceb00k", "netf1ix",
                       "paypaI", "arnazon", "go0gle", "mlcrosoft", "llnkedin"]
    if any(domain in sender_lower for domain in spoofed_domains):
        threat_indicators.append("Suspicious sender domain (possible spoofing)")
        threat_score += 0.4
        has_suspicious_sender = True
    
    # Privacy-focused email providers sending business/payment emails = suspicious
    privacy_domains = ["proton.me", "protonmail.com", "protonmail.ch", "tutanota.com", 
                       "tutamail.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
                       "yopmail.com", "mailinator.com", "10minutemail.com", "sharklasers.com"]
    if any(pd in sender_domain for pd in privacy_domains):
        threat_indicators.append(f"Privacy/disposable email sender: {sender_domain}")
        threat_score += 0.15
        has_suspicious_sender = True
    
    # Misspelled sender names (common in phishing)
    sender_name = sender.split('<')[0].strip().lower()
    misspell_patterns = ["recomnd", "securty", "verific", "notific", "paymt", "accont", "confrim"]
    if any(mp in sender_name for mp in misspell_patterns):
        threat_indicators.append(f"Misspelled sender name: '{sender_name}'")
        threat_score += 0.15
        has_suspicious_sender = True
    
    # ========== SUBJECT ANALYSIS ==========
    subject_lower = subject.lower()
    
    urgency_keywords = ["urgent", "immediate", "action required", "suspended", "verify now", 
                       "account locked", "security alert", "unusual activity", "expire",
                       "password reset", "confirm your", "update your payment", "final notice",
                       "last warning", "account will be", "within 24 hours", "within 48 hours",
                       "act now", "time sensitive", "response required"]
    
    for keyword in urgency_keywords:
        if keyword in subject_lower:
            threat_indicators.append(f"Urgency language in subject: '{keyword}'")
            threat_score += 0.15
            has_urgency = True
            break  # Only count once from subject
    
    # ========== BODY/CONTENT ANALYSIS ==========
    snippet_lower = snippet.lower()
    all_text_lower = f"{subject_lower} {snippet_lower}"
    
    # Urgency patterns in body (check body too, not just subject)
    body_urgency = ["urgent", "immediately", "right away", "as soon as possible", "asap",
                    "without delay", "time is running out", "don't delay", "act fast",
                    "limited time", "final reminder", "last chance"]
    for pattern in body_urgency:
        if pattern in snippet_lower and not has_urgency:
            threat_indicators.append(f"Urgency language in body: '{pattern}'")
            threat_score += 0.1
            has_urgency = True
            break
    
    # Payment/financial phishing patterns
    payment_patterns = ["pending payment", "complete payment", "complete the payment",
                       "outstanding payment", "payment confirmation", "payment is due",
                       "payment is still", "overdue payment", "make the payment",
                       "service interruption", "further action", "avoid any",
                       "wire transfer", "bitcoin", "gift card", "cryptocurrency",
                       "bank transfer", "western union", "moneygram"]
    for pattern in payment_patterns:
        if pattern in snippet_lower:
            threat_indicators.append(f"Payment/financial pressure: '{pattern}'")
            threat_score += 0.2
            has_payment_request = True
            break  # Count category once
    
    # Credential harvesting patterns
    credential_patterns = ["click here", "verify your", "confirm your identity",
                          "log in immediately", "enter your password", "update payment",
                          "click the link", "click the button", "click below",
                          "secure link", "verify your account", "confirm your account",
                          "reset your password", "update your information",
                          "click here to complete", "submit your details"]
    for pattern in credential_patterns:
        if pattern in snippet_lower:
            threat_indicators.append(f"Credential/click bait: '{pattern}'")
            threat_score += 0.15
            has_credential_request = True
            break  # Count category once
    
    # Classic scam patterns (high confidence)
    scam_patterns = ["lottery winner", "inheritance", "prince", "million dollars",
                    "congratulations you have won", "unclaimed funds", "beneficiary",
                    "nigerian", "gold bars", "diplomatic bag"]
    for pattern in scam_patterns:
        if pattern in snippet_lower:
            threat_indicators.append(f"Classic scam phrase: '{pattern}'")
            threat_score += 0.35
            break
    
    # Impersonation patterns
    impersonation_patterns = ["your company", "your bank", "your account has been",
                             "we have detected", "unusual activity on your", 
                             "we noticed a suspicious", "security team",
                             "IT department", "tech support"]
    for pattern in impersonation_patterns:
        if pattern in snippet_lower:
            threat_indicators.append(f"Impersonation attempt: '{pattern}'")
            threat_score += 0.1
    
    # ========== URL ANALYSIS ==========
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    all_text = f"{subject} {snippet}"
    urls = url_pattern.findall(all_text)
    urls = [u.rstrip('.,;!?)') for u in urls]  # Clean trailing punctuation
    
    # Suspicious TLDs
    suspicious_tlds = {
        '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws', '.info', '.biz',
        '.top', '.xyz', '.club', '.work', '.click', '.link', '.buzz', '.surf',
        '.rest', '.icu', '.sbs', '.cfd', '.cyou', '.lol', '.fun', '.store',
        '.site', '.online', '.live', '.su', '.monster'
    }
    
    # Dangerous file extensions
    dangerous_extensions = {
        '.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs',
        '.js', '.ps1', '.sh', '.bash', '.bin', '.elf',
        '.dll', '.sys', '.zip', '.rar', '.7z', '.tar', '.gz',
        '.iso', '.img', '.dmg', '.pkg', '.deb', '.rpm', '.apk',
        '.jar', '.docm', '.xlsm', '.pptm', '.hta', '.inf', '.reg', '.lnk'
    }
    
    # Malware distribution paths (common in botnet/malware URLs)
    malware_path_patterns = [
        '/bins/', '/bin/', '/payload/', '/exploit/', '/exec/',
        '/download/', '/dropper/', '/loader/', '/bot/', '/malware/',
        '/tmp/', '/shell/', '/backdoor/', '/trojan/', '/rat/',
        '/c2/', '/cnc/', '/gate/', '/panel/'
    ]
    
    # Malware binary names (architecture-specific, common in IoT botnets like Mirai)
    malware_binary_names = [
        'x86_64', 'x86', 'i686', 'i586', 'arm', 'arm5', 'arm6', 'arm7',
        'aarch64', 'mips', 'mipsel', 'mips64', 'powerpc', 'ppc', 'sparc',
        'sh4', 'm68k', 'arc', 'xtensa', 'riscv64'
    ]
    
    for url in urls:
        url_clean = url.rstrip('.,;!?)')
        try:
            parsed = urlparse(url_clean)
            domain = parsed.netloc.lower()
            domain_no_port = domain.split(':')[0]
            path = parsed.path.lower()
            path_filename = path.split('/')[-1] if '/' in path else ''
            
            has_suspicious_url = True  # Any URL in a phishing-context email is notable
            
            # Check for IP-based URL
            ip_pattern_check = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            if ip_pattern_check.match(domain_no_port):
                threat_indicators.append(f"IP-based URL: {domain_no_port}")
                threat_score += 0.35
                
                # IP + non-standard port = very dangerous
                if ':' in domain:
                    try:
                        port = int(domain.split(':')[1])
                        if port not in (80, 443, 8080, 8443):
                            threat_indicators.append(f"Non-standard port: {port}")
                            threat_score += 0.25
                    except (ValueError, IndexError):
                        pass
            
            # Check for suspicious TLD
            if any(domain_no_port.endswith(tld) for tld in suspicious_tlds):
                threat_indicators.append(f"Suspicious TLD in URL: {domain}")
                threat_score += 0.25
            
            # Check for dangerous file extension in path
            if any(path.endswith(ext) for ext in dangerous_extensions):
                threat_indicators.append(f"Dangerous file download: {path_filename}")
                threat_score += 0.35
            
            # Check for malware distribution paths
            for mp in malware_path_patterns:
                if mp in path:
                    threat_indicators.append(f"Malware distribution path: {mp.strip('/')}")
                    threat_score += 0.35
                    break
            
            # Check for malware binary names in path
            for binary_name in malware_binary_names:
                if binary_name in path_filename or path.endswith(f'/{binary_name}'):
                    threat_indicators.append(f"Malware binary name in URL: {binary_name}")
                    threat_score += 0.3
                    break
            
            # Deeply nested subdomains (e.g., proxyzabc.zabc.net)
            subdomain_parts = domain_no_port.split('.')
            if len(subdomain_parts) >= 3:
                # Random-looking subdomain
                sub = subdomain_parts[0]
                if len(sub) > 8 and any(c.isdigit() for c in sub):
                    threat_indicators.append(f"Suspicious subdomain pattern: {domain_no_port}")
                    threat_score += 0.15
            
            # HTTP (not HTTPS) for non-localhost
            if parsed.scheme == 'http' and domain_no_port not in ('localhost', '127.0.0.1'):
                threat_indicators.append(f"Insecure HTTP link: {domain}")
                threat_score += 0.1
            
            # URL shortener
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link', 'ow.ly',
                         'is.gd', 'v.gd', 'tiny.cc', 'shorturl.at']
            if any(s in domain for s in shorteners):
                threat_indicators.append(f"URL shortener: {domain}")
                threat_score += 0.2
        except Exception:
            continue
    
    # ========== COMPOUND SCORING (multiple signal categories = much higher risk) ==========
    signal_count = sum([has_urgency, has_payment_request, has_credential_request, 
                       has_suspicious_url, has_suspicious_sender])
    
    if signal_count >= 4:
        threat_indicators.append("Multiple high-risk signal categories detected")
        threat_score += 0.3
    elif signal_count >= 3:
        threat_indicators.append("Multiple risk signals combined")
        threat_score += 0.2
    elif signal_count >= 2:
        threat_score += 0.1
    
    # Specific dangerous combos
    if has_urgency and has_payment_request and has_suspicious_url:
        threat_indicators.append("Urgent payment request with external link")
        threat_score += 0.15
    
    if has_credential_request and has_suspicious_url:
        threat_score += 0.1
    
    # Multiple malicious URL signals
    url_indicator_count = sum(1 for i in threat_indicators if any(kw in i for kw in 
        ['IP-based', 'Non-standard port', 'Dangerous file', 'Suspicious TLD', 'Malware']))
    if url_indicator_count >= 3:
        threat_score += 0.2
    elif url_indicator_count >= 2:
        threat_score += 0.1
    
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
        "confidence": 0.90 if signal_count >= 3 else (0.85 if threat_indicators else 0.6),
        "threat_indicators": threat_indicators[:10]  # Limit indicators
    }
