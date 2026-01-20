"""Real Gmail API endpoint for fetching user emails with proper authentication."""

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, Any, Optional, List
import datetime
import httpx
import asyncio
import jwt

# Import dependencies
from app.db.mongodb import get_mongodb_db
from app.models.mongodb_models import User
from app.config.settings import settings

# Import real threat analyzer
from app.analyzers.real_threat_analyzer import real_threat_analyzer

# MongoDB is primary for this mode
MONGODB_AVAILABLE = True

router = APIRouter(prefix="/api/gmail-simple", tags=["Gmail Test"])
security = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[User]:
    """Get current authenticated user from JWT token."""
    if not credentials:
        return None
    
    try:
        # Decode JWT token
        token = credentials.credentials
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=["HS256"]
        )
        
        # Get user_id from token
        user_email = payload.get("sub")
        
        if not user_email:
            return None
        
        # Find user in MongoDB
        user = await User.find_one({"email": user_email})
        
        if user and user.is_active:
            return user
        
        return None
        
    except Exception as e:
        print(f"DEBUG: Token verification failed: {e}")
        return None

@router.get("/test")
async def test_endpoint():
    """Simple test endpoint."""
    return {"status": "ok", "message": "Gmail simple endpoint is working"}

@router.get("/check-tokens/{user_email}")
async def check_user_tokens(
    user_email: str,
    current_user: Optional[User] = Depends(get_current_user)
):
    """Check if user has stored Gmail tokens - now user-specific."""
    # Check if authenticated user has access to request tokens for this email
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Only allow users to check their own tokens or admin users
    if current_user.email != user_email and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Can only check your own tokens")
    
    # First check MongoDB (primary for this user)
    has_tokens = current_user.gmail_access_token is not None
    
    if has_tokens:
        return {
            "has_tokens": True,
            "user_email": user_email,
            "token_source": "mongodb",
            "token_created": current_user.created_at,
            "has_refresh_token": current_user.gmail_refresh_token is not None
        }
    
    # Fallback to MongoDB for backward compatibility
    if not MONGODB_AVAILABLE:
        return {"has_tokens": False, "user_email": user_email, "error": "No authentication tokens found"}
    
    try:
        mongo_db = await get_mongodb_db()
        users_collection = mongo_db.users
        
        user_doc = await users_collection.find_one({"email": user_email})
        
        if user_doc is None:
            return {
                "user_email": user_email,
                "found": False,
                "message": "No user document found"
            }
        
        has_gmail_token = user_doc.get("gmail_access_token") is not None
        
        return {
            "user_email": user_email,
            "found": True,
            "has_gmail_token": has_gmail_token,
            "available_fields": list(user_doc.keys()),
            "oauth_connected_at": str(user_doc.get("oauth_connected_at", "Not found")),
            "gmail_scopes": user_doc.get("gmail_scopes", [])
        }
        
    except Exception as e:
        return {"error": f"Failed to check tokens: {str(e)}"}

@router.get("/health")
async def gmail_health():
    """Health check for Gmail simple endpoint."""
    return {"status": "ok", "service": "gmail_simple", "mongodb_available": MONGODB_AVAILABLE}

@router.post("/analyze")
async def analyze_user_emails(
    request: Optional[Dict[str, Any]] = None,
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Analyze user's Gmail emails for phishing indicators.
    
    This fetches real emails from the authenticated user's Gmail account using stored OAuth tokens.
    """
    try:
        # Check authentication
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Get request parameters
        max_emails = request.get("max_emails", 10) if request else 10
        user_email = current_user.email
        
        print(f"Fetching emails for authenticated user: {user_email}")
        
        gmail_access_token = current_user.gmail_access_token
        token_source = "mongodb"
        oauth_token = None # No SQLAlchemy token here
        if not gmail_access_token:
            print(f"No Gmail access token found for {user_email} in either OAuth or MongoDB")
            return {
                "total_emails": 0,
                "fetched_emails": 0,
                "emails": [],
                "error": "Authentication required. Please connect your Gmail account."
            }
        
        print(f"Found Gmail token for {user_email} from {token_source}, fetching real emails...")
        
        # Fetch real Gmail emails with pagination
        gmail_result = await fetch_gmail_emails(gmail_access_token, max_emails)
        
        # Handle token expiration (MongoDB simple version)
        if gmail_result.get("error") == "token_expired":
            print(f"Token expired for {user_email}. Refresh needed.")
            # In a real app, we would refresh using current_user.gmail_refresh_token
            return {
                "total_emails": 0,
                "fetched_emails": 0,
                "emails": [],
                "error": "Session expired. Please reconnect your Gmail account."
            }
        
        if gmail_result.get("emails"):
            real_emails = gmail_result["emails"]
            print(f"Successfully fetched {len(real_emails)} real emails")
            return {
                "total_emails": gmail_result.get("total_available", len(real_emails)),
                "fetched_emails": len(real_emails),
                "next_page_token": gmail_result.get("next_page_token"),
                "token_source": token_source,
                "user_email": user_email,
                "emails": real_emails
            }
        else:
            error = gmail_result.get("error")
            if error:
                print(f"Gmail API error: {error}")
            print("No real emails found or API call failed")
            return {
                "total_emails": 0,
                "fetched_emails": 0,
                "emails": [],
                "message": "No emails found in your inbox."
            }
        
    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        print(f"Error in analyze_user_emails: {e}")
        import traceback
        print(f"Error traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


async def fetch_gmail_emails(access_token: str, max_emails: int = 10, page_token: Optional[str] = None) -> Dict[str, Any]:
    """Fetch emails directly from Gmail API with pagination support."""
    try:
        print(f"Starting Gmail API call with max_emails: {max_emails}, page_token: {page_token}")
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        # Get list of message IDs with pagination support
        async with httpx.AsyncClient() as client:
            # Build URL with proper parameters
            params = {
                "maxResults": min(max_emails, 100),  # Gmail API supports up to 500 but let's be conservative
                "q": "in:inbox"
            }
            if page_token:
                params["pageToken"] = page_token
            
            messages_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
            print(f"Calling Gmail API: {messages_url} with params: {params}")
            
            messages_response = await client.get(messages_url, headers=headers, params=params)
            
            print(f"Gmail API response status: {messages_response.status_code}")
            
            if messages_response.status_code == 401:
                print("Gmail API returned 401 - access token likely expired")
                return {"error": "token_expired", "emails": [], "next_page_token": None}
            elif messages_response.status_code != 200:
                print(f"Failed to get message list: {messages_response.status_code}")
                print(f"Response text: {messages_response.text}")
                return {"error": f"gmail_api_error_{messages_response.status_code}", "emails": [], "next_page_token": None}
            
            messages_data = messages_response.json()
            messages = messages_data.get("messages", [])
            next_page_token = messages_data.get("nextPageToken")
            
            print(f"Found {len(messages)} messages from Gmail API")
            print(f"Next page token: {next_page_token}")
            
            if not messages:
                print("No messages found in Gmail")
                return {"emails": [], "next_page_token": None, "total_fetched": 0}
            
            # Fetch detailed email data in batches for better performance
            emails = []
            batch_size = 10  # Process emails in smaller batches to avoid timeouts
            
            for i in range(0, len(messages), batch_size):
                batch = messages[i:i + batch_size]
                print(f"Processing batch {i//batch_size + 1}: emails {i+1}-{min(i+batch_size, len(messages))}")
                
                # Process batch in parallel for better performance
                batch_tasks = []
                for message in batch:
                    message_id = message["id"]
                    message_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}"
                    batch_tasks.append(client.get(message_url, headers=headers))
                
                # Execute batch requests in parallel
                batch_responses = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                # Process email parsing in parallel too
                parse_tasks = []
                for j, response in enumerate(batch_responses):
                    if isinstance(response, Exception):
                        print(f"Error fetching email {batch[j]['id']}: {response}")
                        continue
                        
                    if response.status_code == 200:
                        message_data = response.json()
                        parse_tasks.append(parse_gmail_message(message_data))
                    else:
                        print(f"Failed to fetch email {batch[j]['id']}: {response.status_code}")
                
                # Wait for all parsing to complete
                if parse_tasks:
                    parsed_emails = await asyncio.gather(*parse_tasks, return_exceptions=True)
                    for email_info in parsed_emails:
                        if isinstance(email_info, Exception):
                            print(f"Error parsing email: {email_info}")
                            continue
                        if email_info:
                            emails.append(email_info)
            
            print(f"Successfully processed {len(emails)} emails")
            return {
                "emails": emails,
                "next_page_token": next_page_token,
                "total_fetched": len(emails),
                "total_available": len(messages)
            }
            
    except Exception as e:
        print(f"Error fetching Gmail emails: {e}")
        return {"emails": [], "next_page_token": None, "total_fetched": 0, "error": str(e)}


async def parse_gmail_message(message_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse Gmail message data into our format."""
    try:
        payload = message_data.get("payload", {})
        headers = payload.get("headers", [])
        
        # Extract email information
        email_info = {
            "id": message_data.get("id", ""),
            "subject": "",
            "sender": "",
            "received_at": "",
            "snippet": message_data.get("snippet", ""),
            "phishing_analysis": {
                "risk_score": 0,
                "risk_level": "SAFE",
                "indicators": [],
                "summary": "Real email from Gmail"
            }
        }
        
        # Parse headers
        for header in headers:
            name = header.get("name", "").lower()
            value = header.get("value", "")
            
            if name == "subject":
                email_info["subject"] = value
            elif name == "from":
                email_info["sender"] = value
            elif name == "date":
                # Convert date to ISO format
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(value)
                    email_info["received_at"] = dt.isoformat()
                except:
                    email_info["received_at"] = value
        
        # Real phishing analysis using advanced threat detection
        email_info["phishing_analysis"] = await analyze_email_for_phishing(email_info)
        
        return email_info
        
    except Exception as e:
        print(f"Error parsing Gmail message: {e}")
        return None


async def analyze_email_for_phishing(email_info: Dict[str, Any]) -> Dict[str, Any]:
    """Real phishing analysis for emails using advanced threat detection."""
    try:
        # Extract email components
        subject = email_info.get("subject", "")
        sender = email_info.get("sender", "")
        snippet = email_info.get("snippet", "")
        headers = email_info.get("headers", {})
        
        # Use real threat analyzer instead of mock analysis
        analysis_result = await real_threat_analyzer.analyze_email_threat(
            subject=subject,
            sender=sender,
            body="",  # Gmail API provides snippet instead of full body
            headers=headers,
            snippet=snippet
        )
        
        return analysis_result
        
    except Exception as e:
        print(f"Real threat analysis failed: {e}")
        # Fallback to safe default instead of mock
        return {
            "risk_score": 25,
            "risk_level": "LOW",
            "indicators": ["analysis_error"],
            "summary": "Threat analysis failed - email requires manual review"
        }

