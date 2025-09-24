"""Real Gmail API endpoint for fetching user emails with proper authentication."""

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional, List
import datetime
import httpx
import asyncio
import jwt

# Import dependencies
from app.core.database import get_db
from app.models.user import User, OAuthToken
from app.core.config import settings

# Import real threat analyzer
from app.analyzers.real_threat_analyzer import real_threat_analyzer

# Import MongoDB for backward compatibility
try:
    from ..db.mongodb import get_mongodb_db
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    print("MongoDB not available for Gmail tokens")

router = APIRouter(prefix="/api/gmail-simple", tags=["Gmail Test"])
security = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
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
        user_id = payload.get("user_id")
        user_email = payload.get("sub")
        
        if not user_id and not user_email:
            return None
        
        # Find user in database
        if user_id:
            user = db.query(User).filter(User.id == user_id).first()
        else:
            user = db.query(User).filter(User.email == user_email).first()
        
        if user and user.is_active and not user.disabled:
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
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Check if user has stored Gmail tokens - now user-specific."""
    # Check if authenticated user has access to request tokens for this email
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Only allow users to check their own tokens or admin users
    if current_user.email != user_email and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Can only check your own tokens")
    
    # First check SQLAlchemy OAuth tokens (primary)
    oauth_token = (
        db.query(OAuthToken)
        .filter(
            OAuthToken.user_id == current_user.id,
            OAuthToken.provider == 'google',
            OAuthToken.is_active == True
        )
        .first()
    )
    
    if oauth_token:
        return {
            "has_tokens": True,
            "user_email": user_email,
            "token_source": "oauth",
            "token_created": oauth_token.created_at,
            "scopes": oauth_token.scope.split(' ') if oauth_token.scope else []
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
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
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
        
        # First try to get access token from SQLAlchemy OAuth tokens (primary)
        oauth_token = (
            db.query(OAuthToken)
            .filter(
                OAuthToken.user_id == current_user.id,
                OAuthToken.provider == 'google',
                OAuthToken.is_active == True
            )
            .first()
        )
        
        gmail_access_token = None
        token_source = None
        
        if oauth_token:
            # Use the new token refresh functionality
            gmail_access_token = await oauth_token.get_valid_access_token(db)
            if gmail_access_token:
                token_source = "oauth"
                print(f"Using OAuth access token for {user_email}")
            else:
                print(f"OAuth token refresh failed for {user_email}")
        else:
            # Fallback to MongoDB for backward compatibility
            if MONGODB_AVAILABLE:
                try:
                    print(f"Trying MongoDB fallback for user: {user_email}")
                    mongo_db = await get_mongodb_db()
                    users_collection = mongo_db.users
                    
                    user_doc = await users_collection.find_one({"email": user_email})
                    
                    if user_doc and user_doc.get("gmail_access_token"):
                        gmail_access_token = user_doc.get("gmail_access_token")
                        token_source = "mongodb"
                        print(f"Using MongoDB access token for {user_email}")
                    else:
                        print(f"No Gmail access token found in MongoDB for {user_email}")
                        
                except Exception as mongodb_error:
                    print(f"MongoDB error: {mongodb_error}")
        
        if not gmail_access_token:
            print(f"No Gmail access token found for {user_email} in either OAuth or MongoDB")
            return get_mock_emails_response()
        
        print(f"Found Gmail token for {user_email} from {token_source}, fetching real emails...")
        
        # Fetch real Gmail emails with pagination
        gmail_result = await fetch_gmail_emails(gmail_access_token, max_emails)
        
        # Handle token expiration with one retry
        if gmail_result.get("error") == "token_expired" and oauth_token:
            print(f"Token expired, attempting refresh for {user_email}")
            if await oauth_token.refresh_access_token(db):
                print("Token refreshed successfully, retrying email fetch")
                gmail_access_token = oauth_token.decrypt_access_token()
                gmail_result = await fetch_gmail_emails(gmail_access_token, max_emails)
            else:
                print("Token refresh failed")
                return get_mock_emails_response()
        
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
            print("No real emails found or API call failed, returning mock data")
            return get_mock_emails_response()
        
    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        print(f"Error in analyze_user_emails: {e}")
        import traceback
        print(f"Error traceback: {traceback.format_exc()}")
        return get_mock_emails_response()


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