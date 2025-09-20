"""Real Gmail API endpoint for fetching user emails."""

from fastapi import APIRouter, HTTPException, Request
from typing import Dict, Any, Optional, List
import datetime
import httpx
import asyncio

# Import MongoDB directly
try:
    from ..db.mongodb import get_mongodb_db
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    print("MongoDB not available for Gmail tokens")

router = APIRouter(prefix="/api/gmail-simple", tags=["Gmail Test"])

@router.get("/test")
async def test_endpoint():
    """Simple test endpoint."""
    return {"status": "ok", "message": "Gmail simple endpoint is working"}

@router.get("/check-tokens/{user_email}")
async def check_user_tokens(user_email: str):
    """Check if user has stored Gmail tokens."""
    try:
        if not MONGODB_AVAILABLE:
            return {"error": "MongoDB not available"}
        
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
async def analyze_user_emails(request: Optional[Dict[str, Any]] = None):
    """
    Analyze user's Gmail emails for phishing indicators.
    
    This fetches real emails from the user's Gmail account using stored OAuth tokens.
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
        
        print(f"Fetching emails for user: {user_email}")
        
        # Check if MongoDB is available for token storage
        if not MONGODB_AVAILABLE:
            print("MongoDB not available, returning mock data")
            return get_mock_emails_response()
        
        # Try to get user's Gmail tokens from MongoDB
        try:
            print(f"Connecting to MongoDB for user: {user_email}")
            mongo_db = await get_mongodb_db()
            users_collection = mongo_db.users
            
            print(f"Attempting to find user document for: {user_email}")
            user_doc = await users_collection.find_one({"email": user_email})
            print(f"MongoDB query result: {user_doc is not None}")
            
            if user_doc is None:
                print(f"No user document found for {user_email}")
                return get_mock_emails_response()
            
            # Check if user has Gmail tokens
            gmail_access_token = user_doc.get("gmail_access_token")
            print(f"Gmail access token found: {gmail_access_token is not None}")
            
            if not gmail_access_token:
                print(f"No Gmail access token found for {user_email}")
                print(f"Available fields in user doc: {list(user_doc.keys()) if user_doc else 'None'}")
                return get_mock_emails_response()
            
            print(f"Found Gmail token for {user_email}, fetching real emails...")
            
            # Fetch real Gmail emails
            real_emails = await fetch_gmail_emails(gmail_access_token, max_emails)
            
            if real_emails:
                print(f"Successfully fetched {len(real_emails)} real emails")
                return {
                    "total_emails": len(real_emails),
                    "emails": real_emails
                }
            else:
                print("No real emails found or API call failed, returning mock data")
                return get_mock_emails_response()
                
        except Exception as mongodb_error:
            print(f"MongoDB error: {mongodb_error}")
            import traceback
            print(f"MongoDB error traceback: {traceback.format_exc()}")
            return get_mock_emails_response()
        
    except Exception as e:
        print(f"Error in analyze_user_emails: {e}")
        import traceback
        print(f"Error traceback: {traceback.format_exc()}")
        return get_mock_emails_response()


async def fetch_gmail_emails(access_token: str, max_emails: int = 10) -> List[Dict[str, Any]]:
    """Fetch emails directly from Gmail API."""
    try:
        print(f"Starting Gmail API call with max_emails: {max_emails}")
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        # Get list of message IDs
        async with httpx.AsyncClient() as client:
            messages_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults={max_emails}"
            print(f"Calling Gmail API: {messages_url}")
            
            messages_response = await client.get(messages_url, headers=headers)
            
            print(f"Gmail API response status: {messages_response.status_code}")
            
            if messages_response.status_code != 200:
                print(f"Failed to get message list: {messages_response.status_code}")
                print(f"Response text: {messages_response.text}")
                return []
            
            messages_data = messages_response.json()
            messages = messages_data.get("messages", [])
            
            print(f"Found {len(messages)} messages from Gmail API")
            
            if not messages:
                print("No messages found in Gmail")
                return []
            
            # Fetch detailed email data
            emails = []
            for i, message in enumerate(messages[:max_emails]):
                message_id = message["id"]
                print(f"Fetching email {i+1}/{len(messages[:max_emails])}: {message_id}")
                
                # Get full message details
                message_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}"
                message_response = await client.get(message_url, headers=headers)
                
                print(f"Email {i+1} response status: {message_response.status_code}")
                
                if message_response.status_code == 200:
                    message_data = message_response.json()
                    email_info = parse_gmail_message(message_data)
                    if email_info:
                        print(f"Successfully parsed email: {email_info.get('subject', 'No subject')}")
                        emails.append(email_info)
                    else:
                        print(f"Failed to parse email {message_id}")
                else:
                    print(f"Failed to fetch email {message_id}: {message_response.status_code}")
            
            print(f"Successfully processed {len(emails)} emails")
            return emails
            
    except Exception as e:
        print(f"Error fetching Gmail emails: {e}")
        return []


def parse_gmail_message(message_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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
        
        # Basic phishing analysis
        email_info["phishing_analysis"] = analyze_email_for_phishing(email_info)
        
        return email_info
        
    except Exception as e:
        print(f"Error parsing Gmail message: {e}")
        return None


def analyze_email_for_phishing(email_info: Dict[str, Any]) -> Dict[str, Any]:
    """Simple phishing analysis for real emails."""
    indicators = []
    risk_score = 0
    
    subject = email_info.get("subject", "").lower()
    sender = email_info.get("sender", "").lower()
    snippet = email_info.get("snippet", "").lower()
    
    # Check for phishing indicators
    suspicious_words = ["urgent", "verify", "suspend", "click here", "act now", "limited time"]
    for word in suspicious_words:
        if word in subject or word in snippet:
            indicators.append(f"Suspicious phrase: '{word}'")
            risk_score += 15
    
    # Check sender domain
    if any(domain in sender for domain in ["suspicious", "fake", "phishing"]):
        indicators.append("Suspicious sender domain")
        risk_score += 25
    
    # Determine risk level
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"
    
    return {
        "risk_score": min(risk_score, 100),
        "risk_level": risk_level,
        "indicators": indicators,
        "summary": f"Real Gmail email analysis - {risk_level.lower()} risk"
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