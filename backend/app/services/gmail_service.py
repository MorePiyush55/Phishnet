"""Gmail API service for fetching and analyzing emails."""

import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from app.models.mongodb_models import User
from app.db.mongodb import get_mongodb_db

class GmailService:
    """Service for interacting with Gmail API."""
    
    def __init__(self):
        self.base_url = "https://gmail.googleapis.com/gmail/v1"
    
    async def get_user_tokens(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user's Gmail tokens from database."""
        mongo_db = await get_mongodb_db()
        users_collection = mongo_db.users
        
        user = await users_collection.find_one({"email": email})
        if not user:
            return None
            
        return {
            "access_token": user.get("gmail_access_token"),
            "refresh_token": user.get("gmail_refresh_token"),
            "expires_at": user.get("gmail_token_expires_at")
        }
    
    async def refresh_access_token(self, email: str, refresh_token: str) -> Optional[str]:
        """Refresh expired access token."""
        import os
        
        client_id = os.getenv("GMAIL_CLIENT_ID")
        client_secret = os.getenv("GMAIL_CLIENT_SECRET")
        
        if not client_id or not client_secret:
            raise Exception("OAuth credentials not configured")
        
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            
        if response.status_code != 200:
            raise Exception(f"Token refresh failed: {response.text}")
            
        tokens = response.json()
        new_access_token = tokens.get("access_token")
        
        if not new_access_token:
            raise Exception("No access token in refresh response")
        
        # Update user's access token in database
        mongo_db = await get_mongodb_db()
        users_collection = mongo_db.users
        
        expires_in = tokens.get('expires_in', 3600)
        expires_at = datetime.now(timezone.utc).timestamp() + expires_in
        
        await users_collection.update_one(
            {"email": email},
            {
                "$set": {
                    "gmail_access_token": new_access_token,
                    "gmail_token_expires_at": datetime.fromtimestamp(expires_at, timezone.utc),
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )
        
        return new_access_token
    
    async def get_valid_access_token(self, email: str) -> Optional[str]:
        """Get a valid access token, refreshing if necessary."""
        tokens = await self.get_user_tokens(email)
        if not tokens:
            return None
            
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]
        expires_at = tokens["expires_at"]
        
        # Check if token is expired (with 5 minute buffer)
        if expires_at and datetime.now(timezone.utc) >= expires_at.replace(tzinfo=timezone.utc):
            if refresh_token:
                access_token = await self.refresh_access_token(email, refresh_token)
            else:
                return None
                
        return access_token
    
    async def get_email_list(self, email: str, max_results: int = 10, query: str = "") -> List[Dict[str, Any]]:
        """Get list of emails from user's Gmail."""
        access_token = await self.get_valid_access_token(email)
        if not access_token:
            raise Exception("No valid access token available")
        
        headers = {"Authorization": f"Bearer {access_token}"}
        
        # Build query parameters
        params = {
            "maxResults": max_results,
            "q": query if query else "in:inbox"  # Default to inbox
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/users/me/messages",
                headers=headers,
                params=params
            )
        
        if response.status_code != 200:
            raise Exception(f"Failed to fetch emails: {response.text}")
            
        return response.json().get("messages", [])
    
    async def get_email_details(self, email: str, message_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific email."""
        access_token = await self.get_valid_access_token(email)
        if not access_token:
            raise Exception("No valid access token available")
        
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/users/me/messages/{message_id}",
                headers=headers,
                params={"format": "full"}
            )
        
        if response.status_code != 200:
            raise Exception(f"Failed to fetch email details: {response.text}")
            
        return response.json()
    
    def extract_email_info(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract useful information from Gmail message data."""
        payload = message_data.get("payload", {})
        headers = payload.get("headers", [])
        
        # Extract headers
        email_info = {
            "id": message_data.get("id"),
            "thread_id": message_data.get("threadId"),
            "snippet": message_data.get("snippet", ""),
            "size_estimate": message_data.get("sizeEstimate", 0),
            "received_at": None,
            "subject": "",
            "from": "",
            "to": "",
            "reply_to": "",
            "body_text": "",
            "body_html": "",
            "attachments": []
        }
        
        # Parse headers
        for header in headers:
            name = header.get("name", "").lower()
            value = header.get("value", "")
            
            if name == "subject":
                email_info["subject"] = value
            elif name == "from":
                email_info["from"] = value
            elif name == "to":
                email_info["to"] = value
            elif name == "reply-to":
                email_info["reply_to"] = value
            elif name == "date":
                email_info["received_at"] = value
        
        # Extract body content
        email_info.update(self._extract_body_content(payload))
        
        return email_info
    
    def _extract_body_content(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Extract body content from email payload."""
        result = {"body_text": "", "body_html": "", "attachments": []}
        
        if "parts" in payload:
            # Multi-part message
            for part in payload["parts"]:
                result.update(self._process_message_part(part))
        else:
            # Single part message
            result.update(self._process_message_part(payload))
        
        return result
    
    def _process_message_part(self, part: Dict[str, Any]) -> Dict[str, Any]:
        """Process individual message part."""
        result = {"body_text": "", "body_html": "", "attachments": []}
        
        mime_type = part.get("mimeType", "")
        body = part.get("body", {})
        
        if mime_type == "text/plain":
            data = body.get("data", "")
            if data:
                import base64
                try:
                    result["body_text"] = base64.urlsafe_b64decode(data).decode('utf-8')
                except:
                    pass
                    
        elif mime_type == "text/html":
            data = body.get("data", "")
            if data:
                import base64
                try:
                    result["body_html"] = base64.urlsafe_b64decode(data).decode('utf-8')
                except:
                    pass
        
        elif "parts" in part:
            # Nested parts
            for nested_part in part["parts"]:
                nested_result = self._process_message_part(nested_part)
                result["body_text"] += nested_result["body_text"]
                result["body_html"] += nested_result["body_html"]
                result["attachments"].extend(nested_result["attachments"])
        
        # Handle attachments
        filename = part.get("filename", "")
        if filename and body.get("attachmentId"):
            result["attachments"].append({
                "filename": filename,
                "mime_type": mime_type,
                "size": body.get("size", 0),
                "attachment_id": body.get("attachmentId")
            })
        
        return result
    
    async def analyze_emails_for_phishing(self, email: str, max_emails: int = 10) -> List[Dict[str, Any]]:
        """Fetch emails and analyze them for phishing indicators."""
        
        # Get email list
        email_list = await self.get_email_list(email, max_emails)
        
        analyzed_emails = []
        
        for message in email_list:
            message_id = message["id"]
            
            try:
                # Get detailed email data
                email_details = await self.get_email_details(email, message_id)
                
                # Extract email information
                email_info = self.extract_email_info(email_details)
                
                # Analyze for phishing
                phishing_analysis = self._analyze_phishing_indicators(email_info)
                
                # Combine email info with analysis
                analyzed_email = {
                    **email_info,
                    "phishing_analysis": phishing_analysis
                }
                
                analyzed_emails.append(analyzed_email)
                
            except Exception as e:
                print(f"Error analyzing email {message_id}: {str(e)}")
                continue
        
        return analyzed_emails
    
    def _analyze_phishing_indicators(self, email_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email for phishing indicators."""
        
        indicators = []
        risk_score = 0
        max_score = 100
        
        subject = email_info.get("subject", "").lower()
        sender = email_info.get("from", "").lower()
        body_text = email_info.get("body_text", "").lower()
        body_html = email_info.get("body_html", "").lower()
        
        # Subject line analysis
        suspicious_subject_words = [
            "urgent", "verify", "suspend", "click here", "act now", 
            "limited time", "congratulations", "winner", "prize",
            "account locked", "security alert", "update payment"
        ]
        
        for word in suspicious_subject_words:
            if word in subject:
                indicators.append(f"Suspicious subject word: '{word}'")
                risk_score += 15
        
        # Sender analysis
        if "noreply" in sender or "no-reply" in sender:
            indicators.append("Sender is a no-reply address")
            risk_score += 5
        
        # Domain spoofing (basic check)
        common_spoofed_domains = ["paypal", "amazon", "google", "microsoft", "apple", "bank"]
        for domain in common_spoofed_domains:
            if domain in sender and not sender.endswith(f"@{domain}.com"):
                indicators.append(f"Possible domain spoofing: {domain}")
                risk_score += 25
        
        # Body content analysis
        body_content = body_text + " " + body_html
        
        suspicious_phrases = [
            "click here to verify", "update your payment", "account suspended",
            "verify your identity", "claim your prize", "limited time offer",
            "urgent action required", "security breach", "unusual activity"
        ]
        
        for phrase in suspicious_phrases:
            if phrase in body_content:
                indicators.append(f"Suspicious phrase: '{phrase}'")
                risk_score += 10
        
        # URL analysis (basic)
        import re
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body_content)
        
        for url in urls:
            if len(url) > 50:  # Very long URLs can be suspicious
                indicators.append("Suspicious long URL found")
                risk_score += 10
            
            # Check for URL shorteners
            url_shorteners = ["bit.ly", "tinyurl", "t.co", "short.link"]
            for shortener in url_shorteners:
                if shortener in url:
                    indicators.append(f"URL shortener detected: {shortener}")
                    risk_score += 15
        
        # Determine risk level
        risk_score = min(risk_score, max_score)  # Cap at 100
        
        if risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        elif risk_score >= 10:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators,
            "summary": f"Found {len(indicators)} potential phishing indicators"
        }