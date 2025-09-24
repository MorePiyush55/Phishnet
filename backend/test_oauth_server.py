"""Simple test server to check OAuth callback functionality."""

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI(title="PhishNet OAuth Test", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://phishnet-tau.vercel.app", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "PhishNet OAuth Test Server Running"}

@app.get("/api/test/oauth")
async def start_oauth():
    """Start OAuth flow - redirect to Google."""
    client_id = os.getenv("GMAIL_CLIENT_ID", "your-client-id")
    redirect_uri = "https://phishnet-backend-iuoc.onrender.com/api/test/oauth/callback"
    
    auth_url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"client_id={client_id}&"
        f"redirect_uri={redirect_uri}&"
        f"scope=https://www.googleapis.com/auth/gmail.readonly&"
        f"response_type=code&"
        f"access_type=offline&"
        f"prompt=consent"
    )
    
    return RedirectResponse(auth_url)

@app.get("/api/test/oauth/callback")
async def oauth_callback(code: str = None, error: str = None):
    """OAuth callback - simplified test version."""
    frontend_url = "https://phishnet-tau.vercel.app"
    
    if error:
        return RedirectResponse(f"{frontend_url}/auth/callback?error={error}")
    
    if not code:
        return RedirectResponse(f"{frontend_url}/auth/callback?error=no_code")
    
    # For testing, create dummy JWT tokens
    import jwt
    from datetime import datetime, timedelta
    
    secret = "test-secret-key"
    user_email = "test@example.com"
    
    # Create test tokens
    access_token = jwt.encode({
        "sub": user_email,
        "user_id": 1,
        "exp": datetime.utcnow() + timedelta(days=1)
    }, secret, algorithm="HS256")
    
    refresh_token = jwt.encode({
        "sub": user_email,
        "user_id": 1,
        "exp": datetime.utcnow() + timedelta(days=30)
    }, secret, algorithm="HS256")
    
    # Redirect to frontend with tokens
    from urllib.parse import urlencode
    redirect_params = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_email": user_email
    }
    
    redirect_url = f"{frontend_url}/auth/callback?{urlencode(redirect_params)}"
    return RedirectResponse(redirect_url)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)