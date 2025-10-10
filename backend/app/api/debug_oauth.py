"""Debug endpoint to check OAuth configuration."""

from fastapi import APIRouter
import os

router = APIRouter(prefix="/api/debug", tags=["Debug"])

@router.get("/oauth-config")
async def check_oauth_config():
    """Check OAuth configuration without exposing sensitive data."""
    
    return {
        "oauth_configuration": {
            "gmail_client_id_configured": bool(os.getenv("GMAIL_CLIENT_ID")),
            "gmail_client_secret_configured": bool(os.getenv("GMAIL_CLIENT_SECRET")),
            "gmail_redirect_uri": os.getenv("GMAIL_REDIRECT_URI", "Not set"),
            "frontend_url": os.getenv("FRONTEND_URL", "Not set"),
            "base_url": os.getenv("BASE_URL", "Not set"),
            "environment_check": "OK"
        },
        "credentials_details": {
            "client_id_length": len(os.getenv("GMAIL_CLIENT_ID", "")) if os.getenv("GMAIL_CLIENT_ID") else 0,
            "client_secret_length": len(os.getenv("GMAIL_CLIENT_SECRET", "")) if os.getenv("GMAIL_CLIENT_SECRET") else 0,
            "client_id_format_check": os.getenv("GMAIL_CLIENT_ID", "").endswith(".googleusercontent.com") if os.getenv("GMAIL_CLIENT_ID") else False
        },
        "required_environment_variables": [
            "GMAIL_CLIENT_ID",
            "GMAIL_CLIENT_SECRET",
            "GMAIL_REDIRECT_URI",
            "FRONTEND_URL",
            "BASE_URL"
        ],
        "redirect_uri_analysis": {
            "gmail_redirect_uri": os.getenv("GMAIL_REDIRECT_URI", "Not set"),
            "computed_test_callback": f"https://phishnet-backend-iuoc.onrender.com/api/test/oauth/callback",
            "base_url_configured": bool(os.getenv("BASE_URL")),
            "potential_mismatch": os.getenv("GMAIL_REDIRECT_URI", "") != f"https://phishnet-backend-iuoc.onrender.com/api/test/oauth/callback"
        },
        "instructions": {
            "step_1": "Go to https://console.cloud.google.com/",
            "step_2": "Create OAuth 2.0 credentials",
            "step_3": "Add environment variables to Render dashboard",
            "step_4": "Restart the service after adding variables"
        }
    }