import os
import sys

# Add backend directory to path
backend_dir = os.path.join(os.getcwd(), "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.config.settings import settings

print(f"DEBUG: ENVIRONMENT: {settings.ENVIRONMENT}")
print(f"DEBUG: MONGODB_URI: {settings.MONGODB_URI}")
print(f"DEBUG: GMAIL_CLIENT_ID: {settings.GMAIL_CLIENT_ID}")
