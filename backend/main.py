# -*- coding: utf-8 -*-
"""
PhishNet Backend Server Entry Point
"""
import os
import sys

# Add backend directory to Python path for imports
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Also add project root for other potential imports
project_root = os.path.dirname(backend_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Explicitly load environment variables from backend/.env
from dotenv import load_dotenv
env_path = os.path.join(backend_dir, ".env")
if os.path.exists(env_path):
    load_dotenv(env_path)
    print(f"DEBUG: Loaded .env from {env_path}")
else:
    print(f"DEBUG: .env not found at {env_path}")

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.environ.get("PORT", 8080))
    print(f"Starting PhishNet backend on port {port}")
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
        reload=True
    )