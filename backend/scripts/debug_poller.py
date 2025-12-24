import asyncio
import os
import sys
import logging
import traceback

# Add backend directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.config.settings import get_settings
from app.services.email_poller import email_polling_service
from app.db.mongodb import MongoDBManager
from app.models.mongodb_models import ForwardedEmailAnalysis

# Configure logging to stdout
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def debug_poller():
    print("--- Starting Debug Poller ---")
    settings = get_settings()
    
    # Initialize DB (Required for save())
    if settings.get_mongodb_uri():
        print("Connecting to MongoDB...")
        await MongoDBManager.connect_to_mongo()
        await MongoDBManager.initialize_beanie([ForwardedEmailAnalysis])
        print("MongoDB Connected.")
    else:
        print("WARNING: MongoDB not configured.")

    print("Triggering poll_and_analyze...")
    try:
        await email_polling_service.poll_and_analyze()
        print("--- Polling Complete (Success) ---")
    except Exception:
        print("--- Polling Failed! Traceback: ---")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_poller())
