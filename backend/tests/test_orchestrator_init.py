import asyncio
import logging
import os
import sys

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Mock environment variables if needed
os.environ["REDIS_URL"] = "redis://localhost:6379"

# Add current directory to path
sys.path.append(os.getcwd())

async def test_orchestrator():
    try:
        print("Importing orchestrator...")
        from app.core.orchestrator import get_orchestrator
        
        print("Getting orchestrator instance...")
        orchestrator = get_orchestrator()
        
        print("Starting orchestrator...")
        await orchestrator.start()
        
        print("Orchestrator started successfully!")
        
        # Test a simple email processing job
        print("Testing email processing...")
        email_content = {
            "sender": "test@example.com",
            "subject": "Test Email",
            "body_text": "This is a test email.",
            "message_id": "test-id-123"
        }
        
        result = await orchestrator.orchestrate_email_processing(email_content)
        print(f"Orchestration result: {result}")
        
        print("Stopping orchestrator...")
        await orchestrator.stop()
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_orchestrator())
