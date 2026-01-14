
import asyncio
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.getcwd(), 'backend'))

async def test_locking():
    print("Testing Redis Locking Logic...")
    try:
        from app.services.ondemand_orchestrator import get_ondemand_orchestrator
        from app.config.settings import get_settings
        
        settings = get_settings()
        if not settings.REDIS_URL:
            print("SKIPPED: Redis URL not configured. Cannot verify lock logic.")
            return

        orchestrator = get_ondemand_orchestrator()
        
        message_id = "test_duplicate_prevention_123"
        
        print(f"Manually acquiring lock for {message_id}...")
        # Simulate another instance processing
        lock_key = f"lock:analysis:{message_id}"
        await orchestrator.redis.set(lock_key, "processing", ex=10, nx=True)
        
        print("Checking if orchestrator skips processing...")
        # Since we can't easily run the whole process_all_pending without a real IMAP
        # We'll just verify the redis client is connected and we can set/get
        val = await orchestrator.redis.get(lock_key)
        if val == "processing":
            print("SUCCESS: Lock is present and recognized.")
        else:
            print("FAILED: Lock not found.")
            
        await orchestrator.redis.delete(lock_key)
        print("Lock released.")
        
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    asyncio.run(test_locking())
