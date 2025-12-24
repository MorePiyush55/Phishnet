"""
Quick script to check current inbox state
"""
import asyncio
from app.services.quick_imap import QuickIMAPService
from app.models.mongodb_models import ForwardedEmailAnalysis
from app.db.mongodb import MongoDBManager
from app.config.settings import settings

async def check_inbox():
    # Connect to MongoDB
    print("Connecting to MongoDB...")
    await MongoDBManager.connect_to_mongo(settings.get_mongodb_uri())
    await MongoDBManager.initialize_beanie([ForwardedEmailAnalysis])
    print("✅ MongoDB connected\n")
    
    # Check IMAP
    imap = QuickIMAPService()
    recent_emails = imap.get_recent_emails(limit=10)
    
    print(f"📧 Found {len(recent_emails)} recent emails in inbox:\n")
    
    for email in recent_emails:
        msg_id = email.get('message_id')
        subject = email.get('subject')
        uid = email.get('uid')
        
        # Check if in DB
        exists = await ForwardedEmailAnalysis.find_one({"email_metadata.message_id": msg_id})
        status = "✅ IN DB" if exists else "❌ NOT IN DB (will be processed)"
        
        print(f"  UID {uid}: {subject[:60]}")
        print(f"    Message-ID: {msg_id}")
        print(f"    Status: {status}\n")

if __name__ == "__main__":
    asyncio.run(check_inbox())
