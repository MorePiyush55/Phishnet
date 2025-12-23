import asyncio
import os
import sys
import logging
from datetime import datetime
from typing import List, Dict, Any

# Add backend directory to path so we can import app modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.config.settings import get_settings
from app.services.quick_imap import QuickIMAPService
from app.db.mongodb import MongoDBManager
from app.models.mongodb_models import ForwardedEmailAnalysis

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def diagnose_workflow():
    """
    Diagnose the email analysis workflow.
    
    Steps:
    1. Verify IMAP connection
    2. Fetch recent emails (SEEN and UNSEEN)
    3. Check DB status for these emails
    4. Simulate processing for the most recent email
    """
    logger.info("Starting PhishNet Email Workflow Diagnosis")
    settings = get_settings()
    
    # 1. IMAP Connection Test
    logger.info("\n[1/4] Testing IMAP Connection...")
    imap_service = QuickIMAPService()
    
    if imap_service.test_connection():
        logger.info("✅ IMAP Connection Successful")
    else:
        logger.error("❌ IMAP Connection Failed! Check credentials.")
        return

    # 2. Inbox Access (Recent Emails)
    logger.info("\n[2/4] Checking Recent Emails (Inbox)...")
    try:
        from imap_tools import MailBox, A
        
        recent_emails = []
        with MailBox(imap_service.host).login(imap_service.user, imap_service.password, imap_service.folder) as mailbox:
            # Fetch last 50 emails to catch older ones
            for msg in mailbox.fetch(limit=50, reverse=True):
                recent_emails.append({
                    'uid': msg.uid,
                    'subject': msg.subject,
                    'date': msg.date,
                    'flags': msg.flags,
                    'message_id': msg.headers.get('message-id', [''])[0]
                })
        
        if recent_emails:
            logger.info(f"✅ Found {len(recent_emails)} recent emails:")
            for email in recent_emails:
                status = "READ" if '\\Seen' in email['flags'] else "UNREAD"
                logger.info(f"   - [{status}] {email['date']} | {email['subject']} | UID: {email['uid']}")
        else:
            logger.warning("⚠️ No emails found in Inbox!")
            
    except Exception as e:
        logger.error(f"❌ Failed to fetch emails: {e}")
        return

    # 3. Database Check
    logger.info("\n[3/4] Checking Database Status...")
    try:
        if settings.get_mongodb_uri():
            await MongoDBManager.connect_to_mongo()
            await MongoDBManager.initialize_beanie([ForwardedEmailAnalysis])
            logger.info("✅ Connected to MongoDB")
            
            for email in recent_emails:
                msg_id = email['message_id']
                if not msg_id:
                    logger.warning(f"   - Email UID {email['uid']} has no Message-ID!")
                    continue
                    
                exists = await ForwardedEmailAnalysis.find_one(ForwardedEmailAnalysis.email_metadata.message_id == msg_id)
                # Note: The model field might be nested or we might need to search by a different field 
                # strictly speaking ForwardedEmailAnalysis doesn't have message_id at top level in the definition I saw?
                # Let's check the model definition again.
                # It has: user_id, forwarded_by, original_sender, original_subject...
                # It doesn't seem to have a dedicated `message_id` field at top level! 
                # It has `email_metadata`. 
                
                # Correction: I need to check how I plan to store it. 
                # In my plan I said "Query ForwardedEmailAnalysis for message_id equality".
                # I should probably add a `message_id` field to the model or index `email_metadata.message_id`.
                # For now let's query `email_metadata.message_id`.
                
                exists = await ForwardedEmailAnalysis.find_one({"email_metadata.message_id": msg_id})
                
                if exists:
                    logger.info(f"   - Email {email['subject']} (UID {email['uid']}) -> ✅ PROCESSED (Found in DB)")
                else:
                    logger.info(f"   - Email {email['subject']} (UID {email['uid']}) -> ⚠️  PENDING (Not in DB)")
        else:
            logger.warning("⚠️ MongoDB not configured, skipping DB check.")
            
    except Exception as e:
        logger.error(f"❌ Database check failed: {e}")

    logger.info("\n[4/4] Simulating Processing for Latest Email...")
    if recent_emails:
        latest_uid = recent_emails[0]['uid']
        # ... (simulation code) ...
        
    # 5. Trigger Real Polling (To fix the issue if pending)
    logger.info("\n[5/5] Triggering Real Polling Service (Verification)...")
    try:
        from app.services.email_poller import email_polling_service
        
        logger.info("Running poll_and_analyze()...")
        await email_polling_service.poll_and_analyze()
        logger.info("✅ Polling cycle completed.")
        
        # Verify if it was stored
        if recent_emails:
             msg_id = recent_emails[0]['message_id']
             exists = await ForwardedEmailAnalysis.find_one({"email_metadata.message_id": msg_id})
             if exists:
                 logger.info(f"✅ VERIFIED: Email {msg_id} is now in Database!")
             else:
                 logger.warning(f"⚠️ Email {msg_id} still NOT in Database after polling!")
                 
    except Exception as e:
        logger.error(f"❌ Failed to trigger real polling: {e}")

    logger.info("\nDiagnosis and Fix Verification Complete.")

if __name__ == "__main__":
    asyncio.run(diagnose_workflow())
