"""
Email Polling Service
Background service that periodically checks IMAP for new forwarded emails
and triggers analysis automatically.

REFACTORED: Now delegates to OnDemandOrchestrator for analysis logic.
This eliminates code duplication and ensures consistent behavior.
"""

import asyncio
import logging
from typing import Optional

from app.config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class EmailPollingService:
    """
    Background service to poll IMAP for new emails.
    
    ARCHITECTURE NOTE:
    This service is a thin wrapper that:
    1. Polls IMAP for new emails
    2. Delegates analysis to OnDemandOrchestrator
    
    All analysis logic is centralized in OnDemandOrchestrator.
    """
    
    def __init__(self):
        from app.services.ondemand_orchestrator import OnDemandOrchestrator
        self.orchestrator = OnDemandOrchestrator()
        self.is_running = False
        self.poll_interval = getattr(settings, 'IMAP_POLL_INTERVAL', 60)
        
    async def start(self):
        """Start the polling service."""
        if not getattr(settings, 'IMAP_ENABLED', False):
            logger.info("IMAP polling disabled in settings")
            return
            
        if self.is_running:
            return
            
        self.is_running = True
        logger.info(f"Starting Email Polling Service (Interval: {self.poll_interval}s)")
        
        while self.is_running:
            try:
                await self.poll_and_analyze()
            except Exception as e:
                logger.error(f"Error in email polling loop: {e}")
            
            # Wait for next poll
            await asyncio.sleep(self.poll_interval)
            
    async def stop(self):
        """Stop the polling service."""
        self.is_running = False
        logger.info("Stopping Email Polling Service")
        
    async def poll_and_analyze(self):
        """Check for pending emails and analyze them using OnDemandOrchestrator."""
        try:
            from app.services.quick_imap import QuickIMAPService
            from app.models.mongodb_models import ForwardedEmailAnalysis
            
            imap_service = QuickIMAPService()
            
            # Get RECENT emails (both SEEN and UNSEEN)
            email_limit = getattr(settings, 'IMAP_BATCH_SIZE', 50)
            recent_emails = await asyncio.to_thread(imap_service.get_recent_emails, email_limit)
            
            if not recent_emails:
                return
                
            logger.info(f"Checking {len(recent_emails)} recent emails for new submissions...")
            
            processed_count = 0
            
            for email_meta in recent_emails:
                try:
                    uid = email_meta['uid']
                    message_id = email_meta['message_id']
                    
                    if not message_id:
                        logger.warning(f"Email UID {uid} has no Message-ID, skipping")
                        continue
                        
                    # Check if already processed (deduplication)
                    exists = await ForwardedEmailAnalysis.find_one({
                        "email_metadata.message_id": message_id
                    })
                    
                    if exists:
                        continue  # Already analyzed
                        
                    logger.info(f"Found NEW unanalyzed email: {email_meta['subject']} (UID {uid})")
                    
                    # Delegate to OnDemandOrchestrator
                    # This is the SINGLE source of truth for analysis logic
                    job = await self.orchestrator.process_single_email(uid)
                    
                    if job and job.status.value == 'completed':
                        processed_count += 1
                        logger.info(f"Analysis complete: {job.detection_result.final_verdict}")
                    else:
                        logger.warning(f"Analysis incomplete for UID {uid}: {job.status if job else 'no job'}")
                    
                except Exception as e:
                    logger.error(f"Failed to process email {email_meta.get('uid')}: {e}")
            
            if processed_count > 0:
                logger.info(f"Successfully processed {processed_count} new emails")
                
        except Exception as e:
            logger.error(f"Error during poll_and_analyze: {e}")


# Singleton instance
email_polling_service = EmailPollingService()

