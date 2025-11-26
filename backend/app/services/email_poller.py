"""
Email Polling Service
Background service that periodically checks IMAP for new forwarded emails
and triggers analysis automatically.
"""

import asyncio
import logging
from typing import Optional

from app.config.settings import get_settings
from app.services.quick_imap import QuickIMAPService
from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
from app.api.v1.imap_emails import send_analysis_notification

logger = logging.getLogger(__name__)
settings = get_settings()

class EmailPollingService:
    """
    Background service to poll IMAP for new emails.
    """
    
    def __init__(self):
        self.imap_service = QuickIMAPService()
        self.phishing_analyzer = EnhancedPhishingAnalyzer()
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
        """Check for pending emails and analyze them."""
        # Get pending emails (synchronous IMAP call)
        # In a real async app, we might want to run this in a thread executor
        pending_emails = await asyncio.to_thread(self.imap_service.get_pending_emails)
        
        if not pending_emails:
            return
            
        logger.info(f"Found {len(pending_emails)} pending emails for analysis")
        
        for email_meta in pending_emails:
            try:
                uid = email_meta['uid']
                await self.process_email(uid)
            except Exception as e:
                logger.error(f"Failed to process email {email_meta.get('uid')}: {e}")
                
    async def process_email(self, uid: str):
        """Process a single email by UID."""
        logger.info(f"Processing email UID {uid}")
        
        # 1. Fetch and parse
        email_data = await asyncio.to_thread(self.imap_service.fetch_email_for_analysis, uid)
        
        if not email_data:
            logger.warning(f"Could not fetch data for email {uid}")
            return
            
        # 2. Analyze
        # Note: analyze_email is synchronous in EnhancedPhishingAnalyzer, run in thread
        analysis_result = await asyncio.to_thread(
            self.phishing_analyzer.analyze_email, 
            email_data['raw_email']
        )
        
        # 3. Send Notification
        await send_analysis_notification(
            recipient_email=email_data['forwarded_by'],
            original_subject=email_data['subject'],
            analysis_result=analysis_result
        )
        
        logger.info(f"Completed analysis for email {uid} from {email_data['forwarded_by']}")

# Singleton instance
email_polling_service = EmailPollingService()
