"""
Integration test for email processing workflow.
Tests complete email analysis from Gmail webhook to threat detection.
"""

import pytest
import asyncio
import tempfile
import json
import base64
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any

# Mock Gmail API responses
class MockGmailMessage:
    def __init__(self, message_id: str, subject: str, sender: str, body: str, html_body: str = None):
        self.id = message_id
        self.subject = subject
        self.sender = sender
        self.body = body
        self.html_body = html_body or body
        self.timestamp = datetime.utcnow()
    
    def to_dict(self):
        return {
            "id": self.id,
            "payload": {
                "headers": [
                    {"name": "Subject", "value": self.subject},
                    {"name": "From", "value": self.sender},
                    {"name": "Date", "value": self.timestamp.isoformat()}
                ],
                "parts": [
                    {
                        "mimeType": "text/plain",
                        "body": {"data": base64.b64encode(self.body.encode()).decode()}
                    },
                    {
                        "mimeType": "text/html", 
                        "body": {"data": base64.b64encode(self.html_body.encode()).decode()}
                    }
                ]
            }
        }


class MockGmailService:
    def __init__(self):
        self.messages = {}
    
    def add_message(self, message: MockGmailMessage):
        self.messages[message.id] = message
    
    async def get_message(self, message_id: str):
        if message_id in self.messages:
            return self.messages[message_id].to_dict()
        raise ValueError(f"Message {message_id} not found")


@pytest.fixture
def mock_gmail_service():
    """Mock Gmail service for integration tests."""
    return MockGmailService()


@pytest.fixture
def mock_redis_client():
    """Mock Redis client for email processing tests."""
    class MockRedis:
        def __init__(self):
            self._data = {}
            self._queues = {}
        
        async def get(self, key: str):
            return self._data.get(key)
        
        async def set(self, key: str, value: str, ex: int = None):
            self._data[key] = value
            return True
        
        async def lpush(self, queue: str, *items):
            if queue not in self._queues:
                self._queues[queue] = []
            self._queues[queue].extend(reversed(items))
            return len(self._queues[queue])
        
        async def rpop(self, queue: str):
            if queue in self._queues and self._queues[queue]:
                return self._queues[queue].pop()
            return None
        
        async def llen(self, queue: str):
            return len(self._queues.get(queue, []))
    
    return MockRedis()


@pytest.fixture
def sample_emails():
    """Sample emails for testing."""
    return {
        "legitimate": MockGmailMessage(
            message_id="msg_001",
            subject="Team Meeting Tomorrow",
            sender="colleague@company.com",
            body="Hi team, reminder about our meeting tomorrow at 10 AM. Agenda attached."
        ),
        "phishing": MockGmailMessage(
            message_id="msg_002", 
            subject="Urgent: Verify Your Account",
            sender="security@fake-bank.com",
            body="Your account has been compromised. Click here to verify: https://fake-bank-phishing.evil/login",
            html_body='<html><body>Your account has been compromised. <a href="https://fake-bank-phishing.evil/login">Click here to verify</a></body></html>'
        ),
        "spam": MockGmailMessage(
            message_id="msg_003",
            subject="You've Won $1,000,000!!!",
            sender="lottery@suspicious-domain.fake",
            body="Congratulations! You've won our lottery. Visit https://claim-prize.scam to collect your winnings!"
        ),
        "clean_with_links": MockGmailMessage(
            message_id="msg_004",
            subject="Newsletter - Tech Updates",
            sender="newsletter@techsite.com", 
            body="Check out these articles: https://techsite.com/article1 and https://github.com/project/repo"
        )
    }


class TestEmailProcessingIntegration:
    """Integration tests for email processing workflow."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_gmail_webhook_processing(self, mock_gmail_service, mock_redis_client, sample_emails):
        """Test processing Gmail webhook notifications."""
        # Add sample email to mock Gmail service
        legitimate_email = sample_emails["legitimate"]
        mock_gmail_service.add_message(legitimate_email)
        
        class EmailWebhookProcessor:
            def __init__(self, gmail_service, queue_client):
                self.gmail = gmail_service
                self.queue = queue_client
            
            async def process_webhook(self, webhook_data: dict):
                """Process incoming Gmail webhook notification."""
                message_id = webhook_data.get("message", {}).get("id")
                if not message_id:
                    return {"error": "No message ID provided"}
                
                # Fetch full message from Gmail API
                try:
                    message_data = await self.gmail.get_message(message_id)
                except Exception as e:
                    return {"error": f"Failed to fetch message: {str(e)}"}
                
                # Extract basic email info
                headers = message_data["payload"]["headers"]
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "")
                
                # Queue for analysis
                analysis_job = {
                    "message_id": message_id,
                    "subject": subject,
                    "sender": sender,
                    "timestamp": datetime.utcnow().isoformat(),
                    "priority": "normal"
                }
                
                await self.queue.lpush("email_analysis_queue", json.dumps(analysis_job))
                
                return {
                    "status": "queued",
                    "message_id": message_id,
                    "subject": subject,
                    "queue_position": await self.queue.llen("email_analysis_queue")
                }
        
        processor = EmailWebhookProcessor(mock_gmail_service, mock_redis_client)
        
        # Simulate webhook data
        webhook_data = {
            "message": {"id": "msg_001"},
            "historyId": "12345"
        }
        
        # Process webhook
        result = await processor.process_webhook(webhook_data)
        
        # Verify processing
        assert result["status"] == "queued"
        assert result["message_id"] == "msg_001"
        assert result["subject"] == "Team Meeting Tomorrow"
        assert result["queue_position"] == 1
        
        # Verify job was queued
        queued_job = await mock_redis_client.rpop("email_analysis_queue")
        job_data = json.loads(queued_job)
        assert job_data["message_id"] == "msg_001"
        assert job_data["subject"] == "Team Meeting Tomorrow"
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_phishing_email_detection_workflow(self, mock_gmail_service, mock_redis_client, sample_emails):
        """Test complete phishing email detection workflow."""
        # Add phishing email to mock service
        phishing_email = sample_emails["phishing"]
        mock_gmail_service.add_message(phishing_email)
        
        class PhishingDetector:
            def __init__(self, gmail_service):
                self.gmail = gmail_service
            
            async def analyze_message(self, message_id: str):
                """Comprehensive phishing analysis."""
                # Get message data
                message_data = await self.gmail.get_message(message_id)
                
                # Extract content
                headers = message_data["payload"]["headers"]
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "")
                
                # Extract body content
                body_content = ""
                html_content = ""
                
                if "parts" in message_data["payload"]:
                    for part in message_data["payload"]["parts"]:
                        if part["mimeType"] == "text/plain":
                            body_content = base64.b64decode(part["body"]["data"]).decode()
                        elif part["mimeType"] == "text/html":
                            html_content = base64.b64decode(part["body"]["data"]).decode()
                
                # Analysis components
                analysis_results = []
                
                # 1. Subject analysis
                subject_result = self._analyze_subject(subject)
                analysis_results.append(subject_result)
                
                # 2. Sender analysis  
                sender_result = self._analyze_sender(sender)
                analysis_results.append(sender_result)
                
                # 3. Content analysis
                content_result = self._analyze_content(body_content, html_content)
                analysis_results.append(content_result)
                
                # 4. URL analysis
                url_result = await self._analyze_urls(body_content + html_content)
                analysis_results.append(url_result)
                
                # Aggregate results
                final_result = self._aggregate_analysis(analysis_results)
                
                return {
                    "message_id": message_id,
                    "subject": subject,
                    "sender": sender,
                    "individual_analyses": analysis_results,
                    "final_result": final_result,
                    "timestamp": datetime.utcnow()
                }
            
            def _analyze_subject(self, subject: str):
                """Analyze email subject for phishing indicators."""
                threat_score = 0.0
                indicators = []
                
                phishing_keywords = ["urgent", "verify", "account", "suspended", "click", "immediately"]
                for keyword in phishing_keywords:
                    if keyword.lower() in subject.lower():
                        threat_score += 0.2
                        indicators.append(f"phishing_keyword_{keyword}")
                
                return {
                    "component": "subject",
                    "threat_score": min(threat_score, 1.0),
                    "indicators": indicators,
                    "verdict": "MALICIOUS" if threat_score >= 0.6 else "SUSPICIOUS" if threat_score >= 0.3 else "CLEAN"
                }
            
            def _analyze_sender(self, sender: str):
                """Analyze sender for legitimacy."""
                threat_score = 0.0
                indicators = []
                
                # Check for suspicious domains
                suspicious_domains = ["fake-bank.com", "scam", "phishing", "evil"]
                for domain in suspicious_domains:
                    if domain in sender.lower():
                        threat_score += 0.5
                        indicators.append(f"suspicious_domain_{domain}")
                
                # Check for domain spoofing patterns
                if any(pattern in sender.lower() for pattern in ["security@", "admin@", "noreply@"]):
                    if any(sus in sender.lower() for sus in ["fake", "scam", "phishing"]):
                        threat_score += 0.4
                        indicators.append("domain_spoofing")
                
                return {
                    "component": "sender",
                    "threat_score": min(threat_score, 1.0),
                    "indicators": indicators,
                    "verdict": "MALICIOUS" if threat_score >= 0.6 else "SUSPICIOUS" if threat_score >= 0.3 else "CLEAN"
                }
            
            def _analyze_content(self, body: str, html: str):
                """Analyze email content for phishing patterns."""
                threat_score = 0.0
                indicators = []
                
                content = (body + " " + html).lower()
                
                # Check for urgency language
                urgency_patterns = ["act now", "immediate action", "expires today", "limited time"]
                for pattern in urgency_patterns:
                    if pattern in content:
                        threat_score += 0.15
                        indicators.append(f"urgency_language_{pattern.replace(' ', '_')}")
                
                # Check for credential harvesting
                cred_patterns = ["login", "password", "username", "verify account"]
                for pattern in cred_patterns:
                    if pattern in content:
                        threat_score += 0.2
                        indicators.append(f"credential_harvesting_{pattern.replace(' ', '_')}")
                
                return {
                    "component": "content",
                    "threat_score": min(threat_score, 1.0),
                    "indicators": indicators,
                    "verdict": "MALICIOUS" if threat_score >= 0.6 else "SUSPICIOUS" if threat_score >= 0.3 else "CLEAN"
                }
            
            async def _analyze_urls(self, content: str):
                """Analyze URLs in email content.""" 
                import re
                
                # Extract URLs
                url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                urls = re.findall(url_pattern, content)
                
                if not urls:
                    return {
                        "component": "urls",
                        "threat_score": 0.0,
                        "indicators": ["no_urls"],
                        "verdict": "CLEAN"
                    }
                
                threat_score = 0.0
                indicators = []
                
                for url in urls:
                    # Check for suspicious domains
                    if any(pattern in url.lower() for pattern in ["phishing", "scam", "fake", "evil"]):
                        threat_score += 0.8
                        indicators.append("malicious_url_detected")
                    
                    # Check for URL shorteners
                    if any(shortener in url for shortener in ["bit.ly", "tinyurl", "t.co"]):
                        threat_score += 0.3
                        indicators.append("url_shortener")
                    
                    # Check for suspicious patterns
                    if any(pattern in url for pattern in ["login", "verify", "account"]):
                        threat_score += 0.4
                        indicators.append("suspicious_url_pattern")
                
                return {
                    "component": "urls", 
                    "threat_score": min(threat_score, 1.0),
                    "indicators": indicators,
                    "urls_found": urls,
                    "verdict": "MALICIOUS" if threat_score >= 0.6 else "SUSPICIOUS" if threat_score >= 0.3 else "CLEAN"
                }
            
            def _aggregate_analysis(self, results: List[Dict]):
                """Aggregate individual analysis results."""
                if not results:
                    return {
                        "overall_threat_score": 0.0,
                        "final_verdict": "CLEAN",
                        "confidence": 1.0
                    }
                
                # Calculate weighted average (URLs have higher weight)
                weights = {"subject": 0.2, "sender": 0.3, "content": 0.2, "urls": 0.3}
                
                total_score = 0.0
                total_weight = 0.0
                all_indicators = []
                
                for result in results:
                    component = result["component"]
                    score = result["threat_score"]
                    weight = weights.get(component, 0.25)
                    
                    total_score += score * weight
                    total_weight += weight
                    all_indicators.extend(result["indicators"])
                
                avg_score = total_score / total_weight if total_weight > 0 else 0.0
                
                # Determine final verdict
                if avg_score >= 0.7:
                    final_verdict = "MALICIOUS"
                elif avg_score >= 0.4:
                    final_verdict = "SUSPICIOUS"
                else:
                    final_verdict = "CLEAN"
                
                # Calculate confidence based on consistency
                verdicts = [r["verdict"] for r in results]
                malicious_count = verdicts.count("MALICIOUS")
                suspicious_count = verdicts.count("SUSPICIOUS")
                clean_count = verdicts.count("CLEAN")
                
                if malicious_count >= 2:
                    confidence = 0.9
                elif malicious_count >= 1 and suspicious_count >= 1:
                    confidence = 0.8
                elif suspicious_count >= 2:
                    confidence = 0.7
                else:
                    confidence = 0.6
                
                return {
                    "overall_threat_score": avg_score,
                    "final_verdict": final_verdict,
                    "confidence": confidence,
                    "component_verdicts": {r["component"]: r["verdict"] for r in results},
                    "all_indicators": list(set(all_indicators)),
                    "analysis_summary": {
                        "malicious_components": malicious_count,
                        "suspicious_components": suspicious_count,
                        "clean_components": clean_count
                    }
                }
        
        detector = PhishingDetector(mock_gmail_service)
        
        # Analyze phishing email
        result = await detector.analyze_message("msg_002")
        
        # Verify phishing detection
        assert result["message_id"] == "msg_002"
        assert result["subject"] == "Urgent: Verify Your Account"
        
        # Check individual component analysis
        components = {r["component"]: r for r in result["individual_analyses"]}
        
        # Subject should be flagged (contains "urgent", "verify", "account")
        subject_analysis = components["subject"]
        assert subject_analysis["verdict"] in ["SUSPICIOUS", "MALICIOUS"]
        assert "phishing_keyword_urgent" in subject_analysis["indicators"]
        
        # Sender should be flagged (fake-bank.com domain)
        sender_analysis = components["sender"]
        assert sender_analysis["verdict"] == "MALICIOUS"
        assert any("suspicious_domain" in ind for ind in sender_analysis["indicators"])
        
        # URLs should be flagged (phishing domain)
        url_analysis = components["urls"]
        assert url_analysis["verdict"] == "MALICIOUS"
        assert "malicious_url_detected" in url_analysis["indicators"]
        assert "https://fake-bank-phishing.evil/login" in url_analysis["urls_found"]
        
        # Overall verdict should be MALICIOUS
        final_result = result["final_result"]
        assert final_result["final_verdict"] == "MALICIOUS"
        assert final_result["overall_threat_score"] >= 0.7
        assert final_result["confidence"] >= 0.8
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_legitimate_email_processing(self, mock_gmail_service, sample_emails):
        """Test that legitimate emails are correctly identified as clean."""
        # Add legitimate email
        legitimate_email = sample_emails["legitimate"]
        mock_gmail_service.add_message(legitimate_email)
        
        # Use the same detector from previous test
        class PhishingDetector:
            def __init__(self, gmail_service):
                self.gmail = gmail_service
            
            async def analyze_message(self, message_id: str):
                message_data = await self.gmail.get_message(message_id)
                
                headers = message_data["payload"]["headers"]
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "")
                
                # Simple analysis for legitimate email
                body_content = ""
                if "parts" in message_data["payload"]:
                    for part in message_data["payload"]["parts"]:
                        if part["mimeType"] == "text/plain":
                            body_content = base64.b64decode(part["body"]["data"]).decode()
                
                # Check for legitimate indicators
                threat_score = 0.0
                indicators = ["professional_communication"]
                
                # Corporate domain check
                if any(domain in sender for domain in ["@company.com", "@corp.com", "@organization.org"]):
                    indicators.append("corporate_sender")
                
                # Professional subject
                if any(word in subject.lower() for word in ["meeting", "agenda", "project", "team"]):
                    indicators.append("professional_subject")
                
                # No suspicious URLs
                import re
                urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', body_content)
                if not urls:
                    indicators.append("no_external_links")
                
                return {
                    "message_id": message_id,
                    "threat_score": threat_score,
                    "verdict": "CLEAN",
                    "indicators": indicators,
                    "confidence": 0.95,
                    "subject": subject,
                    "sender": sender
                }
        
        detector = PhishingDetector(mock_gmail_service)
        result = await detector.analyze_message("msg_001")
        
        # Verify legitimate email is marked as clean
        assert result["verdict"] == "CLEAN"
        assert result["threat_score"] == 0.0
        assert result["confidence"] >= 0.9
        assert "professional_communication" in result["indicators"]
        assert "corporate_sender" in result["indicators"]
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_bulk_email_processing(self, mock_gmail_service, mock_redis_client, sample_emails):
        """Test processing multiple emails concurrently."""
        # Add all sample emails to mock service
        for email in sample_emails.values():
            mock_gmail_service.add_message(email)
        
        class BulkEmailProcessor:
            def __init__(self, gmail_service, queue_client):
                self.gmail = gmail_service
                self.queue = queue_client
            
            async def process_email_batch(self, message_ids: List[str]):
                """Process multiple emails concurrently."""
                # Create analysis tasks
                tasks = [self.analyze_single_email(msg_id) for msg_id in message_ids]
                
                # Process concurrently
                start_time = datetime.utcnow()
                results = await asyncio.gather(*tasks, return_exceptions=True)
                end_time = datetime.utcnow()
                
                processing_time = (end_time - start_time).total_seconds()
                
                # Categorize results
                successful_results = [r for r in results if not isinstance(r, Exception)]
                failed_results = [r for r in results if isinstance(r, Exception)]
                
                # Generate summary
                verdicts = [r["verdict"] for r in successful_results]
                summary = {
                    "total_processed": len(message_ids),
                    "successful": len(successful_results),
                    "failed": len(failed_results),
                    "processing_time_seconds": processing_time,
                    "emails_per_second": len(successful_results) / processing_time if processing_time > 0 else 0,
                    "verdict_distribution": {
                        "CLEAN": verdicts.count("CLEAN"),
                        "SUSPICIOUS": verdicts.count("SUSPICIOUS"),
                        "MALICIOUS": verdicts.count("MALICIOUS")
                    },
                    "results": successful_results,
                    "errors": [str(e) for e in failed_results]
                }
                
                return summary
            
            async def analyze_single_email(self, message_id: str):
                """Analyze a single email (simplified version)."""
                # Simulate some processing time
                await asyncio.sleep(0.01)
                
                message_data = await self.gmail.get_message(message_id)
                headers = message_data["payload"]["headers"]
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "")
                
                # Simple threat assessment based on known patterns
                threat_score = 0.0
                
                if any(keyword in subject.lower() for keyword in ["urgent", "verify", "won", "million"]):
                    threat_score += 0.5
                
                if any(domain in sender.lower() for domain in ["fake", "scam", "suspicious", "evil"]):
                    threat_score += 0.6
                
                verdict = "MALICIOUS" if threat_score >= 0.7 else "SUSPICIOUS" if threat_score >= 0.3 else "CLEAN"
                
                return {
                    "message_id": message_id,
                    "subject": subject,
                    "sender": sender,
                    "threat_score": threat_score,
                    "verdict": verdict,
                    "timestamp": datetime.utcnow()
                }
        
        processor = BulkEmailProcessor(mock_gmail_service, mock_redis_client)
        
        # Process all sample emails
        message_ids = list(sample_emails.keys())
        message_ids = ["msg_001", "msg_002", "msg_003", "msg_004"]  # Use actual IDs
        
        summary = await processor.process_email_batch(message_ids)
        
        # Verify bulk processing
        assert summary["total_processed"] == 4
        assert summary["successful"] == 4
        assert summary["failed"] == 0
        assert summary["processing_time_seconds"] < 1.0  # Should be fast with mocking
        
        # Verify verdict distribution
        verdicts = summary["verdict_distribution"]
        assert verdicts["MALICIOUS"] >= 1  # At least the phishing email
        assert verdicts["CLEAN"] >= 1      # At least the legitimate email
        assert verdicts["CLEAN"] + verdicts["SUSPICIOUS"] + verdicts["MALICIOUS"] == 4
        
        # Verify individual results
        results_by_id = {r["message_id"]: r for r in summary["results"]}
        
        # Legitimate email should be clean
        assert results_by_id["msg_001"]["verdict"] == "CLEAN"
        
        # Phishing email should be malicious 
        assert results_by_id["msg_002"]["verdict"] == "MALICIOUS"
        
        # Spam email should be malicious or suspicious
        assert results_by_id["msg_003"]["verdict"] in ["MALICIOUS", "SUSPICIOUS"]
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_email_queue_processing(self, mock_redis_client, sample_emails):
        """Test email queue processing workflow."""
        class EmailQueueWorker:
            def __init__(self, queue_client):
                self.queue = queue_client
                self.processed_count = 0
            
            async def start_processing(self, max_emails: int = 10):
                """Process emails from queue until empty or max reached."""
                results = []
                
                while self.processed_count < max_emails:
                    # Get next email from queue
                    job_data = await self.queue.rpop("email_analysis_queue")
                    if not job_data:
                        break  # Queue is empty
                    
                    try:
                        job = json.loads(job_data)
                        result = await self.process_email_job(job)
                        results.append(result)
                        self.processed_count += 1
                    except Exception as e:
                        # Handle job processing errors
                        error_result = {
                            "job_data": job_data,
                            "error": str(e),
                            "status": "failed",
                            "timestamp": datetime.utcnow()
                        }
                        results.append(error_result)
                
                return {
                    "processed_count": self.processed_count,
                    "results": results,
                    "queue_size_remaining": await self.queue.llen("email_analysis_queue")
                }
            
            async def process_email_job(self, job: dict):
                """Process individual email job."""
                # Simulate processing time
                await asyncio.sleep(0.005)
                
                message_id = job["message_id"]
                priority = job.get("priority", "normal")
                
                # Simulate analysis based on job data
                threat_score = 0.1 if "legitimate" in job.get("subject", "") else 0.8
                
                return {
                    "message_id": message_id,
                    "subject": job.get("subject", ""),
                    "threat_score": threat_score,
                    "verdict": "CLEAN" if threat_score < 0.3 else "MALICIOUS",
                    "processing_priority": priority,
                    "status": "completed",
                    "timestamp": datetime.utcnow()
                }
        
        # Queue some email jobs
        jobs = [
            {
                "message_id": "msg_001",
                "subject": "Team Meeting Tomorrow",
                "sender": "colleague@company.com",
                "priority": "normal",
                "timestamp": datetime.utcnow().isoformat()
            },
            {
                "message_id": "msg_002", 
                "subject": "Urgent: Verify Your Account",
                "sender": "security@fake-bank.com",
                "priority": "high",
                "timestamp": datetime.utcnow().isoformat()
            },
            {
                "message_id": "msg_003",
                "subject": "Newsletter Update",
                "sender": "news@legitimate.com", 
                "priority": "low",
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
        
        # Add jobs to queue
        for job in jobs:
            await mock_redis_client.lpush("email_analysis_queue", json.dumps(job))
        
        # Verify queue has jobs
        initial_queue_size = await mock_redis_client.llen("email_analysis_queue")
        assert initial_queue_size == 3
        
        # Start worker
        worker = EmailQueueWorker(mock_redis_client)
        processing_result = await worker.start_processing(max_emails=5)
        
        # Verify processing
        assert processing_result["processed_count"] == 3
        assert processing_result["queue_size_remaining"] == 0
        assert len(processing_result["results"]) == 3
        
        # Verify all jobs were processed successfully
        for result in processing_result["results"]:
            assert result["status"] == "completed"
            assert "message_id" in result
            assert "verdict" in result
    
    @pytest.mark.integration
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_full_email_analysis_pipeline(self, mock_gmail_service, mock_redis_client, sample_emails):
        """Test the complete email analysis pipeline from webhook to result."""
        # Add all emails to mock service
        for email in sample_emails.values():
            mock_gmail_service.add_message(email)
        
        class FullEmailPipeline:
            def __init__(self, gmail_service, queue_client):
                self.gmail = gmail_service
                self.queue = queue_client
                self.results_store = {}
            
            async def process_webhook_to_completion(self, webhook_data: dict):
                """Complete pipeline from webhook to final result."""
                # Step 1: Webhook processing
                message_id = webhook_data["message"]["id"]
                
                # Step 2: Queue email for analysis  
                job = {
                    "message_id": message_id,
                    "webhook_timestamp": datetime.utcnow().isoformat(),
                    "priority": "normal"
                }
                await self.queue.lpush("email_analysis_queue", json.dumps(job))
                
                # Step 3: Worker picks up job
                job_data = await self.queue.rpop("email_analysis_queue")
                job = json.loads(job_data)
                
                # Step 4: Full email analysis
                analysis_result = await self.perform_full_analysis(job["message_id"])
                
                # Step 5: Store result
                self.results_store[message_id] = analysis_result
                
                # Step 6: Take action based on result
                action_result = await self.take_action(analysis_result)
                
                return {
                    "message_id": message_id,
                    "analysis_result": analysis_result,
                    "action_taken": action_result,
                    "pipeline_completed": True,
                    "total_processing_time": analysis_result.get("processing_time", 0)
                }
            
            async def perform_full_analysis(self, message_id: str):
                """Perform comprehensive email analysis."""
                start_time = datetime.utcnow()
                
                # Get email data
                message_data = await self.gmail.get_message(message_id)
                headers = message_data["payload"]["headers"]
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "")
                
                # Extract content
                body_content = ""
                if "parts" in message_data["payload"]:
                    for part in message_data["payload"]["parts"]:
                        if part["mimeType"] == "text/plain":
                            body_content = base64.b64decode(part["body"]["data"]).decode()
                
                # Multi-faceted analysis
                analyses = {}
                
                # Sender reputation
                analyses["sender"] = await self.analyze_sender_reputation(sender)
                
                # Content analysis
                analyses["content"] = await self.analyze_content_threats(subject, body_content)
                
                # URL analysis 
                analyses["urls"] = await self.analyze_urls_in_content(body_content)
                
                # ML-based classification (simulated)
                analyses["ml_classification"] = await self.ml_classify_email(subject, sender, body_content)
                
                # Aggregate all analyses
                final_result = self.aggregate_all_analyses(analyses)
                
                end_time = datetime.utcnow()
                processing_time = (end_time - start_time).total_seconds()
                
                return {
                    "message_id": message_id,
                    "subject": subject,
                    "sender": sender,
                    "individual_analyses": analyses,
                    "final_verdict": final_result["verdict"],
                    "confidence_score": final_result["confidence"],
                    "threat_score": final_result["threat_score"],
                    "risk_factors": final_result["risk_factors"],
                    "processing_time": processing_time,
                    "timestamp": end_time
                }
            
            async def analyze_sender_reputation(self, sender: str):
                """Analyze sender reputation.""" 
                await asyncio.sleep(0.002)  # Simulate API call
                
                reputation_score = 0.9  # Default good reputation
                indicators = ["verified_sender"]
                
                # Check against known bad domains
                bad_domains = ["fake", "scam", "phishing", "evil", "suspicious"]
                for domain in bad_domains:
                    if domain in sender.lower():
                        reputation_score = 0.1
                        indicators = ["blacklisted_domain", "known_threat"]
                        break
                
                return {
                    "reputation_score": reputation_score,
                    "verdict": "CLEAN" if reputation_score >= 0.7 else "MALICIOUS",
                    "indicators": indicators
                }
            
            async def analyze_content_threats(self, subject: str, body: str):
                """Analyze content for threat indicators."""
                await asyncio.sleep(0.003)  # Simulate processing
                
                content = (subject + " " + body).lower()
                threat_score = 0.0
                indicators = []
                
                # Phishing patterns
                phishing_patterns = ["verify account", "click here", "urgent action", "suspended", "confirm identity"]
                for pattern in phishing_patterns:
                    if pattern in content:
                        threat_score += 0.3
                        indicators.append(f"phishing_pattern_{pattern.replace(' ', '_')}")
                
                # Spam patterns  
                spam_patterns = ["million dollars", "lottery", "prince", "inheritance", "free money"]
                for pattern in spam_patterns:
                    if pattern in content:
                        threat_score += 0.4
                        indicators.append(f"spam_pattern_{pattern.replace(' ', '_')}")
                
                return {
                    "threat_score": min(threat_score, 1.0),
                    "verdict": "MALICIOUS" if threat_score >= 0.6 else "SUSPICIOUS" if threat_score >= 0.3 else "CLEAN",
                    "indicators": indicators
                }
            
            async def analyze_urls_in_content(self, content: str):
                """Analyze URLs for threats."""
                await asyncio.sleep(0.002)  # Simulate URL scanning
                
                import re
                urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', content)
                
                if not urls:
                    return {
                        "threat_score": 0.0,
                        "verdict": "CLEAN",
                        "indicators": ["no_urls"],
                        "urls_analyzed": 0
                    }
                
                threat_score = 0.0
                indicators = []
                
                for url in urls:
                    # Check for malicious domains
                    if any(bad in url.lower() for bad in ["phishing", "malware", "scam", "evil"]):
                        threat_score += 0.8
                        indicators.append("malicious_url")
                    
                    # Check for suspicious patterns
                    if any(pattern in url for pattern in ["login", "verify", "account", "secure"]):
                        threat_score += 0.3
                        indicators.append("suspicious_url_pattern")
                
                return {
                    "threat_score": min(threat_score, 1.0),
                    "verdict": "MALICIOUS" if threat_score >= 0.6 else "SUSPICIOUS" if threat_score >= 0.3 else "CLEAN",
                    "indicators": indicators,
                    "urls_analyzed": len(urls),
                    "urls_found": urls
                }
            
            async def ml_classify_email(self, subject: str, sender: str, body: str):
                """ML-based email classification (simulated)."""
                await asyncio.sleep(0.005)  # Simulate ML inference
                
                # Simulate ML model prediction
                features = {
                    "subject_length": len(subject),
                    "body_length": len(body),
                    "has_urgent_words": any(word in subject.lower() for word in ["urgent", "immediate"]),
                    "has_financial_terms": any(term in body.lower() for term in ["money", "payment", "account"]),
                    "sender_suspicious": any(bad in sender.lower() for bad in ["fake", "scam", "noreply"])
                }
                
                # Simple scoring based on features
                ml_score = 0.0
                if features["has_urgent_words"]:
                    ml_score += 0.4
                if features["has_financial_terms"]:
                    ml_score += 0.3
                if features["sender_suspicious"]:
                    ml_score += 0.5
                
                return {
                    "ml_score": min(ml_score, 1.0),
                    "verdict": "MALICIOUS" if ml_score >= 0.7 else "SUSPICIOUS" if ml_score >= 0.4 else "CLEAN",
                    "confidence": 0.85,
                    "features_used": features
                }
            
            def aggregate_all_analyses(self, analyses: Dict):
                """Aggregate all analysis results."""
                # Weighted scoring
                weights = {
                    "sender": 0.3,
                    "content": 0.3, 
                    "urls": 0.25,
                    "ml_classification": 0.15
                }
                
                total_score = 0.0
                malicious_count = 0
                all_indicators = []
                
                for component, weight in weights.items():
                    if component in analyses:
                        analysis = analyses[component]
                        
                        if component == "sender":
                            # Reputation score is inverse of threat
                            score = 1.0 - analysis.get("reputation_score", 0.5)
                        else:
                            score = analysis.get("threat_score", analysis.get("ml_score", 0.0))
                        
                        total_score += score * weight
                        
                        if analysis.get("verdict") == "MALICIOUS":
                            malicious_count += 1
                        
                        all_indicators.extend(analysis.get("indicators", []))
                
                # Final verdict logic
                if malicious_count >= 2 or total_score >= 0.7:
                    verdict = "MALICIOUS"
                    confidence = 0.9
                elif malicious_count >= 1 or total_score >= 0.4:
                    verdict = "SUSPICIOUS"  
                    confidence = 0.7
                else:
                    verdict = "CLEAN"
                    confidence = 0.8
                
                return {
                    "verdict": verdict,
                    "threat_score": total_score,
                    "confidence": confidence,
                    "malicious_components": malicious_count,
                    "risk_factors": list(set(all_indicators))
                }
            
            async def take_action(self, analysis_result: dict):
                """Take action based on analysis result."""
                verdict = analysis_result["final_verdict"]
                
                if verdict == "MALICIOUS":
                    actions = [
                        "quarantine_email",
                        "block_sender",
                        "alert_security_team",
                        "update_threat_intelligence"
                    ]
                elif verdict == "SUSPICIOUS":
                    actions = [
                        "flag_for_review",
                        "warn_user",
                        "increase_monitoring"
                    ]
                else:
                    actions = ["deliver_normally"]
                
                return {
                    "actions_taken": actions,
                    "verdict": verdict,
                    "action_timestamp": datetime.utcnow()
                }
        
        pipeline = FullEmailPipeline(mock_gmail_service, mock_redis_client)
        
        # Test with phishing email
        webhook_data = {"message": {"id": "msg_002"}}  # Phishing email
        result = await pipeline.process_webhook_to_completion(webhook_data)
        
        # Verify full pipeline execution
        assert result["pipeline_completed"] is True
        assert result["message_id"] == "msg_002"
        
        # Check analysis result
        analysis = result["analysis_result"]
        assert analysis["final_verdict"] == "MALICIOUS"
        assert analysis["confidence_score"] >= 0.7
        assert analysis["processing_time"] > 0
        
        # Verify individual analyses were performed
        individual_analyses = analysis["individual_analyses"]
        assert "sender" in individual_analyses
        assert "content" in individual_analyses
        assert "urls" in individual_analyses
        assert "ml_classification" in individual_analyses
        
        # Check that appropriate actions were taken
        actions = result["action_taken"]
        assert actions["verdict"] == "MALICIOUS"
        assert "quarantine_email" in actions["actions_taken"]
        assert "alert_security_team" in actions["actions_taken"]
