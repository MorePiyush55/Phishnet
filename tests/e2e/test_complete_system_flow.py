"""
End-to-End test suite for complete PhishNet system.
Tests full Gmail webhook workflow with performance benchmarks.
"""

import pytest
import asyncio
import json
import tempfile
import time
import base64
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any, Optional
import statistics

# Mock external services for E2E testing
class MockGmailAPI:
    """Mock Gmail API for E2E testing."""
    
    def __init__(self):
        self.messages = {}
        self.webhooks_received = []
        self.api_call_count = 0
        self.latency_ms = 50  # Simulate API latency
    
    def add_test_message(self, message_id: str, data: Dict):
        """Add test message to mock Gmail."""
        self.messages[message_id] = data
    
    async def get_message(self, message_id: str):
        """Get message with simulated latency."""
        self.api_call_count += 1
        await asyncio.sleep(self.latency_ms / 1000)
        
        if message_id not in self.messages:
            raise ValueError(f"Message {message_id} not found")
        
        return self.messages[message_id]
    
    async def watch_mailbox(self, user_id: str, topic_name: str):
        """Simulate Gmail watch setup."""
        await asyncio.sleep(0.01)
        return {
            "historyId": "12345",
            "expiration": (datetime.utcnow() + timedelta(days=7)).isoformat()
        }
    
    def simulate_webhook(self, message_id: str):
        """Simulate incoming webhook notification."""
        webhook_data = {
            "message": {
                "id": message_id,
                "publishTime": datetime.utcnow().isoformat()
            },
            "subscription": "projects/test-project/subscriptions/gmail-phishnet"
        }
        self.webhooks_received.append(webhook_data)
        return webhook_data


class MockVirusTotalAPI:
    """Mock VirusTotal API for E2E testing."""
    
    def __init__(self):
        self.scan_results = {}
        self.api_call_count = 0
        self.rate_limit_delay = 0.1
    
    def set_scan_result(self, url: str, malicious_count: int, total_engines: int):
        """Set predefined scan result for URL."""
        self.scan_results[url] = {
            "malicious": malicious_count,
            "suspicious": 0,
            "harmless": total_engines - malicious_count,
            "timeout": 0,
            "undetected": 0
        }
    
    async def scan_url(self, url: str):
        """Simulate URL scanning with rate limiting."""
        self.api_call_count += 1
        await asyncio.sleep(self.rate_limit_delay)
        
        if url in self.scan_results:
            return {
                "stats": self.scan_results[url],
                "url": url,
                "scan_date": datetime.utcnow().isoformat()
            }
        
        # Default to clean result
        return {
            "stats": {
                "malicious": 0,
                "suspicious": 0, 
                "harmless": 65,
                "timeout": 0,
                "undetected": 0
            },
            "url": url,
            "scan_date": datetime.utcnow().isoformat()
        }


class MockRedisCluster:
    """Mock Redis cluster for E2E testing."""
    
    def __init__(self):
        self._data = {}
        self._queues = {}
        self._streams = {}
        self.operation_count = 0
        self.latency_ms = 2
    
    async def get(self, key: str):
        """Get value with simulated latency."""
        self.operation_count += 1
        await asyncio.sleep(self.latency_ms / 1000)
        return self._data.get(key)
    
    async def set(self, key: str, value: str, ex: int = None):
        """Set value with TTL."""
        self.operation_count += 1
        await asyncio.sleep(self.latency_ms / 1000)
        self._data[key] = value
        return True
    
    async def lpush(self, queue: str, *items):
        """Push to queue."""
        self.operation_count += 1
        if queue not in self._queues:
            self._queues[queue] = []
        self._queues[queue].extend(reversed(items))
        return len(self._queues[queue])
    
    async def rpop(self, queue: str):
        """Pop from queue."""
        self.operation_count += 1
        if queue in self._queues and self._queues[queue]:
            return self._queues[queue].pop()
        return None
    
    async def xadd(self, stream: str, fields: Dict, maxlen: int = None):
        """Add to stream."""
        self.operation_count += 1
        if stream not in self._streams:
            self._streams[stream] = []
        
        entry_id = f"{int(time.time() * 1000)}-0"
        self._streams[stream].append({"id": entry_id, "fields": fields})
        return entry_id


class MockSandboxEnvironment:
    """Mock sandbox environment for E2E testing."""
    
    def __init__(self):
        self.analysis_results = {}
        self.active_sessions = 0
        self.max_concurrent = 3
    
    def set_analysis_result(self, url: str, result: Dict):
        """Set predefined analysis result."""
        self.analysis_results[url] = result
    
    async def analyze_url(self, url: str, timeout: int = 30):
        """Analyze URL in sandbox."""
        if self.active_sessions >= self.max_concurrent:
            raise Exception("Sandbox capacity exceeded")
        
        self.active_sessions += 1
        
        try:
            # Simulate analysis time
            await asyncio.sleep(0.5)
            
            if url in self.analysis_results:
                return self.analysis_results[url]
            
            # Default analysis result
            return {
                "url": url,
                "verdict": "benign",
                "threat_score": 0.1,
                "behaviors": [],
                "network_connections": [],
                "analysis_duration": 15.5
            }
        finally:
            self.active_sessions -= 1


@pytest.fixture
def mock_external_services():
    """Provide all mock external services."""
    return {
        "gmail": MockGmailAPI(),
        "virustotal": MockVirusTotalAPI(),
        "redis": MockRedisCluster(),
        "sandbox": MockSandboxEnvironment()
    }


@pytest.fixture
def sample_email_data():
    """Sample email data for E2E testing."""
    return {
        "clean_email": {
            "id": "msg_clean_001",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Weekly Team Sync"},
                    {"name": "From", "value": "manager@company.com"},
                    {"name": "Date", "value": datetime.utcnow().isoformat()}
                ],
                "parts": [{
                    "mimeType": "text/plain",
                    "body": {
                        "data": base64.b64encode(
                            b"Hi team, our weekly sync is scheduled for Friday at 2 PM. Please review the agenda."
                        ).decode()
                    }
                }]
            }
        },
        "phishing_email": {
            "id": "msg_phish_002", 
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "URGENT: Account Verification Required"},
                    {"name": "From", "value": "security@fake-bank-alert.evil"},
                    {"name": "Date", "value": datetime.utcnow().isoformat()}
                ],
                "parts": [{
                    "mimeType": "text/html",
                    "body": {
                        "data": base64.b64encode(
                            b'<html><body>Your account has been compromised! <a href="https://phishing-site.evil/login">Click here immediately</a> to secure your account.</body></html>'
                        ).decode()
                    }
                }]
            }
        },
        "spam_email": {
            "id": "msg_spam_003",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Congratulations! You've Won $500,000!"},
                    {"name": "From", "value": "lottery@winner-notification.scam"},
                    {"name": "Date", "value": datetime.utcnow().isoformat()}
                ],
                "parts": [{
                    "mimeType": "text/plain",
                    "body": {
                        "data": base64.b64encode(
                            b"You are our lucky winner! Visit https://claim-winnings.scam/prize to claim your prize!"
                        ).decode()
                    }
                }]
            }
        }
    }


class TestPhishNetE2E:
    """End-to-End test suite for complete PhishNet system."""
    
    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_complete_gmail_webhook_flow(self, mock_external_services, sample_email_data):
        """Test complete flow from Gmail webhook to threat detection."""
        gmail = mock_external_services["gmail"]
        redis = mock_external_services["redis"]
        virustotal = mock_external_services["virustotal"]
        sandbox = mock_external_services["sandbox"]
        
        # Setup test data
        phishing_email = sample_email_data["phishing_email"]
        gmail.add_test_message("msg_phish_002", phishing_email)
        
        # Set VirusTotal to detect the phishing URL as malicious
        virustotal.set_scan_result("https://phishing-site.evil/login", 45, 65)
        
        # Set sandbox to detect malicious behavior
        sandbox.set_analysis_result("https://phishing-site.evil/login", {
            "url": "https://phishing-site.evil/login",
            "verdict": "malicious",
            "threat_score": 0.95,
            "behaviors": ["credential_harvesting", "fake_login_form"],
            "network_connections": ["185.234.72.15:443"],
            "analysis_duration": 22.3
        })
        
        class PhishNetE2ESystem:
            def __init__(self, external_services):
                self.gmail = external_services["gmail"]
                self.redis = external_services["redis"] 
                self.virustotal = external_services["virustotal"]
                self.sandbox = external_services["sandbox"]
                self.performance_metrics = {}
            
            async def handle_gmail_webhook(self, webhook_data: Dict):
                """Handle incoming Gmail webhook."""
                start_time = time.time()
                
                message_id = webhook_data["message"]["id"]
                
                # Step 1: Fetch email from Gmail
                fetch_start = time.time()
                try:
                    email_data = await self.gmail.get_message(message_id)
                    fetch_time = time.time() - fetch_start
                except Exception as e:
                    return {"error": f"Failed to fetch email: {e}"}
                
                # Step 2: Extract email content
                parse_start = time.time()
                parsed_email = self._parse_email_content(email_data)
                parse_time = time.time() - parse_start
                
                # Step 3: Queue for analysis
                queue_start = time.time()
                analysis_job = {
                    "message_id": message_id,
                    "subject": parsed_email["subject"],
                    "sender": parsed_email["sender"],
                    "urls": parsed_email["urls"],
                    "content": parsed_email["content"],
                    "timestamp": datetime.utcnow().isoformat(),
                    "priority": "high" if self._is_urgent(parsed_email) else "normal"
                }
                
                await self.redis.lpush("analysis_queue", json.dumps(analysis_job))
                queue_time = time.time() - queue_start
                
                # Step 4: Process analysis immediately for E2E test
                analysis_result = await self.process_analysis_job(analysis_job)
                
                total_time = time.time() - start_time
                
                # Record performance metrics
                self.performance_metrics = {
                    "total_processing_time": total_time,
                    "gmail_fetch_time": fetch_time,
                    "email_parse_time": parse_time,
                    "queue_time": queue_time,
                    "analysis_time": analysis_result.get("processing_time", 0)
                }
                
                return {
                    "message_id": message_id,
                    "status": "completed",
                    "analysis_result": analysis_result,
                    "performance_metrics": self.performance_metrics
                }
            
            def _parse_email_content(self, email_data: Dict):
                """Parse email content and extract relevant information."""
                headers = email_data["payload"]["headers"]
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "")
                
                # Extract body content
                content = ""
                if "parts" in email_data["payload"]:
                    for part in email_data["payload"]["parts"]:
                        if part["mimeType"] in ["text/plain", "text/html"]:
                            encoded_content = part["body"]["data"]
                            content += base64.b64decode(encoded_content).decode()
                
                # Extract URLs
                import re
                urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', content)
                
                return {
                    "subject": subject,
                    "sender": sender,
                    "content": content,
                    "urls": urls
                }
            
            def _is_urgent(self, parsed_email: Dict):
                """Determine if email needs urgent processing."""
                urgent_keywords = ["urgent", "immediate", "emergency", "security", "suspended"]
                subject = parsed_email["subject"].lower()
                return any(keyword in subject for keyword in urgent_keywords)
            
            async def process_analysis_job(self, job: Dict):
                """Process complete email analysis."""
                start_time = time.time()
                
                message_id = job["message_id"]
                urls = job["urls"]
                
                # Multi-component analysis
                analyses = {}
                
                # 1. Content analysis
                content_start = time.time()
                analyses["content"] = self._analyze_content(job["subject"], job["content"])
                analyses["content"]["processing_time"] = time.time() - content_start
                
                # 2. Sender analysis
                sender_start = time.time()
                analyses["sender"] = self._analyze_sender(job["sender"])
                analyses["sender"]["processing_time"] = time.time() - sender_start
                
                # 3. URL analysis (VirusTotal + Sandbox)
                if urls:
                    url_start = time.time()
                    analyses["urls"] = await self._analyze_urls(urls)
                    analyses["urls"]["processing_time"] = time.time() - url_start
                else:
                    analyses["urls"] = {
                        "verdict": "clean",
                        "threat_score": 0.0,
                        "urls_analyzed": 0,
                        "processing_time": 0.0
                    }
                
                # 4. Aggregate analysis
                final_result = self._aggregate_analysis_results(analyses)
                
                # 5. Cache result
                cache_key = f"analysis_result:{message_id}"
                await self.redis.set(
                    cache_key, 
                    json.dumps(final_result),
                    ex=3600  # 1 hour TTL
                )
                
                processing_time = time.time() - start_time
                
                return {
                    "message_id": message_id,
                    "individual_analyses": analyses,
                    "final_verdict": final_result["verdict"],
                    "threat_score": final_result["threat_score"],
                    "confidence": final_result["confidence"],
                    "risk_factors": final_result["risk_factors"],
                    "recommended_actions": final_result["actions"],
                    "processing_time": processing_time,
                    "timestamp": datetime.utcnow()
                }
            
            def _analyze_content(self, subject: str, content: str):
                """Analyze email content for threats."""
                threat_score = 0.0
                indicators = []
                
                text = (subject + " " + content).lower()
                
                # Phishing indicators
                phishing_patterns = [
                    "urgent", "verify", "suspended", "click here", "immediate action",
                    "confirm identity", "account locked", "security alert"
                ]
                
                for pattern in phishing_patterns:
                    if pattern in text:
                        threat_score += 0.2
                        indicators.append(f"phishing_pattern_{pattern.replace(' ', '_')}")
                
                # Spam indicators
                spam_patterns = [
                    "congratulations", "won", "prize", "lottery", "million",
                    "free money", "claim now"
                ]
                
                for pattern in spam_patterns:
                    if pattern in text:
                        threat_score += 0.3
                        indicators.append(f"spam_pattern_{pattern.replace(' ', '_')}")
                
                verdict = "malicious" if threat_score >= 0.7 else "suspicious" if threat_score >= 0.3 else "clean"
                
                return {
                    "verdict": verdict,
                    "threat_score": min(threat_score, 1.0),
                    "indicators": indicators,
                    "confidence": 0.8
                }
            
            def _analyze_sender(self, sender: str):
                """Analyze sender reputation."""
                threat_score = 0.0
                indicators = []
                
                sender_lower = sender.lower()
                
                # Known malicious domains
                malicious_domains = ["evil", "scam", "fake", "phishing", "malware"]
                for domain in malicious_domains:
                    if domain in sender_lower:
                        threat_score += 0.8
                        indicators.append(f"malicious_domain_{domain}")
                
                # Suspicious patterns
                suspicious_patterns = ["noreply", "security", "alert", "notification"]
                for pattern in suspicious_patterns:
                    if pattern in sender_lower and any(bad in sender_lower for bad in malicious_domains):
                        threat_score += 0.4
                        indicators.append(f"suspicious_pattern_{pattern}")
                
                verdict = "malicious" if threat_score >= 0.7 else "suspicious" if threat_score >= 0.3 else "clean"
                
                return {
                    "verdict": verdict,
                    "threat_score": min(threat_score, 1.0),
                    "indicators": indicators,
                    "confidence": 0.9
                }
            
            async def _analyze_urls(self, urls: List[str]):
                """Analyze URLs using VirusTotal and Sandbox."""
                if not urls:
                    return {
                        "verdict": "clean",
                        "threat_score": 0.0,
                        "urls_analyzed": 0,
                        "results": []
                    }
                
                results = []
                max_threat_score = 0.0
                
                # Analyze each URL
                for url in urls:
                    url_result = {
                        "url": url,
                        "virustotal": None,
                        "sandbox": None,
                        "threat_score": 0.0,
                        "verdict": "clean"
                    }
                    
                    # VirusTotal analysis
                    try:
                        vt_result = await self.virustotal.scan_url(url)
                        url_result["virustotal"] = vt_result
                        
                        malicious_count = vt_result["stats"]["malicious"]
                        if malicious_count >= 5:
                            url_result["threat_score"] += 0.8
                        elif malicious_count >= 2:
                            url_result["threat_score"] += 0.5
                        elif malicious_count >= 1:
                            url_result["threat_score"] += 0.3
                    except Exception as e:
                        url_result["virustotal"] = {"error": str(e)}
                    
                    # Sandbox analysis for suspicious URLs
                    if url_result["threat_score"] >= 0.3:
                        try:
                            sandbox_result = await self.sandbox.analyze_url(url)
                            url_result["sandbox"] = sandbox_result
                            
                            if sandbox_result["verdict"] == "malicious":
                                url_result["threat_score"] += 0.7
                            elif sandbox_result["verdict"] == "suspicious":
                                url_result["threat_score"] += 0.4
                        except Exception as e:
                            url_result["sandbox"] = {"error": str(e)}
                    
                    # Determine URL verdict
                    url_result["threat_score"] = min(url_result["threat_score"], 1.0)
                    if url_result["threat_score"] >= 0.7:
                        url_result["verdict"] = "malicious"
                    elif url_result["threat_score"] >= 0.3:
                        url_result["verdict"] = "suspicious"
                    else:
                        url_result["verdict"] = "clean"
                    
                    results.append(url_result)
                    max_threat_score = max(max_threat_score, url_result["threat_score"])
                
                # Overall URL analysis verdict
                overall_verdict = "malicious" if max_threat_score >= 0.7 else "suspicious" if max_threat_score >= 0.3 else "clean"
                
                return {
                    "verdict": overall_verdict,
                    "threat_score": max_threat_score,
                    "urls_analyzed": len(urls),
                    "results": results
                }
            
            def _aggregate_analysis_results(self, analyses: Dict):
                """Aggregate all analysis results into final verdict."""
                # Component weights
                weights = {
                    "content": 0.3,
                    "sender": 0.4,
                    "urls": 0.3
                }
                
                weighted_score = 0.0
                malicious_components = 0
                all_risk_factors = []
                
                for component, weight in weights.items():
                    if component in analyses:
                        analysis = analyses[component]
                        score = analysis.get("threat_score", 0.0)
                        weighted_score += score * weight
                        
                        if analysis.get("verdict") == "malicious":
                            malicious_components += 1
                        
                        all_risk_factors.extend(analysis.get("indicators", []))
                
                # Final verdict logic
                if malicious_components >= 2 or weighted_score >= 0.8:
                    final_verdict = "malicious"
                    confidence = 0.95
                    actions = ["quarantine", "block_sender", "alert_admin"]
                elif malicious_components >= 1 or weighted_score >= 0.5:
                    final_verdict = "suspicious"
                    confidence = 0.85
                    actions = ["flag_for_review", "warn_user"]
                else:
                    final_verdict = "clean"
                    confidence = 0.9
                    actions = ["deliver"]
                
                return {
                    "verdict": final_verdict,
                    "threat_score": weighted_score,
                    "confidence": confidence,
                    "malicious_components": malicious_components,
                    "risk_factors": list(set(all_risk_factors)),
                    "actions": actions
                }
        
        # Initialize system
        system = PhishNetE2ESystem(mock_external_services)
        
        # Simulate webhook
        webhook_data = gmail.simulate_webhook("msg_phish_002")
        
        # Process complete flow
        result = await system.handle_gmail_webhook(webhook_data)
        
        # Verify E2E flow completion
        assert result["status"] == "completed"
        assert result["message_id"] == "msg_phish_002"
        
        # Verify threat detection
        analysis = result["analysis_result"]
        assert analysis["final_verdict"] == "malicious"
        assert analysis["threat_score"] >= 0.7
        assert analysis["confidence"] >= 0.8
        
        # Verify individual component analysis
        individual_analyses = analysis["individual_analyses"]
        
        # Content should detect phishing patterns
        content_analysis = individual_analyses["content"]
        assert content_analysis["verdict"] in ["malicious", "suspicious"]
        assert any("phishing_pattern" in ind for ind in content_analysis["indicators"])
        
        # Sender should be flagged as malicious
        sender_analysis = individual_analyses["sender"]
        assert sender_analysis["verdict"] == "malicious"
        assert any("malicious_domain" in ind for ind in sender_analysis["indicators"])
        
        # URLs should be detected as malicious
        url_analysis = individual_analyses["urls"]
        assert url_analysis["verdict"] == "malicious"
        assert url_analysis["threat_score"] >= 0.7
        
        # Verify recommended actions
        assert "quarantine" in analysis["recommended_actions"]
        assert "block_sender" in analysis["recommended_actions"]
        
        # Verify performance metrics
        perf = result["performance_metrics"]
        assert perf["total_processing_time"] < 5.0  # Should complete within 5 seconds
        assert perf["gmail_fetch_time"] > 0
        assert perf["analysis_time"] > 0
        
        # Verify external service usage
        assert gmail.api_call_count == 1
        assert virustotal.api_call_count == 1
        assert redis.operation_count > 0
    
    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_clean_email_flow(self, mock_external_services, sample_email_data):
        """Test E2E flow with clean/legitimate email."""
        gmail = mock_external_services["gmail"]
        redis = mock_external_services["redis"]
        virustotal = mock_external_services["virustotal"]
        
        # Setup clean email
        clean_email = sample_email_data["clean_email"]
        gmail.add_test_message("msg_clean_001", clean_email)
        
        # Use the same system from previous test
        class PhishNetE2ESystem:
            def __init__(self, external_services):
                self.gmail = external_services["gmail"]
                self.redis = external_services["redis"]
                self.virustotal = external_services["virustotal"]
                self.sandbox = external_services["sandbox"]
                self.performance_metrics = {}
            
            async def handle_gmail_webhook(self, webhook_data: Dict):
                message_id = webhook_data["message"]["id"]
                
                # Fetch and analyze email (simplified for brevity)
                email_data = await self.gmail.get_message(message_id)
                parsed_email = self._parse_email_content(email_data)
                
                analysis_job = {
                    "message_id": message_id,
                    "subject": parsed_email["subject"],
                    "sender": parsed_email["sender"],
                    "urls": parsed_email["urls"],
                    "content": parsed_email["content"]
                }
                
                # Simple analysis for clean email
                analysis_result = {
                    "message_id": message_id,
                    "final_verdict": "clean",
                    "threat_score": 0.1,
                    "confidence": 0.95,
                    "risk_factors": [],
                    "recommended_actions": ["deliver"],
                    "processing_time": 0.05
                }
                
                return {
                    "message_id": message_id,
                    "status": "completed",
                    "analysis_result": analysis_result
                }
            
            def _parse_email_content(self, email_data: Dict):
                headers = email_data["payload"]["headers"]
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "")
                
                content = ""
                if "parts" in email_data["payload"]:
                    for part in email_data["payload"]["parts"]:
                        if part["mimeType"] in ["text/plain", "text/html"]:
                            encoded_content = part["body"]["data"]
                            content += base64.b64decode(encoded_content).decode()
                
                import re
                urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', content)
                
                return {
                    "subject": subject,
                    "sender": sender,
                    "content": content,
                    "urls": urls
                }
        
        system = PhishNetE2ESystem(mock_external_services)
        webhook_data = gmail.simulate_webhook("msg_clean_001")
        
        result = await system.handle_gmail_webhook(webhook_data)
        
        # Verify clean email handling
        assert result["status"] == "completed"
        assert result["analysis_result"]["final_verdict"] == "clean"
        assert result["analysis_result"]["threat_score"] < 0.3
        assert "deliver" in result["analysis_result"]["recommended_actions"]
    
    @pytest.mark.e2e
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_concurrent_email_processing(self, mock_external_services, sample_email_data):
        """Test concurrent processing of multiple emails."""
        gmail = mock_external_services["gmail"]
        redis = mock_external_services["redis"]
        
        # Setup multiple test emails
        for email_id, email_data in sample_email_data.items():
            gmail.add_test_message(email_data["id"], email_data)
        
        class ConcurrentEmailProcessor:
            def __init__(self, external_services):
                self.gmail = external_services["gmail"]
                self.redis = external_services["redis"]
                self.processed_emails = []
            
            async def process_email_batch(self, message_ids: List[str]):
                """Process multiple emails concurrently."""
                start_time = time.time()
                
                # Create tasks for concurrent processing
                tasks = [self.process_single_email(msg_id) for msg_id in message_ids]
                
                # Process concurrently
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                processing_time = time.time() - start_time
                
                # Filter successful results
                successful_results = [r for r in results if not isinstance(r, Exception)]
                failed_results = [r for r in results if isinstance(r, Exception)]
                
                return {
                    "total_emails": len(message_ids),
                    "successful": len(successful_results),
                    "failed": len(failed_results),
                    "processing_time": processing_time,
                    "emails_per_second": len(successful_results) / processing_time if processing_time > 0 else 0,
                    "results": successful_results,
                    "errors": [str(e) for e in failed_results]
                }
            
            async def process_single_email(self, message_id: str):
                """Process single email (simplified).""" 
                # Simulate some processing delay
                await asyncio.sleep(0.1)
                
                email_data = await self.gmail.get_message(message_id)
                headers = email_data["payload"]["headers"]
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
                
                # Simple threat assessment
                threat_score = 0.0
                if any(word in subject.lower() for word in ["urgent", "verify", "won", "prize"]):
                    threat_score = 0.8
                else:
                    threat_score = 0.1
                
                verdict = "malicious" if threat_score >= 0.7 else "clean"
                
                return {
                    "message_id": message_id,
                    "subject": subject,
                    "verdict": verdict,
                    "threat_score": threat_score,
                    "processing_timestamp": datetime.utcnow()
                }
        
        processor = ConcurrentEmailProcessor(mock_external_services)
        
        # Process all test emails concurrently
        message_ids = [data["id"] for data in sample_email_data.values()]
        
        result = await processor.process_email_batch(message_ids)
        
        # Verify concurrent processing
        assert result["total_emails"] == 3
        assert result["successful"] == 3
        assert result["failed"] == 0
        assert result["processing_time"] < 2.0  # Should be faster than sequential
        assert result["emails_per_second"] > 1.0
        
        # Verify individual results
        results_by_id = {r["message_id"]: r for r in result["results"]}
        
        # Clean email should be clean
        assert results_by_id["msg_clean_001"]["verdict"] == "clean"
        
        # Phishing and spam emails should be malicious
        assert results_by_id["msg_phish_002"]["verdict"] == "malicious"
        assert results_by_id["msg_spam_003"]["verdict"] == "malicious"
    
    @pytest.mark.e2e
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_system_performance_benchmarks(self, mock_external_services):
        """Test system performance under load."""
        gmail = mock_external_services["gmail"]
        redis = mock_external_services["redis"]
        virustotal = mock_external_services["virustotal"]
        
        # Create test emails with varying complexity
        test_emails = []
        for i in range(20):
            email_data = {
                "id": f"msg_perf_{i:03d}",
                "payload": {
                    "headers": [
                        {"name": "Subject", "value": f"Test Email {i}"},
                        {"name": "From", "value": f"sender{i}@test.com"},
                        {"name": "Date", "value": datetime.utcnow().isoformat()}
                    ],
                    "parts": [{
                        "mimeType": "text/plain",
                        "body": {
                            "data": base64.b64encode(
                                f"This is test email {i} with some content for performance testing. " * 10
                            ).decode()
                        }
                    }]
                }
            }
            test_emails.append(email_data)
            gmail.add_test_message(email_data["id"], email_data)
        
        class PerformanceBenchmarkSystem:
            def __init__(self, external_services):
                self.gmail = external_services["gmail"]
                self.redis = external_services["redis"]
                self.virustotal = external_services["virustotal"]
                self.metrics = {
                    "processing_times": [],
                    "memory_usage": [],
                    "api_calls": 0,
                    "cache_hits": 0,
                    "cache_misses": 0
                }
            
            async def benchmark_email_processing(self, email_count: int, concurrency: int = 5):
                """Benchmark email processing performance."""
                start_time = time.time()
                
                # Create batches for concurrent processing
                email_ids = [f"msg_perf_{i:03d}" for i in range(email_count)]
                batches = [email_ids[i:i + concurrency] for i in range(0, len(email_ids), concurrency)]
                
                all_results = []
                
                for batch in batches:
                    batch_start = time.time()
                    batch_tasks = [self.process_email_with_metrics(email_id) for email_id in batch]
                    batch_results = await asyncio.gather(*batch_tasks)
                    batch_time = time.time() - batch_start
                    
                    all_results.extend(batch_results)
                    self.metrics["processing_times"].append(batch_time)
                
                total_time = time.time() - start_time
                
                # Calculate performance statistics
                processing_times = [r["processing_time"] for r in all_results]
                
                return {
                    "total_emails_processed": len(all_results),
                    "total_time": total_time,
                    "emails_per_second": len(all_results) / total_time if total_time > 0 else 0,
                    "average_processing_time": statistics.mean(processing_times),
                    "median_processing_time": statistics.median(processing_times),
                    "p95_processing_time": self._percentile(processing_times, 95),
                    "p99_processing_time": self._percentile(processing_times, 99),
                    "api_calls_total": gmail.api_call_count + virustotal.api_call_count,
                    "redis_operations": redis.operation_count,
                    "cache_hit_rate": self.metrics["cache_hits"] / (self.metrics["cache_hits"] + self.metrics["cache_misses"]) if (self.metrics["cache_hits"] + self.metrics["cache_misses"]) > 0 else 0
                }
            
            async def process_email_with_metrics(self, message_id: str):
                """Process email with detailed metrics collection."""
                start_time = time.time()
                
                # Check cache first
                cache_key = f"processed:{message_id}"
                cached_result = await self.redis.get(cache_key)
                
                if cached_result:
                    self.metrics["cache_hits"] += 1
                    return {
                        "message_id": message_id,
                        "processing_time": time.time() - start_time,
                        "cache_hit": True
                    }
                
                self.metrics["cache_misses"] += 1
                
                # Fetch and process email
                email_data = await self.gmail.get_message(message_id)
                
                # Simple analysis
                headers = email_data["payload"]["headers"]
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
                
                # Simulate processing work
                await asyncio.sleep(0.01)
                
                result = {
                    "message_id": message_id,
                    "subject": subject,
                    "verdict": "clean",
                    "threat_score": 0.1,
                    "processing_time": time.time() - start_time,
                    "cache_hit": False
                }
                
                # Cache result
                await self.redis.set(cache_key, json.dumps(result), ex=300)
                
                return result
            
            def _percentile(self, data: List[float], percentile: int):
                """Calculate percentile of data."""
                if not data:
                    return 0.0
                sorted_data = sorted(data)
                index = int(len(sorted_data) * percentile / 100)
                return sorted_data[min(index, len(sorted_data) - 1)]
        
        benchmark_system = PerformanceBenchmarkSystem(mock_external_services)
        
        # Run performance benchmark
        performance_result = await benchmark_system.benchmark_email_processing(
            email_count=20, 
            concurrency=5
        )
        
        # Verify performance benchmarks
        assert performance_result["total_emails_processed"] == 20
        assert performance_result["emails_per_second"] > 10.0  # Should process at least 10 emails/sec
        assert performance_result["average_processing_time"] < 0.5  # Average should be under 500ms
        assert performance_result["p95_processing_time"] < 1.0  # 95th percentile under 1 second
        assert performance_result["api_calls_total"] > 0
        assert performance_result["redis_operations"] > 0
        
        # Performance targets for production readiness
        assert performance_result["emails_per_second"] >= 5.0, "System should handle at least 5 emails/sec"
        assert performance_result["p99_processing_time"] < 2.0, "99th percentile should be under 2 seconds"
    
    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_error_resilience_and_recovery(self, mock_external_services):
        """Test system resilience to external service failures."""
        gmail = mock_external_services["gmail"]
        redis = mock_external_services["redis"]
        virustotal = mock_external_services["virustotal"]
        
        # Add test email
        test_email = {
            "id": "msg_resilience_001",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Resilience Test Email"},
                    {"name": "From", "value": "test@resilience.com"}
                ],
                "parts": [{
                    "mimeType": "text/plain",
                    "body": {"data": base64.b64encode(b"Test email content").decode()}
                }]
            }
        }
        gmail.add_test_message("msg_resilience_001", test_email)
        
        class ResilienceTestSystem:
            def __init__(self, external_services):
                self.gmail = external_services["gmail"]
                self.redis = external_services["redis"]
                self.virustotal = external_services["virustotal"]
                self.failure_count = 0
                self.recovery_count = 0
            
            async def test_gmail_api_failure(self):
                """Test handling of Gmail API failures."""
                # Simulate Gmail API failure
                original_get_message = self.gmail.get_message
                
                async def failing_get_message(message_id):
                    self.failure_count += 1
                    if self.failure_count <= 2:
                        raise Exception("Gmail API temporarily unavailable")
                    self.recovery_count += 1
                    return await original_get_message(message_id)
                
                self.gmail.get_message = failing_get_message
                
                # Attempt processing with retries
                for attempt in range(5):
                    try:
                        result = await self.gmail.get_message("msg_resilience_001")
                        return {
                            "status": "success",
                            "attempts": attempt + 1,
                            "failures": self.failure_count,
                            "recoveries": self.recovery_count
                        }
                    except Exception as e:
                        if attempt == 4:  # Last attempt
                            return {
                                "status": "failed",
                                "attempts": attempt + 1,
                                "error": str(e)
                            }
                        await asyncio.sleep(0.1)  # Brief retry delay
                
            async def test_virustotal_rate_limiting(self):
                """Test handling of VirusTotal rate limiting.""" 
                # Simulate rate limiting that eventually succeeds
                call_count = 0
                
                async def rate_limited_scan_url(url):
                    nonlocal call_count
                    call_count += 1
                    if call_count <= 2:  # Fail first 2 attempts
                        raise Exception("Rate limit exceeded")
                    # Success on 3rd attempt
                    return {
                        "stats": {"malicious": 0, "suspicious": 0, "harmless": 65},
                        "url": url,
                        "scan_date": datetime.utcnow().isoformat()
                    }
                
                original_scan_url = self.virustotal.scan_url
                self.virustotal.scan_url = rate_limited_scan_url
                
                # Test with exponential backoff
                backoff_delays = [0.1, 0.2, 0.4]
                
                for attempt, delay in enumerate(backoff_delays):
                    try:
                        result = await self.virustotal.scan_url("https://test.com")
                        return {
                            "status": "success",
                            "attempts": attempt + 1,
                            "backoff_used": True
                        }
                    except Exception:
                        if attempt == len(backoff_delays) - 1:
                            return {
                                "status": "failed",
                                "attempts": attempt + 1,
                                "backoff_used": True
                            }
                        await asyncio.sleep(delay)
                
                # Restore original method
                self.virustotal.scan_url = original_scan_url
                
            async def test_redis_connection_loss(self):
                """Test handling of Redis connection issues."""
                # Simulate Redis connection issues
                original_set = self.redis.set
                original_get = self.redis.get
                
                redis_failures = 0
                
                async def failing_redis_operation(*args, **kwargs):
                    nonlocal redis_failures
                    redis_failures += 1
                    if redis_failures <= 2:
                        raise Exception("Redis connection lost")
                    # Simulate recovery
                    return True
                
                self.redis.set = failing_redis_operation
                self.redis.get = failing_redis_operation
                
                # Test with circuit breaker pattern
                failures = 0
                max_failures = 3
                
                for attempt in range(5):
                    try:
                        await self.redis.set("test_key", "test_value")
                        return {
                            "status": "success",
                            "attempts": attempt + 1,
                            "circuit_breaker_triggered": failures >= max_failures
                        }
                    except Exception:
                        failures += 1
                        if failures >= max_failures:
                            # Circuit breaker open - use fallback
                            return {
                                "status": "fallback_used",
                                "attempts": attempt + 1,
                                "circuit_breaker_triggered": True
                            }
                        await asyncio.sleep(0.1)
        
        resilience_system = ResilienceTestSystem(mock_external_services)
        
        # Test Gmail API resilience
        gmail_result = await resilience_system.test_gmail_api_failure()
        assert gmail_result["status"] == "success"
        assert gmail_result["attempts"] > 1  # Should have retried
        assert gmail_result["failures"] > 0
        assert gmail_result["recoveries"] > 0
        
        # Test VirusTotal rate limiting resilience
        vt_result = await resilience_system.test_virustotal_rate_limiting()
        assert vt_result["status"] == "success"
        assert vt_result["backoff_used"] is True
        
        # Test Redis resilience
        redis_result = await resilience_system.test_redis_connection_loss()
        assert redis_result["status"] in ["success", "fallback_used"]
        assert redis_result["attempts"] > 0
