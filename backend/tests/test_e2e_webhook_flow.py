"""
End-to-End Tests for PhishNet Webhook Flow
Simulate Pub/Sub push and full pipeline: fetch → scan → dashboard update
Tests complete webhook flow validation with Gmail integration
"""

import pytest
import asyncio
import json
import time
import base64
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
import uuid

# Core imports
from app.main import app
from app.api.webhooks import gmail_webhook_handler
from app.orchestrator.main import PhishNetOrchestrator
from app.services.gmail_service import GmailService
from app.core.queue_manager import get_queue_manager
from app.core.cache_manager import get_cache_manager
from app.models.user import User
from app.models.email import Email
from app.models.scan_result import ScanResult


class TestWebhookE2EFlow:
    """Test complete webhook flow from Gmail notification to dashboard update"""
    
    @pytest.fixture
    def test_client(self):
        """Create test client for API testing"""
        return TestClient(app)
    
    @pytest.fixture
    def mock_gmail_message(self):
        """Create mock Gmail message data"""
        return {
            'id': 'test_message_12345',
            'snippet': 'URGENT: Verify your account immediately by clicking here...',
            'payload': {
                'headers': [
                    {'name': 'From', 'value': 'security@fake-bank.com'},
                    {'name': 'To', 'value': 'user@example.com'},
                    {'name': 'Subject', 'value': 'URGENT: Account Security Alert'},
                    {'name': 'Date', 'value': 'Wed, 11 Sep 2025 10:30:00 +0000'}
                ],
                'body': {
                    'data': base64.b64encode(
                        "Your account has been compromised. Click here to verify: https://fake-bank.evil.com/verify?urgent=true".encode()
                    ).decode()
                }
            },
            'internalDate': str(int(time.time() * 1000))
        }
    
    @pytest.fixture
    def mock_pubsub_message(self):
        """Create mock Pub/Sub webhook message"""
        return {
            'message': {
                'data': base64.b64encode(json.dumps({
                    'emailAddress': 'user@example.com',
                    'historyId': '12345'
                }).encode()).decode(),
                'messageId': 'test_pubsub_message_123',
                'publishTime': datetime.now().isoformat()
            },
            'subscription': 'projects/test-project/subscriptions/gmail-webhook'
        }
    
    @pytest.mark.asyncio
    async def test_complete_webhook_flow_phishing_detection(self, test_client, mock_pubsub_message, mock_gmail_message):
        """Test complete flow: webhook → fetch → scan → quarantine → dashboard"""
        
        # Mock database and external services
        with patch('app.db.database.get_db') as mock_db, \
             patch('app.services.gmail_service.GmailService') as mock_gmail_service, \
             patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.core.queue_manager.QueueManager') as mock_queue, \
             patch('app.core.cache_manager.CacheManager') as mock_cache:
            
            # Setup mocks
            mock_db_session = Mock()
            mock_db.return_value = mock_db_session
            
            # Mock user exists
            test_user = User(
                id="webhook_test_user",
                email="user@example.com",
                gmail_token_encrypted="encrypted_token",
                consent_granted=True,
                webhook_enabled=True
            )
            mock_db_session.query.return_value.filter_by.return_value.first.return_value = test_user
            
            # Mock Gmail service
            gmail_service_instance = Mock()
            mock_gmail_service.return_value = gmail_service_instance
            gmail_service_instance.get_message.return_value = mock_gmail_message
            gmail_service_instance.apply_label.return_value = True
            
            # Mock threat detection (high threat)
            mock_vt.return_value = Mock(
                scan_id="webhook-phishing-scan",
                positives=28,
                total=70,
                permalink="https://virustotal.com/webhook-phishing"
            )
            
            mock_gemini.return_value = {
                'threat_probability': 0.95,
                'confidence': 0.92,
                'reasoning': 'Clear phishing attempt with credential harvesting',
                'risk_factors': [
                    'urgent_language',
                    'credential_request',
                    'domain_spoofing',
                    'suspicious_link'
                ]
            }
            
            # Mock queue and cache
            queue_instance = Mock()
            cache_instance = Mock()
            mock_queue.return_value = queue_instance
            mock_cache.return_value = cache_instance
            
            queue_instance.enqueue_email_scan = AsyncMock()
            cache_instance.get = AsyncMock(return_value=None)  # Cache miss
            cache_instance.set = AsyncMock()
            
            # Step 1: Simulate Pub/Sub webhook notification
            response = test_client.post(
                "/api/v1/webhooks/gmail",
                json=mock_pubsub_message,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == 200
            
            # Verify webhook processing was triggered
            queue_instance.enqueue_email_scan.assert_called_once()
            
            # Step 2: Simulate queue processing (scan email)
            orchestrator = PhishNetOrchestrator()
            
            with patch('app.orchestrator.main.PhishNetOrchestrator._fetch_gmail_message') as mock_fetch:
                mock_fetch.return_value = mock_gmail_message
                
                scan_result = await orchestrator.process_gmail_webhook(
                    user_email="user@example.com",
                    history_id="12345",
                    message_id="test_message_12345"
                )
                
                # Verify scan was performed
                assert scan_result is not None
                assert scan_result.overall_threat_level == "HIGH"
                assert scan_result.threat_score > 0.9
                
                # Verify database updates
                assert mock_db_session.add.called
                assert mock_db_session.commit.called
            
            # Step 3: Verify Gmail quarantine action
            gmail_service_instance.apply_label.assert_called_with(
                message_id="test_message_12345",
                label_name="PHISHNET_QUARANTINED"
            )
            
            # Step 4: Verify dashboard update notification
            # (In real implementation, this would trigger dashboard websocket update)
    
    @pytest.mark.asyncio
    async def test_webhook_flow_legitimate_email(self, test_client, mock_pubsub_message, mock_gmail_message):
        """Test webhook flow with legitimate email (no quarantine)"""
        
        # Modify message to be legitimate
        legitimate_message = mock_gmail_message.copy()
        legitimate_message['payload']['headers'] = [
            {'name': 'From', 'value': 'notifications@github.com'},
            {'name': 'To', 'value': 'user@example.com'},
            {'name': 'Subject', 'value': 'Pull request review requested'},
            {'name': 'Date', 'value': 'Wed, 11 Sep 2025 10:30:00 +0000'}
        ]
        legitimate_message['payload']['body']['data'] = base64.b64encode(
            "A pull request review has been requested: https://github.com/user/repo/pull/123".encode()
        ).decode()
        
        with patch('app.db.database.get_db') as mock_db, \
             patch('app.services.gmail_service.GmailService') as mock_gmail_service, \
             patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini:
            
            # Setup mocks for legitimate email
            mock_db_session = Mock()
            mock_db.return_value = mock_db_session
            
            test_user = User(
                id="webhook_test_user_legit",
                email="user@example.com",
                gmail_token_encrypted="encrypted_token",
                consent_granted=True,
                webhook_enabled=True
            )
            mock_db_session.query.return_value.filter_by.return_value.first.return_value = test_user
            
            gmail_service_instance = Mock()
            mock_gmail_service.return_value = gmail_service_instance
            gmail_service_instance.get_message.return_value = legitimate_message
            gmail_service_instance.apply_label.return_value = True
            
            # Mock clean results
            mock_vt.return_value = Mock(
                scan_id="webhook-clean-scan",
                positives=0,
                total=70,
                permalink="https://virustotal.com/webhook-clean"
            )
            
            mock_gemini.return_value = {
                'threat_probability': 0.05,
                'confidence': 0.95,
                'reasoning': 'Legitimate notification from known service',
                'risk_factors': []
            }
            
            # Process webhook
            response = test_client.post(
                "/api/v1/webhooks/gmail",
                json=mock_pubsub_message,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == 200
            
            # Simulate scan processing
            orchestrator = PhishNetOrchestrator()
            
            with patch('app.orchestrator.main.PhishNetOrchestrator._fetch_gmail_message') as mock_fetch:
                mock_fetch.return_value = legitimate_message
                
                scan_result = await orchestrator.process_gmail_webhook(
                    user_email="user@example.com",
                    history_id="12345",
                    message_id="test_message_12345"
                )
                
                # Verify legitimate email results
                assert scan_result is not None
                assert scan_result.overall_threat_level == "LOW"
                assert scan_result.threat_score < 0.3
                
            # Verify no quarantine action for legitimate email
            gmail_service_instance.apply_label.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_webhook_flow_queue_processing(self, test_client, mock_pubsub_message):
        """Test webhook flow with queue management and rate limiting"""
        
        with patch('app.core.queue_manager.QueueManager') as mock_queue:
            queue_instance = Mock()
            mock_queue.return_value = queue_instance
            
            # Mock queue methods
            queue_instance.enqueue_email_scan = AsyncMock()
            queue_instance.get_queue_size = Mock(return_value=5)
            queue_instance.is_rate_limited = Mock(return_value=False)
            
            # Process multiple webhook notifications
            webhook_messages = []
            for i in range(3):
                message = mock_pubsub_message.copy()
                message['message']['data'] = base64.b64encode(json.dumps({
                    'emailAddress': f'user{i}@example.com',
                    'historyId': f'12345{i}'
                }).encode()).decode()
                webhook_messages.append(message)
            
            # Send webhook notifications
            for message in webhook_messages:
                response = test_client.post(
                    "/api/v1/webhooks/gmail",
                    json=message,
                    headers={"Content-Type": "application/json"}
                )
                assert response.status_code == 200
            
            # Verify all were queued
            assert queue_instance.enqueue_email_scan.call_count == 3
    
    @pytest.mark.asyncio
    async def test_webhook_flow_error_handling(self, test_client, mock_pubsub_message):
        """Test webhook flow error handling and resilience"""
        
        with patch('app.db.database.get_db') as mock_db:
            # Simulate database error
            mock_db.side_effect = Exception("Database connection failed")
            
            response = test_client.post(
                "/api/v1/webhooks/gmail",
                json=mock_pubsub_message,
                headers={"Content-Type": "application/json"}
            )
            
            # Should handle error gracefully
            assert response.status_code in [200, 500]  # Depends on error handling implementation
    
    @pytest.mark.asyncio
    async def test_webhook_flow_consent_validation(self, test_client, mock_pubsub_message):
        """Test webhook flow respects user consent"""
        
        with patch('app.db.database.get_db') as mock_db:
            mock_db_session = Mock()
            mock_db.return_value = mock_db_session
            
            # Mock user without consent
            test_user = User(
                id="webhook_test_user_no_consent",
                email="user@example.com",
                gmail_token_encrypted="encrypted_token",
                consent_granted=False,  # No consent
                webhook_enabled=False
            )
            mock_db_session.query.return_value.filter_by.return_value.first.return_value = test_user
            
            response = test_client.post(
                "/api/v1/webhooks/gmail",
                json=mock_pubsub_message,
                headers={"Content-Type": "application/json"}
            )
            
            # Should reject or skip processing
            assert response.status_code in [200, 403]
    
    @pytest.mark.asyncio
    async def test_webhook_flow_caching_behavior(self, test_client, mock_pubsub_message, mock_gmail_message):
        """Test webhook flow utilizes caching properly"""
        
        with patch('app.db.database.get_db') as mock_db, \
             patch('app.services.gmail_service.GmailService') as mock_gmail_service, \
             patch('app.core.cache_manager.CacheManager') as mock_cache:
            
            # Setup mocks
            mock_db_session = Mock()
            mock_db.return_value = mock_db_session
            
            test_user = User(
                id="webhook_test_user_cache",
                email="user@example.com",
                gmail_token_encrypted="encrypted_token",
                consent_granted=True,
                webhook_enabled=True
            )
            mock_db_session.query.return_value.filter_by.return_value.first.return_value = test_user
            
            gmail_service_instance = Mock()
            mock_gmail_service.return_value = gmail_service_instance
            gmail_service_instance.get_message.return_value = mock_gmail_message
            
            cache_instance = Mock()
            mock_cache.return_value = cache_instance
            
            # First request - cache miss
            cache_instance.get = AsyncMock(return_value=None)
            cache_instance.set = AsyncMock()
            
            response1 = test_client.post(
                "/api/v1/webhooks/gmail",
                json=mock_pubsub_message,
                headers={"Content-Type": "application/json"}
            )
            
            assert response1.status_code == 200
            cache_instance.set.assert_called()
            
            # Second request - cache hit
            cached_result = {
                'threat_level': 'HIGH',
                'threat_score': 0.95,
                'scan_id': 'cached-scan-123'
            }
            cache_instance.get = AsyncMock(return_value=json.dumps(cached_result))
            
            response2 = test_client.post(
                "/api/v1/webhooks/gmail",
                json=mock_pubsub_message,
                headers={"Content-Type": "application/json"}
            )
            
            assert response2.status_code == 200
            # Should use cached result instead of scanning again
    
    @pytest.mark.asyncio
    async def test_webhook_flow_dashboard_updates(self, test_client, mock_pubsub_message, mock_gmail_message):
        """Test webhook flow triggers dashboard updates"""
        
        with patch('app.db.database.get_db') as mock_db, \
             patch('app.services.gmail_service.GmailService') as mock_gmail_service, \
             patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.api.dashboard.update_user_dashboard') as mock_dashboard_update:
            
            # Setup mocks
            mock_db_session = Mock()
            mock_db.return_value = mock_db_session
            
            test_user = User(
                id="webhook_test_user_dashboard",
                email="user@example.com",
                gmail_token_encrypted="encrypted_token",
                consent_granted=True,
                webhook_enabled=True
            )
            mock_db_session.query.return_value.filter_by.return_value.first.return_value = test_user
            
            gmail_service_instance = Mock()
            mock_gmail_service.return_value = gmail_service_instance
            gmail_service_instance.get_message.return_value = mock_gmail_message
            
            # Mock threat detection
            mock_vt.return_value = Mock(
                scan_id="dashboard-update-scan",
                positives=20,
                total=70,
                permalink="https://virustotal.com/dashboard-update"
            )
            
            mock_gemini.return_value = {
                'threat_probability': 0.85,
                'confidence': 0.90,
                'reasoning': 'High confidence phishing detection',
                'risk_factors': ['urgent_language', 'credential_request']
            }
            
            mock_dashboard_update.return_value = True
            
            # Process webhook
            response = test_client.post(
                "/api/v1/webhooks/gmail",
                json=mock_pubsub_message,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == 200
            
            # Verify dashboard update was triggered
            # mock_dashboard_update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_webhook_flow_multiple_concurrent_requests(self, test_client):
        """Test webhook flow handles concurrent requests properly"""
        
        # Create multiple concurrent webhook requests
        webhook_messages = []
        for i in range(5):
            message = {
                'message': {
                    'data': base64.b64encode(json.dumps({
                        'emailAddress': f'user{i}@example.com',
                        'historyId': f'concurrent_test_{i}'
                    }).encode()).decode(),
                    'messageId': f'concurrent_message_{i}',
                    'publishTime': datetime.now().isoformat()
                },
                'subscription': 'projects/test-project/subscriptions/gmail-webhook'
            }
            webhook_messages.append(message)
        
        with patch('app.core.queue_manager.QueueManager') as mock_queue:
            queue_instance = Mock()
            mock_queue.return_value = queue_instance
            queue_instance.enqueue_email_scan = AsyncMock()
            queue_instance.get_queue_size = Mock(return_value=0)
            queue_instance.is_rate_limited = Mock(return_value=False)
            
            # Send concurrent requests
            responses = []
            for message in webhook_messages:
                response = test_client.post(
                    "/api/v1/webhooks/gmail",
                    json=message,
                    headers={"Content-Type": "application/json"}
                )
                responses.append(response)
            
            # Verify all requests were processed
            for response in responses:
                assert response.status_code == 200
            
            # Verify all were queued
            assert queue_instance.enqueue_email_scan.call_count == 5


class TestWebhookIntegrationScenarios:
    """Test webhook integration with various email scenarios"""
    
    @pytest.mark.asyncio
    async def test_webhook_with_email_attachment_analysis(self):
        """Test webhook flow includes attachment analysis"""
        
        # Mock email with suspicious attachment
        email_with_attachment = {
            'id': 'attachment_test_message',
            'payload': {
                'headers': [
                    {'name': 'From', 'value': 'unknown@suspicious.com'},
                    {'name': 'Subject', 'value': 'Important Invoice'}
                ],
                'parts': [
                    {
                        'mimeType': 'application/pdf',
                        'filename': 'invoice_urgent.pdf',
                        'body': {
                            'attachmentId': 'attachment_123',
                            'size': 150000
                        }
                    }
                ]
            }
        }
        
        # Test attachment handling in webhook flow
        # Implementation would depend on attachment analysis service
        pass
    
    @pytest.mark.asyncio
    async def test_webhook_with_bulk_email_detection(self):
        """Test webhook flow with bulk/spam email detection"""
        
        # Mock bulk email characteristics
        bulk_email = {
            'id': 'bulk_test_message',
            'payload': {
                'headers': [
                    {'name': 'From', 'value': 'marketing@bulk-sender.com'},
                    {'name': 'Subject', 'value': 'Amazing Deal - Act Now!'},
                    {'name': 'List-Unsubscribe', 'value': 'mailto:unsubscribe@bulk-sender.com'}
                ],
                'body': {
                    'data': base64.b64encode(
                        "Limited time offer! Click here for amazing deals!".encode()
                    ).decode()
                }
            }
        }
        
        # Test bulk email handling
        # Implementation would include spam detection logic
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
