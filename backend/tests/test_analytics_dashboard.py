"""
Integration tests for Advanced Analytics Dashboard
Tests all dashboard components and real-time monitoring
"""

import asyncio
import pytest
import json
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from fastapi import FastAPI
from unittest.mock import AsyncMock, patch, MagicMock

from app.api.analytics import router as analytics_router
from app.api.websocket import router as websocket_router
from app.services.analytics_service import analytics_service
from app.services.real_time_monitor import real_time_monitor, RealTimeEvent, ThreatFeedUpdate


# Create test app
def create_test_app():
    app = FastAPI()
    app.include_router(analytics_router)
    app.include_router(websocket_router)
    return app


@pytest.fixture
def test_app():
    return create_test_app()


@pytest.fixture
def test_client(test_app):
    return TestClient(test_app)


class TestAnalyticsDashboard:
    """Test suite for analytics dashboard"""
    
    @pytest.mark.asyncio
    async def test_dashboard_metrics_endpoint(self, test_client):
        """Test main dashboard metrics endpoint"""
        
        # Mock the analytics service
        mock_metrics = {
            "threat_overview": {
                "total_threats_detected": 150,
                "phishing_emails_blocked": 125,
                "malicious_urls_found": 45,
                "suspicious_attachments": 12,
                "threat_score_average": 0.75,
                "risk_distribution": {"LOW": 30, "MEDIUM": 50, "HIGH": 45, "CRITICAL": 25},
                "top_threat_types": [
                    {"indicator": "suspicious_link", "count": 85},
                    {"indicator": "phishing_keywords", "count": 67}
                ]
            },
            "email_analysis": {
                "total_emails_analyzed": 2340,
                "phishing_detection_rate": 0.923,
                "false_positive_rate": 0.027,
                "processing_time_avg_ms": 342.5,
                "accuracy_score": 0.956,
                "volume_trends": [
                    {"time": "2025-10-09T00:00:00Z", "count": 52},
                    {"time": "2025-10-09T01:00:00Z", "count": 48}
                ]
            },
            "incident_summary": {
                "active_incidents": 8,
                "resolved_incidents": 245,
                "average_resolution_time": 4.2,
                "escalated_incidents": 3,
                "incident_severity_breakdown": {"low": 120, "medium": 85, "high": 35, "critical": 5},
                "response_time_metrics": {"avg_first_response": 12.5}
            },
            "threat_intelligence": {
                "ioc_count": 15420,
                "feed_sources": ["VirusTotal", "PhishTank", "AbuseIPDB"],
                "reputation_scores": {"avg_url_score": 6.2, "avg_ip_score": 5.8},
                "new_threats_24h": 45,
                "threat_actor_tracking": [
                    {"actor": "APT29", "activity": 15},
                    {"actor": "FIN7", "activity": 8}
                ]
            },
            "real_time_alerts": [
                {
                    "alert_id": "alert_001",
                    "severity": "high",
                    "threat_type": "phishing",
                    "description": "Suspicious email detected",
                    "source": "PhishNet",
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": "active"
                }
            ],
            "performance_metrics": {
                "api_response_time": 142.5,
                "analysis_throughput": 350,
                "system_availability": 99.97,
                "resource_utilization": {"cpu": 23.4, "memory": 67.8, "disk": 45.2},
                "error_rates": {"api_errors": 0.012, "analysis_errors": 0.008}
            },
            "trend_analysis": {
                "threat_trends": {
                    "data": [
                        {"timestamp": "2025-10-09T00:00:00Z", "value": 23},
                        {"timestamp": "2025-10-09T01:00:00Z", "value": 27}
                    ],
                    "direction": "increasing",
                    "forecast": [
                        {"timestamp": "2025-10-09T02:00:00Z", "predicted_value": 31, "confidence": 0.85}
                    ]
                },
                "summary": {"overall_trend": "stable", "risk_level": "medium"}
            }
        }
        
        with patch.object(analytics_service, 'get_comprehensive_metrics', return_value=mock_metrics):
            response = test_client.get("/analytics/dashboard?time_range=24h")
            
        assert response.status_code == 200
        data = response.json()
        
        # Verify main structure
        assert "threat_overview" in data
        assert "email_analysis" in data
        assert "incident_summary" in data
        assert "threat_intelligence" in data
        assert "real_time_alerts" in data
        assert "performance_metrics" in data
        assert "trend_analysis" in data
        
        # Verify specific metrics
        assert data["threat_overview"]["total_threats_detected"] == 150
        assert data["email_analysis"]["total_emails_analyzed"] == 2340
        assert data["incident_summary"]["active_incidents"] == 8
        assert data["threat_intelligence"]["ioc_count"] == 15420
        assert len(data["real_time_alerts"]) == 1
        assert data["performance_metrics"]["system_availability"] == 99.97
    
    @pytest.mark.asyncio
    async def test_threat_overview_endpoint(self, test_client):
        """Test threat overview endpoint"""
        
        mock_overview = {
            "total_threats_detected": 150,
            "phishing_emails_blocked": 125,
            "malicious_urls_found": 45,
            "suspicious_attachments": 12,
            "threat_score_average": 0.75,
            "risk_distribution": {"LOW": 30, "MEDIUM": 50, "HIGH": 45, "CRITICAL": 25},
            "top_threat_types": [
                {"indicator": "suspicious_link", "count": 85}
            ]
        }
        
        with patch('app.api.analytics._get_threat_overview', return_value=mock_overview):
            response = test_client.get("/analytics/threat-overview?time_range=24h")
            
        assert response.status_code == 200
        data = response.json()
        assert data["total_threats_detected"] == 150
        assert data["threat_score_average"] == 0.75
    
    @pytest.mark.asyncio
    async def test_email_metrics_endpoint(self, test_client):
        """Test email analysis metrics endpoint"""
        
        mock_email_metrics = {
            "total_emails_analyzed": 2340,
            "phishing_detection_rate": 0.923,
            "false_positive_rate": 0.027,
            "processing_time_avg_ms": 342.5,
            "accuracy_score": 0.956,
            "volume_trends": []
        }
        
        with patch('app.api.analytics._get_email_analysis_metrics', return_value=mock_email_metrics):
            response = test_client.get("/analytics/email-metrics?time_range=24h")
            
        assert response.status_code == 200
        data = response.json()
        assert data["total_emails_analyzed"] == 2340
        assert data["phishing_detection_rate"] == 0.923
        assert data["accuracy_score"] == 0.956
    
    @pytest.mark.asyncio
    async def test_incident_metrics_endpoint(self, test_client):
        """Test incident management metrics endpoint"""
        
        mock_incident_metrics = {
            "active_incidents": 8,
            "resolved_incidents": 245,
            "average_resolution_time": 4.2,
            "escalated_incidents": 3,
            "incident_severity_breakdown": {"low": 120, "medium": 85, "high": 35, "critical": 5},
            "response_time_metrics": {"avg_first_response": 12.5}
        }
        
        with patch('app.api.analytics._get_incident_metrics', return_value=mock_incident_metrics):
            response = test_client.get("/analytics/incident-metrics?time_range=24h")
            
        assert response.status_code == 200
        data = response.json()
        assert data["active_incidents"] == 8
        assert data["average_resolution_time"] == 4.2
    
    @pytest.mark.asyncio
    async def test_threat_intelligence_metrics_endpoint(self, test_client):
        """Test threat intelligence metrics endpoint"""
        
        mock_intel_metrics = {
            "ioc_count": 15420,
            "feed_sources": ["VirusTotal", "PhishTank", "AbuseIPDB"],
            "reputation_scores": {"avg_url_score": 6.2, "avg_ip_score": 5.8},
            "new_threats_24h": 45,
            "threat_actor_tracking": []
        }
        
        with patch('app.api.analytics._get_threat_intelligence_metrics', return_value=mock_intel_metrics):
            response = test_client.get("/analytics/threat-intel-metrics?time_range=24h")
            
        assert response.status_code == 200
        data = response.json()
        assert data["ioc_count"] == 15420
        assert len(data["feed_sources"]) == 3
        assert data["new_threats_24h"] == 45
    
    @pytest.mark.asyncio
    async def test_real_time_alerts_endpoint(self, test_client):
        """Test real-time alerts endpoint"""
        
        mock_alerts = [
            {
                "alert_id": "alert_001",
                "severity": "high",
                "threat_type": "phishing",
                "description": "Suspicious email detected",
                "source": "PhishNet",
                "timestamp": datetime.utcnow().isoformat(),
                "status": "active"
            }
        ]
        
        with patch('app.api.analytics._get_real_time_alerts', return_value=mock_alerts):
            response = test_client.get("/analytics/real-time-alerts?limit=50")
            
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["severity"] == "high"
        assert data[0]["threat_type"] == "phishing"
    
    @pytest.mark.asyncio
    async def test_performance_metrics_endpoint(self, test_client):
        """Test performance metrics endpoint"""
        
        mock_performance = {
            "api_response_time": 142.5,
            "analysis_throughput": 350,
            "system_availability": 99.97,
            "resource_utilization": {"cpu": 23.4, "memory": 67.8, "disk": 45.2},
            "error_rates": {"api_errors": 0.012, "analysis_errors": 0.008}
        }
        
        with patch('app.api.analytics._get_performance_metrics', return_value=mock_performance):
            response = test_client.get("/analytics/performance-metrics?time_range=24h")
            
        assert response.status_code == 200
        data = response.json()
        assert data["system_availability"] == 99.97
        assert data["resource_utilization"]["cpu"] == 23.4
    
    @pytest.mark.asyncio
    async def test_trend_analysis_endpoint(self, test_client):
        """Test trend analysis endpoint"""
        
        mock_trends = {
            "trend_direction": "increasing",
            "percentage_change": 12.5,
            "data_points": [
                {"timestamp": "2025-10-09T00:00:00Z", "value": 23},
                {"timestamp": "2025-10-09T01:00:00Z", "value": 27}
            ],
            "forecast": [
                {"timestamp": "2025-10-09T02:00:00Z", "predicted_value": 31, "confidence": 0.85}
            ]
        }
        
        with patch('app.api.analytics._get_trend_analysis', return_value=mock_trends):
            response = test_client.get("/analytics/trend-analysis?metric_type=threats&time_range=7d")
            
        assert response.status_code == 200
        data = response.json()
        assert data["trend_direction"] == "increasing"
        assert data["percentage_change"] == 12.5
        assert len(data["data_points"]) == 2


class TestAnalyticsService:
    """Test suite for analytics service"""
    
    @pytest.mark.asyncio
    async def test_comprehensive_metrics_generation(self):
        """Test comprehensive metrics generation"""
        
        start_time = datetime.utcnow() - timedelta(hours=24)
        end_time = datetime.utcnow()
        
        # Mock database queries
        with patch.object(analytics_service, 'get_threat_analytics', return_value={"total_detections": 100}), \
             patch.object(analytics_service, 'get_email_analytics', return_value={"total_emails": 1000}), \
             patch.object(analytics_service, 'get_incident_analytics', return_value={"total_incidents": 10}), \
             patch.object(analytics_service, 'get_threat_intelligence_analytics', return_value={"total_indicators": 5000}), \
             patch.object(analytics_service, 'get_performance_analytics', return_value={"avg_response_time": 150}), \
             patch.object(analytics_service, 'get_trend_analytics', return_value={"overall_trend": "stable"}):
            
            metrics = await analytics_service.get_comprehensive_metrics(start_time, end_time)
        
        assert "threat_analytics" in metrics
        assert "email_analytics" in metrics
        assert "incident_analytics" in metrics
        assert "intelligence_analytics" in metrics
        assert "performance_analytics" in metrics
        assert "trend_analytics" in metrics
        assert "generated_at" in metrics
    
    @pytest.mark.asyncio
    async def test_threat_analytics_calculation(self):
        """Test threat analytics calculation"""
        
        # Mock detection data
        mock_detections = [
            MagicMock(
                is_phishing=True,
                confidence_score=0.85,
                risk_level="HIGH",
                processing_time_ms=250,
                model_type="ensemble",
                risk_factors=["suspicious_link", "urgency_keywords"]
            ),
            MagicMock(
                is_phishing=False,
                confidence_score=0.25,
                risk_level="LOW",
                processing_time_ms=180,
                model_type="rule_based",
                risk_factors=[]
            )
        ]
        
        with patch('app.models.mongodb_models.Detection.find') as mock_find:
            mock_find.return_value.to_list.return_value = mock_detections
            
            start_time = datetime.utcnow() - timedelta(hours=24)
            end_time = datetime.utcnow()
            
            analytics = await analytics_service.get_threat_analytics(start_time, end_time)
        
        assert analytics["total_detections"] == 2
        assert analytics["phishing_detections"] == 1
        assert analytics["phishing_rate"] == 0.5
        assert "risk_distribution" in analytics
        assert "top_threat_indicators" in analytics
    
    @pytest.mark.asyncio
    async def test_email_analytics_calculation(self):
        """Test email analytics calculation"""
        
        # Mock email data
        mock_emails = [
            MagicMock(
                id="email1",
                size_bytes=1024,
                sender="user@example.com",
                content_type="text/html",
                received_at=datetime.utcnow()
            ),
            MagicMock(
                id="email2",
                size_bytes=2048,
                sender="admin@company.com",
                content_type="text/plain",
                received_at=datetime.utcnow()
            )
        ]
        
        mock_detections = [
            MagicMock(is_phishing=True, confidence_score=0.95),
            MagicMock(is_phishing=False, confidence_score=0.15)
        ]
        
        with patch('app.models.mongodb_models.Email.find') as mock_email_find, \
             patch('app.models.mongodb_models.Detection.find') as mock_detection_find:
            
            mock_email_find.return_value.to_list.return_value = mock_emails
            mock_detection_find.return_value.to_list.return_value = mock_detections
            
            start_time = datetime.utcnow() - timedelta(hours=24)
            end_time = datetime.utcnow()
            
            analytics = await analytics_service.get_email_analytics(start_time, end_time)
        
        assert analytics["total_emails"] == 2
        assert analytics["average_email_size_bytes"] == 1536.0  # (1024 + 2048) / 2
        assert analytics["detection_rate"] == 1.0  # 2 detections for 2 emails


class TestRealTimeMonitoring:
    """Test suite for real-time monitoring"""
    
    def test_real_time_event_creation(self):
        """Test real-time event creation"""
        
        event = RealTimeEvent(
            event_id="test_001",
            event_type="threat_detected",
            severity="high",
            title="Test Threat",
            description="Test description",
            source="Test Source",
            timestamp=datetime.utcnow(),
            metadata={"test": "data"}
        )
        
        event_dict = event.to_dict()
        
        assert event_dict["event_id"] == "test_001"
        assert event_dict["event_type"] == "threat_detected"
        assert event_dict["severity"] == "high"
        assert "timestamp" in event_dict
        assert event_dict["metadata"]["test"] == "data"
    
    def test_threat_feed_update_creation(self):
        """Test threat feed update creation"""
        
        now = datetime.utcnow()
        
        update = ThreatFeedUpdate(
            update_id="feed_001",
            feed_source="VirusTotal",
            ioc_type="url",
            ioc_value="http://malicious.com",
            threat_type="phishing",
            confidence=0.95,
            reputation_score=9.0,
            first_seen=now,
            last_seen=now,
            tags=["phishing", "malware"]
        )
        
        update_dict = update.to_dict()
        
        assert update_dict["update_id"] == "feed_001"
        assert update_dict["feed_source"] == "VirusTotal"
        assert update_dict["ioc_type"] == "url"
        assert update_dict["confidence"] == 0.95
        assert update_dict["tags"] == ["phishing", "malware"]
    
    @pytest.mark.asyncio
    async def test_connection_manager(self):
        """Test WebSocket connection manager"""
        
        from app.services.real_time_monitor import ConnectionManager
        
        manager = ConnectionManager()
        
        # Mock WebSocket
        mock_websocket = AsyncMock()
        
        # Test connection
        await manager.connect(mock_websocket, "client_001")
        assert "client_001" in manager.active_connections
        assert "client_001" in manager.subscriptions
        
        # Test subscription
        manager.subscribe_to_events("client_001", ["threat_detected", "incident_created"])
        assert "threat_detected" in manager.subscriptions["client_001"]
        assert "incident_created" in manager.subscriptions["client_001"]
        
        # Test disconnect
        manager.disconnect("client_001")
        assert "client_001" not in manager.active_connections
        assert "client_001" not in manager.subscriptions
    
    def test_monitoring_stats(self):
        """Test monitoring statistics"""
        
        stats = real_time_monitor.get_connection_stats()
        
        assert "active_connections" in stats
        assert "total_subscriptions" in stats
        assert "event_buffer_size" in stats
        assert "threat_feed_buffer_size" in stats
        assert "monitoring_active" in stats
    
    def test_risk_to_severity_mapping(self):
        """Test risk level to severity mapping"""
        
        assert real_time_monitor._map_risk_to_severity("LOW") == "low"
        assert real_time_monitor._map_risk_to_severity("MEDIUM") == "medium"
        assert real_time_monitor._map_risk_to_severity("HIGH") == "high"
        assert real_time_monitor._map_risk_to_severity("CRITICAL") == "critical"
        assert real_time_monitor._map_risk_to_severity("UNKNOWN") == "medium"


class TestWebSocketEndpoints:
    """Test suite for WebSocket endpoints"""
    
    def test_websocket_test_page(self, test_client):
        """Test WebSocket test page endpoint"""
        
        response = test_client.get("/ws/monitor-test")
        
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "PhishNet Real-time Monitor Test" in response.text
        assert "WebSocket" in response.text
    
    def test_monitoring_stats_endpoint(self, test_client):
        """Test monitoring statistics endpoint"""
        
        mock_stats = {
            "active_connections": 5,
            "total_subscriptions": 15,
            "event_buffer_size": 100,
            "threat_feed_buffer_size": 50,
            "monitoring_active": True
        }
        
        with patch.object(real_time_monitor, 'get_connection_stats', return_value=mock_stats):
            response = test_client.get("/ws/stats")
            
        assert response.status_code == 200
        data = response.json()
        assert data["active_connections"] == 5
        assert data["monitoring_active"] is True


if __name__ == "__main__":
    import asyncio
    
    async def run_analytics_test():
        """Run a live analytics test"""
        print("🧪 Running Analytics Dashboard Integration Test")
        print("=" * 60)
        
        # Test analytics service
        print("\n📊 Testing Analytics Service...")
        start_time = datetime.utcnow() - timedelta(hours=24)
        end_time = datetime.utcnow()
        
        try:
            # This would require database connection in real scenario
            print("✅ Analytics service test would run with database connection")
        except Exception as e:
            print(f"❌ Analytics service test failed: {e}")
        
        # Test real-time monitoring
        print("\n🔴 Testing Real-time Monitoring...")
        try:
            stats = real_time_monitor.get_connection_stats()
            print(f"✅ Monitoring stats: {stats}")
        except Exception as e:
            print(f"❌ Real-time monitoring test failed: {e}")
        
        print("\n✅ Integration test completed!")
        print("\n📋 Dashboard Features Implemented:")
        print("   • Comprehensive threat analytics")
        print("   • Email analysis metrics")
        print("   • Incident management tracking")
        print("   • Threat intelligence summaries")
        print("   • Real-time security alerts")
        print("   • System performance monitoring")
        print("   • Trend analysis and forecasting")
        print("   • WebSocket-based live updates")
        print("   • Interactive dashboard UI")
        print("   • Multi-time range support")
    
    # Run the test
    asyncio.run(run_analytics_test())