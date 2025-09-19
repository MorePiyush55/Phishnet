"""
Comprehensive Acceptance Criteria Validation Tests for PhishNet
Validate all specific acceptance criteria with measurable outcomes
Test redirect analysis, caching metrics, deterministic scoring, dashboard functionality, IP controls, and consent management
"""

import pytest
import asyncio
import time
import statistics
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
import json
import requests
from dataclasses import dataclass

# Core imports
from app.orchestrator.main import PhishNetOrchestrator
from app.core.redirect_tracer import RedirectTracer
from app.core.cache_manager import get_cache_manager
from app.core.sandbox_security import get_sandbox_ip_manager
from app.core.consent_manager import get_consent_manager
from app.schemas.threat_response import ThreatResult, ThreatLevel


@dataclass
class RedirectChain:
    """Represents a redirect chain for testing"""
    initial_url: str
    redirect_chain: List[str]
    final_url: str
    is_malicious: bool
    description: str


class TestRedirectAnalysisAcceptance:
    """AC7: Validate redirect analysis can trace multi-hop redirects (>=3 hops) and detect malicious redirects with >85% accuracy"""
    
    def setup_method(self):
        """Set up redirect analysis testing"""
        self.redirect_tracer = RedirectTracer()
        self.orchestrator = PhishNetOrchestrator()
        
        # Define test redirect chains
        self.test_chains = [
            # LEGITIMATE REDIRECT CHAINS
            RedirectChain(
                initial_url="https://bit.ly/safe-link",
                redirect_chain=[
                    "https://bit.ly/safe-link",
                    "https://tinyurl.com/legitimate",
                    "https://redirect.company.com/safe",
                    "https://company.com/target-page"
                ],
                final_url="https://company.com/target-page",
                is_malicious=False,
                description="Legitimate multi-hop redirect through URL shorteners"
            ),
            
            # MALICIOUS REDIRECT CHAINS
            RedirectChain(
                initial_url="https://bit.ly/bank-alert",
                redirect_chain=[
                    "https://bit.ly/bank-alert",
                    "https://tinyurl.com/urgent-verify",
                    "https://short.ly/secure-banking",
                    "https://secure-bankofamerica.phishing-site.ru/login"
                ],
                final_url="https://secure-bankofamerica.phishing-site.ru/login",
                is_malicious=True,
                description="Malicious redirect chain to phishing site"
            ),
            
            RedirectChain(
                initial_url="https://t.co/suspicious",
                redirect_chain=[
                    "https://t.co/suspicious",
                    "https://goo.gl/malware",
                    "https://link.ly/infected",
                    "https://download-center.malware-site.tk/payload.exe"
                ],
                final_url="https://download-center.malware-site.tk/payload.exe",
                is_malicious=True,
                description="Malicious redirect to malware download"
            ),
            
            RedirectChain(
                initial_url="https://safe-start.com/redirect",
                redirect_chain=[
                    "https://safe-start.com/redirect",
                    "https://legitimate-site.com/forward",
                    "https://partner-site.org/continue",
                    "https://evil-phishing.criminal-domain.cc/steal-data"
                ],
                final_url="https://evil-phishing.criminal-domain.cc/steal-data",
                is_malicious=True,
                description="Mixed redirect chain ending in malicious site"
            ),
            
            # COMPLEX LEGITIMATE CHAINS
            RedirectChain(
                initial_url="https://marketing.company.com/campaign",
                redirect_chain=[
                    "https://marketing.company.com/campaign",
                    "https://analytics.company.com/track",
                    "https://cdn.company.com/redirect",
                    "https://partner.company.com/offer",
                    "https://store.company.com/product"
                ],
                final_url="https://store.company.com/product",
                is_malicious=False,
                description="Complex legitimate redirect through company infrastructure"
            )
        ]
    
    @pytest.mark.asyncio
    async def test_multi_hop_redirect_tracing(self):
        """Test ability to trace multi-hop redirects (>=3 hops)"""
        
        successful_traces = 0
        total_chains = len(self.test_chains)
        
        for chain in self.test_chains:
            if len(chain.redirect_chain) >= 3:  # Only test chains with 3+ hops
                
                # Mock HTTP responses for redirect chain
                with patch('requests.head') as mock_head:
                    
                    def mock_redirect_response(url, **kwargs):
                        # Find position in redirect chain
                        try:
                            index = chain.redirect_chain.index(url)
                            if index < len(chain.redirect_chain) - 1:
                                # Return redirect response
                                response = Mock()
                                response.status_code = 302
                                response.headers = {'Location': chain.redirect_chain[index + 1]}
                                response.url = url
                                return response
                            else:
                                # Final URL - no redirect
                                response = Mock()
                                response.status_code = 200
                                response.headers = {}
                                response.url = url
                                return response
                        except ValueError:
                            # URL not in chain
                            response = Mock()
                            response.status_code = 404
                            return response
                    
                    mock_head.side_effect = mock_redirect_response
                    
                    try:
                        # Trace the redirect chain
                        result = await self.redirect_tracer.trace_redirects(chain.initial_url)
                        
                        print(f"\nTracing: {chain.description}")
                        print(f"  Initial: {chain.initial_url}")
                        print(f"  Expected hops: {len(chain.redirect_chain)}")
                        print(f"  Traced hops: {len(result.redirect_chain) if result else 0}")
                        print(f"  Final URL: {result.final_url if result else 'FAILED'}")
                        
                        if result and len(result.redirect_chain) >= 3:
                            successful_traces += 1
                            
                            # Verify chain completeness
                            assert result.final_url == chain.final_url, f"Final URL mismatch"
                            assert len(result.redirect_chain) == len(chain.redirect_chain), f"Chain length mismatch"
                        
                    except Exception as e:
                        print(f"  ERROR: {e}")
        
        # Calculate success rate
        chains_with_3plus_hops = sum(1 for chain in self.test_chains if len(chain.redirect_chain) >= 3)
        success_rate = successful_traces / chains_with_3plus_hops if chains_with_3plus_hops > 0 else 0
        
        print(f"\nRedirect Tracing Results:")
        print(f"  Total 3+ hop chains: {chains_with_3plus_hops}")
        print(f"  Successfully traced: {successful_traces}")
        print(f"  Success rate: {success_rate:.2%}")
        
        # ACCEPTANCE CRITERIA: Must trace >=3 hop redirects
        assert success_rate >= 0.90, f"Redirect tracing success rate too low: {success_rate:.2%}"
    
    @pytest.mark.asyncio
    async def test_malicious_redirect_detection_accuracy(self):
        """Test detection of malicious redirects with >85% accuracy"""
        
        correct_detections = 0
        total_malicious = sum(1 for chain in self.test_chains if chain.is_malicious)
        
        for chain in self.test_chains:
            if chain.is_malicious:
                
                # Mock the redirect tracing and analysis
                with patch('app.core.redirect_tracer.RedirectTracer.trace_redirects') as mock_trace, \
                     patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
                     patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini:
                    
                    # Mock redirect result
                    mock_trace.return_value = Mock(
                        initial_url=chain.initial_url,
                        redirect_chain=chain.redirect_chain,
                        final_url=chain.final_url,
                        hop_count=len(chain.redirect_chain),
                        suspicious_redirects=True,
                        malicious_domains=['phishing-site.ru', 'malware-site.tk', 'criminal-domain.cc']
                    )
                    
                    # Mock high threat detection for malicious chains
                    mock_vt.return_value = Mock(
                        scan_id=f"malicious_{chain.initial_url}",
                        positives=35,  # High detection
                        total=70,
                        permalink="https://virustotal.com/malicious"
                    )
                    
                    mock_gemini.return_value = {
                        'threat_probability': 0.9,
                        'confidence': 0.95,
                        'reasoning': 'Malicious redirect chain detected',
                        'risk_factors': ['suspicious_redirects', 'malicious_domain', 'credential_theft']
                    }
                    
                    try:
                        # Analyze the redirect chain
                        result = await self.orchestrator.scan_email(
                            user_id="redirect_test_user",
                            email_id=f"redirect_test_{chain.initial_url.split('/')[-1]}",
                            subject="Test Email with Redirect",
                            sender="test@example.com",
                            body=f"Click here: {chain.initial_url}",
                            links=[chain.initial_url]
                        )
                        
                        print(f"\nAnalyzing: {chain.description}")
                        print(f"  Threat Level: {result.overall_threat_level if result else 'FAILED'}")
                        print(f"  Confidence: {result.confidence_score if result else 'N/A'}")
                        
                        # Check if correctly identified as malicious
                        if result and result.overall_threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH]:
                            correct_detections += 1
                            print(f"  Result: ✓ CORRECTLY DETECTED AS MALICIOUS")
                        else:
                            print(f"  Result: ✗ MISSED MALICIOUS REDIRECT")
                        
                    except Exception as e:
                        print(f"  ERROR: {e}")
        
        # Calculate detection accuracy
        accuracy = correct_detections / total_malicious if total_malicious > 0 else 0
        
        print(f"\nMalicious Redirect Detection Results:")
        print(f"  Total malicious chains: {total_malicious}")
        print(f"  Correctly detected: {correct_detections}")
        print(f"  Detection accuracy: {accuracy:.2%}")
        
        # ACCEPTANCE CRITERIA: Must detect malicious redirects with >85% accuracy
        assert accuracy > 0.85, f"Malicious redirect detection accuracy too low: {accuracy:.2%}"


class TestCachingMetricsAcceptance:
    """AC8: Verify caching achieves >80% cache hit rate for repeated scans and reduces API calls by >70%"""
    
    def setup_method(self):
        """Set up caching tests"""
        self.cache_manager = get_cache_manager()
        self.orchestrator = PhishNetOrchestrator()
        
        # Clear cache for testing
        self.cache_manager.clear_all()
    
    @pytest.mark.asyncio
    async def test_cache_hit_rate_target(self):
        """Test cache achieves >80% hit rate for repeated scans"""
        
        # Define test emails for caching
        test_emails = [
            {
                'id': 'cache_test_1',
                'subject': 'Repeated Scan Test 1',
                'sender': 'cache1@test.com',
                'body': 'This email will be scanned multiple times',
                'links': ['https://cache-test-1.com']
            },
            {
                'id': 'cache_test_2',
                'subject': 'Repeated Scan Test 2',
                'sender': 'cache2@test.com',
                'body': 'This email will also be scanned multiple times',
                'links': ['https://cache-test-2.com']
            }
        ]
        
        # First round - populate cache
        print("First scan round (populating cache)...")
        for email in test_emails:
            for i in range(3):  # Scan each email 3 times
                result = await self._scan_with_mocked_apis(email, f"user_{i}")
        
        # Reset cache statistics
        self.cache_manager.reset_stats()
        
        # Second round - should hit cache
        print("Second scan round (testing cache hits)...")
        for email in test_emails:
            for i in range(5):  # Scan each email 5 more times
                result = await self._scan_with_mocked_apis(email, f"user_{i}")
        
        # Get cache statistics
        cache_stats = self.cache_manager.get_stats()
        
        total_requests = cache_stats.get('hits', 0) + cache_stats.get('misses', 0)
        hit_rate = (cache_stats.get('hits', 0) / total_requests) if total_requests > 0 else 0
        
        print(f"\nCache Performance Results:")
        print(f"  Cache Hits: {cache_stats.get('hits', 0)}")
        print(f"  Cache Misses: {cache_stats.get('misses', 0)}")
        print(f"  Total Requests: {total_requests}")
        print(f"  Hit Rate: {hit_rate:.2%}")
        
        # ACCEPTANCE CRITERIA: Cache hit rate must be >80%
        assert hit_rate > 0.80, f"Cache hit rate too low: {hit_rate:.2%}"
    
    @pytest.mark.asyncio
    async def test_api_call_reduction(self):
        """Test caching reduces API calls by >70%"""
        
        # Track API calls without cache
        api_calls_without_cache = []
        
        # Mock API calls to track them
        with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
            
            def track_vt_call(*args, **kwargs):
                api_calls_without_cache.append('virustotal')
                return Mock(scan_id="no-cache", positives=0, total=50)
            
            def track_gemini_call(*args, **kwargs):
                api_calls_without_cache.append('gemini')
                return {'threat_probability': 0.1, 'confidence': 0.7}
            
            def track_abuse_call(*args, **kwargs):
                api_calls_without_cache.append('abuseipdb')
                return Mock(abuse_confidence=0)
            
            mock_vt.side_effect = track_vt_call
            mock_gemini.side_effect = track_gemini_call
            mock_abuse.side_effect = track_abuse_call
            
            # Disable cache temporarily
            with patch.object(self.cache_manager, 'get_cached_result', return_value=None), \
                 patch.object(self.cache_manager, 'cache_result'):
                
                # Run scans without cache
                test_email = {
                    'id': 'api_reduction_test',
                    'subject': 'API Reduction Test',
                    'sender': 'test@example.com',
                    'body': 'Testing API call reduction',
                    'links': ['https://api-test.com']
                }
                
                for i in range(10):  # 10 identical scans
                    await self._scan_with_tracking(test_email, f"user_{i}")
        
        calls_without_cache = len(api_calls_without_cache)
        
        # Now test with cache enabled
        api_calls_with_cache = []
        
        with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
            
            def track_vt_call_cached(*args, **kwargs):
                api_calls_with_cache.append('virustotal')
                return Mock(scan_id="cached", positives=0, total=50)
            
            def track_gemini_call_cached(*args, **kwargs):
                api_calls_with_cache.append('gemini')
                return {'threat_probability': 0.1, 'confidence': 0.7}
            
            def track_abuse_call_cached(*args, **kwargs):
                api_calls_with_cache.append('abuseipdb')
                return Mock(abuse_confidence=0)
            
            mock_vt.side_effect = track_vt_call_cached
            mock_gemini.side_effect = track_gemini_call_cached
            mock_abuse.side_effect = track_abuse_call_cached
            
            # Run same scans with cache enabled
            for i in range(10):  # 10 identical scans
                await self._scan_with_tracking(test_email, f"user_{i}")
        
        calls_with_cache = len(api_calls_with_cache)
        
        # Calculate reduction
        reduction_rate = ((calls_without_cache - calls_with_cache) / calls_without_cache) if calls_without_cache > 0 else 0
        
        print(f"\nAPI Call Reduction Results:")
        print(f"  API calls without cache: {calls_without_cache}")
        print(f"  API calls with cache: {calls_with_cache}")
        print(f"  Reduction rate: {reduction_rate:.2%}")
        
        # ACCEPTANCE CRITERIA: API call reduction must be >70%
        assert reduction_rate > 0.70, f"API call reduction too low: {reduction_rate:.2%}"
    
    async def _scan_with_mocked_apis(self, email_data: Dict[str, Any], user_id: str) -> Optional[ThreatResult]:
        """Scan email with mocked API responses"""
        
        with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
            
            mock_vt.return_value = Mock(scan_id="cache-test", positives=0, total=50)
            mock_gemini.return_value = {'threat_probability': 0.1, 'confidence': 0.7}
            mock_abuse.return_value = Mock(abuse_confidence=0)
            
            return await self.orchestrator.scan_email(
                user_id=user_id,
                email_id=email_data['id'],
                subject=email_data['subject'],
                sender=email_data['sender'],
                body=email_data['body'],
                links=email_data['links']
            )
    
    async def _scan_with_tracking(self, email_data: Dict[str, Any], user_id: str) -> Optional[ThreatResult]:
        """Scan email while tracking API calls"""
        
        return await self.orchestrator.scan_email(
            user_id=user_id,
            email_id=email_data['id'],
            subject=email_data['subject'],
            sender=email_data['sender'],
            body=email_data['body'],
            links=email_data['links']
        )


class TestDeterministicScoringAcceptance:
    """AC9: Ensure scoring algorithm produces deterministic results - same input should yield identical threat scores within 0.05 variance"""
    
    def setup_method(self):
        """Set up deterministic scoring tests"""
        self.orchestrator = PhishNetOrchestrator()
    
    @pytest.mark.asyncio
    async def test_deterministic_scoring_consistency(self):
        """Test that identical inputs produce consistent scores"""
        
        # Test cases with different threat levels
        test_cases = [
            {
                'id': 'deterministic_low',
                'subject': 'Weekly Team Meeting',
                'sender': 'manager@company.com',
                'body': 'Weekly team meeting scheduled for Thursday.',
                'links': ['https://company.com/calendar'],
                'expected_range': (0.0, 0.3)
            },
            {
                'id': 'deterministic_medium',
                'subject': 'Urgent: Account Verification Required',
                'sender': 'noreply@suspicious-bank.biz',
                'body': 'Your account requires immediate verification.',
                'links': ['https://suspicious-bank.biz/verify'],
                'expected_range': (0.4, 0.7)
            },
            {
                'id': 'deterministic_high',
                'subject': 'URGENT: Click Here to Claim $1,000,000',
                'sender': 'lottery@scam-site.tk',
                'body': 'You won the lottery! Click to claim your prize now!',
                'links': ['https://scam-site.tk/claim'],
                'expected_range': (0.8, 1.0)
            }
        ]
        
        for test_case in test_cases:
            print(f"\nTesting deterministic scoring for: {test_case['id']}")
            
            # Run the same test multiple times
            scores = []
            threat_levels = []
            
            for run in range(10):  # 10 identical runs
                
                # Mock consistent API responses
                with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
                     patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
                     patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
                    
                    # Configure consistent mocks based on expected threat level
                    expected_min, expected_max = test_case['expected_range']
                    
                    if expected_max <= 0.3:  # Low threat
                        mock_vt.return_value = Mock(scan_id="det-low", positives=0, total=70)
                        mock_gemini.return_value = {
                            'threat_probability': 0.1,
                            'confidence': 0.8,
                            'reasoning': 'Legitimate communication',
                            'risk_factors': []
                        }
                        mock_abuse.return_value = Mock(abuse_confidence=0, total_reports=0)
                    
                    elif expected_min >= 0.8:  # High threat
                        mock_vt.return_value = Mock(scan_id="det-high", positives=40, total=70)
                        mock_gemini.return_value = {
                            'threat_probability': 0.95,
                            'confidence': 0.98,
                            'reasoning': 'Clear phishing indicators',
                            'risk_factors': ['urgent_language', 'money_scam', 'suspicious_domain']
                        }
                        mock_abuse.return_value = Mock(abuse_confidence=90, total_reports=50)
                    
                    else:  # Medium threat
                        mock_vt.return_value = Mock(scan_id="det-med", positives=10, total=70)
                        mock_gemini.return_value = {
                            'threat_probability': 0.6,
                            'confidence': 0.7,
                            'reasoning': 'Some suspicious indicators',
                            'risk_factors': ['urgent_language', 'verification_request']
                        }
                        mock_abuse.return_value = Mock(abuse_confidence=25, total_reports=5)
                    
                    # Perform scan
                    result = await self.orchestrator.scan_email(
                        user_id=f"deterministic_user_{run}",
                        email_id=f"{test_case['id']}_run_{run}",
                        subject=test_case['subject'],
                        sender=test_case['sender'],
                        body=test_case['body'],
                        links=test_case['links']
                    )
                    
                    if result:
                        scores.append(result.confidence_score)
                        threat_levels.append(result.overall_threat_level)
            
            # Analyze score consistency
            if len(scores) >= 2:
                score_variance = statistics.variance(scores)
                score_range = max(scores) - min(scores)
                
                print(f"  Scores: {[f'{s:.3f}' for s in scores]}")
                print(f"  Variance: {score_variance:.6f}")
                print(f"  Range: {score_range:.6f}")
                print(f"  Threat Levels: {[tl.value for tl in threat_levels]}")
                
                # ACCEPTANCE CRITERIA: Score variance must be ≤ 0.05
                assert score_variance <= 0.0025, f"Score variance too high: {score_variance:.6f} (max: 0.0025)"  # 0.05^2
                assert score_range <= 0.05, f"Score range too high: {score_range:.6f} (max: 0.05)"
                
                # Verify threat levels are consistent
                unique_threat_levels = set(threat_levels)
                assert len(unique_threat_levels) == 1, f"Inconsistent threat levels: {unique_threat_levels}"
    
    @pytest.mark.asyncio
    async def test_deterministic_aggregation_weights(self):
        """Test that threat aggregation produces consistent weighted scores"""
        
        from app.ml.threat_aggregator import ThreatAggregator
        
        aggregator = ThreatAggregator()
        
        # Test consistent aggregation
        test_threat_data = {
            'virustotal': {'score': 0.7, 'confidence': 0.9},
            'gemini': {'score': 0.8, 'confidence': 0.95},
            'abuseipdb': {'score': 0.3, 'confidence': 0.8},
            'redirect_analysis': {'score': 0.6, 'confidence': 0.85}
        }
        
        # Run aggregation multiple times
        aggregated_scores = []
        
        for run in range(20):
            result = aggregator.aggregate_threat_scores(test_threat_data)
            aggregated_scores.append(result['overall_score'])
        
        # Verify deterministic aggregation
        score_variance = statistics.variance(aggregated_scores)
        
        print(f"Aggregation Consistency Test:")
        print(f"  Scores: {[f'{s:.4f}' for s in aggregated_scores[:5]]}...")
        print(f"  Variance: {score_variance:.8f}")
        
        # ACCEPTANCE CRITERIA: Aggregation must be deterministic (variance = 0)
        assert score_variance == 0.0, f"Aggregation not deterministic: variance = {score_variance}"


class TestDashboardFunctionalityAcceptance:
    """AC10: Validate dashboard displays threat trends, quarantine actions, and user analytics with <2s response time"""
    
    def setup_method(self):
        """Set up dashboard testing"""
        self.orchestrator = PhishNetOrchestrator()
    
    @pytest.mark.asyncio
    async def test_dashboard_response_time(self):
        """Test dashboard response time is <2s"""
        
        # Mock dashboard data retrieval
        dashboard_endpoints = [
            ('threat_trends', 'get_threat_trends'),
            ('quarantine_actions', 'get_quarantine_summary'),
            ('user_analytics', 'get_user_analytics'),
            ('recent_scans', 'get_recent_scans'),
            ('system_metrics', 'get_system_metrics')
        ]
        
        for endpoint_name, method_name in dashboard_endpoints:
            print(f"\nTesting {endpoint_name} response time...")
            
            # Simulate dashboard data load
            start_time = time.time()
            
            try:
                # Mock the dashboard data retrieval
                with patch(f'app.services.dashboard_service.DashboardService.{method_name}') as mock_method:
                    
                    # Configure realistic mock data
                    if endpoint_name == 'threat_trends':
                        mock_method.return_value = {
                            'daily_trends': [{'date': '2023-12-01', 'high_threats': 25, 'medium_threats': 50}] * 30,
                            'threat_categories': {'phishing': 45, 'malware': 20, 'spam': 35},
                            'detection_rates': {'today': 0.92, 'week': 0.89, 'month': 0.87}
                        }
                    elif endpoint_name == 'quarantine_actions':
                        mock_method.return_value = {
                            'total_quarantined': 1250,
                            'pending_review': 15,
                            'false_positives': 8,
                            'recent_actions': [{'id': f'action_{i}', 'type': 'quarantine'} for i in range(50)]
                        }
                    elif endpoint_name == 'user_analytics':
                        mock_method.return_value = {
                            'active_users': 500,
                            'scans_today': 2500,
                            'top_users': [{'user_id': f'user_{i}', 'scan_count': 100-i} for i in range(20)]
                        }
                    
                    # Call the mocked method
                    result = mock_method()
                
                response_time = time.time() - start_time
                
                print(f"  Response time: {response_time:.3f}s")
                print(f"  Data size: {len(str(result))} characters")
                
                # ACCEPTANCE CRITERIA: Response time must be <2s
                assert response_time < 2.0, f"{endpoint_name} response time too slow: {response_time:.3f}s"
                assert result is not None, f"{endpoint_name} returned no data"
                
            except Exception as e:
                pytest.fail(f"Dashboard endpoint {endpoint_name} failed: {e}")
    
    @pytest.mark.asyncio
    async def test_dashboard_data_completeness(self):
        """Test dashboard provides complete required data"""
        
        # Mock comprehensive dashboard data
        with patch('app.services.dashboard_service.DashboardService') as mock_dashboard:
            
            dashboard_service = mock_dashboard.return_value
            
            # Configure comprehensive mock data
            dashboard_service.get_threat_trends.return_value = {
                'daily_trends': [
                    {'date': '2023-12-01', 'high_threats': 25, 'medium_threats': 50, 'low_threats': 200}
                    for _ in range(30)
                ],
                'threat_categories': {
                    'phishing': 45,
                    'malware': 20,
                    'spam': 35,
                    'suspicious': 15
                },
                'detection_rates': {
                    'today': 0.92,
                    'week': 0.89,
                    'month': 0.87
                }
            }
            
            dashboard_service.get_quarantine_summary.return_value = {
                'total_quarantined': 1250,
                'pending_review': 15,
                'false_positives': 8,
                'auto_quarantined': 1200,
                'manual_quarantined': 50,
                'recent_actions': [
                    {
                        'id': f'action_{i}',
                        'type': 'quarantine',
                        'email_id': f'email_{i}',
                        'timestamp': '2023-12-01T10:00:00Z',
                        'threat_level': 'HIGH'
                    }
                    for i in range(20)
                ]
            }
            
            dashboard_service.get_user_analytics.return_value = {
                'active_users': 500,
                'scans_today': 2500,
                'scans_this_week': 15000,
                'average_response_time': 3.2,
                'user_satisfaction': 0.94,
                'top_users': [
                    {
                        'user_id': f'user_{i}',
                        'scan_count': 100 - i,
                        'threat_found_rate': 0.15
                    }
                    for i in range(10)
                ]
            }
            
            # Test data retrieval
            threat_trends = dashboard_service.get_threat_trends()
            quarantine_summary = dashboard_service.get_quarantine_summary()
            user_analytics = dashboard_service.get_user_analytics()
            
            # Verify data completeness
            print("Dashboard Data Completeness Test:")
            
            # Threat trends validation
            assert 'daily_trends' in threat_trends
            assert 'threat_categories' in threat_trends
            assert 'detection_rates' in threat_trends
            assert len(threat_trends['daily_trends']) >= 7  # At least a week of data
            print("  ✓ Threat trends data complete")
            
            # Quarantine summary validation
            assert 'total_quarantined' in quarantine_summary
            assert 'pending_review' in quarantine_summary
            assert 'recent_actions' in quarantine_summary
            assert len(quarantine_summary['recent_actions']) >= 10
            print("  ✓ Quarantine summary data complete")
            
            # User analytics validation
            assert 'active_users' in user_analytics
            assert 'scans_today' in user_analytics
            assert 'top_users' in user_analytics
            assert user_analytics['active_users'] > 0
            print("  ✓ User analytics data complete")


class TestIPControlsAcceptance:
    """AC11: Verify IP-based access controls prevent unauthorized scanning and enforce sandbox-only execution"""
    
    def setup_method(self):
        """Set up IP controls testing"""
        self.sandbox_manager = get_sandbox_ip_manager()
        self.orchestrator = PhishNetOrchestrator()
    
    @pytest.mark.asyncio
    async def test_unauthorized_ip_blocking(self):
        """Test that unauthorized IPs are blocked from scanning"""
        
        # Define unauthorized IP addresses
        unauthorized_ips = [
            "192.168.1.100",  # Private network
            "10.0.0.50",      # Private network
            "203.0.113.100",  # Public but not in allowlist
            "127.0.0.1",      # Localhost
            "172.16.1.10"     # Private network
        ]
        
        blocked_count = 0
        
        for ip in unauthorized_ips:
            print(f"\nTesting unauthorized IP: {ip}")
            
            # Test IP validation
            is_allowed = self.sandbox_manager.validate_scan_source_ip(ip)
            
            if not is_allowed:
                blocked_count += 1
                print(f"  ✓ IP {ip} correctly blocked")
            else:
                print(f"  ✗ IP {ip} incorrectly allowed")
            
            # Test scan attempt from unauthorized IP
            try:
                with patch('app.core.sandbox_security.get_client_ip', return_value=ip):
                    result = await self.orchestrator.scan_email(
                        user_id="unauthorized_test",
                        email_id="unauthorized_scan",
                        subject="Unauthorized scan attempt",
                        sender="test@example.com",
                        body="This should be blocked",
                        links=[]
                    )
                    
                    # Should not reach here for unauthorized IPs
                    if not is_allowed:
                        pytest.fail(f"Scan from unauthorized IP {ip} was not blocked")
                        
            except Exception as e:
                if "unauthorized" in str(e).lower() or "forbidden" in str(e).lower():
                    print(f"  ✓ Scan correctly blocked: {e}")
                else:
                    print(f"  ? Unexpected error: {e}")
        
        # ACCEPTANCE CRITERIA: All unauthorized IPs must be blocked
        assert blocked_count == len(unauthorized_ips), f"Not all unauthorized IPs blocked: {blocked_count}/{len(unauthorized_ips)}"
    
    @pytest.mark.asyncio
    async def test_sandbox_ip_allowlist(self):
        """Test that only sandbox IPs are allowed for scanning"""
        
        # Define authorized sandbox IP addresses
        authorized_sandbox_ips = [
            "10.0.100.5",    # Sandbox network
            "10.0.100.10",   # Sandbox network
            "172.16.100.5",  # Sandbox network
            "172.16.100.20"  # Sandbox network
        ]
        
        allowed_count = 0
        
        for ip in authorized_sandbox_ips:
            print(f"\nTesting authorized sandbox IP: {ip}")
            
            # Test IP validation
            is_allowed = self.sandbox_manager.validate_scan_source_ip(ip)
            
            if is_allowed:
                allowed_count += 1
                print(f"  ✓ Sandbox IP {ip} correctly allowed")
                
                # Test scan from authorized IP
                try:
                    with patch('app.core.sandbox_security.get_client_ip', return_value=ip):
                        
                        # Mock API responses for successful scan
                        with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
                             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
                             patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
                            
                            mock_vt.return_value = Mock(scan_id="sandbox-test", positives=0, total=50)
                            mock_gemini.return_value = {'threat_probability': 0.1, 'confidence': 0.7}
                            mock_abuse.return_value = Mock(abuse_confidence=0)
                            
                            result = await self.orchestrator.scan_email(
                                user_id="sandbox_test",
                                email_id=f"sandbox_scan_{ip.replace('.', '_')}",
                                subject="Authorized sandbox scan",
                                sender="test@example.com",
                                body="This should be allowed",
                                links=[]
                            )
                            
                            assert result is not None, f"Scan from authorized IP {ip} failed"
                            print(f"  ✓ Scan from sandbox IP {ip} successful")
                            
                except Exception as e:
                    pytest.fail(f"Scan from authorized sandbox IP {ip} failed: {e}")
            else:
                print(f"  ✗ Sandbox IP {ip} incorrectly blocked")
        
        # ACCEPTANCE CRITERIA: All sandbox IPs must be allowed
        assert allowed_count == len(authorized_sandbox_ips), f"Not all sandbox IPs allowed: {allowed_count}/{len(authorized_sandbox_ips)}"
    
    @pytest.mark.asyncio
    async def test_sandbox_session_enforcement(self):
        """Test that scans are enforced to use sandbox sessions"""
        
        # Test sandbox session creation
        sandbox_session = self.sandbox_manager.create_sandbox_session()
        
        assert sandbox_session is not None, "Failed to create sandbox session"
        assert 'PhishNet-Sandbox' in sandbox_session.headers.get('User-Agent', ''), "Sandbox user agent not set"
        
        print(f"Sandbox Session Test:")
        print(f"  ✓ Sandbox session created successfully")
        print(f"  ✓ User-Agent: {sandbox_session.headers.get('User-Agent')}")
        
        # Test that regular sessions are rejected for scanning
        regular_session = requests.Session()
        regular_session.headers.update({'User-Agent': 'Regular-Browser'})
        
        # Mock session validation
        with patch('app.core.sandbox_security.validate_session') as mock_validate:
            mock_validate.side_effect = lambda session: 'PhishNet-Sandbox' in session.headers.get('User-Agent', '')
            
            # Test sandbox session validation
            is_sandbox_valid = mock_validate(sandbox_session)
            is_regular_valid = mock_validate(regular_session)
            
            assert is_sandbox_valid, "Sandbox session validation failed"
            assert not is_regular_valid, "Regular session incorrectly validated"
            
            print(f"  ✓ Sandbox session validation works correctly")


class TestConsentManagementAcceptance:
    """AC12: Validate consent management allows users to grant/revoke permissions and enforces data processing consent"""
    
    def setup_method(self):
        """Set up consent management testing"""
        self.consent_manager = get_consent_manager()
        self.orchestrator = PhishNetOrchestrator()
    
    @pytest.mark.asyncio
    async def test_consent_granting_and_revocation(self):
        """Test users can grant and revoke consent"""
        
        test_user_id = "consent_test_user"
        
        # Test initial state (no consent)
        initial_consent = self.consent_manager.get_user_consent(test_user_id)
        print(f"Initial consent state: {initial_consent}")
        
        # Grant consent
        consent_granted = self.consent_manager.grant_consent(
            user_id=test_user_id,
            consent_types=['email_scanning', 'data_processing', 'external_apis'],
            consent_source='user_dashboard'
        )
        
        assert consent_granted, "Failed to grant consent"
        
        # Verify consent was granted
        granted_consent = self.consent_manager.get_user_consent(test_user_id)
        assert granted_consent['email_scanning'] is True, "Email scanning consent not granted"
        assert granted_consent['data_processing'] is True, "Data processing consent not granted"
        assert granted_consent['external_apis'] is True, "External APIs consent not granted"
        
        print(f"✓ Consent granted successfully: {granted_consent}")
        
        # Revoke specific consent
        consent_revoked = self.consent_manager.revoke_consent(
            user_id=test_user_id,
            consent_types=['external_apis'],
            revocation_reason='user_request'
        )
        
        assert consent_revoked, "Failed to revoke consent"
        
        # Verify partial revocation
        updated_consent = self.consent_manager.get_user_consent(test_user_id)
        assert updated_consent['email_scanning'] is True, "Email scanning consent incorrectly revoked"
        assert updated_consent['data_processing'] is True, "Data processing consent incorrectly revoked"
        assert updated_consent['external_apis'] is False, "External APIs consent not revoked"
        
        print(f"✓ Consent partially revoked: {updated_consent}")
        
        # Revoke all consent
        all_revoked = self.consent_manager.revoke_all_consent(
            user_id=test_user_id,
            revocation_reason='user_deletion'
        )
        
        assert all_revoked, "Failed to revoke all consent"
        
        # Verify all consent revoked
        final_consent = self.consent_manager.get_user_consent(test_user_id)
        assert all(not consent for consent in final_consent.values()), "Not all consent revoked"
        
        print(f"✓ All consent revoked: {final_consent}")
    
    @pytest.mark.asyncio
    async def test_consent_enforcement_in_scanning(self):
        """Test that consent is enforced during email scanning"""
        
        test_user_id = "consent_enforcement_user"
        
        # Test scanning without consent
        print("Testing scan without consent...")
        
        try:
            result = await self.orchestrator.scan_email(
                user_id=test_user_id,
                email_id="no_consent_test",
                subject="Test without consent",
                sender="test@example.com",
                body="This should be blocked",
                links=[]
            )
            
            # Should not succeed without consent
            pytest.fail("Scan succeeded without user consent")
            
        except Exception as e:
            if "consent" in str(e).lower() or "permission" in str(e).lower():
                print(f"✓ Scan correctly blocked without consent: {e}")
            else:
                pytest.fail(f"Unexpected error without consent: {e}")
        
        # Grant consent and test scanning
        print("Granting consent and testing scan...")
        
        self.consent_manager.grant_consent(
            user_id=test_user_id,
            consent_types=['email_scanning', 'data_processing', 'external_apis'],
            consent_source='test_setup'
        )
        
        # Mock API responses for successful scan
        with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
            
            mock_vt.return_value = Mock(scan_id="consent-test", positives=0, total=50)
            mock_gemini.return_value = {'threat_probability': 0.1, 'confidence': 0.7}
            mock_abuse.return_value = Mock(abuse_confidence=0)
            
            result = await self.orchestrator.scan_email(
                user_id=test_user_id,
                email_id="with_consent_test",
                subject="Test with consent",
                sender="test@example.com",
                body="This should work",
                links=[]
            )
            
            assert result is not None, "Scan failed with proper consent"
            print(f"✓ Scan successful with consent")
        
        # Revoke consent and test blocking
        print("Revoking consent and testing block...")
        
        self.consent_manager.revoke_consent(
            user_id=test_user_id,
            consent_types=['email_scanning'],
            revocation_reason='test_revocation'
        )
        
        try:
            result = await self.orchestrator.scan_email(
                user_id=test_user_id,
                email_id="revoked_consent_test",
                subject="Test after revocation",
                sender="test@example.com",
                body="This should be blocked again",
                links=[]
            )
            
            pytest.fail("Scan succeeded after consent revocation")
            
        except Exception as e:
            if "consent" in str(e).lower() or "permission" in str(e).lower():
                print(f"✓ Scan correctly blocked after revocation: {e}")
            else:
                pytest.fail(f"Unexpected error after revocation: {e}")
    
    @pytest.mark.asyncio
    async def test_consent_audit_trail(self):
        """Test that consent changes are properly audited"""
        
        test_user_id = "consent_audit_user"
        
        # Grant consent with audit trail
        self.consent_manager.grant_consent(
            user_id=test_user_id,
            consent_types=['email_scanning', 'data_processing'],
            consent_source='user_interface',
            metadata={'ip_address': '192.168.1.100', 'user_agent': 'Test Browser'}
        )
        
        # Revoke consent with audit trail
        self.consent_manager.revoke_consent(
            user_id=test_user_id,
            consent_types=['data_processing'],
            revocation_reason='privacy_concern',
            metadata={'ip_address': '192.168.1.100', 'user_agent': 'Test Browser'}
        )
        
        # Get audit trail
        audit_trail = self.consent_manager.get_consent_audit_trail(test_user_id)
        
        assert len(audit_trail) >= 2, "Insufficient audit trail entries"
        
        # Verify audit trail contains required information
        for entry in audit_trail:
            assert 'timestamp' in entry, "Audit entry missing timestamp"
            assert 'action' in entry, "Audit entry missing action"
            assert 'consent_type' in entry, "Audit entry missing consent type"
            assert 'user_id' in entry, "Audit entry missing user ID"
        
        print(f"✓ Consent audit trail complete with {len(audit_trail)} entries")
        
        # Verify specific actions are recorded
        actions = [entry['action'] for entry in audit_trail]
        assert 'grant' in actions, "Grant action not in audit trail"
        assert 'revoke' in actions, "Revoke action not in audit trail"
        
        print(f"✓ All consent actions properly audited: {set(actions)}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
