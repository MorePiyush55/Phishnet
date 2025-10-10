"""
Advanced Analytics Service for PhishNet Security Operations
Provides data aggregation, calculations, and analytics for the dashboard
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import statistics
import json

from app.config.logging import get_logger
from app.models.mongodb_models import (
    Email, Detection, Incident, ThreatIntelligence, 
    WorkflowExecution, FileAnalysis
)

logger = get_logger(__name__)


class AnalyticsService:
    """Advanced analytics service for security operations dashboard"""
    
    def __init__(self):
        self.cache_duration = timedelta(minutes=5)
        self._cache = {}
        self._cache_timestamps = {}
    
    async def get_comprehensive_metrics(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> Dict[str, Any]:
        """Get comprehensive security metrics for dashboard"""
        try:
            logger.info(f"Generating comprehensive metrics from {start_time} to {end_time}")
            
            # Run all analytics in parallel for better performance
            results = await asyncio.gather(
                self.get_threat_analytics(start_time, end_time),
                self.get_email_analytics(start_time, end_time),
                self.get_incident_analytics(start_time, end_time),
                self.get_threat_intelligence_analytics(start_time, end_time),
                self.get_performance_analytics(start_time, end_time),
                self.get_trend_analytics(start_time, end_time),
                return_exceptions=True
            )
            
            threat_analytics, email_analytics, incident_analytics, \
            intel_analytics, performance_analytics, trend_analytics = results
            
            return {
                "threat_analytics": threat_analytics if not isinstance(threat_analytics, Exception) else {},
                "email_analytics": email_analytics if not isinstance(email_analytics, Exception) else {},
                "incident_analytics": incident_analytics if not isinstance(incident_analytics, Exception) else {},
                "intelligence_analytics": intel_analytics if not isinstance(intel_analytics, Exception) else {},
                "performance_analytics": performance_analytics if not isinstance(performance_analytics, Exception) else {},
                "trend_analytics": trend_analytics if not isinstance(trend_analytics, Exception) else {},
                "generated_at": datetime.utcnow()
            }
            
        except Exception as e:
            logger.error(f"Error generating comprehensive metrics: {e}")
            return {}
    
    async def get_threat_analytics(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> Dict[str, Any]:
        """Get threat detection analytics"""
        try:
            # Get threat detections from database
            detections = await Detection.find({
                "created_at": {"$gte": start_time, "$lte": end_time}
            }).to_list()
            
            if not detections:
                return self._empty_threat_analytics()
            
            # Calculate threat metrics
            total_detections = len(detections)
            phishing_detections = sum(1 for d in detections if d.is_phishing)
            phishing_rate = phishing_detections / total_detections if total_detections > 0 else 0
            
            # Risk level distribution
            risk_distribution = Counter(d.risk_level for d in detections)
            
            # Confidence statistics
            confidence_scores = [d.confidence_score for d in detections]
            avg_confidence = statistics.mean(confidence_scores) if confidence_scores else 0
            
            # Top threat indicators
            all_risk_factors = []
            for d in detections:
                if d.risk_factors:
                    all_risk_factors.extend(d.risk_factors)
            
            top_indicators = Counter(all_risk_factors).most_common(10)
            
            # Threat score analysis
            threat_scores = [d.confidence_score for d in detections if d.is_phishing]
            avg_threat_score = statistics.mean(threat_scores) if threat_scores else 0
            
            # Processing time analytics
            processing_times = [d.processing_time_ms for d in detections if d.processing_time_ms]
            avg_processing_time = statistics.mean(processing_times) if processing_times else 0
            
            return {
                "total_detections": total_detections,
                "phishing_detections": phishing_detections,
                "phishing_rate": round(phishing_rate, 3),
                "risk_distribution": dict(risk_distribution),
                "average_confidence": round(avg_confidence, 3),
                "average_threat_score": round(avg_threat_score, 3),
                "average_processing_time_ms": round(avg_processing_time, 2),
                "top_threat_indicators": [
                    {"indicator": indicator, "count": count} 
                    for indicator, count in top_indicators
                ],
                "model_performance": {
                    "ensemble_detections": sum(1 for d in detections if d.model_type == "ensemble"),
                    "rule_based_detections": sum(1 for d in detections if d.model_type == "rule_based"),
                    "neural_detections": sum(1 for d in detections if d.model_type == "neural")
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting threat analytics: {e}")
            return self._empty_threat_analytics()
    
    async def get_email_analytics(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> Dict[str, Any]:
        """Get email analysis analytics"""
        try:
            # Get emails from database
            emails = await Email.find({
                "received_at": {"$gte": start_time, "$lte": end_time}
            }).to_list()
            
            if not emails:
                return self._empty_email_analytics()
            
            total_emails = len(emails)
            
            # Get corresponding detections
            email_ids = [str(email.id) for email in emails]
            detections = await Detection.find({
                "email_id": {"$in": email_ids}
            }).to_list()
            
            # Email volume analysis
            email_sizes = [email.size_bytes for email in emails if email.size_bytes]
            avg_email_size = statistics.mean(email_sizes) if email_sizes else 0
            
            # Sender analysis
            sender_domains = [email.sender.split('@')[-1] for email in emails if '@' in email.sender]
            top_sender_domains = Counter(sender_domains).most_common(10)
            
            # Content type analysis
            content_types = Counter(email.content_type for email in emails if email.content_type)
            
            # Detection accuracy metrics
            detection_count = len(detections)
            detection_rate = detection_count / total_emails if total_emails > 0 else 0
            
            # False positive analysis (simplified)
            verified_phishing = sum(1 for d in detections if d.is_phishing and d.confidence_score > 0.8)
            potential_false_positives = sum(1 for d in detections if d.is_phishing and d.confidence_score < 0.6)
            
            return {
                "total_emails": total_emails,
                "average_email_size_bytes": round(avg_email_size, 2),
                "detection_rate": round(detection_rate, 3),
                "verified_phishing_count": verified_phishing,
                "potential_false_positives": potential_false_positives,
                "top_sender_domains": [
                    {"domain": domain, "count": count} 
                    for domain, count in top_sender_domains
                ],
                "content_type_distribution": dict(content_types),
                "volume_by_hour": await self._get_email_volume_by_hour(emails),
                "language_detection": await self._analyze_email_languages(emails)
            }
            
        except Exception as e:
            logger.error(f"Error getting email analytics: {e}")
            return self._empty_email_analytics()
    
    async def get_incident_analytics(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> Dict[str, Any]:
        """Get incident management analytics"""
        try:
            # Get incidents from database
            incidents = await Incident.find({
                "created_at": {"$gte": start_time, "$lte": end_time}
            }).to_list()
            
            if not incidents:
                return self._empty_incident_analytics()
            
            total_incidents = len(incidents)
            
            # Status analysis
            status_distribution = Counter(incident.status for incident in incidents)
            
            # Severity analysis
            severity_distribution = Counter(incident.severity for incident in incidents)
            
            # Resolution time analysis
            resolved_incidents = [i for i in incidents if i.status == "resolved" and i.resolved_at]
            resolution_times = []
            for incident in resolved_incidents:
                if incident.resolved_at and incident.created_at:
                    resolution_time = (incident.resolved_at - incident.created_at).total_seconds() / 3600  # hours
                    resolution_times.append(resolution_time)
            
            avg_resolution_time = statistics.mean(resolution_times) if resolution_times else 0
            median_resolution_time = statistics.median(resolution_times) if resolution_times else 0
            
            # Escalation analysis
            escalated_incidents = sum(1 for i in incidents if i.escalated)
            escalation_rate = escalated_incidents / total_incidents if total_incidents > 0 else 0
            
            # Response time analysis
            response_times = []
            for incident in incidents:
                if incident.first_response_at and incident.created_at:
                    response_time = (incident.first_response_at - incident.created_at).total_seconds() / 60  # minutes
                    response_times.append(response_time)
            
            avg_response_time = statistics.mean(response_times) if response_times else 0
            
            # Incident type analysis
            incident_types = Counter(incident.incident_type for incident in incidents)
            
            return {
                "total_incidents": total_incidents,
                "status_distribution": dict(status_distribution),
                "severity_distribution": dict(severity_distribution),
                "average_resolution_time_hours": round(avg_resolution_time, 2),
                "median_resolution_time_hours": round(median_resolution_time, 2),
                "escalation_rate": round(escalation_rate, 3),
                "average_response_time_minutes": round(avg_response_time, 2),
                "incident_type_distribution": dict(incident_types),
                "sla_compliance": await self._calculate_sla_compliance(incidents),
                "workload_distribution": await self._analyze_incident_workload(incidents)
            }
            
        except Exception as e:
            logger.error(f"Error getting incident analytics: {e}")
            return self._empty_incident_analytics()
    
    async def get_threat_intelligence_analytics(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> Dict[str, Any]:
        """Get threat intelligence analytics"""
        try:
            # Get threat intelligence data
            intel_items = await ThreatIntelligence.find({
                "last_updated": {"$gte": start_time, "$lte": end_time}
            }).to_list()
            
            if not intel_items:
                return self._empty_threat_intel_analytics()
            
            total_indicators = len(intel_items)
            
            # IOC type analysis
            ioc_types = Counter(item.ioc_type for item in intel_items)
            
            # Threat type analysis
            threat_types = Counter(item.threat_type for item in intel_items)
            
            # Confidence analysis
            confidence_scores = [item.confidence for item in intel_items if item.confidence]
            avg_confidence = statistics.mean(confidence_scores) if confidence_scores else 0
            
            # Source analysis
            sources = Counter(item.source for item in intel_items if item.source)
            
            # Reputation score analysis
            reputation_scores = [item.reputation_score for item in intel_items if item.reputation_score is not None]
            avg_reputation = statistics.mean(reputation_scores) if reputation_scores else 0
            
            # Active vs expired indicators
            current_time = datetime.utcnow()
            active_indicators = sum(1 for item in intel_items 
                                 if not item.expires_at or item.expires_at > current_time)
            expired_indicators = total_indicators - active_indicators
            
            # High-risk indicators
            high_risk_indicators = sum(1 for item in intel_items 
                                     if item.reputation_score is not None and item.reputation_score >= 8.0)
            
            return {
                "total_indicators": total_indicators,
                "active_indicators": active_indicators,
                "expired_indicators": expired_indicators,
                "high_risk_indicators": high_risk_indicators,
                "ioc_type_distribution": dict(ioc_types),
                "threat_type_distribution": dict(threat_types),
                "source_distribution": dict(sources),
                "average_confidence": round(avg_confidence, 3),
                "average_reputation_score": round(avg_reputation, 2),
                "feed_health": await self._analyze_feed_health(intel_items),
                "coverage_analysis": await self._analyze_threat_coverage(intel_items)
            }
            
        except Exception as e:
            logger.error(f"Error getting threat intelligence analytics: {e}")
            return self._empty_threat_intel_analytics()
    
    async def get_performance_analytics(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> Dict[str, Any]:
        """Get system performance analytics"""
        try:
            # Get workflow executions for performance metrics
            workflows = await WorkflowExecution.find({
                "started_at": {"$gte": start_time, "$lte": end_time}
            }).to_list()
            
            # Calculate performance metrics
            total_workflows = len(workflows)
            
            if total_workflows == 0:
                return self._empty_performance_analytics()
            
            # Execution time analysis
            execution_times = [w.execution_time_ms for w in workflows if w.execution_time_ms]
            avg_execution_time = statistics.mean(execution_times) if execution_times else 0
            
            # Success rate analysis
            successful_workflows = sum(1 for w in workflows if w.status == "completed")
            success_rate = successful_workflows / total_workflows if total_workflows > 0 else 0
            
            # Error analysis
            failed_workflows = sum(1 for w in workflows if w.status == "failed")
            error_rate = failed_workflows / total_workflows if total_workflows > 0 else 0
            
            # Workflow type performance
            workflow_performance = defaultdict(list)
            for workflow in workflows:
                if workflow.execution_time_ms:
                    workflow_performance[workflow.workflow_type].append(workflow.execution_time_ms)
            
            workflow_avg_times = {
                wf_type: statistics.mean(times) 
                for wf_type, times in workflow_performance.items()
            }
            
            # System throughput
            time_diff_hours = (end_time - start_time).total_seconds() / 3600
            throughput_per_hour = total_workflows / time_diff_hours if time_diff_hours > 0 else 0
            
            return {
                "total_workflows": total_workflows,
                "average_execution_time_ms": round(avg_execution_time, 2),
                "success_rate": round(success_rate, 3),
                "error_rate": round(error_rate, 3),
                "throughput_per_hour": round(throughput_per_hour, 2),
                "workflow_performance": {
                    wf_type: round(avg_time, 2) 
                    for wf_type, avg_time in workflow_avg_times.items()
                },
                "resource_utilization": await self._get_resource_utilization(),
                "api_performance": await self._get_api_performance_metrics(start_time, end_time)
            }
            
        except Exception as e:
            logger.error(f"Error getting performance analytics: {e}")
            return self._empty_performance_analytics()
    
    async def get_trend_analytics(
        self, 
        start_time: datetime, 
        end_time: datetime,
        granularity: str = "hour"
    ) -> Dict[str, Any]:
        """Get trend analytics for various metrics"""
        try:
            # Calculate time buckets based on granularity
            time_buckets = self._generate_time_buckets(start_time, end_time, granularity)
            
            # Get trend data for different metrics
            threat_trends = await self._get_threat_trends(time_buckets)
            email_trends = await self._get_email_trends(time_buckets)
            incident_trends = await self._get_incident_trends(time_buckets)
            
            # Calculate trend directions and forecasts
            threat_direction = self._calculate_trend_direction(threat_trends)
            email_direction = self._calculate_trend_direction(email_trends)
            incident_direction = self._calculate_trend_direction(incident_trends)
            
            return {
                "threat_trends": {
                    "data": threat_trends,
                    "direction": threat_direction,
                    "forecast": await self._generate_simple_forecast(threat_trends)
                },
                "email_trends": {
                    "data": email_trends,
                    "direction": email_direction,
                    "forecast": await self._generate_simple_forecast(email_trends)
                },
                "incident_trends": {
                    "data": incident_trends,
                    "direction": incident_direction,
                    "forecast": await self._generate_simple_forecast(incident_trends)
                },
                "summary": {
                    "overall_trend": self._calculate_overall_trend(
                        threat_direction, email_direction, incident_direction
                    ),
                    "risk_level": self._assess_trend_risk(
                        threat_direction, email_direction, incident_direction
                    )
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting trend analytics: {e}")
            return {}
    
    # Helper methods
    def _empty_threat_analytics(self) -> Dict[str, Any]:
        """Return empty threat analytics structure"""
        return {
            "total_detections": 0,
            "phishing_detections": 0,
            "phishing_rate": 0.0,
            "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "average_confidence": 0.0,
            "average_threat_score": 0.0,
            "average_processing_time_ms": 0.0,
            "top_threat_indicators": [],
            "model_performance": {
                "ensemble_detections": 0,
                "rule_based_detections": 0,
                "neural_detections": 0
            }
        }
    
    def _empty_email_analytics(self) -> Dict[str, Any]:
        """Return empty email analytics structure"""
        return {
            "total_emails": 0,
            "average_email_size_bytes": 0.0,
            "detection_rate": 0.0,
            "verified_phishing_count": 0,
            "potential_false_positives": 0,
            "top_sender_domains": [],
            "content_type_distribution": {},
            "volume_by_hour": [],
            "language_detection": {}
        }
    
    def _empty_incident_analytics(self) -> Dict[str, Any]:
        """Return empty incident analytics structure"""
        return {
            "total_incidents": 0,
            "status_distribution": {},
            "severity_distribution": {},
            "average_resolution_time_hours": 0.0,
            "median_resolution_time_hours": 0.0,
            "escalation_rate": 0.0,
            "average_response_time_minutes": 0.0,
            "incident_type_distribution": {},
            "sla_compliance": {},
            "workload_distribution": {}
        }
    
    def _empty_threat_intel_analytics(self) -> Dict[str, Any]:
        """Return empty threat intelligence analytics structure"""
        return {
            "total_indicators": 0,
            "active_indicators": 0,
            "expired_indicators": 0,
            "high_risk_indicators": 0,
            "ioc_type_distribution": {},
            "threat_type_distribution": {},
            "source_distribution": {},
            "average_confidence": 0.0,
            "average_reputation_score": 0.0,
            "feed_health": {},
            "coverage_analysis": {}
        }
    
    def _empty_performance_analytics(self) -> Dict[str, Any]:
        """Return empty performance analytics structure"""
        return {
            "total_workflows": 0,
            "average_execution_time_ms": 0.0,
            "success_rate": 0.0,
            "error_rate": 0.0,
            "throughput_per_hour": 0.0,
            "workflow_performance": {},
            "resource_utilization": {},
            "api_performance": {}
        }
    
    async def _get_email_volume_by_hour(self, emails: List) -> List[Dict[str, Any]]:
        """Calculate email volume by hour"""
        try:
            hourly_counts = defaultdict(int)
            for email in emails:
                if email.received_at:
                    hour_key = email.received_at.replace(minute=0, second=0, microsecond=0)
                    hourly_counts[hour_key] += 1
            
            return [
                {"timestamp": hour.isoformat(), "count": count}
                for hour, count in sorted(hourly_counts.items())
            ]
        except Exception as e:
            logger.error(f"Error calculating email volume by hour: {e}")
            return []
    
    async def _analyze_email_languages(self, emails: List) -> Dict[str, int]:
        """Analyze email languages (simplified)"""
        try:
            # Simplified language detection - could integrate with actual language detection
            languages = defaultdict(int)
            for email in emails:
                # Simple heuristic - could be replaced with proper language detection
                if email.content and len(email.content) > 100:
                    # For now, assume English - could add proper language detection
                    languages["en"] += 1
                else:
                    languages["unknown"] += 1
            
            return dict(languages)
        except Exception as e:
            logger.error(f"Error analyzing email languages: {e}")
            return {}
    
    async def _calculate_sla_compliance(self, incidents: List) -> Dict[str, Any]:
        """Calculate SLA compliance metrics"""
        try:
            # Define SLA targets (in hours)
            sla_targets = {
                "critical": 1,  # 1 hour
                "high": 4,      # 4 hours
                "medium": 24,   # 24 hours
                "low": 72       # 72 hours
            }
            
            compliance_stats = {}
            for severity, target_hours in sla_targets.items():
                severity_incidents = [i for i in incidents if i.severity == severity and i.resolved_at]
                
                if not severity_incidents:
                    compliance_stats[severity] = {"compliance_rate": 1.0, "count": 0}
                    continue
                
                within_sla = 0
                for incident in severity_incidents:
                    if incident.resolved_at and incident.created_at:
                        resolution_hours = (incident.resolved_at - incident.created_at).total_seconds() / 3600
                        if resolution_hours <= target_hours:
                            within_sla += 1
                
                compliance_rate = within_sla / len(severity_incidents)
                compliance_stats[severity] = {
                    "compliance_rate": round(compliance_rate, 3),
                    "count": len(severity_incidents),
                    "within_sla": within_sla
                }
            
            return compliance_stats
        except Exception as e:
            logger.error(f"Error calculating SLA compliance: {e}")
            return {}
    
    async def _analyze_incident_workload(self, incidents: List) -> Dict[str, Any]:
        """Analyze incident workload distribution"""
        try:
            # Analyze by assigned analyst
            analyst_workload = defaultdict(int)
            for incident in incidents:
                analyst = incident.assigned_to or "unassigned"
                analyst_workload[analyst] += 1
            
            # Analyze by time of day
            hourly_distribution = defaultdict(int)
            for incident in incidents:
                if incident.created_at:
                    hour = incident.created_at.hour
                    hourly_distribution[hour] += 1
            
            return {
                "analyst_distribution": dict(analyst_workload),
                "hourly_distribution": dict(hourly_distribution),
                "peak_hours": sorted(hourly_distribution.items(), key=lambda x: x[1], reverse=True)[:3]
            }
        except Exception as e:
            logger.error(f"Error analyzing incident workload: {e}")
            return {}
    
    async def _analyze_feed_health(self, intel_items: List) -> Dict[str, Any]:
        """Analyze threat intelligence feed health"""
        try:
            current_time = datetime.utcnow()
            
            # Group by source
            source_stats = defaultdict(lambda: {"count": 0, "recent_updates": 0, "avg_age_hours": 0})
            
            for item in intel_items:
                source = item.source or "unknown"
                source_stats[source]["count"] += 1
                
                # Check if updated in last 24 hours
                if item.last_updated and (current_time - item.last_updated).total_seconds() < 86400:
                    source_stats[source]["recent_updates"] += 1
                
                # Calculate average age
                if item.last_updated:
                    age_hours = (current_time - item.last_updated).total_seconds() / 3600
                    source_stats[source]["avg_age_hours"] += age_hours
            
            # Calculate averages
            for source, stats in source_stats.items():
                if stats["count"] > 0:
                    stats["avg_age_hours"] = round(stats["avg_age_hours"] / stats["count"], 2)
                    stats["freshness_score"] = max(0, 100 - (stats["avg_age_hours"] / 24 * 10))
            
            return dict(source_stats)
        except Exception as e:
            logger.error(f"Error analyzing feed health: {e}")
            return {}
    
    async def _analyze_threat_coverage(self, intel_items: List) -> Dict[str, Any]:
        """Analyze threat intelligence coverage"""
        try:
            coverage_stats = {
                "geographic_coverage": defaultdict(int),
                "threat_actor_coverage": defaultdict(int),
                "attack_vector_coverage": defaultdict(int)
            }
            
            for item in intel_items:
                # Analyze metadata for coverage insights
                if hasattr(item, 'metadata') and item.metadata:
                    metadata = item.metadata
                    
                    # Geographic coverage
                    if 'country' in metadata:
                        coverage_stats["geographic_coverage"][metadata['country']] += 1
                    
                    # Threat actor coverage
                    if 'threat_actor' in metadata:
                        coverage_stats["threat_actor_coverage"][metadata['threat_actor']] += 1
                    
                    # Attack vector coverage
                    if 'attack_vector' in metadata:
                        coverage_stats["attack_vector_coverage"][metadata['attack_vector']] += 1
            
            return {
                "geographic_coverage": dict(coverage_stats["geographic_coverage"]),
                "threat_actor_coverage": dict(coverage_stats["threat_actor_coverage"]),
                "attack_vector_coverage": dict(coverage_stats["attack_vector_coverage"])
            }
        except Exception as e:
            logger.error(f"Error analyzing threat coverage: {e}")
            return {}
    
    async def _get_resource_utilization(self) -> Dict[str, float]:
        """Get system resource utilization (mock data)"""
        # In a real implementation, this would query system metrics
        return {
            "cpu_usage": 25.5,
            "memory_usage": 68.2,
            "disk_usage": 45.8,
            "network_io": 15.3
        }
    
    async def _get_api_performance_metrics(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get API performance metrics (mock data)"""
        # In a real implementation, this would query API logs/metrics
        return {
            "average_response_time_ms": 145.2,
            "requests_per_second": 23.8,
            "error_rate": 0.012,
            "top_endpoints": [
                {"endpoint": "/api/v1/analyze/email", "avg_response_time": 180.5, "request_count": 1250},
                {"endpoint": "/api/v1/threat-intel", "avg_response_time": 95.2, "request_count": 890},
                {"endpoint": "/api/v1/incidents", "avg_response_time": 120.8, "request_count": 650}
            ]
        }
    
    def _generate_time_buckets(self, start_time: datetime, end_time: datetime, granularity: str) -> List[datetime]:
        """Generate time buckets for trend analysis"""
        buckets = []
        current = start_time
        
        if granularity == "hour":
            delta = timedelta(hours=1)
        elif granularity == "day":
            delta = timedelta(days=1)
        elif granularity == "week":
            delta = timedelta(weeks=1)
        else:
            delta = timedelta(hours=1)
        
        while current <= end_time:
            buckets.append(current)
            current += delta
        
        return buckets
    
    async def _get_threat_trends(self, time_buckets: List[datetime]) -> List[Dict[str, Any]]:
        """Get threat trend data for time buckets"""
        try:
            trend_data = []
            for bucket in time_buckets:
                next_bucket = bucket + timedelta(hours=1)  # Assuming hourly buckets
                
                # Count threats in this time bucket
                threat_count = await Detection.count_documents({
                    "created_at": {"$gte": bucket, "$lt": next_bucket},
                    "is_phishing": True
                })
                
                trend_data.append({
                    "timestamp": bucket.isoformat(),
                    "value": threat_count
                })
            
            return trend_data
        except Exception as e:
            logger.error(f"Error getting threat trends: {e}")
            return []
    
    async def _get_email_trends(self, time_buckets: List[datetime]) -> List[Dict[str, Any]]:
        """Get email trend data for time buckets"""
        try:
            trend_data = []
            for bucket in time_buckets:
                next_bucket = bucket + timedelta(hours=1)
                
                email_count = await Email.count_documents({
                    "received_at": {"$gte": bucket, "$lt": next_bucket}
                })
                
                trend_data.append({
                    "timestamp": bucket.isoformat(),
                    "value": email_count
                })
            
            return trend_data
        except Exception as e:
            logger.error(f"Error getting email trends: {e}")
            return []
    
    async def _get_incident_trends(self, time_buckets: List[datetime]) -> List[Dict[str, Any]]:
        """Get incident trend data for time buckets"""
        try:
            trend_data = []
            for bucket in time_buckets:
                next_bucket = bucket + timedelta(hours=1)
                
                incident_count = await Incident.count_documents({
                    "created_at": {"$gte": bucket, "$lt": next_bucket}
                })
                
                trend_data.append({
                    "timestamp": bucket.isoformat(),
                    "value": incident_count
                })
            
            return trend_data
        except Exception as e:
            logger.error(f"Error getting incident trends: {e}")
            return []
    
    def _calculate_trend_direction(self, trend_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate trend direction and percentage change"""
        if len(trend_data) < 2:
            return {"direction": "stable", "change_percentage": 0.0}
        
        values = [point["value"] for point in trend_data]
        
        # Simple linear trend calculation
        first_half = values[:len(values)//2]
        second_half = values[len(values)//2:]
        
        first_avg = statistics.mean(first_half) if first_half else 0
        second_avg = statistics.mean(second_half) if second_half else 0
        
        if first_avg == 0:
            change_percentage = 0.0
        else:
            change_percentage = ((second_avg - first_avg) / first_avg) * 100
        
        if change_percentage > 5:
            direction = "increasing"
        elif change_percentage < -5:
            direction = "decreasing"
        else:
            direction = "stable"
        
        return {
            "direction": direction,
            "change_percentage": round(change_percentage, 2)
        }
    
    async def _generate_simple_forecast(self, trend_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate simple forecast based on trend data"""
        if len(trend_data) < 3:
            return []
        
        values = [point["value"] for point in trend_data]
        
        # Simple moving average forecast
        window_size = min(3, len(values))
        recent_avg = statistics.mean(values[-window_size:])
        
        # Generate 3 forecast points
        forecast = []
        last_timestamp = datetime.fromisoformat(trend_data[-1]["timestamp"].replace("Z", "+00:00"))
        
        for i in range(1, 4):
            forecast_time = last_timestamp + timedelta(hours=i)
            # Simple forecast - could be improved with better algorithms
            forecast_value = max(0, int(recent_avg * (0.9 + 0.2 * (i / 3))))
            
            forecast.append({
                "timestamp": forecast_time.isoformat(),
                "predicted_value": forecast_value,
                "confidence": max(0.5, 0.9 - (i * 0.15))
            })
        
        return forecast
    
    def _calculate_overall_trend(self, threat_trend: Dict, email_trend: Dict, incident_trend: Dict) -> str:
        """Calculate overall security trend"""
        trends = [threat_trend["direction"], email_trend["direction"], incident_trend["direction"]]
        
        increasing_count = trends.count("increasing")
        decreasing_count = trends.count("decreasing")
        
        if increasing_count >= 2:
            return "deteriorating"
        elif decreasing_count >= 2:
            return "improving"
        else:
            return "stable"
    
    def _assess_trend_risk(self, threat_trend: Dict, email_trend: Dict, incident_trend: Dict) -> str:
        """Assess overall risk level based on trends"""
        threat_change = abs(threat_trend.get("change_percentage", 0))
        email_change = abs(email_trend.get("change_percentage", 0))
        incident_change = abs(incident_trend.get("change_percentage", 0))
        
        max_change = max(threat_change, email_change, incident_change)
        
        if max_change > 50:
            return "high"
        elif max_change > 25:
            return "medium"
        else:
            return "low"


# Global instance
analytics_service = AnalyticsService()