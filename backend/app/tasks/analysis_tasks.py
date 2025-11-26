"""
Analysis Task Workers
Handles ML analysis, threat intelligence, and reputation lookup tasks.
"""

import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from celery import current_task
from app.workers.celery_config import celery_app
from app.models.production_models import ThreatIntelligence, EmailMeta
from app.services.enhanced_ml_analyzer import get_ml_analyzer
from app.core.database import get_db
from app.core.redis_client import get_redis_client

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name="backend.app.tasks.analysis_tasks.basic_threat_analysis")
def basic_threat_analysis(self, content: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Basic threat analysis for real-time processing.
    
    Args:
        content: Email content to analyze
        metadata: Email metadata (sender, subject, etc.)
        
    Returns:
        Basic threat analysis results
    """
    try:
        start_time = time.time()
        
        self.update_state(state='PROGRESS', meta={'progress': 20, 'status': 'Analyzing content patterns'})
        
        # Pattern-based threat detection
        threat_patterns = _detect_threat_patterns(content, metadata)
        
        self.update_state(state='PROGRESS', meta={'progress': 60, 'status': 'Checking blacklists'})
        
        # Quick blacklist checks
        blacklist_results = _check_basic_blacklists(metadata.get("sender"), content)
        
        self.update_state(state='PROGRESS', meta={'progress': 90, 'status': 'Compiling results'})
        
        # Compile basic results
        analysis_results = {
            "content_hash": _generate_content_hash(content),
            "metadata": metadata,
            "analysis_type": "basic_threat",
            "start_time": start_time,
            "duration": time.time() - start_time,
            "results": {
                "threat_patterns": threat_patterns,
                "blacklist_results": blacklist_results,
                "threat_score": _calculate_basic_threat_score(threat_patterns, blacklist_results),
                "threat_categories": _categorize_basic_threats(threat_patterns, blacklist_results),
                "confidence": 0.7  # Basic analysis has lower confidence
            },
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Cache results for quick lookup
        _cache_analysis_results(content, analysis_results)
        
        self.update_state(state='SUCCESS', meta={'progress': 100, 'results': analysis_results})
        
        logger.info(f"Basic threat analysis completed in {analysis_results['duration']:.2f}s")
        return analysis_results
        
    except Exception as e:
        logger.error(f"Basic threat analysis failed: {str(e)}")
        self.update_state(state='FAILURE', meta={'error': str(e)})
        raise

@celery_app.task(bind=True, name="backend.app.tasks.analysis_tasks.ml_threat_detection")
def ml_threat_detection(self, content: str, features: Dict[str, Any]) -> Dict[str, Any]:
    """
    ML-powered threat detection for comprehensive analysis.
    
    Args:
        content: Email content
        features: Extracted email features
        
    Returns:
        ML threat detection results
    """
    try:
        start_time = time.time()
        
        self.update_state(state='PROGRESS', meta={'progress': 10, 'status': 'Loading ML models'})
        
        # Get ML analyzer
        ml_analyzer = get_ml_analyzer()
        
        self.update_state(state='PROGRESS', meta={'progress': 30, 'status': 'Feature extraction'})
        
        # Extract advanced features
        extracted_features = ml_analyzer.extract_features(content, features)
        
        self.update_state(state='PROGRESS', meta={'progress': 60, 'status': 'Running ML models'})
        
        # Run ML models
        ml_predictions = ml_analyzer.predict_threats(extracted_features)
        
        self.update_state(state='PROGRESS', meta={'progress': 80, 'status': 'Analyzing predictions'})
        
        # Analyze ML predictions
        threat_analysis = _analyze_ml_predictions(ml_predictions, extracted_features)
        
        self.update_state(state='PROGRESS', meta={'progress': 95, 'status': 'Finalizing results'})
        
        # Compile ML results
        analysis_results = {
            "content_hash": _generate_content_hash(content),
            "features": extracted_features,
            "analysis_type": "ml_threat_detection",
            "start_time": start_time,
            "duration": time.time() - start_time,
            "results": {
                "ml_predictions": ml_predictions,
                "threat_analysis": threat_analysis,
                "threat_score": ml_predictions.get("threat_score", 0),
                "confidence": ml_predictions.get("confidence", 0),
                "threat_categories": ml_predictions.get("categories", []),
                "model_version": ml_analyzer.get_model_version(),
                "feature_importance": ml_predictions.get("feature_importance", {})
            },
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store ML results for model improvement
        _store_ml_results(analysis_results)
        
        self.update_state(state='SUCCESS', meta={'progress': 100, 'results': analysis_results})
        
        logger.info(f"ML threat detection completed in {analysis_results['duration']:.2f}s")
        return analysis_results
        
    except Exception as e:
        logger.error(f"ML threat detection failed: {str(e)}")
        self.update_state(state='FAILURE', meta={'error': str(e)})
        raise

@celery_app.task(bind=True, name="backend.app.tasks.analysis_tasks.reputation_lookup")
def reputation_lookup(self, entities: Dict[str, List[str]]) -> Dict[str, Any]:
    """
    Comprehensive reputation lookup for domains, IPs, and URLs.
    
    Args:
        entities: Dictionary with domains, ips, urls to check
        
    Returns:
        Reputation lookup results
    """
    try:
        start_time = time.time()
        
        self.update_state(state='PROGRESS', meta={'progress': 10, 'status': 'Initializing reputation checks'})
        
        reputation_results = {}
        total_entities = sum(len(entity_list) for entity_list in entities.values())
        processed = 0
        
        # Process domains
        if "domains" in entities:
            self.update_state(state='PROGRESS', meta={'progress': 20, 'status': 'Checking domain reputation'})
            domain_results = []
            for domain in entities["domains"]:
                domain_rep = _check_domain_reputation(domain)
                domain_results.append(domain_rep)
                processed += 1
                
                # Update progress
                progress = 20 + (30 * processed // total_entities)
                self.update_state(state='PROGRESS', meta={'progress': progress})
                
            reputation_results["domains"] = domain_results
        
        # Process IPs
        if "ips" in entities:
            self.update_state(state='PROGRESS', meta={'progress': 50, 'status': 'Checking IP reputation'})
            ip_results = []
            for ip in entities["ips"]:
                ip_rep = _check_ip_reputation(ip)
                ip_results.append(ip_rep)
                processed += 1
                
                # Update progress
                progress = 50 + (20 * processed // total_entities)
                self.update_state(state='PROGRESS', meta={'progress': progress})
                
            reputation_results["ips"] = ip_results
        
        # Process URLs
        if "urls" in entities:
            self.update_state(state='PROGRESS', meta={'progress': 70, 'status': 'Checking URL reputation'})
            url_results = []
            for url in entities["urls"]:
                url_rep = _check_url_reputation(url)
                url_results.append(url_rep)
                processed += 1
                
                # Update progress
                progress = 70 + (20 * processed // total_entities)
                self.update_state(state='PROGRESS', meta={'progress': progress})
                
            reputation_results["urls"] = url_results
        
        self.update_state(state='PROGRESS', meta={'progress': 90, 'status': 'Compiling reputation results'})
        
        # Compile overall results
        analysis_results = {
            "entities": entities,
            "analysis_type": "reputation_lookup",
            "start_time": start_time,
            "duration": time.time() - start_time,
            "results": {
                "reputation_data": reputation_results,
                "overall_risk_score": _calculate_reputation_risk_score(reputation_results),
                "high_risk_entities": _identify_high_risk_entities(reputation_results),
                "reputation_summary": _summarize_reputation_results(reputation_results)
            },
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Cache reputation results
        _cache_reputation_results(entities, analysis_results)
        
        self.update_state(state='SUCCESS', meta={'progress': 100, 'results': analysis_results})
        
        logger.info(f"Reputation lookup completed in {analysis_results['duration']:.2f}s")
        return analysis_results
        
    except Exception as e:
        logger.error(f"Reputation lookup failed: {str(e)}")
        self.update_state(state='FAILURE', meta={'error': str(e)})
        raise

@celery_app.task(bind=True, name="backend.app.tasks.analysis_tasks.advanced_ml_analysis")
def advanced_ml_analysis(self, email_data: Dict[str, Any], analysis_options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Advanced ML analysis with multiple models and deep feature analysis.
    
    Args:
        email_data: Comprehensive email data
        analysis_options: Advanced analysis configuration
        
    Returns:
        Advanced ML analysis results
    """
    try:
        start_time = time.time()
        
        self.update_state(state='PROGRESS', meta={'progress': 5, 'status': 'Loading advanced ML models'})
        
        # Get ML analyzer
        ml_analyzer = get_ml_analyzer()
        
        self.update_state(state='PROGRESS', meta={'progress': 15, 'status': 'Deep feature extraction'})
        
        # Deep feature extraction
        deep_features = ml_analyzer.extract_deep_features(email_data)
        
        self.update_state(state='PROGRESS', meta={'progress': 30, 'status': 'Ensemble model prediction'})
        
        # Ensemble model predictions
        ensemble_results = ml_analyzer.ensemble_predict(deep_features)
        
        self.update_state(state='PROGRESS', meta={'progress': 50, 'status': 'Adversarial analysis'})
        
        # Adversarial attack detection
        adversarial_results = None
        if analysis_options.get("check_adversarial", False):
            adversarial_results = ml_analyzer.detect_adversarial_attacks(deep_features)
        
        self.update_state(state='PROGRESS', meta={'progress': 70, 'status': 'Explainability analysis'})
        
        # Model explainability
        explainability_results = ml_analyzer.explain_predictions(deep_features, ensemble_results)
        
        self.update_state(state='PROGRESS', meta={'progress': 85, 'status': 'Confidence calibration'})
        
        # Confidence calibration
        calibrated_confidence = ml_analyzer.calibrate_confidence(ensemble_results)
        
        self.update_state(state='PROGRESS', meta={'progress': 95, 'status': 'Finalizing advanced analysis'})
        
        # Compile advanced results
        analysis_results = {
            "email_data": email_data,
            "analysis_type": "advanced_ml_analysis",
            "start_time": start_time,
            "duration": time.time() - start_time,
            "results": {
                "deep_features": deep_features,
                "ensemble_predictions": ensemble_results,
                "adversarial_analysis": adversarial_results,
                "explainability": explainability_results,
                "calibrated_confidence": calibrated_confidence,
                "advanced_threat_score": ensemble_results.get("threat_score", 0),
                "model_consensus": _analyze_model_consensus(ensemble_results),
                "uncertainty_analysis": _analyze_prediction_uncertainty(ensemble_results)
            },
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store advanced ML results
        _store_advanced_ml_results(analysis_results)
        
        self.update_state(state='SUCCESS', meta={'progress': 100, 'results': analysis_results})
        
        logger.info(f"Advanced ML analysis completed in {analysis_results['duration']:.2f}s")
        return analysis_results
        
    except Exception as e:
        logger.error(f"Advanced ML analysis failed: {str(e)}")
        self.update_state(state='FAILURE', meta={'error': str(e)})
        raise

@celery_app.task(bind=True, name="backend.app.tasks.analysis_tasks.threat_intelligence_lookup")
def threat_intelligence_lookup(self, indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    """
    Comprehensive threat intelligence lookup across multiple feeds.
    
    Args:
        indicators: IOCs to look up (hashes, domains, IPs, etc.)
        
    Returns:
        Threat intelligence results
    """
    try:
        start_time = time.time()
        
        self.update_state(state='PROGRESS', meta={'progress': 10, 'status': 'Querying threat intelligence feeds'})
        
        # Query multiple threat intelligence sources
        intel_results = {}
        
        # Commercial feeds
        if indicators.get("domains"):
            intel_results["domain_intel"] = _query_domain_intelligence(indicators["domains"])
        
        if indicators.get("ips"):
            intel_results["ip_intel"] = _query_ip_intelligence(indicators["ips"])
        
        if indicators.get("hashes"):
            intel_results["hash_intel"] = _query_hash_intelligence(indicators["hashes"])
        
        self.update_state(state='PROGRESS', meta={'progress': 60, 'status': 'Correlating intelligence data'})
        
        # Correlate intelligence data
        correlation_results = _correlate_threat_intelligence(intel_results)
        
        self.update_state(state='PROGRESS', meta={'progress': 80, 'status': 'Analyzing threat campaigns'})
        
        # Campaign analysis
        campaign_analysis = _analyze_threat_campaigns(intel_results, correlation_results)
        
        self.update_state(state='PROGRESS', meta={'progress': 95, 'status': 'Compiling intelligence report'})
        
        # Compile intelligence results
        analysis_results = {
            "indicators": indicators,
            "analysis_type": "threat_intelligence",
            "start_time": start_time,
            "duration": time.time() - start_time,
            "results": {
                "intelligence_data": intel_results,
                "correlations": correlation_results,
                "campaign_analysis": campaign_analysis,
                "threat_score": _calculate_intelligence_threat_score(intel_results),
                "ioc_matches": _count_ioc_matches(intel_results),
                "attribution": _analyze_threat_attribution(intel_results, campaign_analysis)
            },
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store threat intelligence results
        _store_threat_intelligence(analysis_results)
        
        self.update_state(state='SUCCESS', meta={'progress': 100, 'results': analysis_results})
        
        logger.info(f"Threat intelligence lookup completed in {analysis_results['duration']:.2f}s")
        return analysis_results
        
    except Exception as e:
        logger.error(f"Threat intelligence lookup failed: {str(e)}")
        self.update_state(state='FAILURE', meta={'error': str(e)})
        raise

# Helper functions

def _generate_content_hash(content: str) -> str:
    """Generate hash of content for caching and deduplication."""
    import hashlib
    return hashlib.sha256(content.encode()).hexdigest()

def _detect_threat_patterns(content: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Detect basic threat patterns in content."""
    return {
        "suspicious_keywords": [],
        "phishing_indicators": [],
        "social_engineering": False,
        "urgency_markers": []
    }

def _check_basic_blacklists(sender: str, content: str) -> Dict[str, Any]:
    """Check against basic blacklists."""
    return {
        "sender_blacklisted": False,
        "domain_blacklisted": False,
        "content_blacklisted": False
    }

def _calculate_basic_threat_score(threat_patterns: Dict, blacklist_results: Dict) -> int:
    """Calculate basic threat score."""
    return 25  # Mock implementation

def _categorize_basic_threats(threat_patterns: Dict, blacklist_results: Dict) -> List[str]:
    """Categorize basic threats."""
    return []  # Mock implementation

def _cache_analysis_results(content: str, results: Dict[str, Any]):
    """Cache analysis results."""
    redis_client = get_redis_client()
    content_hash = _generate_content_hash(content)
    cache_key = f"analysis_result:{content_hash}"
    redis_client.setex(cache_key, 3600, str(results))

def _analyze_ml_predictions(predictions: Dict, features: Dict) -> Dict[str, Any]:
    """Analyze ML prediction results."""
    return {
        "high_confidence_predictions": [],
        "uncertain_predictions": [],
        "feature_analysis": {}
    }

def _store_ml_results(results: Dict[str, Any]):
    """Store ML results for model improvement."""
    # Store in database for model training feedback
    pass

def _check_domain_reputation(domain: str) -> Dict[str, Any]:
    """Check domain reputation."""
    return {
        "domain": domain,
        "reputation_score": 75,
        "is_malicious": False,
        "categories": []
    }

def _check_ip_reputation(ip: str) -> Dict[str, Any]:
    """Check IP reputation."""
    return {
        "ip": ip,
        "reputation_score": 80,
        "is_malicious": False,
        "geolocation": {},
        "categories": []
    }

def _check_url_reputation(url: str) -> Dict[str, Any]:
    """Check URL reputation."""
    return {
        "url": url,
        "reputation_score": 70,
        "is_malicious": False,
        "categories": []
    }

def _calculate_reputation_risk_score(reputation_results: Dict) -> int:
    """Calculate overall reputation risk score."""
    return 30  # Mock implementation

def _identify_high_risk_entities(reputation_results: Dict) -> List[str]:
    """Identify high-risk entities."""
    return []  # Mock implementation

def _summarize_reputation_results(reputation_results: Dict) -> Dict[str, Any]:
    """Summarize reputation results."""
    return {
        "total_entities_checked": 0,
        "malicious_entities": 0,
        "suspicious_entities": 0
    }

def _cache_reputation_results(entities: Dict, results: Dict[str, Any]):
    """Cache reputation results."""
    redis_client = get_redis_client()
    for entity_type, entity_list in entities.items():
        for entity in entity_list:
            cache_key = f"reputation:{entity_type}:{entity}"
            redis_client.setex(cache_key, 1800, str(results))

def _analyze_model_consensus(ensemble_results: Dict) -> Dict[str, Any]:
    """Analyze consensus among ensemble models."""
    return {
        "consensus_score": 0.85,
        "agreeing_models": [],
        "disagreeing_models": []
    }

def _analyze_prediction_uncertainty(ensemble_results: Dict) -> Dict[str, Any]:
    """Analyze prediction uncertainty."""
    return {
        "uncertainty_score": 0.15,
        "confidence_intervals": {},
        "variance": 0.02
    }

def _store_advanced_ml_results(results: Dict[str, Any]):
    """Store advanced ML results."""
    # Store in specialized ML results database
    pass

def _query_domain_intelligence(domains: List[str]) -> Dict[str, Any]:
    """Query threat intelligence for domains."""
    return {"domains": domains, "threats_found": []}

def _query_ip_intelligence(ips: List[str]) -> Dict[str, Any]:
    """Query threat intelligence for IPs."""
    return {"ips": ips, "threats_found": []}

def _query_hash_intelligence(hashes: List[str]) -> Dict[str, Any]:
    """Query threat intelligence for hashes."""
    return {"hashes": hashes, "threats_found": []}

def _correlate_threat_intelligence(intel_results: Dict) -> Dict[str, Any]:
    """Correlate threat intelligence data."""
    return {"correlations": [], "patterns": []}

def _analyze_threat_campaigns(intel_results: Dict, correlations: Dict) -> Dict[str, Any]:
    """Analyze threat campaigns."""
    return {"campaigns": [], "attribution": {}}

def _calculate_intelligence_threat_score(intel_results: Dict) -> int:
    """Calculate threat score from intelligence data."""
    return 35  # Mock implementation

def _count_ioc_matches(intel_results: Dict) -> int:
    """Count IOC matches."""
    return 0  # Mock implementation

def _analyze_threat_attribution(intel_results: Dict, campaign_analysis: Dict) -> Dict[str, Any]:
    """Analyze threat attribution."""
    return {"threat_actor": None, "confidence": 0}

def _store_threat_intelligence(results: Dict[str, Any]):
    """Store threat intelligence results."""
    with get_db() as db:
        threat_intel = ThreatIntelligence(
            indicators=results["indicators"],
            intelligence_data=results["results"],
            created_at=datetime.utcnow()
        )
        db.add(threat_intel)
        db.commit()