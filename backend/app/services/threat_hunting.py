"""
Threat Hunting System for PhishNet
Mini-SIEM functionality with advanced pattern searching and analysis
"""

import re
import json
import time
from typing import Dict, Any, List, Optional, Union, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import asyncio

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, text
from fastapi import APIRouter, Depends, Query, HTTPException, status

from app.core.database import get_db
from app.core.security import get_current_user, require_permission, Permission
from app.core.redis_client import get_cache_manager
from app.models.analysis.detection import Detection
from app.models.core.email import Email
from app.config.logging import get_logger

logger = get_logger(__name__)

class SearchType(str, Enum):
    REGEX = "regex"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    EMAIL_ADDRESS = "email_address"
    KEYWORD = "keyword"
    HASH = "hash"
    URL = "url"
    PATTERN = "pattern"

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SearchQuery:
    """Threat hunting search query structure"""
    query: str
    search_type: SearchType
    case_sensitive: bool = False
    time_range_hours: int = 24
    limit: int = 100
    include_benign: bool = False
    fields: List[str] = field(default_factory=lambda: ["content", "sender", "subject"])

@dataclass
class ThreatIndicator:
    """Threat indicator found during hunting"""
    type: str
    value: str
    confidence: float
    threat_level: ThreatLevel
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    related_emails: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class HuntingResult:
    """Result of threat hunting operation"""
    query: SearchQuery
    total_matches: int
    processing_time_ms: float
    matches: List[Dict[str, Any]]
    indicators: List[ThreatIndicator]
    patterns: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    suggestions: List[str]

class ThreatHuntingEngine:
    """Advanced threat hunting engine with SIEM-like capabilities"""
    
    def __init__(self):
        self.cache_manager = get_cache_manager()
        self.search_cache_ttl = 3600  # 1 hour
        
        # Pre-compiled regex patterns for common threats
        self.threat_patterns = {
            "suspicious_urls": re.compile(r'https?://[^\s]+(?:\.tk|\.ml|\.ga|\.cf|bit\.ly|tinyurl|t\.co)', re.IGNORECASE),
            "crypto_addresses": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b'),
            "credit_cards": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
            "ip_addresses": re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            "email_addresses": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "base64_encoded": re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            "phone_numbers": re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
            "urgent_keywords": re.compile(r'\b(?:urgent|immediate|action required|verify|suspend|expire|deadline|click here|act now)\b', re.IGNORECASE)
        }
        
        # Known malicious indicators (would be populated from threat intelligence)
        self.malicious_indicators = {
            "domains": set(),
            "ips": set(),
            "hashes": set(),
            "emails": set()
        }
    
    async def hunt(self, search_query: SearchQuery, db: Session) -> HuntingResult:
        """Execute threat hunting search"""
        start_time = time.time()
        
        try:
            # Check cache first
            cache_key = self._generate_cache_key(search_query)
            cached_result = await self.cache_manager.get(cache_key)
            
            if cached_result:
                logger.info(f"Threat hunt cache hit", query=search_query.query)
                return HuntingResult(**cached_result)
            
            # Execute search based on type
            if search_query.search_type == SearchType.REGEX:
                matches = await self._regex_search(search_query, db)
            elif search_query.search_type == SearchType.DOMAIN:
                matches = await self._domain_search(search_query, db)
            elif search_query.search_type == SearchType.IP_ADDRESS:
                matches = await self._ip_search(search_query, db)
            elif search_query.search_type == SearchType.EMAIL_ADDRESS:
                matches = await self._email_search(search_query, db)
            elif search_query.search_type == SearchType.KEYWORD:
                matches = await self._keyword_search(search_query, db)
            elif search_query.search_type == SearchType.URL:
                matches = await self._url_search(search_query, db)
            elif search_query.search_type == SearchType.PATTERN:
                matches = await self._pattern_search(search_query, db)
            else:
                matches = await self._generic_search(search_query, db)
            
            # Extract threat indicators
            indicators = await self._extract_indicators(matches)
            
            # Analyze patterns
            patterns = await self._analyze_patterns(matches)
            
            # Create timeline
            timeline = self._create_timeline(matches)
            
            # Generate suggestions
            suggestions = await self._generate_suggestions(search_query, matches, indicators)
            
            processing_time = (time.time() - start_time) * 1000
            
            result = HuntingResult(
                query=search_query,
                total_matches=len(matches),
                processing_time_ms=processing_time,
                matches=matches,
                indicators=indicators,
                patterns=patterns,
                timeline=timeline,
                suggestions=suggestions
            )
            
            # Cache result
            await self.cache_manager.set(cache_key, result.__dict__, ttl=self.search_cache_ttl)
            
            logger.info(f"Threat hunt completed", 
                       query=search_query.query, 
                       matches=len(matches),
                       processing_time_ms=processing_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Threat hunting failed: {e}")
            raise
    
    async def _regex_search(self, query: SearchQuery, db: Session) -> List[Dict[str, Any]]:
        """Execute regex-based search across email content"""
        try:
            # Compile regex pattern
            flags = 0 if query.case_sensitive else re.IGNORECASE
            pattern = re.compile(query.query, flags)
            
            # Time range filter
            since_time = datetime.utcnow() - timedelta(hours=query.time_range_hours)
            
            # Query emails
            email_query = db.query(Email, Detection).join(
                Detection, Email.id == Detection.email_id
            ).filter(Email.created_at >= since_time)
            
            if not query.include_benign:
                email_query = email_query.filter(Detection.is_phishing == True)
            
            results = email_query.limit(query.limit * 2).all()  # Get more for filtering
            
            matches = []
            for email, detection in results:
                # Search in specified fields
                content_matches = []
                
                if "content" in query.fields and email.content:
                    content_matches.extend(self._find_regex_matches(pattern, email.content, "content"))
                
                if "sender" in query.fields and email.sender:
                    content_matches.extend(self._find_regex_matches(pattern, email.sender, "sender"))
                
                if "subject" in query.fields and email.subject:
                    content_matches.extend(self._find_regex_matches(pattern, email.subject, "subject"))
                
                if content_matches:
                    matches.append({
                        "email_id": email.id,
                        "detection_id": detection.id,
                        "sender": email.sender,
                        "subject": email.subject,
                        "created_at": email.created_at.isoformat(),
                        "is_phishing": detection.is_phishing,
                        "confidence_score": detection.confidence_score,
                        "risk_level": detection.risk_level,
                        "matches": content_matches,
                        "match_count": len(content_matches)
                    })
                
                if len(matches) >= query.limit:
                    break
            
            return matches
            
        except Exception as e:
            logger.error(f"Regex search failed: {e}")
            return []
    
    async def _domain_search(self, query: SearchQuery, db: Session) -> List[Dict[str, Any]]:
        """Search for specific domain across emails"""
        try:
            domain = query.query.lower().strip()
            since_time = datetime.utcnow() - timedelta(hours=query.time_range_hours)
            
            # Use SQL LIKE for domain matching
            search_pattern = f"%{domain}%"
            
            email_query = db.query(Email, Detection).join(
                Detection, Email.id == Detection.email_id
            ).filter(
                and_(
                    Email.created_at >= since_time,
                    or_(
                        Email.content.ilike(search_pattern),
                        Email.sender.ilike(search_pattern),
                        Email.subject.ilike(search_pattern)
                    )
                )
            )
            
            if not query.include_benign:
                email_query = email_query.filter(Detection.is_phishing == True)
            
            results = email_query.limit(query.limit).all()
            
            matches = []
            for email, detection in results:
                # Extract domain matches
                domain_matches = self._extract_domains_from_text(
                    f"{email.content or ''} {email.sender or ''} {email.subject or ''}"
                )
                
                # Filter for target domain
                relevant_domains = [d for d in domain_matches if domain in d.lower()]
                
                if relevant_domains:
                    matches.append({
                        "email_id": email.id,
                        "detection_id": detection.id,
                        "sender": email.sender,
                        "subject": email.subject,
                        "created_at": email.created_at.isoformat(),
                        "is_phishing": detection.is_phishing,
                        "confidence_score": detection.confidence_score,
                        "risk_level": detection.risk_level,
                        "domains_found": relevant_domains,
                        "total_domains": len(domain_matches)
                    })
            
            return matches
            
        except Exception as e:
            logger.error(f"Domain search failed: {e}")
            return []
    
    async def _ip_search(self, query: SearchQuery, db: Session) -> List[Dict[str, Any]]:
        """Search for IP addresses or IP ranges"""
        try:
            # Parse IP or CIDR range
            try:
                if "/" in query.query:
                    network = ipaddress.ip_network(query.query, strict=False)
                    search_ips = [str(ip) for ip in network][:100]  # Limit to 100 IPs
                else:
                    search_ips = [query.query]
            except ValueError:
                logger.error(f"Invalid IP address format: {query.query}")
                return []
            
            since_time = datetime.utcnow() - timedelta(hours=query.time_range_hours)
            
            matches = []
            for ip in search_ips:
                search_pattern = f"%{ip}%"
                
                email_query = db.query(Email, Detection).join(
                    Detection, Email.id == Detection.email_id
                ).filter(
                    and_(
                        Email.created_at >= since_time,
                        Email.content.ilike(search_pattern)
                    )
                )
                
                if not query.include_benign:
                    email_query = email_query.filter(Detection.is_phishing == True)
                
                results = email_query.limit(50).all()  # Limit per IP
                
                for email, detection in results:
                    # Extract IP addresses from content
                    found_ips = self.threat_patterns["ip_addresses"].findall(email.content or "")
                    
                    if ip in found_ips:
                        matches.append({
                            "email_id": email.id,
                            "detection_id": detection.id,
                            "sender": email.sender,
                            "subject": email.subject,
                            "created_at": email.created_at.isoformat(),
                            "is_phishing": detection.is_phishing,
                            "confidence_score": detection.confidence_score,
                            "risk_level": detection.risk_level,
                            "matched_ip": ip,
                            "all_ips_found": found_ips
                        })
                
                if len(matches) >= query.limit:
                    break
            
            return matches
            
        except Exception as e:
            logger.error(f"IP search failed: {e}")
            return []
    
    async def _pattern_search(self, query: SearchQuery, db: Session) -> List[Dict[str, Any]]:
        """Search using predefined threat patterns"""
        try:
            pattern_name = query.query.lower()
            
            if pattern_name not in self.threat_patterns:
                available_patterns = list(self.threat_patterns.keys())
                raise ValueError(f"Pattern '{pattern_name}' not found. Available: {available_patterns}")
            
            pattern = self.threat_patterns[pattern_name]
            since_time = datetime.utcnow() - timedelta(hours=query.time_range_hours)
            
            email_query = db.query(Email, Detection).join(
                Detection, Email.id == Detection.email_id
            ).filter(Email.created_at >= since_time)
            
            if not query.include_benign:
                email_query = email_query.filter(Detection.is_phishing == True)
            
            results = email_query.limit(query.limit * 2).all()
            
            matches = []
            for email, detection in results:
                content = f"{email.content or ''} {email.sender or ''} {email.subject or ''}"
                pattern_matches = pattern.findall(content)
                
                if pattern_matches:
                    matches.append({
                        "email_id": email.id,
                        "detection_id": detection.id,
                        "sender": email.sender,
                        "subject": email.subject,
                        "created_at": email.created_at.isoformat(),
                        "is_phishing": detection.is_phishing,
                        "confidence_score": detection.confidence_score,
                        "risk_level": detection.risk_level,
                        "pattern_type": pattern_name,
                        "matches": list(set(pattern_matches)),  # Remove duplicates
                        "match_count": len(pattern_matches)
                    })
                
                if len(matches) >= query.limit:
                    break
            
            return matches
            
        except Exception as e:
            logger.error(f"Pattern search failed: {e}")
            return []
    
    async def _extract_indicators(self, matches: List[Dict[str, Any]]) -> List[ThreatIndicator]:
        """Extract threat indicators from search results"""
        indicators = {}
        
        try:
            for match in matches:
                email_id = match["email_id"]
                created_at = datetime.fromisoformat(match["created_at"])
                
                # Extract various indicators based on match content
                content = f"{match.get('sender', '')} {match.get('subject', '')}"
                
                # Extract domains
                domains = self._extract_domains_from_text(content)
                for domain in domains:
                    if domain not in indicators:
                        indicators[domain] = ThreatIndicator(
                            type="domain",
                            value=domain,
                            confidence=0.7,
                            threat_level=ThreatLevel.MEDIUM,
                            first_seen=created_at,
                            last_seen=created_at,
                            occurrences=1,
                            related_emails=[email_id]
                        )
                    else:
                        indicators[domain].occurrences += 1
                        indicators[domain].last_seen = max(indicators[domain].last_seen, created_at)
                        indicators[domain].related_emails.append(email_id)
                
                # Extract IP addresses
                ips = self.threat_patterns["ip_addresses"].findall(content)
                for ip in ips:
                    if self._is_suspicious_ip(ip):
                        if ip not in indicators:
                            indicators[ip] = ThreatIndicator(
                                type="ip_address",
                                value=ip,
                                confidence=0.8,
                                threat_level=ThreatLevel.HIGH,
                                first_seen=created_at,
                                last_seen=created_at,
                                occurrences=1,
                                related_emails=[email_id]
                            )
                        else:
                            indicators[ip].occurrences += 1
                            indicators[ip].last_seen = max(indicators[ip].last_seen, created_at)
                            indicators[ip].related_emails.append(email_id)
            
            # Sort indicators by threat level and occurrences
            sorted_indicators = sorted(
                indicators.values(),
                key=lambda x: (x.threat_level.value, x.occurrences),
                reverse=True
            )
            
            return sorted_indicators[:50]  # Limit to top 50 indicators
            
        except Exception as e:
            logger.error(f"Failed to extract indicators: {e}")
            return []
    
    async def _analyze_patterns(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze patterns in search results"""
        try:
            patterns = []
            
            # Time-based patterns
            time_pattern = self._analyze_time_patterns(matches)
            if time_pattern:
                patterns.append(time_pattern)
            
            # Sender patterns
            sender_pattern = self._analyze_sender_patterns(matches)
            if sender_pattern:
                patterns.append(sender_pattern)
            
            # Content patterns
            content_pattern = self._analyze_content_patterns(matches)
            if content_pattern:
                patterns.append(content_pattern)
            
            return patterns
            
        except Exception as e:
            logger.error(f"Failed to analyze patterns: {e}")
            return []
    
    def _analyze_time_patterns(self, matches: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze temporal patterns in matches"""
        if len(matches) < 3:
            return None
        
        timestamps = [datetime.fromisoformat(m["created_at"]) for m in matches]
        timestamps.sort()
        
        # Check for clustering
        intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                    for i in range(len(timestamps)-1)]
        
        avg_interval = sum(intervals) / len(intervals)
        
        if avg_interval < 3600:  # Less than 1 hour average
            return {
                "type": "temporal_clustering",
                "description": "Emails clustered within short time periods",
                "avg_interval_minutes": round(avg_interval / 60, 2),
                "total_timespan_hours": round((timestamps[-1] - timestamps[0]).total_seconds() / 3600, 2),
                "significance": "high" if avg_interval < 300 else "medium"
            }
        
        return None
    
    def _analyze_sender_patterns(self, matches: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze sender patterns"""
        sender_counts = {}
        for match in matches:
            sender = match.get("sender", "unknown")
            sender_counts[sender] = sender_counts.get(sender, 0) + 1
        
        # Find repeated senders
        repeated_senders = {k: v for k, v in sender_counts.items() if v > 1}
        
        if repeated_senders:
            top_sender = max(repeated_senders.items(), key=lambda x: x[1])
            return {
                "type": "sender_repetition",
                "description": "Multiple emails from same senders",
                "top_sender": top_sender[0],
                "top_sender_count": top_sender[1],
                "total_repeated_senders": len(repeated_senders),
                "significance": "high" if top_sender[1] > 5 else "medium"
            }
        
        return None
    
    def _analyze_content_patterns(self, matches: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze content patterns"""
        subjects = [m.get("subject", "") for m in matches if m.get("subject")]
        
        if len(subjects) < 3:
            return None
        
        # Find common words in subjects
        words = {}
        for subject in subjects:
            for word in subject.lower().split():
                if len(word) > 3:  # Ignore short words
                    words[word] = words.get(word, 0) + 1
        
        # Find frequently repeated words
        common_words = {k: v for k, v in words.items() if v >= len(subjects) * 0.3}
        
        if common_words:
            top_word = max(common_words.items(), key=lambda x: x[1])
            return {
                "type": "content_similarity",
                "description": "Similar content patterns detected",
                "top_keyword": top_word[0],
                "keyword_frequency": top_word[1],
                "total_common_words": len(common_words),
                "significance": "high" if top_word[1] > len(subjects) * 0.5 else "medium"
            }
        
        return None
    
    def _create_timeline(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create timeline of events"""
        timeline = []
        
        # Group by hour
        hourly_groups = {}
        for match in matches:
            timestamp = datetime.fromisoformat(match["created_at"])
            hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
            
            if hour_key not in hourly_groups:
                hourly_groups[hour_key] = []
            hourly_groups[hour_key].append(match)
        
        # Create timeline entries
        for hour, group_matches in sorted(hourly_groups.items()):
            threats = sum(1 for m in group_matches if m["is_phishing"])
            
            timeline.append({
                "timestamp": hour.isoformat(),
                "total_emails": len(group_matches),
                "threat_emails": threats,
                "threat_percentage": round(threats / len(group_matches) * 100, 1),
                "avg_confidence": round(
                    sum(m["confidence_score"] for m in group_matches) / len(group_matches), 3
                )
            })
        
        return timeline
    
    async def _generate_suggestions(self, query: SearchQuery, matches: List[Dict[str, Any]], 
                                  indicators: List[ThreatIndicator]) -> List[str]:
        """Generate hunting suggestions based on results"""
        suggestions = []
        
        try:
            # Suggest related searches based on indicators
            if indicators:
                top_indicator = indicators[0]
                if top_indicator.type == "domain":
                    suggestions.append(f"Search for IP addresses associated with domain: {top_indicator.value}")
                    suggestions.append(f"Search for email addresses from domain: {top_indicator.value}")
                elif top_indicator.type == "ip_address":
                    suggestions.append(f"Search for geolocation of IP: {top_indicator.value}")
                    suggestions.append(f"Search for other IPs in same subnet")
            
            # Suggest expanding time range if few results
            if len(matches) < 10:
                suggestions.append(f"Consider expanding time range beyond {query.time_range_hours} hours")
            
            # Suggest pattern searches based on content
            if matches and query.search_type != SearchType.PATTERN:
                suggestions.append("Try pattern-based searches: suspicious_urls, crypto_addresses, urgent_keywords")
            
            # Suggest including benign emails
            if not query.include_benign:
                suggestions.append("Include benign emails to see the full scope")
            
            return suggestions[:5]  # Limit to 5 suggestions
            
        except Exception as e:
            logger.error(f"Failed to generate suggestions: {e}")
            return []
    
    def _find_regex_matches(self, pattern: re.Pattern, text: str, field: str) -> List[Dict[str, Any]]:
        """Find all regex matches in text"""
        matches = []
        for match in pattern.finditer(text):
            matches.append({
                "field": field,
                "match": match.group(),
                "start": match.start(),
                "end": match.end(),
                "context": text[max(0, match.start()-20):match.end()+20]
            })
        return matches
    
    def _extract_domains_from_text(self, text: str) -> List[str]:
        """Extract domain names from text"""
        # Simple domain extraction (could be enhanced)
        domain_pattern = re.compile(r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}')
        domains = domain_pattern.findall(text)
        return [d[0] + d[1] for d in domains if len(d) == 2]  # Simple heuristic
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if private IP (less suspicious)
            if ip_obj.is_private:
                return False
            
            # Check against known malicious IPs (would be from threat intel)
            if ip in self.malicious_indicators["ips"]:
                return True
            
            # Check for suspicious ranges (simplified)
            suspicious_ranges = [
                "185.220.100.0/22",  # Known Tor exit nodes
                "198.98.50.0/24",    # Known malicious range
            ]
            
            for range_str in suspicious_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return True
            
            return False
            
        except ValueError:
            return False
    
    def _generate_cache_key(self, query: SearchQuery) -> str:
        """Generate cache key for search query"""
        key_data = f"{query.query}:{query.search_type.value}:{query.case_sensitive}:{query.time_range_hours}:{query.limit}:{query.include_benign}"
        return f"threat_hunt:{hash(key_data)}"

# Global threat hunting engine
threat_hunter = ThreatHuntingEngine()

# API Router for threat hunting
router = APIRouter(prefix="/api/v1/threat-hunting", tags=["Threat Hunting"])

@router.post("/hunt", response_model=HuntingResult)
async def execute_hunt(
    query: str = Query(..., description="Search query"),
    search_type: SearchType = Query(SearchType.KEYWORD, description="Type of search"),
    case_sensitive: bool = Query(False, description="Case sensitive search"),
    time_range_hours: int = Query(24, description="Time range in hours"),
    limit: int = Query(100, description="Maximum results"),
    include_benign: bool = Query(False, description="Include benign emails"),
    fields: List[str] = Query(["content", "sender", "subject"], description="Fields to search"),
    current_user: dict = Depends(require_permission(Permission.VIEW_REPORTS)),
    db: Session = Depends(get_db)
):
    """Execute threat hunting search with advanced pattern matching"""
    
    try:
        search_query = SearchQuery(
            query=query,
            search_type=search_type,
            case_sensitive=case_sensitive,
            time_range_hours=min(time_range_hours, 168),  # Max 1 week
            limit=min(limit, 1000),  # Max 1000 results
            include_benign=include_benign,
            fields=fields
        )
        
        result = await threat_hunter.hunt(search_query, db)
        
        logger.info(f"Threat hunt executed", 
                   user_id=current_user["id"], 
                   query=query, 
                   matches=result.total_matches)
        
        return result
        
    except Exception as e:
        logger.error(f"Threat hunt failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat hunting failed: {str(e)}"
        )

@router.get("/patterns", response_model=Dict[str, List[str]])
async def get_available_patterns(
    current_user: dict = Depends(require_permission(Permission.VIEW_REPORTS))
):
    """Get list of available threat patterns"""
    
    patterns = {
        "threat_patterns": list(threat_hunter.threat_patterns.keys()),
        "search_types": [t.value for t in SearchType],
        "example_queries": [
            "suspicious_urls",
            "crypto_addresses", 
            "urgent_keywords",
            "malware.exe",
            "phishing.com",
            "192.168.1.1"
        ]
    }
    
    return patterns

@router.get("/indicators", response_model=List[ThreatIndicator])
async def get_recent_indicators(
    hours: int = Query(24, description="Hours to look back"),
    limit: int = Query(50, description="Maximum indicators"),
    current_user: dict = Depends(require_permission(Permission.VIEW_REPORTS)),
    db: Session = Depends(get_db)
):
    """Get recent threat indicators from automated analysis"""
    
    try:
        # This would typically be populated by background threat analysis
        # For now, return cached indicators
        cache_key = f"recent_indicators:{hours}"
        cached_indicators = await threat_hunter.cache_manager.get(cache_key)
        
        if cached_indicators:
            return [ThreatIndicator(**ind) for ind in cached_indicators[:limit]]
        
        # Generate indicators from recent high-confidence detections
        since_time = datetime.utcnow() - timedelta(hours=hours)
        
        high_confidence_detections = db.query(Detection).filter(
            and_(
                Detection.created_at >= since_time,
                Detection.is_phishing == True,
                Detection.confidence_score > 0.8
            )
        ).limit(100).all()
        
        indicators = []
        for detection in high_confidence_detections:
            # Extract indicators from features
            features = detection.features or {}
            
            if features.get("sender_domain"):
                indicators.append(ThreatIndicator(
                    type="domain",
                    value=features["sender_domain"],
                    confidence=detection.confidence_score,
                    threat_level=ThreatLevel(detection.risk_level.lower()),
                    first_seen=detection.created_at,
                    last_seen=detection.created_at,
                    occurrences=1,
                    related_emails=[str(detection.email_id)]
                ))
        
        return indicators[:limit]
        
    except Exception as e:
        logger.error(f"Failed to get indicators: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve indicators")
