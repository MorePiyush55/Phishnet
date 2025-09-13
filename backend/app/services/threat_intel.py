"""Threat Intelligence service with VirusTotal and AbuseIPDB integration."""

import asyncio
import json
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import re

import httpx
from sqlalchemy import and_

from app.config.logging import get_logger
from app.config.settings import get_settings
from app.models.analysis.link_analysis import ThreatIntelCache, EmailIndicators
from app.core.database import SessionLocal

logger = get_logger(__name__)


class ThreatIntelligenceService:
    """Threat intelligence service with multiple providers."""
    
    def __init__(self):
        self.session = SessionLocal()
        self.http_client = httpx.AsyncClient(timeout=30.0)
        
        # API configurations
        settings = get_settings()
        self.virustotal_api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
        self.abuseipdb_api_key = getattr(settings, 'ABUSEIPDB_API_KEY', None)
        
        # Cache TTL (time to live) in seconds
        self.cache_ttl = {
            'virustotal_url': 3600,      # 1 hour
            'virustotal_domain': 7200,   # 2 hours
            'virustotal_file': 86400,    # 24 hours
            'abuseipdb_ip': 3600,        # 1 hour
        }
        
        # Rate limiting
        self.rate_limits = {
            'virustotal': {'requests_per_minute': 4, 'last_request': 0},
            'abuseipdb': {'requests_per_day': 1000, 'requests_today': 0, 'last_reset': datetime.now().date()}
        }
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http_client.aclose()
        self.session.close()
    
    async def analyze_email_indicators(self, email_id: int, urls: List[str], 
                                     domains: List[str], ips: List[str],
                                     file_hashes: List[str]) -> List[EmailIndicators]:
        """Analyze all indicators for an email."""
        results = []
        
        # Analyze URLs
        for url in urls:
            indicator = await self.check_url_reputation(email_id, url)
            if indicator:
                results.append(indicator)
        
        # Analyze domains
        for domain in domains:
            indicator = await self.check_domain_reputation(email_id, domain)
            if indicator:
                results.append(indicator)
        
        # Analyze IPs
        for ip in ips:
            indicator = await self.check_ip_reputation(email_id, ip)
            if indicator:
                results.append(indicator)
        
        # Analyze file hashes
        for file_hash in file_hashes:
            indicator = await self.check_file_reputation(email_id, file_hash)
            if indicator:
                results.append(indicator)
        
        return results
    
    async def check_url_reputation(self, email_id: int, url: str) -> Optional[EmailIndicators]:
        """Check URL reputation using VirusTotal."""
        cache_key = f"vt_url_{hashlib.md5(url.encode()).hexdigest()}"
        
        # Check cache first
        cached_result = await self._get_cached_result(cache_key)
        if cached_result:
            return self._create_indicator(email_id, url, 'url', 'virustotal', cached_result)
        
        if not self.virustotal_api_key:
            logger.warning("VirusTotal API key not configured")
            return None
        
        try:
            # Rate limiting
            await self._respect_rate_limit('virustotal')
            
            # Prepare URL for VirusTotal API
            url_id = self._encode_url_for_vt(url)
            
            headers = {
                'x-apikey': self.virustotal_api_key,
                'Accept': 'application/json'
            }
            
            # Get URL analysis
            response = await self.http_client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                result = self._parse_vt_url_result(data)
                
                # Cache result
                await self._cache_result(cache_key, result, 'virustotal', self.cache_ttl['virustotal_url'])
                
                return self._create_indicator(email_id, url, 'url', 'virustotal', result)
            
            elif response.status_code == 404:
                # URL not found in VirusTotal, submit for analysis
                await self._submit_url_to_vt(url)
                result = {'reputation': 0.0, 'status': 'not_analyzed', 'details': 'Submitted for analysis'}
                return self._create_indicator(email_id, url, 'url', 'virustotal', result)
            
            else:
                logger.error(f"VirusTotal API error for URL {url}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error checking URL reputation for {url}: {str(e)}")
            return None
    
    async def check_domain_reputation(self, email_id: int, domain: str) -> Optional[EmailIndicators]:
        """Check domain reputation using VirusTotal."""
        cache_key = f"vt_domain_{domain}"
        
        # Check cache first
        cached_result = await self._get_cached_result(cache_key)
        if cached_result:
            return self._create_indicator(email_id, domain, 'domain', 'virustotal', cached_result)
        
        if not self.virustotal_api_key:
            return None
        
        try:
            await self._respect_rate_limit('virustotal')
            
            headers = {
                'x-apikey': self.virustotal_api_key,
                'Accept': 'application/json'
            }
            
            response = await self.http_client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                result = self._parse_vt_domain_result(data)
                
                # Cache result
                await self._cache_result(cache_key, result, 'virustotal', self.cache_ttl['virustotal_domain'])
                
                return self._create_indicator(email_id, domain, 'domain', 'virustotal', result)
            
            else:
                logger.error(f"VirusTotal API error for domain {domain}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error checking domain reputation for {domain}: {str(e)}")
            return None
    
    async def check_ip_reputation(self, email_id: int, ip: str) -> Optional[EmailIndicators]:
        """Check IP reputation using AbuseIPDB."""
        cache_key = f"abuseipdb_ip_{ip}"
        
        # Check cache first
        cached_result = await self._get_cached_result(cache_key)
        if cached_result:
            return self._create_indicator(email_id, ip, 'ip', 'abuseipdb', cached_result)
        
        if not self.abuseipdb_api_key:
            return None
        
        try:
            await self._respect_rate_limit('abuseipdb')
            
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = await self.http_client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                result = self._parse_abuseipdb_result(data)
                
                # Cache result
                await self._cache_result(cache_key, result, 'abuseipdb', self.cache_ttl['abuseipdb_ip'])
                
                return self._create_indicator(email_id, ip, 'ip', 'abuseipdb', result)
            
            else:
                logger.error(f"AbuseIPDB API error for IP {ip}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error checking IP reputation for {ip}: {str(e)}")
            return None
    
    async def check_file_reputation(self, email_id: int, file_hash: str) -> Optional[EmailIndicators]:
        """Check file reputation using VirusTotal."""
        cache_key = f"vt_file_{file_hash}"
        
        # Check cache first
        cached_result = await self._get_cached_result(cache_key)
        if cached_result:
            return self._create_indicator(email_id, file_hash, 'file_hash', 'virustotal', cached_result)
        
        if not self.virustotal_api_key:
            return None
        
        try:
            await self._respect_rate_limit('virustotal')
            
            headers = {
                'x-apikey': self.virustotal_api_key,
                'Accept': 'application/json'
            }
            
            response = await self.http_client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                result = self._parse_vt_file_result(data)
                
                # Cache result
                await self._cache_result(cache_key, result, 'virustotal', self.cache_ttl['virustotal_file'])
                
                return self._create_indicator(email_id, file_hash, 'file_hash', 'virustotal', result)
            
            else:
                logger.debug(f"File hash {file_hash} not found in VirusTotal")
                return None
                
        except Exception as e:
            logger.error(f"Error checking file reputation for {file_hash}: {str(e)}")
            return None
    
    async def _submit_url_to_vt(self, url: str) -> None:
        """Submit URL to VirusTotal for analysis."""
        try:
            headers = {
                'x-apikey': self.virustotal_api_key,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {'url': url}
            
            response = await self.http_client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data=data
            )
            
            if response.status_code == 200:
                logger.info(f"URL {url} submitted to VirusTotal for analysis")
            else:
                logger.error(f"Failed to submit URL to VirusTotal: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error submitting URL to VirusTotal: {str(e)}")
    
    def _encode_url_for_vt(self, url: str) -> str:
        """Encode URL for VirusTotal API."""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    
    def _parse_vt_url_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal URL analysis result."""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        total_engines = sum(stats.values())
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        reputation = 0.0
        if total_engines > 0:
            reputation = (malicious + suspicious * 0.5) / total_engines
        
        return {
            'reputation': reputation,
            'malicious_votes': malicious,
            'suspicious_votes': suspicious,
            'total_engines': total_engines,
            'last_analysis_date': attributes.get('last_analysis_date'),
            'categories': attributes.get('categories', {}),
            'details': attributes
        }
    
    def _parse_vt_domain_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal domain analysis result."""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        total_engines = sum(stats.values())
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        reputation = 0.0
        if total_engines > 0:
            reputation = (malicious + suspicious * 0.5) / total_engines
        
        return {
            'reputation': reputation,
            'malicious_votes': malicious,
            'suspicious_votes': suspicious,
            'total_engines': total_engines,
            'categories': attributes.get('categories', {}),
            'creation_date': attributes.get('creation_date'),
            'registrar': attributes.get('registrar'),
            'details': attributes
        }
    
    def _parse_vt_file_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal file analysis result."""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        total_engines = sum(stats.values())
        malicious = stats.get('malicious', 0)
        
        reputation = 0.0
        if total_engines > 0:
            reputation = malicious / total_engines
        
        return {
            'reputation': reputation,
            'malicious_votes': malicious,
            'total_engines': total_engines,
            'file_type': attributes.get('type_description'),
            'file_size': attributes.get('size'),
            'md5': attributes.get('md5'),
            'sha1': attributes.get('sha1'),
            'sha256': attributes.get('sha256'),
            'details': attributes
        }
    
    def _parse_abuseipdb_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AbuseIPDB result."""
        ip_data = data.get('data', {})
        
        abuse_confidence = ip_data.get('abuseConfidencePercentage', 0)
        reputation = abuse_confidence / 100.0  # Convert percentage to 0-1 scale
        
        return {
            'reputation': reputation,
            'abuse_confidence': abuse_confidence,
            'country_code': ip_data.get('countryCode'),
            'usage_type': ip_data.get('usageType'),
            'isp': ip_data.get('isp'),
            'total_reports': ip_data.get('totalReports', 0),
            'last_reported': ip_data.get('lastReportedAt'),
            'is_whitelisted': ip_data.get('isWhitelisted', False),
            'details': ip_data
        }
    
    def _create_indicator(self, email_id: int, indicator: str, indicator_type: str,
                         source: str, reputation_data: Dict[str, Any]) -> EmailIndicators:
        """Create EmailIndicators object."""
        email_indicator = EmailIndicators(
            email_id=email_id,
            indicator=indicator,
            indicator_type=indicator_type,
            source=source,
            reputation_score=reputation_data.get('reputation', 0.0),
            reputation_data=reputation_data
        )
        
        # Save to database
        try:
            self.session.add(email_indicator)
            self.session.commit()
            self.session.refresh(email_indicator)
        except Exception as e:
            logger.error(f"Failed to save indicator to database: {str(e)}")
            self.session.rollback()
        
        return email_indicator
    
    async def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached threat intelligence result."""
        try:
            cached = self.session.query(ThreatIntelCache).filter(
                ThreatIntelCache.cache_key == cache_key
            ).first()
            
            if cached and not cached.is_expired():
                return cached.cache_value
            elif cached:
                # Remove expired cache entry
                self.session.delete(cached)
                self.session.commit()
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached result: {str(e)}")
            return None
    
    async def _cache_result(self, cache_key: str, result: Dict[str, Any], 
                          source: str, ttl: int) -> None:
        """Cache threat intelligence result."""
        try:
            # Remove existing cache entry
            existing = self.session.query(ThreatIntelCache).filter(
                ThreatIntelCache.cache_key == cache_key
            ).first()
            if existing:
                self.session.delete(existing)
            
            # Create new cache entry
            cache_entry = ThreatIntelCache(
                cache_key=cache_key,
                cache_value=result,
                source=source,
                ttl_seconds=ttl
            )
            
            self.session.add(cache_entry)
            self.session.commit()
            
        except Exception as e:
            logger.error(f"Error caching result: {str(e)}")
            self.session.rollback()
    
    async def _respect_rate_limit(self, service: str) -> None:
        """Respect API rate limits."""
        if service == 'virustotal':
            # VirusTotal: 4 requests per minute
            now = time.time()
            time_since_last = now - self.rate_limits['virustotal']['last_request']
            min_interval = 60 / self.rate_limits['virustotal']['requests_per_minute']
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                await asyncio.sleep(sleep_time)
            
            self.rate_limits['virustotal']['last_request'] = time.time()
        
        elif service == 'abuseipdb':
            # AbuseIPDB: 1000 requests per day
            today = datetime.now().date()
            if self.rate_limits['abuseipdb']['last_reset'] != today:
                self.rate_limits['abuseipdb']['requests_today'] = 0
                self.rate_limits['abuseipdb']['last_reset'] = today
            
            if self.rate_limits['abuseipdb']['requests_today'] >= 1000:
                raise Exception("AbuseIPDB daily rate limit exceeded")
            
            self.rate_limits['abuseipdb']['requests_today'] += 1
    
    def extract_indicators_from_email(self, content: str, headers: str = "") -> Dict[str, List[str]]:
        """Extract indicators (URLs, IPs, domains) from email content."""
        indicators = {
            'urls': [],
            'domains': [],
            'ips': [],
        }
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"\'`|(){}[\]]+[^\s<>"\'`|(){}[\].,!?:;]'
        urls = re.findall(url_pattern, content + " " + headers, re.IGNORECASE)
        indicators['urls'] = list(set(urls))
        
        # Extract domains from URLs
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    indicators['domains'].append(parsed.netloc.lower())
            except:
                continue
        
        # Extract standalone domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, content + " " + headers)
        indicators['domains'].extend(domains)
        indicators['domains'] = list(set(indicators['domains']))
        
        # Extract IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, content + " " + headers)
        # Filter out private/local IPs
        public_ips = []
        for ip in ips:
            parts = ip.split('.')
            if len(parts) == 4:
                try:
                    a, b, c, d = map(int, parts)
                    # Skip private/local ranges
                    if not (
                        (a == 10) or
                        (a == 172 and 16 <= b <= 31) or
                        (a == 192 and b == 168) or
                        (a == 127) or
                        (a == 0) or
                        (a >= 224)
                    ):
                        public_ips.append(ip)
                except ValueError:
                    continue
        indicators['ips'] = list(set(public_ips))
        
        return indicators


async def analyze_email_threat_intel(email_id: int, content: str, 
                                   headers: str = "", file_hashes: List[str] = None) -> List[EmailIndicators]:
    """Analyze email for threat intelligence indicators."""
    async with ThreatIntelligenceService() as service:
        # Extract indicators from email
        indicators = service.extract_indicators_from_email(content, headers)
        
        # Analyze extracted indicators
        results = await service.analyze_email_indicators(
            email_id=email_id,
            urls=indicators['urls'],
            domains=indicators['domains'],
            ips=indicators['ips'],
            file_hashes=file_hashes or []
        )
        
        return results
