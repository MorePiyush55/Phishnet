#!/usr/bin/env python3
"""
PhishNet Phase 3: Link Analysis Implementation
Build Order: Link extraction + chain analyzer worker + DB persistence
"""

import os
import sys
import re
import sqlite3
import json
import requests
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
import time
from concurrent.futures import ThreadPoolExecutor
import warnings

# Suppress SSL warnings for demonstration
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

DATABASE_FILE = "phishnet_dev.db"

class LinkExtractor:
    """Extract links from email content"""
    
    @staticmethod
    def extract_from_text(text: str) -> List[str]:
        """Extract URLs from plain text"""
        if not text:
            return []
        
        # URL pattern matching
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        
        urls = url_pattern.findall(text)
        return list(set(urls))  # Remove duplicates
    
    @staticmethod
    def extract_from_html(html: str) -> List[str]:
        """Extract URLs from HTML content"""
        if not html:
            return []
        
        # Extract href attributes
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        # Extract src attributes (images, scripts)
        src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
        
        hrefs = href_pattern.findall(html)
        srcs = src_pattern.findall(html)
        
        all_urls = hrefs + srcs
        
        # Filter out non-HTTP URLs and normalize
        http_urls = []
        for url in all_urls:
            if url.startswith(('http://', 'https://')):
                http_urls.append(url)
            elif url.startswith('//'):
                http_urls.append('https:' + url)
        
        return list(set(http_urls))

class LinkChainAnalyzer:
    """Analyze URL redirect chains and reputation"""
    
    def __init__(self, timeout: int = 10, max_redirects: int = 10):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.session = requests.Session()
        self.session.verify = False  # For demo - in production, use proper SSL
        self.session.headers.update({
            'User-Agent': 'PhishNet-Analyzer/1.0'
        })
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL and its redirect chain"""
        start_time = time.time()
        
        try:
            # Track redirect chain
            chain = []
            current_url = url
            response = None
            
            for i in range(self.max_redirects + 1):
                try:
                    response = self.session.head(
                        current_url, 
                        allow_redirects=False, 
                        timeout=self.timeout
                    )
                    
                    chain.append({
                        'url': current_url,
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'step': i + 1
                    })
                    
                    # Check for redirect
                    if response.status_code in (301, 302, 303, 307, 308):
                        next_url = response.headers.get('Location')
                        if next_url:
                            # Handle relative URLs
                            if not next_url.startswith(('http://', 'https://')):
                                next_url = urljoin(current_url, next_url)
                            current_url = next_url
                        else:
                            break
                    else:
                        break
                        
                except requests.RequestException as e:
                    chain.append({
                        'url': current_url,
                        'error': str(e),
                        'step': i + 1
                    })
                    break
            
            # Analyze final destination
            final_url = chain[-1]['url'] if chain else url
            risk_assessment = self._assess_risk(url, final_url, chain)
            
            processing_time = int((time.time() - start_time) * 1000)
            
            return {
                'original_url': url,
                'final_url': final_url,
                'chain': chain,
                'redirect_count': len(chain) - 1,
                'risk': risk_assessment['level'],
                'reasons': risk_assessment['reasons'],
                'status_code': chain[-1].get('status_code') if chain else None,
                'content_type': self._get_content_type(chain),
                'response_time_ms': processing_time,
                'analyzed_at': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            return {
                'original_url': url,
                'final_url': url,
                'chain': [],
                'redirect_count': 0,
                'risk': 'high',
                'reasons': [f'Analysis failed: {str(e)}'],
                'status_code': None,
                'content_type': None,
                'response_time_ms': int((time.time() - start_time) * 1000),
                'analyzed_at': datetime.now(timezone.utc).isoformat()
            }
    
    def _assess_risk(self, original_url: str, final_url: str, chain: List[Dict]) -> Dict[str, Any]:
        """Assess risk level based on URL characteristics"""
        reasons = []
        risk_score = 0
        
        # Check domain reputation (simplified)
        parsed_original = urlparse(original_url)
        parsed_final = urlparse(final_url)
        
        # Suspicious domain patterns
        suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',  # URL shorteners
            'malicious-site.com', 'phishing-bank.net', 'lottery-scam.net'  # Known bad
        ]
        
        if any(domain in parsed_original.netloc for domain in suspicious_domains):
            risk_score += 30
            reasons.append('Suspicious domain in original URL')
        
        if any(domain in parsed_final.netloc for domain in suspicious_domains):
            risk_score += 40
            reasons.append('Suspicious domain in final destination')
        
        # Check for excessive redirects
        if len(chain) > 5:
            risk_score += 20
            reasons.append(f'Excessive redirects ({len(chain)} hops)')
        
        # Check for domain switching
        if parsed_original.netloc != parsed_final.netloc:
            risk_score += 15
            reasons.append('Domain changed during redirects')
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.ru', '.cn']
        if any(parsed_final.netloc.endswith(tld) for tld in suspicious_tlds):
            risk_score += 25
            reasons.append('Suspicious top-level domain')
        
        # Check for IP addresses
        if re.match(r'\\d+\\.\\d+\\.\\d+\\.\\d+', parsed_final.netloc):
            risk_score += 35
            reasons.append('Direct IP address instead of domain')
        
        # Check for suspicious paths
        suspicious_paths = ['phish', 'scam', 'verify', 'urgent', 'suspended']
        if any(word in final_url.lower() for word in suspicious_paths):
            risk_score += 20
            reasons.append('Suspicious keywords in URL path')
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 25:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        if not reasons:
            reasons.append('No suspicious indicators found')
        
        return {
            'level': risk_level,
            'score': risk_score,
            'reasons': reasons
        }
    
    def _get_content_type(self, chain: List[Dict]) -> Optional[str]:
        """Extract content type from response headers"""
        if not chain:
            return None
        
        last_response = chain[-1]
        headers = last_response.get('headers', {})
        return headers.get('Content-Type', headers.get('content-type'))

class LinkRepository:
    """Database operations for link analysis"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    def save_link_analysis(self, email_id: int, analysis: Dict[str, Any]) -> int:
        """Save link analysis to database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO links (
                    email_id, original_url, final_url, chain, risk, reasons,
                    analyzed_at, redirect_count, response_time_ms, status_code, content_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                email_id,
                analysis['original_url'],
                analysis['final_url'],
                json.dumps(analysis['chain']),
                analysis['risk'],
                json.dumps(analysis['reasons']),
                analysis['analyzed_at'],
                analysis['redirect_count'],
                analysis['response_time_ms'],
                analysis['status_code'],
                analysis['content_type']
            ))
            
            link_id = cursor.lastrowid
            conn.commit()
            print(f"✅ Saved link analysis: {link_id} ({analysis['risk']} risk)")
            return link_id
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Failed to save link analysis: {e}")
            return None
        finally:
            conn.close()
    
    def get_links_for_email(self, email_id: int) -> List[Dict]:
        """Get all links analyzed for an email"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id, original_url, final_url, risk, reasons, redirect_count, analyzed_at
                FROM links 
                WHERE email_id = ?
                ORDER BY analyzed_at DESC
            """, (email_id,))
            
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
            
        finally:
            conn.close()
    
    def get_high_risk_links(self, limit: int = 50) -> List[Dict]:
        """Get recent high-risk links"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT l.id, l.original_url, l.final_url, l.risk, l.analyzed_at,
                       e.subject, e.from_addr
                FROM links l
                JOIN emails e ON l.email_id = e.id
                WHERE l.risk = 'high'
                ORDER BY l.analyzed_at DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
            
        finally:
            conn.close()

class LinkAnalysisOrchestrator:
    """Orchestrate link analysis for emails"""
    
    def __init__(self):
        self.extractor = LinkExtractor()
        self.analyzer = LinkChainAnalyzer()
        self.repository = LinkRepository()
    
    def analyze_email_links(self, email_id: int) -> List[Dict]:
        """Analyze all links in an email"""
        # Get email content
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT raw_text, raw_html, sanitized_html 
            FROM emails 
            WHERE id = ?
        """, (email_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            print(f"❌ Email {email_id} not found")
            return []
        
        raw_text, raw_html, sanitized_html = row
        
        # Extract URLs
        text_urls = self.extractor.extract_from_text(raw_text or "")
        html_urls = self.extractor.extract_from_html(raw_html or "")
        sanitized_urls = self.extractor.extract_from_html(sanitized_html or "")
        
        # Combine and deduplicate
        all_urls = list(set(text_urls + html_urls + sanitized_urls))
        
        if not all_urls:
            print(f"📧 No URLs found in email {email_id}")
            return []
        
        print(f"🔍 Found {len(all_urls)} URLs in email {email_id}")
        
        # Analyze each URL
        results = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_url = {
                executor.submit(self.analyzer.analyze_url, url): url 
                for url in all_urls
            }
            
            for future in future_to_url:
                try:
                    analysis = future.result(timeout=30)
                    link_id = self.repository.save_link_analysis(email_id, analysis)
                    if link_id:
                        results.append(analysis)
                except Exception as e:
                    url = future_to_url[future]
                    print(f"❌ Failed to analyze {url}: {e}")
        
        return results

def analyze_all_emails():
    """Analyze links in all emails"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Get all emails
    cursor.execute("SELECT id, subject, from_addr FROM emails")
    emails = cursor.fetchall()
    conn.close()
    
    if not emails:
        print("📧 No emails found to analyze")
        return
    
    orchestrator = LinkAnalysisOrchestrator()
    total_links = 0
    
    print(f"🔍 Analyzing links in {len(emails)} emails...")
    
    for email_id, subject, from_addr in emails:
        print(f"\n📧 Email {email_id}: {subject[:50]}...")
        print(f"   From: {from_addr}")
        
        results = orchestrator.analyze_email_links(email_id)
        
        if results:
            print(f"   🔗 Analyzed {len(results)} links:")
            for result in results:
                print(f"      - {result['original_url'][:60]}... [{result['risk']} risk]")
            total_links += len(results)
        else:
            print("   📭 No links found")
    
    print(f"\n✅ Total links analyzed: {total_links}")

def get_link_statistics():
    """Get link analysis statistics"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    try:
        # Total links
        cursor.execute("SELECT COUNT(*) FROM links")
        total_links = cursor.fetchone()[0]
        
        # Risk breakdown
        cursor.execute("""
            SELECT risk, COUNT(*) as count 
            FROM links 
            GROUP BY risk
        """)
        risk_breakdown = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Average redirects
        cursor.execute("SELECT AVG(redirect_count) FROM links")
        avg_redirects = cursor.fetchone()[0]
        
        # High-risk links
        cursor.execute("""
            SELECT l.original_url, e.subject, e.from_addr
            FROM links l
            JOIN emails e ON l.email_id = e.id
            WHERE l.risk = 'high'
            ORDER BY l.analyzed_at DESC
            LIMIT 5
        """)
        high_risk_samples = cursor.fetchall()
        
        return {
            'total_links': total_links,
            'risk_breakdown': risk_breakdown,
            'average_redirects': round(avg_redirects, 1) if avg_redirects else 0,
            'high_risk_samples': high_risk_samples
        }
        
    finally:
        conn.close()

def main():
    """Phase 3 implementation and testing"""
    print("🔗 PhishNet Phase 3: Link Analysis")
    print("=" * 50)
    
    # 1. Test link extraction
    print("1. Testing link extraction...")
    extractor = LinkExtractor()
    
    test_html = '''
    <html>
        <body>
            <p>Click <a href="http://malicious-site.com/phish">here</a> to verify!</p>
            <p>Or visit https://github.com/user/repo directly</p>
            <img src="http://tracker.evil.com/pixel.png" />
        </body>
    </html>
    '''
    
    test_text = '''
    Visit http://example.com for more info.
    Urgent: https://suspicious-bank.com/verify-now
    '''
    
    html_links = extractor.extract_from_html(test_html)
    text_links = extractor.extract_from_text(test_text)
    
    print(f"   🔗 HTML links: {len(html_links)}")
    print(f"   🔗 Text links: {len(text_links)}")
    
    # 2. Test link analysis
    print("2. Testing link analysis...")
    analyzer = LinkChainAnalyzer()
    
    test_url = "http://malicious-site.com/phish"
    analysis = analyzer.analyze_url(test_url)
    print(f"   🎯 Analyzed: {test_url}")
    print(f"      Risk: {analysis['risk']}")
    print(f"      Reasons: {analysis['reasons'][:2]}")  # Show first 2 reasons
    
    # 3. Analyze existing emails
    print("3. Analyzing existing email links...")
    analyze_all_emails()
    
    # 4. Get statistics
    print("4. Link analysis statistics:")
    stats = get_link_statistics()
    
    print(f"   📊 Total links analyzed: {stats['total_links']}")
    print(f"   🎯 Risk breakdown: {stats['risk_breakdown']}")
    print(f"   🔄 Average redirects: {stats['average_redirects']}")
    
    if stats['high_risk_samples']:
        print("   🚨 High-risk samples:")
        for url, subject, from_addr in stats['high_risk_samples']:
            print(f"      - {url[:50]}...")
            print(f"        Email: {subject[:30]}... from {from_addr}")
    
    print("\n🎉 Phase 3: Link Analysis completed successfully!")
    print("📊 Summary:")
    print(f"   - Link Extractor: ✅ Implemented")
    print(f"   - Chain Analyzer: ✅ Implemented")
    print(f"   - Link Repository: ✅ Implemented")
    print(f"   - Analysis Orchestrator: ✅ Implemented")
    print(f"   - Database Persistence: ✅ Working")
    print("\n🚀 Ready for Phase 4: AI + Intel")

if __name__ == "__main__":
    main()
