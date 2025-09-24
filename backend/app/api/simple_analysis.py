"""
Simple Email Analysis API endpoint for testing
Provides basic phishing detection without complex ML dependencies
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime
import re
import urllib.parse

# Import with fallbacks
try:
    from app.core.auth_simple import get_current_user
except ImportError:
    # Fallback auth for deployment
    def get_current_user():
        return {"id": 1, "username": "demo"}

router = APIRouter(prefix="/api/analyze", tags=["Email Analysis"])

class EmailAnalysisRequest(BaseModel):
    subject: str = Field(..., description="Email subject line")
    sender: str = Field(..., description="Sender email address")
    content: str = Field(..., description="Email body content")
    headers: Optional[Dict[str, str]] = Field(None, description="Email headers")

class AnalysisDetails(BaseModel):
    sender_analysis: Dict[str, Any]
    content_analysis: Dict[str, Any]
    link_analysis: Dict[str, Any]
    attachment_analysis: Dict[str, Any]

class EmailAnalysisResponse(BaseModel):
    is_phishing: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_level: str = Field(..., pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    threats_detected: List[str]
    analysis_details: AnalysisDetails
    recommendations: List[str]
    timestamp: str

class EmailAnalyzer:
    """Simple rule-based email analyzer for demonstration"""
    
    # Common phishing indicators
    PHISHING_KEYWORDS = [
        'urgent', 'immediately', 'verify', 'suspend', 'expire', 'confirm',
        'click here', 'act now', 'limited time', 'unauthorized', 'security alert',
        'account locked', 'suspended', 'verify account', 'update payment',
        'confirm identity', 'temporary hold', 'unusual activity'
    ]
    
    SUSPICIOUS_DOMAINS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'paypal-security.com', 'paypal-verify.com', 'bank-security.net',
        'secure-banking.org', 'account-verify.net'
    ]
    
    LEGITIMATE_DOMAINS = [
        'github.com', 'google.com', 'microsoft.com', 'apple.com',
        'paypal.com', 'amazon.com', 'facebook.com', 'twitter.com'
    ]

    def analyze_sender(self, sender: str) -> Dict[str, Any]:
        """Analyze sender email address"""
        domain = sender.split('@')[-1] if '@' in sender else ''
        
        is_suspicious_domain = any(susp in domain for susp in self.SUSPICIOUS_DOMAINS)
        is_legitimate_domain = any(legit in domain for legit in self.LEGITIMATE_DOMAINS)
        
        # Simple checks
        has_typos = any(char in domain for char in ['0', '1', '3', '4', '5', '7', '8', '9'])
        is_freemail = domain in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
        
        trust_score = 0.8
        if is_suspicious_domain:
            trust_score = 0.1
        elif is_legitimate_domain:
            trust_score = 0.9
        elif has_typos:
            trust_score = 0.3
        elif is_freemail:
            trust_score = 0.6
            
        return {
            'domain': domain,
            'domain_trust': trust_score,
            'is_suspicious_domain': is_suspicious_domain,
            'is_legitimate_domain': is_legitimate_domain,
            'auth_status': 'unknown',
            'reputation_score': trust_score
        }

    def analyze_content(self, subject: str, content: str) -> Dict[str, Any]:
        """Analyze email content for phishing indicators"""
        text = (subject + ' ' + content).lower()
        
        # Count suspicious keywords
        keyword_matches = sum(1 for keyword in self.PHISHING_KEYWORDS if keyword in text)
        
        # Check for urgency indicators
        urgency_words = ['urgent', 'immediately', 'now', 'asap', 'expires', 'deadline']
        urgency_score = sum(1 for word in urgency_words if word in text) / len(urgency_words)
        
        # Check for money/financial terms
        financial_terms = ['payment', 'bank', 'credit card', 'account', 'billing', 'invoice']
        financial_score = sum(1 for term in financial_terms if term in text) / len(financial_terms)
        
        # Check for grammar/spelling issues (simplified)
        grammar_issues = len(re.findall(r'\s{2,}', text)) + len(re.findall(r'[.]{2,}', text))
        
        return {
            'suspicious_patterns': keyword_matches,
            'urgency_score': urgency_score,
            'financial_score': financial_score,
            'grammar_issues': grammar_issues,
            'total_words': len(text.split()),
            'keyword_density': keyword_matches / max(len(text.split()), 1)
        }

    def analyze_links(self, content: str) -> Dict[str, Any]:
        """Analyze links in email content"""
        # Simple URL extraction
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, content)
        
        suspicious_links = 0
        shortened_links = 0
        
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                domain = parsed.netloc
                
                if any(short in domain for short in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']):
                    shortened_links += 1
                    suspicious_links += 1
                elif any(susp in domain for susp in self.SUSPICIOUS_DOMAINS):
                    suspicious_links += 1
                    
            except Exception:
                suspicious_links += 1
        
        return {
            'total_links': len(urls),
            'suspicious_links': suspicious_links,
            'shortened_links': shortened_links,
            'risk_ratio': suspicious_links / max(len(urls), 1),
            'extracted_urls': urls[:5]  # Limit for response size
        }

    def analyze_attachments(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Analyze email attachments"""
        # Simplified - just check if Content-Type suggests attachments
        has_attachments = False
        attachment_types = []
        
        if headers:
            content_type = headers.get('Content-Type', '').lower()
            if 'multipart' in content_type:
                has_attachments = True
                if 'application' in content_type:
                    attachment_types.append('binary')
        
        return {
            'has_attachments': has_attachments,
            'attachment_count': len(attachment_types),
            'attachment_types': attachment_types,
            'suspicious_attachments': 0
        }

    def calculate_risk(self, sender_analysis: Dict, content_analysis: Dict, 
                      link_analysis: Dict) -> tuple[bool, float, str]:
        """Calculate overall risk assessment"""
        
        # Risk factors with weights
        risk_score = 0.0
        
        # Sender risk (30% weight)
        sender_risk = (1.0 - sender_analysis['domain_trust']) * 0.3
        risk_score += sender_risk
        
        # Content risk (40% weight)
        content_risk = min(1.0, (
            content_analysis['keyword_density'] * 2 +
            content_analysis['urgency_score'] +
            content_analysis['financial_score']
        ) / 4) * 0.4
        risk_score += content_risk
        
        # Link risk (30% weight)
        link_risk = link_analysis['risk_ratio'] * 0.3
        risk_score += link_risk
        
        # Determine classification
        is_phishing = risk_score > 0.5
        
        if risk_score >= 0.8:
            risk_level = 'CRITICAL'
        elif risk_score >= 0.6:
            risk_level = 'HIGH'
        elif risk_score >= 0.4:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
            
        return is_phishing, risk_score, risk_level

    def generate_threats(self, sender_analysis: Dict, content_analysis: Dict, 
                        link_analysis: Dict) -> List[str]:
        """Generate list of detected threats"""
        threats = []
        
        if sender_analysis['is_suspicious_domain']:
            threats.append("Suspicious sender domain detected")
        
        if sender_analysis['domain_trust'] < 0.3:
            threats.append("Low sender reputation")
            
        if content_analysis['suspicious_patterns'] > 3:
            threats.append("Multiple phishing keywords detected")
            
        if content_analysis['urgency_score'] > 0.5:
            threats.append("High urgency language detected")
            
        if link_analysis['suspicious_links'] > 0:
            threats.append(f"{link_analysis['suspicious_links']} suspicious links found")
            
        if link_analysis['shortened_links'] > 0:
            threats.append("Shortened URLs detected")
            
        return threats

    def generate_recommendations(self, is_phishing: bool, threats: List[str]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if is_phishing:
            recommendations.extend([
                "Do not click any links in this email",
                "Do not download or open any attachments",
                "Do not provide personal information",
                "Report this email to your IT security team",
                "Delete this email immediately"
            ])
        else:
            recommendations.extend([
                "Email appears legitimate, but remain cautious",
                "Verify sender identity if requesting sensitive information",
                "Check URLs before clicking"
            ])
            
        if "suspicious links" in str(threats).lower():
            recommendations.append("Manually type URLs instead of clicking links")
            
        if "urgent" in str(threats).lower():
            recommendations.append("Be suspicious of urgent requests for personal information")
            
        return recommendations

@router.post("/email", response_model=EmailAnalysisResponse)
async def analyze_email(
    request: EmailAnalysisRequest,
    current_user = Depends(get_current_user)
):
    """
    Analyze an email for phishing indicators
    
    This endpoint provides basic phishing detection using rule-based analysis.
    Perfect for testing and demonstration purposes.
    """
    try:
        analyzer = EmailAnalyzer()
        
        # Perform analysis
        sender_analysis = analyzer.analyze_sender(request.sender)
        content_analysis = analyzer.analyze_content(request.subject, request.content)
        link_analysis = analyzer.analyze_links(request.content)
        attachment_analysis = analyzer.analyze_attachments(request.headers)
        
        # Calculate risk
        is_phishing, confidence, risk_level = analyzer.calculate_risk(
            sender_analysis, content_analysis, link_analysis
        )
        
        # Generate threats and recommendations
        threats = analyzer.generate_threats(sender_analysis, content_analysis, link_analysis)
        recommendations = analyzer.generate_recommendations(is_phishing, threats)
        
        return EmailAnalysisResponse(
            is_phishing=is_phishing,
            confidence=confidence,
            risk_level=risk_level,
            threats_detected=threats,
            analysis_details=AnalysisDetails(
                sender_analysis=sender_analysis,
                content_analysis=content_analysis,
                link_analysis=link_analysis,
                attachment_analysis=attachment_analysis
            ),
            recommendations=recommendations,
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )