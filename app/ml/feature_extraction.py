"""Feature extraction for email phishing detection."""

import re
import hashlib
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs
import email
from email import policy
from email.parser import BytesParser
import numpy as np
# Note: textblob is not in our dependencies, we'll use a simple sentiment approach
# from textblob import TextBlob

from app.config.logging import get_logger

logger = get_logger(__name__)


class FeatureExtractor:
    """Feature extractor for email phishing detection."""
    
    def __init__(self):
        """Initialize feature extractor."""
        self.suspicious_keywords = [
            'urgent', 'account suspended', 'verify', 'login', 'password',
            'bank', 'credit card', 'social security', 'irs', 'lottery',
            'inheritance', 'million', 'dollars', 'bitcoin', 'crypto',
            'click here', 'download', 'free', 'limited time', 'act now'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd',
            'v.gd', 'ow.ly', 'su.pr', 'twurl.nl', 'snipurl.com'
        ]
    
    def extract_features(self, email_content: str, subject: str = "", sender: str = "") -> Dict[str, Any]:
        """Extract features from email content."""
        features = {}
        
        # Text-based features
        features.update(self._extract_text_features(email_content, subject))
        
        # URL-based features
        features.update(self._extract_url_features(email_content))
        
        # Header-based features
        features.update(self._extract_header_features(sender))
        
        # Content-based features
        features.update(self._extract_content_features(email_content))
        
        # Statistical features
        features.update(self._extract_statistical_features(email_content))
        
        return features
    
    def _extract_text_features(self, content: str, subject: str) -> Dict[str, Any]:
        """Extract text-based features."""
        features = {}
        
        # Combine content and subject
        full_text = f"{subject} {content}".lower()
        
        # Suspicious keyword count
        keyword_count = sum(1 for keyword in self.suspicious_keywords 
                           if keyword.lower() in full_text)
        features['suspicious_keyword_count'] = keyword_count
        
        # Text length features
        features['content_length'] = len(content)
        features['subject_length'] = len(subject)
        features['word_count'] = len(full_text.split())
        
        # Simple sentiment analysis (positive/negative word counting)
        positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'perfect', 'best', 'love', 'like', 'happy']
        negative_words = ['bad', 'terrible', 'awful', 'horrible', 'worst', 'hate', 'dislike', 'sad', 'angry', 'fear']
        
        words = full_text.lower().split()
        positive_count = sum(1 for word in words if word in positive_words)
        negative_count = sum(1 for word in words if word in negative_words)
        
        features['sentiment_polarity'] = (positive_count - negative_count) / max(len(words), 1)
        features['sentiment_subjectivity'] = (positive_count + negative_count) / max(len(words), 1)
        
        # Character features
        features['uppercase_ratio'] = sum(1 for c in full_text if c.isupper()) / len(full_text) if full_text else 0
        features['digit_ratio'] = sum(1 for c in full_text if c.isdigit()) / len(full_text) if full_text else 0
        features['special_char_ratio'] = sum(1 for c in full_text if not c.isalnum() and not c.isspace()) / len(full_text) if full_text else 0
        
        return features
    
    def _extract_url_features(self, content: str) -> Dict[str, Any]:
        """Extract URL-based features."""
        features = {}
        
        # Find URLs in content
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, content)
        
        features['url_count'] = len(urls)
        features['has_urls'] = len(urls) > 0
        
        if urls:
            # URL analysis
            url_features = []
            for url in urls:
                try:
                    parsed = urlparse(url)
                    url_features.append({
                        'domain': parsed.netloc,
                        'path_length': len(parsed.path),
                        'query_length': len(parsed.query),
                        'is_shortened': parsed.netloc in self.suspicious_domains,
                        'has_redirect': 'redirect' in parsed.path.lower() or 'redirect' in parsed.query.lower()
                    })
                except Exception as e:
                    logger.warning(f"Failed to parse URL {url}: {e}")
            
            # Aggregate URL features
            features['avg_path_length'] = np.mean([u['path_length'] for u in url_features])
            features['avg_query_length'] = np.mean([u['query_length'] for u in url_features])
            features['shortened_url_count'] = sum(1 for u in url_features if u['is_shortened'])
            features['redirect_url_count'] = sum(1 for u in url_features if u['has_redirect'])
        
        return features
    
    def _extract_header_features(self, sender: str) -> Dict[str, Any]:
        """Extract header-based features."""
        features = {}
        
        if not sender:
            features['has_sender'] = False
            return features
        
        features['has_sender'] = True
        
        # Email format validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        features['valid_sender_format'] = bool(re.match(email_pattern, sender))
        
        # Domain analysis
        try:
            domain = sender.split('@')[1] if '@' in sender else ''
            features['sender_domain_length'] = len(domain)
            features['sender_has_subdomain'] = domain.count('.') > 1
        except:
            features['sender_domain_length'] = 0
            features['sender_has_subdomain'] = False
        
        return features
    
    def _extract_content_features(self, content: str) -> Dict[str, Any]:
        """Extract content-based features."""
        features = {}
        
        # HTML content detection
        features['has_html'] = '<html' in content.lower() or '<body' in content.lower()
        
        # JavaScript detection
        features['has_javascript'] = '<script' in content.lower() or 'javascript:' in content.lower()
        
        # Form detection
        features['has_forms'] = '<form' in content.lower()
        
        # Image detection
        features['has_images'] = '<img' in content.lower() or 'data:image' in content.lower()
        
        # Attachment detection
        features['has_attachments'] = 'attachment' in content.lower() or 'filename=' in content.lower()
        
        # External links
        features['external_link_count'] = content.lower().count('http')
        
        return features
    
    def _extract_statistical_features(self, content: str) -> Dict[str, Any]:
        """Extract statistical features."""
        features = {}
        
        # Character frequency analysis
        char_freq = {}
        for char in content.lower():
            if char.isalpha():
                char_freq[char] = char_freq.get(char, 0) + 1
        
        if char_freq:
            # Most common character frequency
            max_freq = max(char_freq.values())
            total_chars = sum(char_freq.values())
            features['max_char_frequency'] = max_freq / total_chars if total_chars > 0 else 0
            
            # Character diversity
            features['char_diversity'] = len(char_freq) / 26  # 26 letters in alphabet
        
        # Word frequency analysis
        words = content.lower().split()
        if words:
            word_freq = {}
            for word in words:
                if len(word) > 2:  # Skip short words
                    word_freq[word] = word_freq.get(word, 0) + 1
            
            if word_freq:
                features['unique_word_ratio'] = len(word_freq) / len(words)
                features['avg_word_length'] = np.mean([len(word) for word in words])
        
        return features
    
    def get_feature_vector(self, features: Dict[str, Any]) -> List[float]:
        """Convert features dictionary to feature vector."""
        feature_names = [
            'suspicious_keyword_count', 'content_length', 'subject_length',
            'word_count', 'sentiment_polarity', 'sentiment_subjectivity',
            'uppercase_ratio', 'digit_ratio', 'special_char_ratio',
            'url_count', 'has_urls', 'avg_path_length', 'avg_query_length',
            'shortened_url_count', 'redirect_url_count', 'has_sender',
            'valid_sender_format', 'sender_domain_length', 'sender_has_subdomain',
            'has_html', 'has_javascript', 'has_forms', 'has_images',
            'has_attachments', 'external_link_count', 'max_char_frequency',
            'char_diversity', 'unique_word_ratio', 'avg_word_length'
        ]
        
        vector = []
        for feature_name in feature_names:
            value = features.get(feature_name, 0.0)
            # Handle boolean values
            if isinstance(value, bool):
                value = 1.0 if value else 0.0
            vector.append(float(value))
        
        return vector
