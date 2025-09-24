"""
Privacy compliance utilities and helpers.
Provides utility functions for common privacy operations.
"""

import re
import hashlib
import secrets
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from backend.app.privacy import PIIRedactor, ConsentType, PrivacyRightType
from backend.app.observability import get_logger

logger = get_logger(__name__)

class DataAnonymizer:
    """Utility class for data anonymization and pseudonymization."""
    
    @staticmethod
    def anonymize_email(email: str) -> str:
        """Anonymize email address while preserving domain for analysis."""
        if '@' not in email:
            return PIIRedactor.redact_pii(email)
        
        local, domain = email.split('@', 1)
        # Hash the local part
        hashed_local = hashlib.sha256(local.encode()).hexdigest()[:8]
        return f"user_{hashed_local}@{domain}"
    
    @staticmethod
    def anonymize_ip(ip_address: str) -> str:
        """Anonymize IP address by masking last octet."""
        parts = ip_address.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        return "xxx.xxx.xxx.xxx"
    
    @staticmethod
    def pseudonymize_user_id(user_id: str, salt: str = None) -> str:
        """Create pseudonymous user ID."""
        salt = salt or "phishnet_pseudonym_salt"
        combined = f"{user_id}_{salt}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]

class PrivacyPolicyValidator:
    """Validates privacy policy compliance for data operations."""
    
    @staticmethod
    def validate_data_collection(
        data_types: List[str],
        purpose: str,
        legal_basis: str,
        retention_days: int
    ) -> Dict[str, Any]:
        """Validate if data collection complies with privacy policy."""
        
        # Define allowed data types and purposes
        allowed_combinations = {
            "email_content": {
                "purposes": ["security_analysis", "threat_detection"],
                "legal_bases": ["consent", "legitimate_interest"],
                "max_retention_days": 90
            },
            "user_profile": {
                "purposes": ["service_provision", "account_management"],
                "legal_bases": ["contract", "consent"],
                "max_retention_days": 365
            },
            "oauth_tokens": {
                "purposes": ["authentication", "service_provision"],
                "legal_bases": ["contract"],
                "max_retention_days": 90
            }
        }
        
        validation_result = {
            "valid": True,
            "warnings": [],
            "errors": [],
            "recommendations": []
        }
        
        for data_type in data_types:
            if data_type not in allowed_combinations:
                validation_result["errors"].append(
                    f"Data type '{data_type}' not allowed by privacy policy"
                )
                validation_result["valid"] = False
                continue
            
            config = allowed_combinations[data_type]
            
            # Check purpose
            if purpose not in config["purposes"]:
                validation_result["errors"].append(
                    f"Purpose '{purpose}' not allowed for data type '{data_type}'"
                )
                validation_result["valid"] = False
            
            # Check legal basis
            if legal_basis not in config["legal_bases"]:
                validation_result["errors"].append(
                    f"Legal basis '{legal_basis}' not valid for data type '{data_type}'"
                )
                validation_result["valid"] = False
            
            # Check retention period
            if retention_days > config["max_retention_days"]:
                validation_result["warnings"].append(
                    f"Retention period {retention_days} days exceeds maximum "
                    f"{config['max_retention_days']} days for '{data_type}'"
                )
        
        return validation_result

class ConsentChecker:
    """Helper class for checking user consent status."""
    
    def __init__(self, consent_manager):
        self.consent_manager = consent_manager
    
    async def check_processing_consent(self, user_id: str) -> bool:
        """Check if user has given consent for data processing."""
        return await self.consent_manager.has_consent(
            user_id, ConsentType.DATA_PROCESSING
        )
    
    async def check_analytics_consent(self, user_id: str) -> bool:
        """Check if user has given consent for analytics."""
        return await self.consent_manager.has_consent(
            user_id, ConsentType.ANALYTICS
        )
    
    async def check_marketing_consent(self, user_id: str) -> bool:
        """Check if user has given consent for marketing."""
        return await self.consent_manager.has_consent(
            user_id, ConsentType.MARKETING
        )
    
    async def get_consent_summary(self, user_id: str) -> Dict[str, bool]:
        """Get summary of all user consents."""
        consent_types = [
            ConsentType.ESSENTIAL,
            ConsentType.ANALYTICS,
            ConsentType.MARKETING,
            ConsentType.DATA_PROCESSING,
            ConsentType.THIRD_PARTY_SHARING
        ]
        
        summary = {}
        for consent_type in consent_types:
            summary[consent_type.value] = await self.consent_manager.has_consent(
                user_id, consent_type
            )
        
        return summary

class PrivacyMetrics:
    """Collect privacy-related metrics for compliance monitoring."""
    
    def __init__(self, db_manager):
        self.db = db_manager
    
    async def get_consent_metrics(
        self, 
        start_date: datetime, 
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get consent-related metrics."""
        # This would query the database for actual metrics
        return {
            "total_consent_records": 0,  # await self.db.count_consent_records(start_date, end_date)
            "consent_grants": 0,
            "consent_withdrawals": 0,
            "consent_by_type": {},
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            }
        }
    
    async def get_rights_request_metrics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get data subject rights request metrics."""
        return {
            "total_requests": 0,
            "requests_by_type": {
                "access": 0,
                "rectification": 0,
                "erasure": 0,
                "portability": 0,
                "restriction": 0,
                "objection": 0
            },
            "average_processing_time_days": 0.0,
            "requests_within_deadline": 0,
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            }
        }
    
    async def get_data_breach_metrics(self) -> Dict[str, Any]:
        """Get data breach metrics (should always be zero!)."""
        return {
            "total_breaches": 0,
            "breaches_by_severity": {
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0
            },
            "breaches_reported_to_authorities": 0,
            "average_containment_time_hours": 0.0
        }

class LegalBasisManager:
    """Manages legal basis for data processing under GDPR."""
    
    LEGAL_BASES = {
        "consent": "The data subject has given consent to the processing",
        "contract": "Processing is necessary for the performance of a contract",
        "legal_obligation": "Processing is necessary for compliance with a legal obligation",
        "vital_interests": "Processing is necessary to protect vital interests",
        "public_task": "Processing is necessary for performance of a public task",
        "legitimate_interests": "Processing is necessary for legitimate interests"
    }
    
    @classmethod
    def get_legal_basis_description(cls, legal_basis: str) -> str:
        """Get description of legal basis."""
        return cls.LEGAL_BASES.get(legal_basis, "Unknown legal basis")
    
    @classmethod
    def validate_legal_basis(cls, legal_basis: str, data_type: str, purpose: str) -> bool:
        """Validate if legal basis is appropriate for data type and purpose."""
        # Simplified validation logic
        if data_type == "oauth_tokens" and legal_basis != "contract":
            return False
        if purpose == "marketing" and legal_basis not in ["consent"]:
            return False
        if data_type == "email_content" and legal_basis not in ["consent", "legitimate_interests"]:
            return False
        
        return legal_basis in cls.LEGAL_BASES

class PrivacyImpactAssessment:
    """Conducts Privacy Impact Assessments (PIA) for new data processing."""
    
    @staticmethod
    def assess_processing_risk(
        data_types: List[str],
        processing_purpose: str,
        data_subjects_count: int,
        retention_days: int,
        third_party_sharing: bool = False,
        automated_decision_making: bool = False
    ) -> Dict[str, Any]:
        """Conduct privacy impact assessment."""
        
        risk_score = 0
        risk_factors = []
        
        # Assess data sensitivity
        sensitive_data_types = ["email_content", "personal_identifiers", "location_data"]
        for data_type in data_types:
            if data_type in sensitive_data_types:
                risk_score += 2
                risk_factors.append(f"Processing sensitive data type: {data_type}")
        
        # Assess scale
        if data_subjects_count > 10000:
            risk_score += 3
            risk_factors.append("Large scale processing (>10,000 data subjects)")
        elif data_subjects_count > 1000:
            risk_score += 1
            risk_factors.append("Medium scale processing (>1,000 data subjects)")
        
        # Assess retention period
        if retention_days > 365:
            risk_score += 2
            risk_factors.append("Long retention period (>1 year)")
        
        # Assess third party sharing
        if third_party_sharing:
            risk_score += 2
            risk_factors.append("Data shared with third parties")
        
        # Assess automated decision making
        if automated_decision_making:
            risk_score += 2
            risk_factors.append("Automated decision making involved")
        
        # Determine risk level
        if risk_score >= 8:
            risk_level = "HIGH"
            recommendations = [
                "Conduct full Data Protection Impact Assessment (DPIA)",
                "Consult with Data Protection Officer",
                "Consider consulting supervisory authority",
                "Implement additional safeguards"
            ]
        elif risk_score >= 5:
            risk_level = "MEDIUM"
            recommendations = [
                "Review data minimization opportunities",
                "Ensure appropriate technical and organizational measures",
                "Regular compliance monitoring"
            ]
        else:
            risk_level = "LOW"
            recommendations = [
                "Ensure basic privacy compliance",
                "Regular compliance check"
            ]
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "recommendations": recommendations,
            "dpia_required": risk_level == "HIGH",
            "assessment_date": datetime.utcnow().isoformat()
        }

def generate_privacy_notice(
    data_controller: str,
    data_types: List[str],
    purposes: List[str],
    legal_bases: List[str],
    retention_period: str,
    third_parties: List[str] = None,
    contact_email: str = "privacy@example.com"
) -> str:
    """Generate a privacy notice for data processing."""
    
    notice = f"""
PRIVACY NOTICE

Data Controller: {data_controller}

We process the following categories of personal data:
{chr(10).join(f"- {dt}" for dt in data_types)}

Purposes of processing:
{chr(10).join(f"- {purpose}" for purpose in purposes)}

Legal basis for processing:
{chr(10).join(f"- {basis}" for basis in legal_bases)}

Data retention period: {retention_period}

Third parties who may receive your data:
{chr(10).join(f"- {party}" for party in (third_parties or ["None"]))}

Your rights:
- Right to access your personal data
- Right to rectify inaccurate data
- Right to erasure (right to be forgotten)
- Right to restrict processing
- Right to object to processing
- Right to data portability
- Right to withdraw consent (where applicable)

Contact: {contact_email}

This notice was generated on {datetime.utcnow().strftime("%Y-%m-%d")}
    """.strip()
    
    return notice

# Export utility functions
__all__ = [
    'DataAnonymizer',
    'PrivacyPolicyValidator',
    'ConsentChecker',
    'PrivacyMetrics',
    'LegalBasisManager',
    'PrivacyImpactAssessment',
    'generate_privacy_notice'
]