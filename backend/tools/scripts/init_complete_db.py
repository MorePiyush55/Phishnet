"""
Database initialization script with sample data
"""

import asyncio
import sys
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

# Add the project root to the Python path
sys.path.append('.')

from app.models.complete_schema import (
    Base, User, Email, Link, EmailAIResult, EmailIndicator, 
    Action, Audit, RefreshToken, UserRole, EmailStatus, LinkRisk
)
from app.config.settings import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_sample_data():
    """Create sample data for testing and development"""
    
    # Create database engine
    engine = create_engine(settings.DATABASE_URL)
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Create session
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        # Create sample users
        admin_user = User(
            email="admin@phishnet.local",
            password_hash=pwd_context.hash("admin123"),
            role=UserRole.ADMIN,
            name="PhishNet Administrator",
            disabled=False
        )
        
        analyst_user = User(
            email="analyst@phishnet.local", 
            password_hash=pwd_context.hash("analyst123"),
            role=UserRole.ANALYST,
            name="Security Analyst",
            disabled=False
        )
        
        viewer_user = User(
            email="viewer@phishnet.local",
            password_hash=pwd_context.hash("viewer123"),
            role=UserRole.VIEWER,
            name="Security Viewer",
            disabled=False
        )
        
        db.add_all([admin_user, analyst_user, viewer_user])
        db.commit()
        
        print("✅ Created sample users:")
        print("   - admin@phishnet.local (password: admin123)")
        print("   - analyst@phishnet.local (password: analyst123)")
        print("   - viewer@phishnet.local (password: viewer123)")
        
        # Create sample emails
        sample_emails = [
            {
                "gmail_msg_id": "msg_001_phishing",
                "thread_id": "thread_001",
                "from_addr": "security@paypaI-verify.com",  # Typosquatting
                "to_addr": "user@company.com",
                "subject": "Urgent: Account Verification Required",
                "received_at": datetime.utcnow() - timedelta(hours=2),
                "raw_text": "Your PayPal account requires immediate verification. Click here: https://paypaI-verify.com/login",
                "raw_html": "<p>Your PayPal account requires immediate verification. <a href='https://paypaI-verify.com/login'>Click here</a></p>",
                "sanitized_html": "<p>Your PayPal account requires immediate verification. <a href='#'>Click here</a></p>",
                "score": 0.85,
                "status": EmailStatus.QUARANTINED,
                "raw_headers": {
                    "Message-ID": "<001@paypaI-verify.com>",
                    "From": "security@paypaI-verify.com",
                    "To": "user@company.com",
                    "Subject": "Urgent: Account Verification Required"
                }
            },
            {
                "gmail_msg_id": "msg_002_safe",
                "thread_id": "thread_002", 
                "from_addr": "notifications@github.com",
                "to_addr": "developer@company.com",
                "subject": "Pull Request #123 merged",
                "received_at": datetime.utcnow() - timedelta(hours=1),
                "raw_text": "Your pull request has been successfully merged into main branch.",
                "raw_html": "<p>Your pull request has been successfully merged into main branch.</p>",
                "sanitized_html": "<p>Your pull request has been successfully merged into main branch.</p>",
                "score": 0.15,
                "status": EmailStatus.SAFE,
                "raw_headers": {
                    "Message-ID": "<002@github.com>",
                    "From": "notifications@github.com", 
                    "To": "developer@company.com",
                    "Subject": "Pull Request #123 merged"
                }
            },
            {
                "gmail_msg_id": "msg_003_suspicious",
                "thread_id": "thread_003",
                "from_addr": "winner@lottery-international.biz",
                "to_addr": "user@company.com", 
                "subject": "CONGRATULATIONS! You've Won $1,000,000!",
                "received_at": datetime.utcnow() - timedelta(minutes=30),
                "raw_text": "You have won the international lottery! Send us your bank details to claim your prize.",
                "raw_html": "<p>You have won the international lottery! Send us your bank details to claim your prize.</p>",
                "sanitized_html": "<p>You have won the international lottery! Send us your bank details to claim your prize.</p>",
                "score": 0.72,
                "status": EmailStatus.ANALYZED,
                "raw_headers": {
                    "Message-ID": "<003@lottery-international.biz>",
                    "From": "winner@lottery-international.biz",
                    "To": "user@company.com",
                    "Subject": "CONGRATULATIONS! You've Won $1,000,000!"
                }
            }
        ]
        
        email_objects = []
        for email_data in sample_emails:
            email = Email(**email_data)
            email_objects.append(email)
        
        db.add_all(email_objects)
        db.commit()
        
        print(f"✅ Created {len(email_objects)} sample emails")
        
        # Create sample links
        phishing_email = email_objects[0]  # PayPal phishing
        
        phishing_link = Link(
            email_id=phishing_email.id,
            original_url="https://paypaI-verify.com/login",
            final_url="https://malicious-harvester.ru/steal-creds",
            chain=["https://paypaI-verify.com/login", "https://bit.ly/abc123", "https://malicious-harvester.ru/steal-creds"],
            risk=LinkRisk.HIGH,
            reasons=["typosquatting", "suspicious_redirect", "malicious_domain"],
            redirect_count=2,
            response_time_ms=1250,
            status_code=200
        )
        
        db.add(phishing_link)
        db.commit()
        
        print("✅ Created sample link analysis")
        
        # Create sample AI results
        ai_result = EmailAIResult(
            email_id=phishing_email.id,
            model="gemini-pro",
            score=0.95,
            labels={
                "phishing": 0.95,
                "credential_harvesting": 0.88,
                "urgency_tactics": 0.92
            },
            summary="High confidence phishing email attempting credential harvesting using PayPal impersonation and urgency tactics.",
            prompt_version="v1.2",
            processing_time_ms=2847,
            tokens_used=156,
            api_cost=0.002340
        )
        
        db.add(ai_result)
        db.commit()
        
        print("✅ Created sample AI analysis result")
        
        # Create sample threat indicators
        domain_indicator = EmailIndicator(
            email_id=phishing_email.id,
            indicator="paypaI-verify.com",
            type="domain",
            source="virustotal",
            reputation="malicious",
            details={
                "detections": 5,
                "total_scans": 89,
                "categories": ["phishing", "typosquatting"],
                "first_seen": "2025-08-13T00:00:00Z"
            }
        )
        
        ip_indicator = EmailIndicator(
            email_id=phishing_email.id,
            indicator="185.220.101.182",
            type="ip", 
            source="abuseipdb",
            reputation="suspicious",
            details={
                "confidence": 75,
                "reports": 23,
                "categories": ["phishing", "malware"],
                "country": "Russia"
            }
        )
        
        db.add_all([domain_indicator, ip_indicator])
        db.commit()
        
        print("✅ Created sample threat intelligence indicators")
        
        # Create sample actions
        quarantine_action = Action(
            email_id=phishing_email.id,
            type="quarantine",
            params={"reason": "high_risk_score", "auto_quarantine": True},
            created_by=None,  # System action
            result={"success": True, "quarantine_location": "/quarantine/2025/08/14/"},
            success=True,
            execution_time_ms=145
        )
        
        db.add(quarantine_action)
        db.commit()
        
        print("✅ Created sample actions")
        
        # Create sample audit entries
        audit_entries = [
            Audit(
                actor_id=admin_user.id,
                action="user_login",
                resource="authentication",
                details={"login_method": "password", "success": True},
                ip="192.168.1.100",
                request_id="req_001",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                endpoint="/api/v1/auth/login",
                method="POST",
                status_code=200,
                response_time_ms=234
            ),
            Audit(
                actor_id=None,  # System action
                action="email_analyzed",
                resource="email",
                details={"email_id": phishing_email.id, "risk_score": 0.85},
                request_id="req_002",
                endpoint="/api/v1/analysis/1",
                method="POST",
                status_code=200,
                response_time_ms=2847
            ),
            Audit(
                actor_id=None,  # System action
                action="email_quarantined",
                resource="email",
                details={"email_id": phishing_email.id, "reason": "high_risk_score"},
                request_id="req_003",
                endpoint="/api/v1/emails/1/quarantine",
                method="POST", 
                status_code=200,
                response_time_ms=145
            )
        ]
        
        db.add_all(audit_entries)
        db.commit()
        
        print("✅ Created sample audit trail entries")
        
        print("\n🎉 Database initialization complete!")
        print("📊 Sample data created:")
        print(f"   - {len([admin_user, analyst_user, viewer_user])} users")
        print(f"   - {len(email_objects)} emails")
        print(f"   - 1 link analysis")
        print(f"   - 1 AI result")
        print(f"   - 2 threat indicators")
        print(f"   - 1 action")
        print(f"   - {len(audit_entries)} audit entries")
        
    except Exception as e:
        print(f"❌ Error creating sample data: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_sample_data()
