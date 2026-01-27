"""
Seed Script: Generate Mock Enterprise Data
==========================================
Generates random Phishing/Suspicious/Safe forwarded emails for a demo tenant.
Usage: python seed_data.py
"""

import sys
import os
import asyncio
from datetime import datetime, timedelta
import random

# Ensure we can import app modules
sys.path.append(os.getcwd())

from app.db.mongodb import MongoDBManager
from app.models.mongodb_models import Tenant, ForwardedEmailAnalysis

async def seed():
    print("🌱 Seeding Enterprise Data...")
    
    # Connect
    await MongoDBManager.connect_to_mongo()
    await MongoDBManager.initialize_beanie([ForwardedEmailAnalysis, Tenant])
    
    # 1. Ensure Tenant exists
    domain = "demo.com"
    tenant = await Tenant.find_one(Tenant.domain == domain)
    if not tenant:
        print(f"Creating tenant: {domain}")
        tenant = Tenant(
            name="Demo Corp", 
            domain=domain, 
            admin_email=f"admin@{domain}"
        )
        await tenant.save()
    
    # 2. Generate Random Emails
    verdicts = ["SAFE", "SAFE", "SAFE", "SUSPICIOUS", "PHISHING"] # 60% Safe
    
    for i in range(20):
        verdict = random.choice(verdicts)
        
        # Calculate scores
        if verdict == "SAFE":
            score = random.randint(0, 30)
        elif verdict == "SUSPICIOUS":
            score = random.randint(40, 70)
        else:
            score = random.randint(80, 100)
            
        uid = f"SEED-{random.randint(1000, 9999)}"
        
        analysis = ForwardedEmailAnalysis(
            user_id=f"user{i}@{domain}",
            forwarded_by=f"user{i}@{domain}",
            org_domain=domain,
            original_sender=f"external-sender-{i}@random.com",
            original_subject=f"Urgent Invoice #{random.randint(100,999)}" if verdict != "SAFE" else f"Meeting Minutes - {datetime.now().strftime('%B')}",
            threat_score=float(score)/100.0,
            risk_level=verdict,
            analysis_result={
                "verdict": verdict,
                "score": score,
                "confidence": 0.95,
                "risk_factors": ["Suspicious Link", "Urgency"] if verdict != "SAFE" else []
            },
            email_metadata={
                "uid": uid,
                "subject": "Test Subject",
                "date": datetime.utcnow().isoformat()
            },
            tags=["finance"] if "Invoice" in "Subject" else [],
            created_at=datetime.utcnow() - timedelta(days=random.randint(0, 7))
        )
        await analysis.save()
        print(f"  + Created {verdict} email from user{i}")

    print("✅ Seeding Complete!")

if __name__ == "__main__":
    asyncio.run(seed())
