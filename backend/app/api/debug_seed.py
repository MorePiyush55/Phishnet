from fastapi import APIRouter, Depends
from app.api.auth import require_analyst
from app.models.user import User
from app.services.email_polling_worker import get_email_polling_worker
import asyncio

router = APIRouter()

@router.post("/debug/seed-data")
async def seed_server_data(current_user: User = Depends(require_analyst)):
    """Generates dummy data on the server for visualization"""
    from app.models.mongodb_models import ForwardedEmailAnalysis, Tenant
    from datetime import datetime, timedelta
    import random
    
    domain = current_user.email.split('@')[1]
    
    # Generate 5 random emails
    for i in range(5):
        verdict = random.choice(["SAFE", "SUSPICIOUS", "PHISHING"])
        score = random.randint(0, 30) if verdict == "SAFE" else random.randint(70, 100)
        
        analysis = ForwardedEmailAnalysis(
            user_id=current_user.email,
            forwarded_by=current_user.email,
            org_domain=domain,
            original_sender=f"test{i}@example.com",
            original_subject=f"Simulation Check #{random.randint(100,999)}",
            threat_score=score/100.0,
            risk_level=verdict,
            email_metadata={"uid": f"SIM-{random.randint(1000,9999)}"},
            created_at=datetime.utcnow()
        )
        await analysis.save()
        
    return {"success": True, "message": f"Seeded 5 simulation emails for {domain}"}
