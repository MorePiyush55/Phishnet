#!/usr/bin/env python3
"""Database initialization script for PhishNet."""

import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.core.database import init_db, engine
from app.models.core.user import User
from app.models.core.email import Email, EmailAttachment
from app.models.analysis.detection import Detection, DetectionRule
from app.models.security.federated import FederatedClient, FederatedTrainingRound, FederatedModel
from app.core.security import get_password_hash
from app.config.logging import get_logger

logger = get_logger(__name__)


def create_tables():
    """Create all database tables."""
    try:
        logger.info("Creating database tables...")
        init_db()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create tables: {e}")
        raise


def create_admin_user():
    """Create a default admin user."""
    try:
        from sqlalchemy.orm import sessionmaker
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        
        # Check if admin user already exists
        admin_user = db.query(User).filter(User.email == "admin@phishnet.com").first()
        if admin_user:
            logger.info("Admin user already exists")
            return
        
        # Create admin user
        admin_user = User(
            email="admin@phishnet.com",
            username="admin",
            full_name="PhishNet Administrator",
            hashed_password=get_password_hash("admin123"),  # Change this in production!
            is_active=True,
            is_verified=True,
            is_superuser=True
        )
        
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        
        logger.info("Admin user created successfully")
        logger.info("Email: admin@phishnet.com")
        logger.info("Password: admin123")
        logger.warning("Please change the admin password in production!")
        
    except Exception as e:
        logger.error(f"Failed to create admin user: {e}")
        raise
    finally:
        db.close()


def create_sample_data():
    """Create sample data for testing."""
    try:
        from sqlalchemy.orm import sessionmaker
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        
        # Get admin user
        admin_user = db.query(User).filter(User.email == "admin@phishnet.com").first()
        if not admin_user:
            logger.warning("Admin user not found, skipping sample data creation")
            return
        
        # Create sample federated model
        sample_model = FederatedModel(
            version="1.0.0",
            name="Initial Phishing Detection Model",
            description="Baseline model for phishing detection",
            model_path="models/initial_model.pkl",
            accuracy=0.92,
            loss=0.08,
            precision=0.89,
            recall=0.94,
            f1_score=0.91,
            total_rounds=0,
            total_clients=0,
            total_samples=0,
            is_active=True,
            is_deployed=True
        )
        
        db.add(sample_model)
        db.commit()
        
        logger.info("Sample data created successfully")
        
    except Exception as e:
        logger.error(f"Failed to create sample data: {e}")
        raise
    finally:
        db.close()


def main():
    """Main initialization function."""
    logger.info("Starting PhishNet database initialization...")
    
    try:
        # Create tables
        create_tables()
        
        # Create admin user
        create_admin_user()
        
        # Create sample data
        create_sample_data()
        
        logger.info("Database initialization completed successfully!")
        logger.info("You can now start the PhishNet application.")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        sys.exit(1)


# Now available via CLI: python phishnet-cli.py setup database
if __name__ == "__main__":
    main()


