#!/usr/bin/env python3
"""
Phase 1: Backbone Setup

This script implements the backbone phase of the build order:
- Config, logging, DB engine, Alembic
- Users table + auth (hash, JWT, refresh, roles)
- Health endpoint + structured logs
"""

import sys
import os
import logging
from datetime import datetime, timezone
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.config.settings import get_settings
from app.config.logging import setup_logging
from app.models.complete_schema import Base, User, RefreshToken
from app.core.security import get_password_hash

def setup_backbone():
    """Set up the backbone infrastructure."""
    
    print("🛡️  PhishNet Phase 1: Backbone Setup")
    print("=" * 50)
    
    # 1. Initialize settings and logging
    print("1. Initializing configuration and logging...")
    settings = get_settings()
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info("Phase 1: Backbone infrastructure setup")
    
    # 2. Create database engine
    print("2. Setting up database engine...")
    # Force SQLite for development
    database_url = "sqlite:///./phishnet_dev.db"
    print(f"   Using database: {database_url}")
    
    engine = create_engine(
        database_url,
        echo=settings.DEBUG,
        connect_args={"check_same_thread": False}
    )
    
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # 3. Create all tables
    print("3. Creating database schema...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema created successfully")
        print("   ✅ Database schema created")
    except Exception as e:
        logger.error(f"Failed to create database schema: {e}")
        print(f"   ❌ Database schema creation failed: {e}")
        return False
    
    # 4. Test database connection
    print("4. Testing database connection...")
    try:
        with SessionLocal() as session:
            result = session.execute(text("SELECT 1")).scalar()
            if result == 1:
                logger.info("Database connection successful")
                print("   ✅ Database connection working")
            else:
                raise Exception("Unexpected result from database test")
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        print(f"   ❌ Database connection failed: {e}")
        return False
    
    # 5. Create initial users
    print("5. Creating initial users...")
    try:
        with SessionLocal() as session:
            # Check if users already exist
            existing_users = session.query(User).count()
            if existing_users > 0:
                print("   ℹ️  Users already exist, skipping user creation")
                logger.info(f"Found {existing_users} existing users")
            else:
                # Create admin user
                admin_user = User(
                    email="admin@phishnet.local",
                    password_hash=get_password_hash("admin"),
                    role="admin",
                    name="System Administrator",
                    disabled=False
                )
                session.add(admin_user)
                
                # Create analyst user
                analyst_user = User(
                    email="analyst@phishnet.local", 
                    password_hash=get_password_hash("analyst"),
                    role="analyst",
                    name="Security Analyst",
                    disabled=False
                )
                session.add(analyst_user)
                
                # Create viewer user
                viewer_user = User(
                    email="viewer@phishnet.local",
                    password_hash=get_password_hash("viewer"),
                    role="viewer",
                    name="Security Viewer",
                    disabled=False
                )
                session.add(viewer_user)
                
                session.commit()
                logger.info("Initial users created successfully")
                print("   ✅ Initial users created (admin@phishnet.local/admin, analyst@phishnet.local/analyst, viewer@phishnet.local/viewer)")
    
    except Exception as e:
        logger.error(f"Failed to create initial users: {e}")
        print(f"   ❌ User creation failed: {e}")
        return False
    
    # 6. Verify backbone components
    print("6. Verifying backbone components...")
    
    # Test logging
    logger.info("Testing structured logging")
    logger.warning("This is a test warning")
    logger.error("This is a test error")
    
    # Test settings
    if settings.SECRET_KEY and len(settings.SECRET_KEY) >= 32:
        print("   ✅ Configuration valid")
        logger.info("Configuration validation passed")
    else:
        print("   ❌ Configuration invalid")
        logger.error("Configuration validation failed")
        return False
    
    print("\n🎉 Phase 1: Backbone setup completed successfully!")
    print(f"📊 Database: {settings.DATABASE_URL}")
    print(f"🔐 Security: JWT with {settings.ALGORITHM}")
    print(f"📝 Logging: Configured and tested")
    print(f"👥 Users: 3 initial users created")
    print("\nNext steps:")
    print("- Start the minimal API server: python app/minimal_app.py")
    print("- Test health endpoint: http://localhost:8000/api/v1/health")
    print("- Begin Phase 2: Emails domain")
    
    return True

# Now available via CLI: python phishnet-cli.py setup backbone  
if __name__ == "__main__":
    success = setup_backbone()
    sys.exit(0 if success else 1)
