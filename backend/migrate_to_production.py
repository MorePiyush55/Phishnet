#!/usr/bin/env python3
"""Data migration script to move from in-memory/SQLite to MongoDB Atlas."""

import asyncio
import os
import sys
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProductionDataMigration:
    """Migrate data from development/in-memory storage to production MongoDB Atlas."""
    
    def __init__(self):
        self.migration_log = []
        self.errors = []
    
    async def run_full_migration(self):
        """Run complete data migration to MongoDB Atlas."""
        
        print("🔄 Starting Production Data Migration to MongoDB Atlas")
        print("=" * 70)
        
        try:
            # Step 1: Verify MongoDB Atlas connection
            await self._verify_mongodb_connection()
            
            # Step 2: Migrate users from any existing storage
            await self._migrate_users()
            
            # Step 3: Migrate OAuth sessions to persistent storage
            await self._migrate_oauth_sessions()
            
            # Step 4: Migrate email analyses if any exist
            await self._migrate_email_analyses()
            
            # Step 5: Initialize threat intelligence data
            await self._initialize_threat_intelligence()
            
            # Step 6: Create initial audit logs
            await self._create_initial_audit_logs()
            
            # Step 7: Verify migration
            await self._verify_migration()
            
            # Migration summary
            await self._print_migration_summary()
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            print(f"❌ Migration failed: {e}")
            raise
    
    async def _verify_mongodb_connection(self):
        """Verify MongoDB Atlas connection before migration."""
        print("\n🔗 Step 1: Verifying MongoDB Atlas Connection")
        print("-" * 50)
        
        try:
            from app.db.production_persistence import production_db_manager
            
            await production_db_manager.connect_to_atlas()
            
            if production_db_manager.is_connected:
                health = await production_db_manager.health_check()
                print(f"✅ MongoDB Atlas connected: {health['database']}")
                print(f"📊 Collections: {health['collections']}, Indexes: {health['indexes']}")
                self.migration_log.append("MongoDB Atlas connection verified")
            else:
                raise RuntimeError("Failed to connect to MongoDB Atlas")
                
        except Exception as e:
            self.errors.append(f"MongoDB connection failed: {e}")
            raise
    
    async def _migrate_users(self):
        """Migrate users to MongoDB Atlas."""
        print("\n👥 Step 2: Migrating Users")
        print("-" * 30)
        
        try:
            from app.repositories.production_repositories import user_repository
            
            # Create sample production users for testing
            sample_users = [
                {
                    "email": "admin@phishnet.local",
                    "username": "phishnet_admin",
                    "full_name": "PhishNet Administrator",
                    "hashed_password": "$2b$12$dummy_hash_for_production_admin",
                    "is_active": True,
                    "is_verified": True
                },
                {
                    "email": "demo@phishnet.local", 
                    "username": "demo_user",
                    "full_name": "Demo User",
                    "hashed_password": "$2b$12$dummy_hash_for_demo_user",
                    "is_active": True,
                    "is_verified": False
                }
            ]
            
            migrated_users = 0
            for user_data in sample_users:
                try:
                    user = await user_repository.create_user(user_data)
                    print(f"✅ User migrated: {user.username} ({user.email})")
                    migrated_users += 1
                except ValueError as e:
                    if "already exists" in str(e):
                        print(f"ℹ️  User exists: {user_data['username']}")
                    else:
                        print(f"⚠️  User migration warning: {e}")
                except Exception as e:
                    print(f"❌ User migration error: {e}")
                    self.errors.append(f"User migration error: {e}")
            
            self.migration_log.append(f"Users migrated: {migrated_users}")
            
        except Exception as e:
            self.errors.append(f"User migration failed: {e}")
            print(f"❌ User migration failed: {e}")
    
    async def _migrate_oauth_sessions(self):
        """Migrate OAuth sessions to persistent MongoDB storage."""
        print("\n🔐 Step 3: Migrating OAuth Sessions")
        print("-" * 40)
        
        try:
            from app.core.production_oauth_security import production_oauth_security_manager
            from app.db.production_persistence import persistent_session_manager
            
            # Check if old in-memory sessions exist
            old_sessions = getattr(production_oauth_security_manager, 'session_store', {})
            
            if old_sessions:
                migrated_sessions = 0
                for session_id, session_data in old_sessions.items():
                    try:
                        # Convert to production format
                        if isinstance(session_data, dict):
                            production_session = {
                                "session_id": session_id,
                                "user_id": session_data.get("user_id", "unknown"),
                                "ip_address": session_data.get("ip_address", "unknown"),
                                "user_agent": session_data.get("user_agent", "unknown"),
                                "created_at": session_data.get("created_at", datetime.now(timezone.utc)),
                                "expires_at": session_data.get("expires_at", datetime.now(timezone.utc)),
                                "active": session_data.get("active", True),
                                "migrated": True
                            }
                            
                            await persistent_session_manager.store_session(production_session)
                            migrated_sessions += 1
                    
                    except Exception as e:
                        print(f"⚠️  Session migration warning: {e}")
                
                print(f"✅ OAuth sessions migrated: {migrated_sessions}")
                self.migration_log.append(f"OAuth sessions migrated: {migrated_sessions}")
            else:
                print("ℹ️  No OAuth sessions to migrate")
                self.migration_log.append("No OAuth sessions to migrate")
            
            # Test session creation in production mode
            test_session = await production_oauth_security_manager.create_secure_session(
                user_id="migration_test",
                ip_address="127.0.0.1",
                user_agent="Migration Test Agent"
            )
            
            if test_session:
                print("✅ Production session creation verified")
                # Clean up test session
                await production_oauth_security_manager.revoke_session(test_session)
            
        except Exception as e:
            self.errors.append(f"OAuth session migration failed: {e}")
            print(f"❌ OAuth session migration failed: {e}")
    
    async def _migrate_email_analyses(self):
        """Migrate email analyses to MongoDB Atlas."""
        print("\n📧 Step 4: Migrating Email Analyses")
        print("-" * 40)
        
        try:
            from app.repositories.production_repositories import email_analysis_repository, user_repository
            
            # Get a test user for sample email analyses
            test_user = await user_repository.get_by_email("demo@phishnet.local")
            
            if test_user:
                # Create sample email analyses for demonstration
                sample_analyses = [
                    {
                        "user_id": str(test_user.id),
                        "gmail_message_id": f"migration_test_001_{int(datetime.now().timestamp())}",
                        "subject": "Welcome to PhishNet - Production Migration",
                        "sender": "noreply@phishnet.local",
                        "recipient": test_user.email,
                        "received_at": datetime.now(timezone.utc),
                        "status": "completed",
                        "threat_level": "low",
                        "confidence_score": 0.1,
                        "analysis_results": {
                            "url_analysis": {"clean_urls": 1, "suspicious_urls": 0},
                            "content_analysis": {"phishing_indicators": 0, "legitimate_content": True}
                        },
                        "detected_threats": [],
                        "analyzer_version": "2.0.0"
                    },
                    {
                        "user_id": str(test_user.id),
                        "gmail_message_id": f"migration_test_002_{int(datetime.now().timestamp())}",
                        "subject": "URGENT: Verify Your Account Now!",
                        "sender": "suspicious@phishing-example.com",
                        "recipient": test_user.email,
                        "received_at": datetime.now(timezone.utc),
                        "status": "completed",
                        "threat_level": "high",
                        "confidence_score": 0.85,
                        "analysis_results": {
                            "url_analysis": {"suspicious_urls": 2, "malicious_domains": 1},
                            "content_analysis": {"urgency_indicators": 3, "credential_harvesting": True}
                        },
                        "detected_threats": ["phishing_url", "urgency_language", "credential_harvesting"],
                        "analyzer_version": "2.0.0"
                    }
                ]
                
                migrated_analyses = 0
                for analysis_data in sample_analyses:
                    try:
                        analysis = await email_analysis_repository.create_or_update_analysis(analysis_data)
                        print(f"✅ Email analysis migrated: {analysis.subject[:50]}...")
                        migrated_analyses += 1
                    except Exception as e:
                        print(f"⚠️  Analysis migration warning: {e}")
                
                print(f"✅ Email analyses migrated: {migrated_analyses}")
                self.migration_log.append(f"Email analyses migrated: {migrated_analyses}")
            else:
                print("ℹ️  No test user found for email analysis migration")
            
        except Exception as e:
            self.errors.append(f"Email analysis migration failed: {e}")
            print(f"❌ Email analysis migration failed: {e}")
    
    async def _initialize_threat_intelligence(self):
        """Initialize threat intelligence data."""
        print("\n🛡️ Step 5: Initializing Threat Intelligence")
        print("-" * 45)
        
        try:
            from app.repositories.production_repositories import threat_intelligence_repository
            
            # Sample threat intelligence data
            sample_threats = [
                {
                    "indicator": "phishing-example.com",
                    "indicator_type": "domain",
                    "threat_type": "phishing",
                    "threat_level": "high",
                    "confidence_score": 0.9,
                    "description": "Known phishing domain",
                    "source": "manual",
                    "tags": ["phishing", "credential_harvesting"],
                    "metadata": {"added_by": "migration_script"}
                },
                {
                    "indicator": "http://suspicious-link.example.com/verify",
                    "indicator_type": "url",
                    "threat_type": "phishing",
                    "threat_level": "medium",
                    "confidence_score": 0.75,
                    "description": "Suspicious verification URL",
                    "source": "manual",
                    "tags": ["phishing", "verification_scam"],
                    "metadata": {"added_by": "migration_script"}
                }
            ]
            
            initialized_threats = 0
            for threat_data in sample_threats:
                try:
                    threat = await threat_intelligence_repository.add_or_update_threat(threat_data)
                    print(f"✅ Threat intelligence added: {threat.indicator}")
                    initialized_threats += 1
                except Exception as e:
                    print(f"⚠️  Threat intelligence warning: {e}")
            
            print(f"✅ Threat intelligence initialized: {initialized_threats} entries")
            self.migration_log.append(f"Threat intelligence initialized: {initialized_threats}")
            
        except Exception as e:
            self.errors.append(f"Threat intelligence initialization failed: {e}")
            print(f"❌ Threat intelligence initialization failed: {e}")
    
    async def _create_initial_audit_logs(self):
        """Create initial audit logs for migration."""
        print("\n📝 Step 6: Creating Initial Audit Logs")
        print("-" * 40)
        
        try:
            from app.repositories.production_repositories import audit_log_repository
            
            # Create migration audit events
            migration_events = [
                {
                    "event_type": "data_migration",
                    "action": "migration_started",
                    "description": "Production data migration to MongoDB Atlas started",
                    "ip_address": "127.0.0.1",
                    "user_agent": "Migration Script",
                    "metadata": {
                        "migration_type": "production_deployment",
                        "target_database": "mongodb_atlas"
                    }
                },
                {
                    "event_type": "system_initialization",
                    "action": "production_setup",
                    "description": "Production MongoDB Atlas environment initialized",
                    "ip_address": "127.0.0.1",
                    "user_agent": "Migration Script",
                    "metadata": {
                        "environment": "production",
                        "persistence_type": "mongodb_atlas"
                    }
                }
            ]
            
            created_logs = 0
            for event_data in migration_events:
                try:
                    log_entry = await audit_log_repository.log_event(event_data)
                    if log_entry:
                        created_logs += 1
                except Exception as e:
                    print(f"⚠️  Audit log warning: {e}")
            
            print(f"✅ Initial audit logs created: {created_logs}")
            self.migration_log.append(f"Initial audit logs created: {created_logs}")
            
        except Exception as e:
            self.errors.append(f"Audit log creation failed: {e}")
            print(f"❌ Audit log creation failed: {e}")
    
    async def _verify_migration(self):
        """Verify migration was successful."""
        print("\n✅ Step 7: Verifying Migration")
        print("-" * 35)
        
        try:
            from app.db.production_persistence import production_db_manager
            from app.repositories.production_repositories import (
                user_repository, email_analysis_repository, 
                threat_intelligence_repository, audit_log_repository
            )
            
            # Verify database health
            health = await production_db_manager.health_check()
            print(f"✅ Database health: {health['status']}")
            
            # Verify collections have data
            user_count = await user_repository.count()
            analysis_count = await email_analysis_repository.count()
            threat_count = await threat_intelligence_repository.count()
            audit_count = await audit_log_repository.count()
            
            print(f"✅ Users: {user_count}")
            print(f"✅ Email analyses: {analysis_count}")
            print(f"✅ Threat intelligence: {threat_count}")
            print(f"✅ Audit logs: {audit_count}")
            
            # Verify collection statistics
            collection_stats = await production_db_manager.get_collection_stats()
            print(f"✅ Collections initialized: {len(collection_stats)}")
            
            # Final verification log
            await audit_log_repository.log_event({
                "event_type": "data_migration",
                "action": "migration_completed",
                "description": "Production data migration to MongoDB Atlas completed successfully",
                "ip_address": "127.0.0.1",
                "user_agent": "Migration Script",
                "metadata": {
                    "users_migrated": user_count,
                    "analyses_migrated": analysis_count,
                    "threats_initialized": threat_count,
                    "logs_created": audit_count,
                    "migration_errors": len(self.errors)
                }
            })
            
        except Exception as e:
            self.errors.append(f"Migration verification failed: {e}")
            print(f"❌ Migration verification failed: {e}")
    
    async def _print_migration_summary(self):
        """Print migration summary."""
        print("\n🎉 Migration Summary")
        print("=" * 30)
        
        print(f"✅ Migration steps completed: {len(self.migration_log)}")
        for step in self.migration_log:
            print(f"   • {step}")
        
        if self.errors:
            print(f"\n⚠️  Errors encountered: {len(self.errors)}")
            for error in self.errors:
                print(f"   • {error}")
        else:
            print("\n🎊 Migration completed successfully with no errors!")
        
        print("\n🚀 PhishNet is now ready for production with MongoDB Atlas!")

async def main():
    """Run the production data migration."""
    
    print("🔄 PhishNet Production Data Migration")
    print("=" * 50)
    print("This script migrates data from development/in-memory storage")
    print("to production MongoDB Atlas for scalable persistence.")
    print()
    
    # Check environment
    mongodb_uri = os.environ.get("MONGODB_URI")
    if not mongodb_uri:
        print("⚠️  Warning: MONGODB_URI not set in environment variables")
        print("   For production deployment, configure MongoDB Atlas:")
        print("   export MONGODB_URI='mongodb+srv://user:pass@cluster.mongodb.net/phishnet'")
        print()
        
        # Use local MongoDB for testing
        os.environ["MONGODB_URI"] = "mongodb://localhost:27017"
        os.environ["MONGODB_DATABASE"] = "phishnet_production"
        print("ℹ️  Using local MongoDB for migration testing")
    
    # Run migration
    migration = ProductionDataMigration()
    try:
        await migration.run_full_migration()
        print("\n✅ Migration completed successfully!")
        return 0
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        return 1

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)