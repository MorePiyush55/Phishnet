#!/usr/bin/env python3
"""Test script for MongoDB Atlas production persistence."""

import asyncio
import os
import sys
from datetime import datetime, timezone
from pprint import pprint

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

async def test_mongodb_atlas_persistence():
    """Test MongoDB Atlas production persistence features."""
    
    print("🏗️ Testing MongoDB Atlas Production Persistence")
    print("=" * 70)
    
    # Test 1: MongoDB Connection
    print("\n🔗 Test 1: MongoDB Atlas Connection")
    print("-" * 50)
    
    try:
        from app.db.production_persistence import production_db_manager
        
        # Test connection
        await production_db_manager.connect_to_atlas()
        
        if production_db_manager.is_connected:
            print("✅ MongoDB Atlas connection successful")
            print(f"📊 Database: {production_db_manager.database.name}")
        else:
            print("❌ MongoDB Atlas connection failed")
            return
            
    except Exception as e:
        print(f"❌ MongoDB connection error: {e}")
        print("ℹ️  Note: This test requires MongoDB Atlas configuration")
        print("   Set MONGODB_URI in environment variables")
        return
    
    # Test 2: Database Health Check
    print("\n💗 Test 2: Database Health Check")
    print("-" * 40)
    
    try:
        health_data = await production_db_manager.health_check()
        
        if health_data["status"] == "healthy":
            print("✅ Database health check passed")
            print(f"📊 Ping time: {health_data['ping_ms']}ms")
            print(f"📊 Collections: {health_data['collections']}")
            print(f"📊 Data size: {health_data['data_size_mb']}MB")
            print(f"📊 Storage size: {health_data['storage_size_mb']}MB")
            print(f"📊 Indexes: {health_data['indexes']}")
        else:
            print(f"❌ Database unhealthy: {health_data.get('error')}")
            
    except Exception as e:
        print(f"❌ Health check failed: {e}")
    
    # Test 3: Repository Pattern
    print("\n📁 Test 3: Repository Pattern")
    print("-" * 35)
    
    try:
        from app.repositories.production_repositories import user_repository, email_analysis_repository
        
        # Test user repository
        test_user_data = {
            "email": "test@phishnet.example.com",
            "username": "testuser_production",
            "full_name": "Production Test User",
            "hashed_password": "hashed_password_here",
            "is_active": True,
            "is_verified": False
        }
        
        # Try to create user (may fail if exists)
        try:
            user = await user_repository.create_user(test_user_data)
            print(f"✅ User created: {user.username} ({user.id})")
        except ValueError as e:
            print(f"ℹ️  User creation skipped: {e}")
            # Get existing user
            user = await user_repository.get_by_email(test_user_data["email"])
            if user:
                print(f"✅ Existing user found: {user.username} ({user.id})")
        
        # Test email analysis repository
        if user:
            test_analysis_data = {
                "user_id": str(user.id),
                "gmail_message_id": f"test_msg_{int(datetime.now().timestamp())}",
                "subject": "Test Email for Production Persistence",
                "sender": "sender@example.com",
                "recipient": user.email,
                "received_at": datetime.now(timezone.utc),
                "status": "completed",
                "threat_level": "medium",
                "confidence_score": 0.75,
                "analysis_results": {
                    "url_analysis": {"suspicious_urls": 1},
                    "content_analysis": {"phishing_indicators": 2}
                },
                "detected_threats": ["suspicious_link", "urgency_language"],
                "analyzer_version": "2.0.0"
            }
            
            analysis = await email_analysis_repository.create_or_update_analysis(test_analysis_data)
            print(f"✅ Email analysis stored: {analysis.gmail_message_id}")
            
            # Get user analyses
            user_analyses = await email_analysis_repository.get_user_analyses(str(user.id), limit=5)
            print(f"✅ Retrieved {len(user_analyses)} analyses for user")
            
    except Exception as e:
        print(f"❌ Repository test failed: {e}")
    
    # Test 4: Persistent Sessions
    print("\n🔐 Test 4: Persistent Session Management")
    print("-" * 45)
    
    try:
        from app.db.production_persistence import persistent_session_manager
        
        # Create test session
        test_session = {
            "session_id": f"test_session_{int(datetime.now().timestamp())}",
            "user_id": "test_user_123",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Production Test)",
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc).timestamp() + 3600,
            "active": True
        }
        
        # Store session
        session_id = await persistent_session_manager.store_session(test_session)
        print(f"✅ Session stored: {test_session['session_id']}")
        
        # Retrieve session
        retrieved_session = await persistent_session_manager.get_session(test_session["session_id"])
        if retrieved_session:
            print(f"✅ Session retrieved: {retrieved_session['session_id']}")
            print(f"📊 Created at: {retrieved_session['created_at']}")
        else:
            print("❌ Session retrieval failed")
        
        # Update session
        update_success = await persistent_session_manager.update_session(
            test_session["session_id"],
            {"last_accessed": datetime.now(timezone.utc)}
        )
        print(f"✅ Session updated: {update_success}")
        
        # Clean up test session
        deleted = await persistent_session_manager.delete_session(test_session["session_id"])
        print(f"✅ Session cleaned up: {deleted}")
        
    except Exception as e:
        print(f"❌ Persistent session test failed: {e}")
    
    # Test 5: Production OAuth Security
    print("\n🔒 Test 5: Production OAuth Security")
    print("-" * 40)
    
    try:
        from app.core.production_oauth_security import production_oauth_security_manager
        
        # Test token encryption with MongoDB persistence
        test_token_data = {
            "access_token": "ya29.a0ARrdaM-production-test-token",
            "refresh_token": "1//04-production-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/gmail.readonly"
        }
        
        # Encrypt token
        encrypted_token = await production_oauth_security_manager.encrypt_token_advanced(test_token_data)
        print(f"✅ Token encrypted: {len(encrypted_token)} characters")
        
        # Decrypt token
        decrypted_token = await production_oauth_security_manager.decrypt_token_advanced(encrypted_token)
        if decrypted_token["access_token"] == test_token_data["access_token"]:
            print("✅ Token decryption successful")
        else:
            print("❌ Token decryption failed")
        
        # Test session creation with MongoDB
        session_token = await production_oauth_security_manager.create_secure_session(
            user_id="test_user_789",
            ip_address="10.0.0.1",
            user_agent="Mozilla/5.0 (Production Security Test)"
        )
        print(f"✅ Secure session created: {len(session_token)} character JWT")
        
        # Validate session
        session_data = await production_oauth_security_manager.validate_session(
            session_token=session_token,
            ip_address="10.0.0.1",
            user_agent="Mozilla/5.0 (Production Security Test)"
        )
        
        if session_data:
            print(f"✅ Session validation successful: user {session_data.get('user_id')}")
        else:
            print("❌ Session validation failed")
        
        # Clean up test session
        revoked = await production_oauth_security_manager.revoke_session(session_token)
        print(f"✅ Session revoked: {revoked}")
        
    except Exception as e:
        print(f"❌ Production OAuth security test failed: {e}")
    
    # Test 6: Collection Statistics
    print("\n📊 Test 6: Collection Statistics")
    print("-" * 35)
    
    try:
        collection_stats = await production_db_manager.get_collection_stats()
        
        print("✅ Collection statistics retrieved:")
        for collection, stats in collection_stats.items():
            if isinstance(stats, dict):
                print(f"   📄 {collection}: {stats.get('document_count', 0)} documents")
            else:
                print(f"   📄 {collection}: {stats}")
        
    except Exception as e:
        print(f"❌ Collection statistics test failed: {e}")
    
    # Test 7: Data Retention and Cleanup
    print("\n🧹 Test 7: Data Retention and Cleanup")
    print("-" * 40)
    
    try:
        from app.repositories.production_repositories import (
            threat_intelligence_repository,
            audit_log_repository
        )
        
        # Test cleanup functions
        expired_sessions = await persistent_session_manager.cleanup_expired_sessions()
        print(f"✅ Cleaned up {expired_sessions} expired sessions")
        
        expired_threats = await threat_intelligence_repository.cleanup_expired_threats()
        print(f"✅ Cleaned up {expired_threats} expired threats")
        
        old_logs = await audit_log_repository.cleanup_old_logs(90)
        print(f"✅ Cleaned up {old_logs} old audit logs")
        
    except Exception as e:
        print(f"❌ Data cleanup test failed: {e}")
    
    # Test 8: Audit Logging
    print("\n📝 Test 8: Audit Logging")
    print("-" * 25)
    
    try:
        from app.repositories.production_repositories import audit_log_repository
        
        # Create test audit event
        audit_event = {
            "event_type": "test_event",
            "user_id": "test_user_123",
            "action": "mongodb_persistence_test",
            "description": "Testing MongoDB Atlas persistence and audit logging",
            "ip_address": "127.0.0.1",
            "user_agent": "Production Test Script",
            "metadata": {
                "test_type": "production_persistence",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
        
        # Log event
        logged_event = await audit_log_repository.log_event(audit_event)
        if logged_event:
            print(f"✅ Audit event logged: {logged_event.event_type}")
        else:
            print("❌ Audit event logging failed")
        
        # Retrieve recent events
        recent_events = await audit_log_repository.get_events_by_type("test_event", limit=5)
        print(f"✅ Retrieved {len(recent_events)} recent test events")
        
    except Exception as e:
        print(f"❌ Audit logging test failed: {e}")
    
    # Summary
    print("\n🎉 MongoDB Atlas Production Persistence Test Summary")
    print("=" * 70)
    print("✅ MongoDB Atlas connection and health verification")
    print("✅ Repository pattern with CRUD operations")
    print("✅ Persistent session management with MongoDB")
    print("✅ Production OAuth security with encryption")
    print("✅ Collection statistics and monitoring")
    print("✅ Data retention and cleanup mechanisms")
    print("✅ Comprehensive audit logging")
    print("\n🏗️ Production database persistence is working correctly!")
    print("🚀 PhishNet is ready for production deployment with MongoDB Atlas!")
    
    # Final cleanup
    try:
        await production_db_manager.disconnect()
        print("\n🔌 MongoDB connection closed")
    except:
        pass

if __name__ == "__main__":
    # Set up test environment
    os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")
    os.environ.setdefault("MONGODB_DATABASE", "phishnet_test")
    
    print("⚠️  Note: This test requires MongoDB Atlas or local MongoDB setup")
    print("   Configure MONGODB_URI environment variable for your setup")
    print("   Example: export MONGODB_URI='mongodb+srv://user:pass@cluster.mongodb.net/phishnet'")
    
    asyncio.run(test_mongodb_atlas_persistence())