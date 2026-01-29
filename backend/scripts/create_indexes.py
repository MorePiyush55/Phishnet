"""
Create MongoDB Indexes for Mode 1
==================================
Run this script to create all required indexes for production.
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from app.config.settings import get_settings

async def create_indexes():
    """Create all MongoDB indexes for Mode 1."""
    settings = get_settings()
    client = AsyncIOMotorClient(settings.MONGODB_URI)
    db = client.get_default_database()
    
    print("Creating MongoDB indexes...")
    
    # Content Hashes (Deduplication)
    print("  - content_hashes indexes...")
    await db.content_hashes.create_index(
        [("message_id_hash", 1), ("tenant_id", 1)],
        unique=True,
        name="message_id_tenant_unique"
    )
    await db.content_hashes.create_index(
        [("created_at", 1)],
        expireAfterSeconds=2592000,  # 30 days TTL
        name="created_at_ttl"
    )
    await db.content_hashes.create_index(
        [("tenant_id", 1), ("created_at", -1)],
        name="tenant_created_idx"
    )
    
    # Mailbox Configs
    print("  - mailbox_configs indexes...")
    await db.mailbox_configs.create_index(
        [("tenant_id", 1)],
        unique=True,
        name="tenant_id_unique"
    )
    await db.mailbox_configs.create_index(
        [("status", 1)],
        name="status_idx"
    )
    await db.mailbox_configs.create_index(
        [("ownership", 1)],
        name="ownership_idx"
    )
    
    # Mode 1 Audit Logs
    print("  - mode1_audit_logs indexes...")
    await db.mode1_audit_logs.create_index(
        [("tenant_id", 1), ("timestamp", -1)],
        name="tenant_timestamp_idx"
    )
    await db.mode1_audit_logs.create_index(
        [("event_type", 1)],
        name="event_type_idx"
    )
    await db.mode1_audit_logs.create_index(
        [("timestamp", 1)],
        expireAfterSeconds=7776000,  # 90 days TTL
        name="timestamp_ttl"
    )
    
    # Email Analysis Results
    print("  - email_analysis indexes...")
    await db.email_analysis.create_index(
        [("tenant_id", 1), ("analyzed_at", -1)],
        name="tenant_analyzed_idx"
    )
    await db.email_analysis.create_index(
        [("verdict", 1)],
        name="verdict_idx"
    )
    await db.email_analysis.create_index(
        [("message_id", 1)],
        name="message_id_idx"
    )
    
    print("✅ All indexes created successfully!")
    
    # Print index stats
    print("\nIndex Statistics:")
    for collection_name in ["content_hashes", "mailbox_configs", "mode1_audit_logs", "email_analysis"]:
        indexes = await db[collection_name].index_information()
        print(f"  {collection_name}: {len(indexes)} indexes")
    
    client.close()

if __name__ == "__main__":
    asyncio.run(create_indexes())
