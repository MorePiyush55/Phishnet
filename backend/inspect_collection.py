"""
MongoDB Collection Inspector

Checks the state of the forwarded_email_analyses collection.
"""

from pymongo import MongoClient

# MongoDB connection string
MONGODB_URI = "mongodb+srv://Propam:Propam%405553@phisnet-db.4qvmhkw.mongodb.net/?retryWrites=true&w=majority&appName=PhisNet-DB"

def inspect_collection():
    """Inspect the forwarded_email_analyses collection."""
    
    client = MongoClient(MONGODB_URI)
    db = client['phishnet']
    collection = db['forwarded_email_analyses']
    
    print("Collection Inspection Report")
    print("=" * 60)
    
    # Count total documents
    total_count = collection.count_documents({})
    print(f"\nTotal documents: {total_count}")
    
    # Count documents with null message_id
    null_count = collection.count_documents({
        "$or": [
            {"email_metadata.message_id": None},
            {"email_metadata.message_id": {"$exists": False}}
        ]
    })
    print(f"Documents with null message_id: {null_count}")
    
    # Count documents with non-null message_id
    non_null_count = collection.count_documents({
        "email_metadata.message_id": {"$exists": True, "$ne": None}
    })
    print(f"Documents with non-null message_id: {non_null_count}")
    
    # Show sample documents
    if total_count > 0:
        print("\nSample documents:")
        print("-" * 60)
        for doc in collection.find().limit(3):
            print(f"\nDocument ID: {doc.get('_id')}")
            email_metadata = doc.get('email_metadata', {})
            message_id = email_metadata.get('message_id') if email_metadata else None
            print(f"  message_id: {message_id}")
            print(f"  forwarded_by: {doc.get('forwarded_by', 'N/A')}")
    
    # List all indexes
    print("\n" + "=" * 60)
    print("Indexes:")
    indexes = list(collection.list_indexes())
    if indexes:
        for idx in indexes:
            print(f"  - {idx['name']}: {idx['key']}")
    else:
        print("  No indexes found")
    
    print("\n" + "=" * 60)
    print("\nRecommendation:")
    if null_count > 1:
        print(f"⚠️  Found {null_count} documents with null message_id")
        print("   This will cause duplicate key error when creating unique index.")
        print("   Solution: Delete these documents or set unique message_ids")
    elif null_count == 1:
        print("✅ Only 1 document with null message_id - this is OK with sparse index")
    else:
        print("✅ No documents with null message_id - ready for sparse index creation")
    
    client.close()

if __name__ == "__main__":
    inspect_collection()
