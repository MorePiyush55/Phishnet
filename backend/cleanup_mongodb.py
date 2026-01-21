"""
MongoDB Cleanup Script - Remove documents with null message_id

This script removes all documents from the forwarded_email_analyses collection
that have null message_id values, which are causing the duplicate key error.

Run this script ONCE to clean up the data, then Render will be able to create
the sparse index successfully.
"""

from pymongo import MongoClient
import os

# MongoDB connection string from your Render environment
MONGODB_URI = "mongodb+srv://Propam:Propam%405553@phisnet-db.4qvmhkw.mongodb.net/?retryWrites=true&w=majority&appName=PhisNet-DB"

def cleanup_null_message_ids():
    """Remove documents with null message_id from forwarded_email_analyses collection."""
    
    # Connect to MongoDB
    client = MongoClient(MONGODB_URI)
    db = client['phishnet']
    collection = db['forwarded_email_analyses']
    
    # Find documents with null message_id
    query = {
        "$or": [
            {"email_metadata.message_id": None},
            {"email_metadata.message_id": {"$exists": False}}
        ]
    }
    
    # Count how many documents will be deleted
    count = collection.count_documents(query)
    print(f"Found {count} documents with null message_id")
    
    if count == 0:
        print("No documents to delete. You're good to go!")
        return
    
    # Ask for confirmation
    response = input(f"Do you want to delete these {count} documents? (yes/no): ")
    
    if response.lower() == 'yes':
        # Delete the documents
        result = collection.delete_many(query)
        print(f"✅ Deleted {result.deleted_count} documents")
        print("MongoDB is now clean. Render will create the sparse index on next deployment.")
    else:
        print("Cancelled. No documents were deleted.")
    
    client.close()

if __name__ == "__main__":
    print("MongoDB Cleanup Script")
    print("=" * 50)
    cleanup_null_message_ids()
