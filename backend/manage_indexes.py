"""
MongoDB Index Management Script

This script checks for existing indexes and drops the problematic
email_metadata.message_id_1 index if it exists.
"""

from pymongo import MongoClient

# MongoDB connection string from your Render environment
MONGODB_URI = "mongodb+srv://Propam:Propam%405553@phisnet-db.4qvmhkw.mongodb.net/?retryWrites=true&w=majority&appName=PhisNet-DB"

def manage_indexes():
    """Check and manage indexes on forwarded_email_analyses collection."""
    
    # Connect to MongoDB
    client = MongoClient(MONGODB_URI)
    db = client['phishnet']
    collection = db['forwarded_email_analyses']
    
    print("Current indexes on forwarded_email_analyses collection:")
    print("=" * 60)
    
    # List all indexes
    indexes = collection.list_indexes()
    index_found = False
    
    for idx in indexes:
        print(f"\nIndex: {idx['name']}")
        print(f"  Keys: {idx['key']}")
        if 'unique' in idx:
            print(f"  Unique: {idx['unique']}")
        if 'sparse' in idx:
            print(f"  Sparse: {idx['sparse']}")
        
        # Check if this is the problematic index
        if idx['name'] == 'email_metadata.message_id_1':
            index_found = True
            print("  ⚠️  This is the problematic index!")
    
    print("\n" + "=" * 60)
    
    if index_found:
        print("\n⚠️  Found the problematic index: email_metadata.message_id_1")
        response = input("Do you want to drop this index? (yes/no): ")
        
        if response.lower() == 'yes':
            try:
                collection.drop_index('email_metadata.message_id_1')
                print("✅ Successfully dropped the index!")
                print("Render will create the new sparse index on next deployment.")
            except Exception as e:
                print(f"❌ Error dropping index: {e}")
        else:
            print("Cancelled. Index was not dropped.")
    else:
        print("\n✅ The problematic index does not exist.")
        print("The sparse index will be created on next Render deployment.")
    
    client.close()

if __name__ == "__main__":
    print("MongoDB Index Management Script")
    print("=" * 60)
    manage_indexes()
