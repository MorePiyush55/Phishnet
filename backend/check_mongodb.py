"""Check MongoDB for processed emails"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

load_dotenv()

async def check_db():
    uri = os.getenv('MONGODB_URI', '').strip('"')
    print(f'Connecting to MongoDB...')
    print(f'URI: {uri[:60]}...')
    
    client = AsyncIOMotorClient(uri)
    db = client['phishnet']
    
    # Check forwarded email analyses
    collection = db['forwarded_email_analyses']
    count = await collection.count_documents({})
    print(f'\nTotal forwarded email analyses in DB: {count}')
    
    # Get recent ones
    cursor = collection.find().sort('created_at', -1).limit(5)
    docs = await cursor.to_list(length=5)
    
    print(f'\nRecent analyses:')
    if not docs:
        print('  No analyses found in database!')
    for doc in docs:
        print(f'  - Subject: {str(doc.get("original_subject", "N/A"))[:50]}...')
        print(f'    From: {doc.get("forwarded_by", "N/A")}')
        print(f'    Verdict: {doc.get("risk_level", "N/A")}')
        print(f'    Reply sent: {doc.get("reply_sent", False)}')
        print(f'    Created: {doc.get("created_at", "N/A")}')
        msg_id = doc.get("email_metadata", {}).get("message_id", "N/A")
        print(f'    Message-ID: {str(msg_id)[:60]}...')
        print()
    
    client.close()
    print('Done!')

if __name__ == "__main__":
    asyncio.run(check_db())
