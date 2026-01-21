import asyncio
import os
import sys

# Add backend to path
backend_dir = os.path.join(os.getcwd(), "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Load env before imports
from dotenv import load_dotenv
env_path = os.path.join(backend_dir, ".env")
if os.path.exists(env_path):
    load_dotenv(env_path)

from app.db.mongodb import MongoDBManager

async def check():
    await MongoDBManager.connect_to_mongo()
    db = MongoDBManager.get_database()
    user = await db["users"].find_one({"email": "propam5553@gmail.com"})
    print(f"User propam5553@gmail.com found: {user is not None}")
    if user:
        print(f"Has gmail_access_token: {user.get('gmail_access_token') is not None}")
        print(f"Has oauth_token reference: {user.get('oauth_token') is not None}")
    
    await MongoDBManager.close_mongo_connection()

if __name__ == "__main__":
    asyncio.run(check())
