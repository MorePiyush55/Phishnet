# MongoDB Setup Guide for PhishNet

## Overview

PhishNet now supports MongoDB Atlas as an alternative to SQLite/PostgreSQL. This guide helps you configure and use MongoDB for production deployments.

## MongoDB Atlas Connection

### Your MongoDB Details:
- **Cluster URI**: `mongodb+srv://Propam:<db_password>@phisnet-db.4qvmhkw.mongodb.net/?retryWrites=true&w=majority&appName=PhisNet-DB`
- **Database Name**: `phishnet`
- **Username**: `Propam`

## Configuration Steps

### 1. Set Environment Variables

Update your `backend/.env` file:

```bash
# Enable MongoDB
USE_MONGODB=true

# MongoDB Configuration
MONGODB_URI=mongodb+srv://Propam:<db_password>@phisnet-db.4qvmhkw.mongodb.net/?retryWrites=true&w=majority&appName=PhisNet-DB
MONGODB_DATABASE=phishnet
MONGODB_PASSWORD=your-actual-mongodb-password
```

### 2. Install MongoDB Dependencies

The following packages have been added to `requirements.txt`:

```
# MongoDB Support
motor==3.3.2          # Async MongoDB driver
pymongo==4.6.1        # MongoDB Python driver
beanie==1.23.6         # MongoDB ODM for Python
```

Install them:

```bash
cd backend
pip install -r requirements.txt
```

### 3. Document Models

MongoDB documents are defined in `backend/app/models/mongodb_models.py`:

- **User**: User accounts and OAuth tokens
- **EmailAnalysis**: Email analysis results and metadata
- **ThreatIntelligence**: Threat indicators and intelligence data
- **AnalysisJob**: Background job tracking
- **AuditLog**: System audit logs

### 4. Database Connection

The MongoDB connection is managed by `backend/app/db/mongodb.py`:

- Automatic connection management
- Connection pooling
- Error handling and retries
- Health checks

## Usage Examples

### 1. User Management

```python
from app.models.mongodb_models import User
from datetime import datetime, timezone

# Create a new user
user = User(
    email="user@example.com",
    username="testuser",
    full_name="Test User",
    hashed_password="hashed_password_here",
    created_at=datetime.now(timezone.utc)
)
await user.save()

# Find user by email
user = await User.find_one(User.email == "user@example.com")

# Update user
user.is_verified = True
await user.save()
```

### 2. Email Analysis

```python
from app.models.mongodb_models import EmailAnalysis, ThreatLevel, EmailStatus

# Create email analysis
analysis = EmailAnalysis(
    user_id=str(user.id),
    gmail_message_id="msg_123",
    subject="Suspicious Email",
    sender="suspicious@example.com",
    recipient="user@example.com",
    received_at=datetime.now(timezone.utc),
    status=EmailStatus.COMPLETED,
    threat_level=ThreatLevel.HIGH,
    confidence_score=0.95,
    detected_threats=["phishing", "credential_harvesting"]
)
await analysis.save()

# Query analyses
high_threat_emails = await EmailAnalysis.find(
    EmailAnalysis.threat_level == ThreatLevel.HIGH
).to_list()
```

### 3. Threat Intelligence

```python
from app.models.mongodb_models import ThreatIntelligence

# Add threat indicator
threat = ThreatIntelligence(
    indicator="malicious-site.com",
    indicator_type="domain",
    threat_type="phishing",
    threat_level=ThreatLevel.HIGH,
    confidence_score=0.9,
    source="manual",
    description="Known phishing domain"
)
await threat.save()

# Check if URL is malicious
domain = "suspicious-site.com"
threat_info = await ThreatIntelligence.find_one(
    ThreatIntelligence.indicator == domain
)
```

## Health Checks

MongoDB health is monitored through:

```bash
# Check MongoDB connectivity
curl http://localhost:8000/health

# MongoDB-specific health check
curl http://localhost:8000/health/mongodb
```

## Migration from SQLite

### 1. Data Export (if needed)

If you have existing data in SQLite, create a migration script:

```python
# migration_script.py
import asyncio
from sqlalchemy import create_engine
from app.db.mongodb import MongoDBManager
from app.models.mongodb_models import DOCUMENT_MODELS

async def migrate_data():
    # Initialize MongoDB
    await MongoDBManager.connect_to_mongo()
    await MongoDBManager.initialize_beanie(DOCUMENT_MODELS)
    
    # Your migration logic here
    # Read from SQLite, transform, write to MongoDB
```

### 2. Switch Configuration

Update environment variables:

```bash
# Change from SQLite to MongoDB
USE_MONGODB=true
```

## Production Deployment

### 1. Environment Variables

For production, set these environment variables:

```bash
USE_MONGODB=true
MONGODB_URI=mongodb+srv://Propam:YOUR_PASSWORD@phisnet-db.4qvmhkw.mongodb.net/?retryWrites=true&w=majority&appName=PhisNet-DB
MONGODB_DATABASE=phishnet
MONGODB_PASSWORD=your-secure-production-password
```

### 2. Security Considerations

- **Connection Security**: MongoDB Atlas provides encrypted connections
- **Authentication**: Uses MongoDB native authentication
- **Network Access**: Configure IP whitelist in MongoDB Atlas
- **Backup**: MongoDB Atlas provides automated backups

### 3. Performance Optimization

The models include optimized indexes:

- User queries by email/username
- Email analysis by user and date
- Threat intelligence by indicator
- Efficient compound indexes for common queries

## Monitoring

### Database Metrics

Monitor these MongoDB metrics:

- Connection count
- Query performance
- Storage usage
- Index usage
- Replication lag (if applicable)

### Application Metrics

The health check system monitors:

- Connection status
- Query response times
- Error rates
- Document counts

## Troubleshooting

### Common Issues

1. **Connection Timeout**
   - Check network connectivity
   - Verify MongoDB Atlas IP whitelist
   - Check firewall settings

2. **Authentication Failed**
   - Verify username/password
   - Check connection string format
   - Ensure user has proper permissions

3. **Performance Issues**
   - Review query patterns
   - Check index usage
   - Monitor connection pool

### Debug Commands

```bash
# Test MongoDB connection
python -c "
import asyncio
from app.db.mongodb import ping_mongodb
print(asyncio.run(ping_mongodb()))
"

# Check collection status
python -c "
import asyncio
from app.db.mongodb import get_mongo_database
async def check():
    db = await get_mongo_database()
    collections = await db.list_collection_names()
    print('Collections:', collections)
asyncio.run(check())
"
```

## Support

For MongoDB-related issues:

1. Check the application logs for connection errors
2. Verify MongoDB Atlas cluster status
3. Test connection with MongoDB Compass
4. Review network and firewall settings

Your PhishNet application is now ready to use MongoDB Atlas for scalable, production-ready data storage! 🚀