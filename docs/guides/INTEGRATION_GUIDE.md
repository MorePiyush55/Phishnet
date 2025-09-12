# PhishNet Integration Guide

This document explains how to integrate the React frontend with the FastAPI backend.

## Quick Start

### 1. Start the Backend

```bash
# In the project root directory
cd c:\Users\piyus\AppData\Local\Programs\Python\Python313\project\Phishnet

# Activate virtual environment
phishnet_env\Scripts\Activate.ps1

# Install backend dependencies (if not already done)
pip install -r requirements.txt

# Initialize the database
python scripts/init_complete_db.py

# Start the backend server
python run.py
```

The backend will be available at `http://localhost:8000`

### 2. Start the Frontend

```bash
# In a new terminal, navigate to frontend directory
cd frontend

# Install dependencies (first time only)
npm install

# Start the development server
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Backend Integration Points

### 1. API Endpoints

The frontend connects to these backend endpoints:

- **Authentication**: `/api/v1/auth/login`, `/api/v1/auth/refresh`
- **Emails**: `/api/v1/emails/`, `/api/v1/emails/{id}`
- **Links**: `/api/v1/links/`, `/api/v1/emails/{id}/links`
- **Analysis**: `/api/v1/analysis/reprocess/{id}`
- **Audits**: `/api/v1/audits/logs`
- **System**: `/api/v1/system/stats`, `/api/v1/system/health`
- **WebSocket**: `/api/v1/ws`

### 2. Authentication Flow

1. Frontend sends credentials to `/api/v1/auth/login`
2. Backend returns access_token and refresh_token
3. Frontend stores tokens in localStorage
4. All subsequent API requests include `Authorization: Bearer {access_token}`
5. On 401 errors, frontend automatically refreshes token using `/api/v1/auth/refresh`

### 3. WebSocket Integration

- Frontend connects to WebSocket at `/api/v1/ws?token={access_token}`
- Backend sends real-time events for email processing, status updates, threats
- Frontend automatically updates UI and React Query cache based on events

## Backend Requirements

### 1. CORS Configuration

Ensure the backend allows requests from `http://localhost:3000`:

```python
# In app/main.py
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 2. Database Schema

The frontend expects the complete database schema implemented in:
- `app/models/complete_schema.py`
- Migration: `migrations/versions/001_create_complete_schema.py`

### 3. Sample Data

Initialize the database with sample data:

```bash
python scripts/init_complete_db.py
```

This creates:
- 3 test users (admin/admin, analyst/analyst, viewer/viewer)
- Sample phishing and legitimate emails
- Link analysis data
- AI analysis results

## Testing the Integration

### 1. Login Test

1. Open `http://localhost:3000`
2. Should redirect to login page
3. Use credentials: `admin` / `admin`
4. Should redirect to dashboard and show email list

### 2. Real-time Updates

1. Have the dashboard open in browser
2. Use another tool (Postman, curl) to update an email status via API
3. Dashboard should automatically reflect the changes without refresh

### 3. Email Operations

1. Select an email from the list
2. View details in the right panel
3. Use actions (Quarantine, Mark Safe, Delete)
4. Verify the email status updates in the backend database

## Troubleshooting

### Backend Issues

1. **Port 8000 in use**: Change port in `run.py` and update frontend `.env`
2. **Database connection errors**: Check PostgreSQL is running and connection string
3. **Import errors**: Ensure all dependencies installed with `pip install -r requirements.txt`

### Frontend Issues

1. **API connection fails**: Verify backend is running on port 8000
2. **CORS errors**: Check CORS middleware configuration in backend
3. **Authentication fails**: Verify JWT secret and database user accounts

### Common Integration Issues

1. **WebSocket connection fails**:
   - Check backend WebSocket endpoint is implemented
   - Verify authentication token is valid
   - Check browser developer tools for WebSocket errors

2. **Data not loading**:
   - Verify backend API endpoints return expected JSON format
   - Check browser network tab for API request/response
   - Ensure database is initialized with sample data

3. **Real-time updates not working**:
   - Verify WebSocket connection in browser developer tools
   - Check backend is sending events in expected format
   - Ensure frontend event handlers are properly registered

## Production Deployment

### Environment Variables

**Backend** (.env):
```
DATABASE_URL=postgresql://user:password@localhost/phishnet
JWT_SECRET_KEY=your-secret-key
GMAIL_CREDENTIALS_PATH=/path/to/credentials.json
```

**Frontend** (.env):
```
REACT_APP_API_URL=https://your-api-domain.com
```

### Build Commands

**Backend**:
```bash
# Use a production ASGI server like uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Frontend**:
```bash
# Build for production
npm run build

# Serve with a static file server
npx serve -s dist -l 3000
```

## API Documentation

Once the backend is running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

This provides interactive API documentation for all endpoints.
