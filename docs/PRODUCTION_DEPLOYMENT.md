# PhishNet Production Deployment Guide

## Overview
This guide provides step-by-step instructions for deploying PhishNet to production environments.

## Prerequisites

### 1. Production Infrastructure
- **Backend**: Container hosting service (Render, Railway, Fly.io, AWS ECS, etc.)
- **Frontend**: Static hosting service (Vercel, Netlify, AWS S3+CloudFront, etc.)
- **Database**: PostgreSQL instance (managed service recommended)
- **Domain**: Custom domain names for both frontend and backend

### 2. External Service Accounts
- **Google Cloud Console**: For Gmail OAuth integration
- **VirusTotal**: API key for malware analysis
- **AbuseIPDB**: API key for IP reputation checks
- **Google AI Studio**: API key for Gemini AI services
- **MongoDB Atlas**: Database hosting (or PostgreSQL alternative)

## Backend Deployment

### Step 1: Prepare Environment Configuration

1. **Copy production template**:
   ```bash
   cp backend/.env.production backend/.env
   ```

2. **Update configuration** with your production values:
   ```bash
   # Database - Choose MongoDB or PostgreSQL
   # Option A: MongoDB Atlas
   USE_MONGODB=true
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database
   MONGODB_DATABASE=phishnet
   MONGODB_PASSWORD=your_mongodb_password
   
   # Option B: PostgreSQL
   DATABASE_URL=postgresql://user:password@host:5432/phishnet
   
   # API Keys
   VIRUSTOTAL_API_KEY=your_actual_key
   ABUSEIPDB_API_KEY=your_actual_key
   GOOGLE_API_KEY=your_actual_key
   
   # Security
   JWT_SECRET_KEY=your_secure_random_key
   SECRET_KEY=your_secure_random_key
   PHISHNET_MASTER_KEY=your_master_encryption_key
   
   # URLs
   BASE_URL=https://your-api-domain.com
   FRONTEND_URL=https://your-frontend-domain.com
   CORS_ORIGINS=["https://your-frontend-domain.com"]
   
   # OAuth
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   GOOGLE_REDIRECT_URI=https://your-api-domain.com/oauth2callback
   ```

### Step 2: Configure Google OAuth

1. **Update Google Cloud Console**:
   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Navigate to Credentials > OAuth 2.0 Client IDs
   - Update authorized redirect URIs:
     ```
     https://your-api-domain.com/oauth2callback
     ```
   - Update authorized JavaScript origins:
     ```
     https://your-frontend-domain.com
     ```

### Step 3: Deploy Backend

#### Option A: Render.com
1. Connect your GitHub repository
2. Create new Web Service
3. Configure build and start commands:
   ```
   Build Command: pip install -r requirements.txt
   Start Command: uvicorn app.main:app --host 0.0.0.0 --port $PORT
   ```
4. Add environment variables from your `.env` file

#### Option B: Railway
1. Connect GitHub repository
2. Deploy with environment variables
3. Configure custom domain

#### Option C: Docker
1. Build and push to container registry:
   ```bash
   docker build -t phishnet-backend .
   docker tag phishnet-backend your-registry/phishnet-backend
   docker push your-registry/phishnet-backend
   ```

### Step 4: Database Setup

1. **Run migrations**:
   ```bash
   alembic upgrade head
   ```

2. **Verify health endpoints**:
   ```bash
   curl https://your-api-domain.com/health
   curl https://your-api-domain.com/docs
   ```

## Frontend Deployment

### Step 1: Configure Environment

1. **Copy production template**:
   ```bash
   cp frontend/.env.production frontend/.env
   ```

2. **Update with production URLs**:
   ```bash
   VITE_API_BASE_URL=https://your-api-domain.com
   VITE_API_URL=https://your-api-domain.com
   VITE_WS_BASE_URL=wss://your-api-domain.com
   VITE_GOOGLE_CLIENT_ID=your_google_client_id
   ```

### Step 2: Build and Deploy

#### Option A: Vercel
1. Connect GitHub repository
2. Configure build settings:
   ```
   Framework Preset: Vite
   Build Command: npm run build
   Output Directory: dist
   ```
3. Add environment variables
4. Deploy

#### Option B: Netlify
1. Connect repository
2. Configure build:
   ```
   Build command: npm run build
   Publish directory: dist
   ```
3. Set environment variables
4. Deploy

#### Option C: AWS S3 + CloudFront
1. Build locally:
   ```bash
   npm run build
   ```
2. Upload to S3 bucket
3. Configure CloudFront distribution
4. Set up custom domain

## Security Configuration

### 1. SSL/TLS Certificates
- Enable HTTPS on both frontend and backend
- Use managed certificates (Let's Encrypt, cloud provider managed)
- Configure HSTS headers

### 2. Firewall and Access Control
- Restrict database access to backend only
- Configure API rate limiting
- Set up WAF rules if using cloud services

### 3. Secret Management
- Use cloud secret managers (AWS Secrets Manager, etc.)
- Rotate API keys regularly
- Monitor access to sensitive endpoints

## Google OAuth Publication

### 1. Privacy Policy and Terms of Service
Your app needs these pages accessible at:
- `https://your-api-domain.com/privacy`
- `https://your-api-domain.com/terms`

### 2. OAuth Consent Screen Configuration
1. Complete all required fields in Google Cloud Console
2. Add authorized domains:
   - `your-frontend-domain.com`
   - `your-api-domain.com`
3. Configure scopes:
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `https://www.googleapis.com/auth/userinfo.email`
   - `https://www.googleapis.com/auth/userinfo.profile`

### 3. App Verification (Optional)
For production use without "unverified app" warning:
1. Submit for Google verification
2. Provide app demonstration video
3. Complete security assessment

## Monitoring and Maintenance

### 1. Health Monitoring
Set up monitoring for:
- `/health` endpoint
- Database connectivity
- External API availability

### 2. Logging
Configure structured logging:
- Application logs
- Access logs
- Error tracking (Sentry recommended)

### 3. Backup Strategy
- Automated database backups
- Configuration backup
- Recovery procedures

### 4. Updates
- Monitor for security updates
- Test updates in staging environment
- Implement blue-green deployment

## Environment Variables Summary

### Required Backend Variables
```bash
DATABASE_URL=postgresql://...
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
GOOGLE_API_KEY=...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
JWT_SECRET_KEY=...
SECRET_KEY=...
BASE_URL=https://your-api-domain.com
FRONTEND_URL=https://your-frontend-domain.com
GOOGLE_REDIRECT_URI=https://your-api-domain.com/oauth2callback
CORS_ORIGINS=["https://your-frontend-domain.com"]
```

### Required Frontend Variables
```bash
VITE_API_BASE_URL=https://your-api-domain.com
VITE_GOOGLE_CLIENT_ID=...
```

## Troubleshooting

### Common Issues
1. **CORS Errors**: Verify CORS_ORIGINS includes your frontend domain
2. **OAuth Errors**: Check redirect URIs in Google Cloud Console
3. **Database Connection**: Verify DATABASE_URL and firewall rules
4. **API Timeouts**: Adjust timeout settings for external services

### Testing Production Deployment
1. Test OAuth flow end-to-end
2. Verify email analysis functionality
3. Check all API endpoints
4. Test WebSocket connections
5. Validate security headers

## Support
For deployment issues, check:
1. Application logs
2. Service provider status pages
3. External API status (VirusTotal, Google, etc.)
4. Database connectivity