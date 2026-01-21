# PhishNet Frontend - Premium Landing Page

## Overview
This is the premium landing page for PhishNet, an AI-powered phishing detection platform. The frontend is deployed on Vercel and integrates with the PhishNet backend for OAuth authentication.

## Structure

### Main Files
- **index.html** - Premium landing page with Tailwind CSS
- **app.js** - Backend integration and OAuth flow handling
- **vercel.json** - Vercel deployment configuration

### Archived Files
- **src.backup/** - Previous React/TypeScript dashboard (archived)
- **package.json** - Node.js dependencies (kept for reference)

## Features

### Landing Page
- 🎨 Premium dark mode design with glassmorphism
- 🚀 Smooth animations and micro-interactions
- 📱 Fully responsive for all devices
- ⚡ Fast loading with minimal dependencies
- 🔒 SEO optimized with proper meta tags

### Backend Integration
- 🔐 Google OAuth authentication flow
- 💾 Local storage for authentication state
- 🔄 Automatic dashboard redirect after login
- 📊 User session management
- 🛡️ Secure token handling

## Deployment

### Vercel
The site is configured for static deployment on Vercel:

```bash
# Deploy to Vercel
vercel --prod
```

### Environment Variables
Set in Vercel dashboard:
- `BACKEND_URL` - Backend API URL (https://phishnet-backend-iuoc.onrender.com)

### Dashboard Redirect
After OAuth authentication, users are redirected to:
- Production: https://phishnet-tau.vercel.app/

## Local Development

### Option 1: Simple HTTP Server
```bash
# Python
python -m http.server 8080

# Node.js
npx http-server -p 8080
```

### Option 2: Live Server (VS Code)
Install the "Live Server" extension and click "Go Live"

## Backend Endpoints

### OAuth Flow
1. **Login**: `GET /auth/google`
   - Initiates Google OAuth flow
   
2. **Callback**: `GET /auth/callback`
   - Handles OAuth callback
   - Returns access token
   
3. **User Info**: `GET /api/v2/user/me`
   - Requires: `Authorization: Bearer <token>`
   - Returns user profile

## File Organization

```
frontend/
├── index.html          # Main landing page
├── app.js             # Backend integration
├── vercel.json        # Deployment config
├── README.md          # This file
├── package.json       # Dependencies (legacy)
└── src.backup/        # Archived React code
```

## Browser Support
- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## Security Features
- Content Security Policy headers
- XSS protection
- Frame protection
- Secure token storage
- HTTPS enforcement

## Notes

### Previous React Dashboard
The previous React/TypeScript dashboard has been archived to `src.backup/`. It can be restored if needed, but the new landing page provides a better first impression and simpler deployment.

### Dashboard Access
Users access the full dashboard at https://phishnet-tau.vercel.app/ after authenticating through the landing page.

## Support
For issues or questions, please refer to the main PhishNet repository documentation.
