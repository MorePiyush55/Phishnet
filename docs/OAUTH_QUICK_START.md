PhishNet OAuth Quick Start

This file explains the minimal steps to configure Google OAuth for PhishNet and how to set environment variables on Vercel (frontend) and Render (backend).

1) Google Cloud Console
- Create OAuth 2.0 Client ID (Web Application)
- Authorized JavaScript origins:
  - https://phishnet-rouge.vercel.app
- Authorized redirect URIs (backend flow):
  - https://phishnet-1ed1.onrender.com/api/v1/auth/google/callback

2) Backend (Render) environment variables
Set the following vars in Render dashboard for the `phishnet-backend` service:
- GOOGLE_CLIENT_ID = <your-client-id>
- GOOGLE_CLIENT_SECRET = <your-client-secret>  (keep secret)
- GOOGLE_REDIRECT_URI = https://phishnet-1ed1.onrender.com/api/v1/auth/google/callback
- FRONTEND_URL = https://phishnet-rouge.vercel.app
- CORS_ORIGINS = https://phishnet-rouge.vercel.app,https://localhost:3000
- DATABASE_URL, REDIS_URL, SECRET_KEY, JWT_SECRET_KEY as required

3) Frontend (Vercel) env vars
- VITE_GOOGLE_CLIENT_ID = <your-client-id>
- VITE_API_BASE_URL = https://phishnet-1ed1.onrender.com

4) Testing locally
- Start backend with:

```powershell
$env:GOOGLE_CLIENT_ID="<your-client-id>"; $env:GOOGLE_CLIENT_SECRET="<your-client-secret>"; python -m uvicorn app.main:app --reload
```

- Start frontend per `frontend/README.md` or `npm run dev` and open https://localhost:3000
- Test login by visiting: https://phishnet-rouge.vercel.app (or the backend /api/v1/auth/login endpoint)

Security notes
- Do NOT commit `GOOGLE_CLIENT_SECRET` to the repo or to Vercel frontend envs.
- Use server-side token exchange. The backend implements `/api/v1/auth/google/callback` to exchange code.
- Use HttpOnly secure cookies for refresh tokens in production.
