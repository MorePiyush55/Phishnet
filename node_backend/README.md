PhishNet Node OAuth Backend

This folder contains a minimal Express-based OAuth backend for PhishNet (Phase 2 - Backend Implementation).

Quick start
1. Copy `.env.example` to `.env` and fill in values (do NOT commit `.env`).
2. Install dependencies:
   npm install
3. Start server:
   npm start

Endpoints
- GET /auth/google -> Redirects to Google OAuth consent
- GET /auth/google/callback -> OAuth callback, returns JSON with accessToken, refreshToken and user info (in this scaffold)
- POST /auth/logout -> Logs out session

Notes
- This is a minimal scaffold for development and demonstration. In production you should:
  - Persist users in a database and associate refresh tokens securely.
  - Store secrets using the hosting provider's secret manager (Render/Vercel environment variables).
  - Use secure, httpOnly cookies for session tokens where appropriate.
  - Add CSRF/state validation and secure session management.

Smoke test (what I ran)
1. From the repository root install node deps:
   cd node_backend
   npm install

2. Start the server with test environment variables (PowerShell example):

   $env:GOOGLE_CLIENT_ID='test-node-client-123'; $env:GOOGLE_CLIENT_SECRET='test-secret'; $env:GOOGLE_REDIRECT_URI='https://your-backend.render.com/auth/google/callback'; $env:FRONTEND_URL='https://your-frontend.vercel.app'; node server.js

3. In another shell, request the OAuth initiation endpoint without following redirects (PowerShell example):

   Invoke-WebRequest -Uri 'http://localhost:5000/auth/google' -MaximumRedirection 0 -ErrorAction SilentlyContinue | Select-Object StatusCode,Headers

You should see a 3xx response and a Location header containing the Google accounts URL with `client_id` and `redirect_uri`.

4. Stop the server (Ctrl+C in the server terminal) when finished.

Security: do not run this with your real client secret on a public or shared machine. Use environment variables on the host or Render/Vercel secrets in production.
