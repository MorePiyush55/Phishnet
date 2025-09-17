Deployment checklist for PhishNet

Frontend (Vercel)
- Ensure `frontend/vercel.json` exists and maps environment variables to Vercel secrets.
- Set Vercel Environment Variables (in Project Settings > Environment Variables):
  - `NEXT_PUBLIC_GOOGLE_CLIENT_ID` -> value or add as a Vercel Secret `@google-client-id`
  - `NEXT_PUBLIC_BACKEND_URL` -> your backend URL (e.g., https://phishnet-1ed1.onrender.com)
- Connect your repo to Vercel and enable automatic deployments from the `main` branch.
- If using Next.js, set build command `npm run build` and output directory as `out` for static build or use `next start` for server.

Backend (Render)
- For the FastAPI backend, ensure `backend/render.yaml` is present.
- In Render Dashboard > Environment, set these values (do not commit secrets):
  - `GOOGLE_CLIENT_ID`
  - `GOOGLE_CLIENT_SECRET`
  - `GOOGLE_REDIRECT_URI` = https://<your-backend>.onrender.com/api/v1/auth/google/callback
  - `JWT_SECRET_KEY`
  - `FRONTEND_URL` = https://phishnet-rouge.vercel.app
  - `CORS_ORIGINS` include https://phishnet-rouge.vercel.app and https://localhost:3000 for dev
- Enable Auto deploy from GitHub for the `main` branch.

Optional: Node backend
- If you prefer the Node OAuth backend, add the example service entry in `backend/render.yaml` (see comments) and set secrets accordingly.

Domain & Google Cloud
- Add production redirect URIs to the Google Cloud Console OAuth credentials:
  - https://phishnet-rouge.vercel.app/auth/callback (frontend client redirects)
  - https://phishnet-1ed1.onrender.com/api/v1/auth/google/callback (backend token exchange)
- Update `CORS_ORIGINS` on backend(s) to include production domains.

Testing checklist
1. Development
   - Start backend locally with environment variables.
   - Start frontend Next dev server.
   - Visit http://localhost:3000 -> click login -> ensure redirect to Google accounts URL with correct client_id and redirect_uri.
2. OAuth flow
   - Complete consent screen; verify the backend receives the code at `/api/v1/auth/google/callback`.
   - Verify access token returned and refresh cookie set (httpOnly) in the backend response.
   - Test `/api/v1/auth/refresh` to get a new access token using the cookie.
3. Gmail API
   - Using the granted access token, call the `/emails` or use `app.services.email_service.fetch_and_parse_messages` to fetch messages and ensure scopes were sufficient.

Security checklist
- Do not commit secrets.
- Use httpOnly cookies for refresh tokens.
- Limit CORS origins to production + developer hosts.
- Validate OAuth state on callback.
- Enforce minimal scopes and log access.

Troubleshooting
- If OAuth redirects are incorrect, check the Google Cloud OAuth redirect URIs match exactly.
- For CORS issues, ensure the backend's `CORS_ORIGINS` matches the frontend origin including protocol.
- If tokens fail to exchange, verify `GOOGLE_CLIENT_SECRET` is correctly set in Render.
