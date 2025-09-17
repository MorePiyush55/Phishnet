Security considerations for PhishNet

Critical points

- Never expose the Google OAuth client secret in the frontend or public repos.
- Use HTTPS for all production endpoints (Vercel/Render provide TLS by default).
- Use httpOnly, secure cookies for refresh tokens; keep access tokens short-lived.
- Validate OAuth state parameter and implement CSRF protection for form endpoints.
- Limit OAuth scopes to the minimal set required (gmail.readonly, profile, email, openid).
- Log all authentication and email access events to an audit store.
- Rotate secrets regularly and enforce strong JWT secrets and expiration.

Recommended mitigations

- Store client secrets in Render/Vercel environment variables or a secrets manager.
- Use server-side token exchange and never perform token exchange in the browser.
- Use Content-Security-Policy and other browser hardening headers.
- Review CORS config to allow only expected origins.
