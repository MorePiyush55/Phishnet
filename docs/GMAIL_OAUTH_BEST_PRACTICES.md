# Gmail OAuth & API Best Practices for PhishNet

This document summarizes best practices for integrating Google OAuth and the Gmail API in PhishNet. It covers minimal scopes, error handling for API limits, caching strategies, privacy considerations, token refresh logic, a production checklist, and troubleshooting guidance.

## Principle: Least privilege (request minimal required scopes)
- Start with the narrowest scopes you need and expand only when absolutely necessary.
  - Recommended minimal scopes for read-only email analysis:
    - `openid` (identification), `email`, `profile`
    - `https://www.googleapis.com/auth/gmail.readonly` (read-only access)
  - If you only need a user's basic profile + email address: `openid email profile`.
  - If you only need access to specific messages (e.g., messages with a label) prefer incremental/granular access and request the Gmail-read scope only when the user opts in.
- Use incremental authorization when possible (request base scopes first, then request Gmail scopes only when the user chooses to connect their mailbox).

## Token handling & refresh logic
- Store client secrets only on the backend and keep them out of source control.
- Use the Authorization Code flow with server-side exchange (never expose client_secret on the frontend).
- Persist refresh tokens server-side (encrypted at rest) and associate them with a user record and device/session metadata.
  - Consider rotating refresh tokens and storing the latest refresh token; detect revocation and re-auth accordingly.
- Use short-lived access tokens and the refresh token to obtain new access tokens when needed.
- Refresh flow recommendations:
  - Prefer a dedicated backend endpoint (e.g., `/auth/refresh`) that reads a refresh token from a secure httpOnly cookie or server session and returns a fresh access token.
  - Respect Google's refresh behavior: the first token response may include a refresh token, subsequent responses may not (unless `access_type=offline` and `prompt=consent` are used).
  - Handle failures gracefully: if refresh fails due to invalid_grant, force re-authentication (inform the user and clear stored sessions).
  - Protect the refresh endpoint with rate limits and monitoring.
- Revoke tokens on logout and provide a way for users to disconnect their account (call Google revocation endpoint and delete stored refresh tokens).

## Respect user privacy — only access necessary emails
- Principle: only read messages the user explicitly allows the app to analyze.
- Avoid blanket access to all mailboxes. Limit access to:
  - A single label/folder that the user opts to analyze, or
  - Messages the user selects via the UI.
- Minimize storage of email content; if you must store, store only derived metadata or hashes and ensure clear retention policies.
- Provide clear UI prompts during consent explaining what kinds of emails will be accessed and why.
- Annotate audit logs with purpose, scope, and user consent for every mailbox access.

## Caching and sync strategies
- Prefer incremental sync using Gmail's `historyId` where possible to only fetch changed messages rather than full mailboxes.
- Use conditional requests and `If-Modified-Since`/`ETag` patterns where applicable for other APIs.
- Cache parsed results (e.g., parsed headers, snippets, aggregated features) instead of full raw messages to reduce API calls and storage.
- Implement cache invalidation logic tied to message updates and historyId changes.
- Respect privacy and retention when implementing caches — expire cached email-derived data according to policy.

## Rate limits & error handling
- Detect and handle HTTP 429 (Too Many Requests) and 5xx errors with exponential backoff and jitter.
  - Observe `Retry-After` response headers when provided and honor them.
- Throttle requests per-user and globally to avoid hitting quotas.
  - Implement per-user token bucket or leaky-bucket throttling to smooth bursts.
- Use exponential backoff with jitter for retries; cap retry count and log failures for monitoring.
- For transient failures (network, 5xx) retry; for client errors (4xx) do not retry except where recommended (e.g., 429).
- Monitor API usage and errors (set alerts for error rate spikes and approaching quota limits).

## Performance & cost considerations
- Prefer batch or partial fetches: request only the fields needed via `fields`/`format` parameters (e.g., `format=metadata` instead of `full` when possible).
- Avoid fetching full message bodies unless necessary; use snippets or metadata for classification heuristics.
- Use the `messages.list` endpoint with reasonable `maxResults` and paging.

## Security and operational best practices
- Keep all secrets (client_secret, API keys) in secure secret stores (Render secrets, Vercel environment variables) — never commit them.
- Use HTTPS everywhere; restrict cookie scope and use `Secure`, `HttpOnly`, and `SameSite` attributes for cookies storing refresh tokens.
- Validate the `state` parameter on OAuth responses to mitigate CSRF.
- Use PKCE if supporting public clients.
- Enforce least-privilege IAM for the GCP project; enable only the Gmail API.
- Log access to mailbox data (audit trail) and surface meaningful alerts for suspicious patterns (bulk downloads, unusual label access).

## Production checklist (Before going live)
- Test the complete authentication flow end-to-end in a staging environment (including consent screen flows and refresh token issuance).
- Verify the Gmail API is enabled in the GCP project and OAuth consent screen is published.
- Confirm all production URLs (redirect URIs) are configured properly in the GCP console.
- Ensure environment variables and secret values are set in Render/Vercel and not in source.
- Test error scenarios: rate limits, revoked tokens, network failures, invalid credentials.
- Implement monitoring and alerting for API errors, quota usage, and auth failures.
- Set up backup auth methods for admin access (e.g., SSO or emergency admin accounts) in case Google OAuth is unavailable.
- Test with multiple Google accounts and tenants to validate consent screen behavior and edge cases.
- Review GDPR/data protection implications; provide data deletion and export options as required.
- Document expected API rate limits and quotas for your team and include mitigation strategies.

## Troubleshooting common issues

### Authentication issues
- Invalid redirect URI: Verify redirect URI exactly matches the one registered in the Google Cloud Console (including trailing slashes and https vs http).
- Access blocked / consent not shown: Ensure OAuth consent screen is configured and published; verify the scopes are approved for the user pool (test users vs public app).
- Token refresh fails: Check refresh token persistence and validity; inspect error from Google (e.g., `invalid_grant` means token revoked or expired). Force re-auth if needed.
- CORS errors: Ensure your backend allows the frontend origin in CORS settings (do not rely on wildcard in production).

### Email access issues
- Insufficient permissions: Confirm you requested the correct Gmail scopes and that the user granted them.
- API not enabled: Ensure Gmail API is enabled in GCP project.
- Quota exceeded: Monitor usage; apply throttling and consider requesting quota increases from Google if justified.
- Invalid credentials: Check the stored refresh token or access token; attempt a refresh and re-authenticate on persistent failures.

## Operational suggestions
- Consider using Gmail Push Notifications (watch API) to receive changes instead of polling, but be careful with webhook scaling & security.
- For heavy analysis workloads, design a per-user job queue and rate-limited workers to process mailboxes in the background.
- Regularly audit which accounts have granted access and offer users an easy way to disconnect their account.

## References and links
- Gmail API: https://developers.google.com/gmail/api
- OAuth 2.0 for Web Server Applications: https://developers.google.com/identity/protocols/oauth2/web-server
- Best practices for using Google APIs: https://cloud.google.com/apis/docs/best-practices


---

Created by the PhishNet engineering helper — use this as a living document and update it as you learn from production telemetry.
