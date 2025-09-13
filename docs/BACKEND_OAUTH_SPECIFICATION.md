# Backend OAuth2 Endpoints Technical Specification

## Overview

This document provides detailed technical specifications for implementing the backend OAuth2 endpoints for Gmail integration in PhishNet.

## API Endpoint Specifications

### 1. OAuth Initiation Endpoint

**Endpoint**: `POST /api/v1/oauth/gmail/initiate`

**Purpose**: Initiate OAuth2 flow with PKCE and state validation

**Authentication**: Required (JWT Bearer token)

**Rate Limiting**: 5 requests per minute per user

**Request Body**: None

**Implementation Steps**:

1. **Validate User Authentication**
   - Verify JWT token validity
   - Ensure user is active and not disabled
   - Check if user already has active Gmail connection

2. **Generate Security Parameters**
   ```python
   # Generate cryptographically secure state (32 bytes)
   state = secrets.token_urlsafe(32)
   
   # Generate PKCE code verifier (128 characters)
   code_verifier = secrets.token_urlsafe(96)
   
   # Create code challenge
   code_challenge = base64.urlsafe_b64encode(
       hashlib.sha256(code_verifier.encode()).digest()
   ).decode().rstrip('=')
   ```

3. **Store State and PKCE in Redis**
   ```python
   redis_key = f"oauth_state:{user_id}:{state}"
   redis_data = {
       "code_verifier": code_verifier,
       "user_id": user_id,
       "timestamp": datetime.utcnow().isoformat()
   }
   redis_client.setex(redis_key, 600, json.dumps(redis_data))  # 10 min TTL
   ```

4. **Build Authorization URL**
   ```python
   auth_url = (
       "https://accounts.google.com/o/oauth2/v2/auth?"
       f"client_id={settings.GOOGLE_OAUTH_CLIENT_ID}&"
       f"redirect_uri={settings.OAUTH_REDIRECT_URI}&"
       "response_type=code&"
       "scope=https://www.googleapis.com/auth/gmail.readonly "
       "https://www.googleapis.com/auth/gmail.modify&"
       f"state={state}&"
       f"code_challenge={code_challenge}&"
       "code_challenge_method=S256&"
       "access_type=offline&"
       "prompt=consent"
   )
   ```

**Response**:
```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "state": "generated_state_value",
  "expires_in": 600
}
```

**Error Responses**:
- 401: Unauthorized (invalid JWT)
- 429: Rate limit exceeded
- 409: Gmail already connected
- 500: Internal server error

### 2. OAuth Callback Endpoint

**Endpoint**: `GET /api/v1/oauth/gmail/callback`

**Purpose**: Handle Google OAuth callback and exchange code for tokens

**Authentication**: None (public endpoint)

**Query Parameters**:
- `code`: Authorization code from Google
- `state`: State parameter for CSRF protection
- `error`: Error code if authorization failed
- `error_description`: Human-readable error description

**Implementation Steps**:

1. **Validate State Parameter**
   ```python
   redis_key = f"oauth_state:*:{state}"
   stored_data = redis_client.get(redis_key)
   if not stored_data:
       raise HTTPException(400, "Invalid or expired state")
   ```

2. **Exchange Code for Tokens**
   ```python
   token_request_data = {
       "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
       "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
       "code": code,
       "grant_type": "authorization_code",
       "redirect_uri": settings.OAUTH_REDIRECT_URI,
       "code_verifier": stored_data["code_verifier"]
   }
   
   async with httpx.AsyncClient() as client:
       response = await client.post(
           "https://oauth2.googleapis.com/token",
           data=token_request_data
       )
   ```

3. **Encrypt and Store Tokens**
   ```python
   # Encrypt tokens before storage
   encrypted_access_token = encrypt_token(tokens["access_token"])
   encrypted_refresh_token = encrypt_token(tokens["refresh_token"])
   
   # Store in database
   oauth_token = OAuthToken(
       user_id=user_id,
       provider="gmail",
       encrypted_access_token=encrypted_access_token,
       encrypted_refresh_token=encrypted_refresh_token,
       access_token_expires_at=datetime.utcnow() + timedelta(seconds=tokens["expires_in"]),
       granted_scopes=tokens["scope"],
       token_version=1
   )
   ```

4. **Create Audit Log**
   ```python
   audit_log = GmailAuditLog(
       user_id=user_id,
       operation_type="oauth_grant",
       operation_timestamp=datetime.utcnow(),
       ip_address=request.client.host,
       user_agent=request.headers.get("user-agent"),
       operation_result="success"
   )
   ```

5. **Clean Up Redis**
   ```python
   redis_client.delete(redis_key)
   ```

**Success Response**: Redirect to frontend with success parameter
```
Location: https://your-frontend.vercel.app/gmail-connect?status=success
```

**Error Response**: Redirect to frontend with error parameter
```
Location: https://your-frontend.vercel.app/gmail-connect?status=error&reason=oauth_error
```

### 3. Connection Status Endpoint

**Endpoint**: `GET /api/v1/oauth/gmail/status`

**Purpose**: Check Gmail connection status and token validity

**Authentication**: Required (JWT Bearer token)

**Implementation Steps**:

1. **Retrieve User's OAuth Token**
   ```python
   oauth_token = db.query(OAuthToken).filter(
       OAuthToken.user_id == current_user.id,
       OAuthToken.provider == "gmail",
       OAuthToken.is_active == True
   ).first()
   ```

2. **Validate Token Health**
   ```python
   if oauth_token:
       # Check if access token is expired
       if oauth_token.access_token_expires_at <= datetime.utcnow():
           # Attempt token refresh
           success = await refresh_access_token(oauth_token)
           if not success:
               oauth_token.is_active = False
   ```

3. **Test API Access**
   ```python
   if oauth_token and oauth_token.is_active:
       try:
           # Test with a simple Gmail API call
           profile = await gmail_service.get_user_profile(current_user.id)
           api_access_valid = True
       except Exception:
           api_access_valid = False
   ```

**Response**:
```json
{
  "connected": true,
  "email_address": "user@gmail.com",
  "connection_date": "2024-01-15T10:30:00Z",
  "last_token_refresh": "2024-01-20T08:15:00Z",
  "granted_scopes": [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify"
  ],
  "api_access_valid": true,
  "last_scan": "2024-01-20T12:00:00Z",
  "total_emails_scanned": 150
}
```

### 4. Token Refresh Endpoint

**Endpoint**: `POST /api/v1/oauth/gmail/refresh`

**Purpose**: Manually refresh access token

**Authentication**: Required (JWT Bearer token)

**Implementation Steps**:

1. **Retrieve Refresh Token**
   ```python
   oauth_token = get_active_oauth_token(current_user.id, "gmail")
   if not oauth_token:
       raise HTTPException(404, "No Gmail connection found")
   
   refresh_token = decrypt_token(oauth_token.encrypted_refresh_token)
   ```

2. **Request New Access Token**
   ```python
   refresh_data = {
       "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
       "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
       "refresh_token": refresh_token,
       "grant_type": "refresh_token"
   }
   
   response = await httpx.post(
       "https://oauth2.googleapis.com/token",
       data=refresh_data
   )
   ```

3. **Update Stored Token**
   ```python
   new_tokens = response.json()
   oauth_token.encrypted_access_token = encrypt_token(new_tokens["access_token"])
   oauth_token.access_token_expires_at = datetime.utcnow() + timedelta(seconds=new_tokens["expires_in"])
   oauth_token.token_version += 1
   oauth_token.last_used_at = datetime.utcnow()
   
   # Handle refresh token rotation if provided
   if "refresh_token" in new_tokens:
       oauth_token.encrypted_refresh_token = encrypt_token(new_tokens["refresh_token"])
   ```

**Response**:
```json
{
  "success": true,
  "token_refreshed_at": "2024-01-20T14:30:00Z",
  "expires_at": "2024-01-20T15:30:00Z"
}
```

### 5. Revoke Access Endpoint

**Endpoint**: `DELETE /api/v1/oauth/gmail/revoke`

**Purpose**: Revoke Gmail access and delete stored tokens

**Authentication**: Required (JWT Bearer token)

**Implementation Steps**:

1. **Retrieve Active Token**
   ```python
   oauth_token = get_active_oauth_token(current_user.id, "gmail")
   if not oauth_token:
       raise HTTPException(404, "No Gmail connection found")
   ```

2. **Revoke Token at Google**
   ```python
   refresh_token = decrypt_token(oauth_token.encrypted_refresh_token)
   
   # Revoke refresh token (this revokes all associated tokens)
   revoke_response = await httpx.post(
       "https://oauth2.googleapis.com/revoke",
       data={"token": refresh_token}
   )
   ```

3. **Mark Token as Revoked**
   ```python
   oauth_token.is_active = False
   oauth_token.revoked_at = datetime.utcnow()
   oauth_token.revocation_reason = "user_requested"
   
   # Clear sensitive data
   oauth_token.encrypted_access_token = None
   oauth_token.encrypted_refresh_token = None
   ```

4. **Update User Gmail Settings**
   ```python
   current_user.email_monitoring_enabled = False
   current_user.gmail_watch_expiration = None
   ```

5. **Create Audit Log**
   ```python
   audit_log = GmailAuditLog(
       user_id=current_user.id,
       operation_type="oauth_revoke",
       operation_timestamp=datetime.utcnow(),
       ip_address=request.client.host,
       user_agent=request.headers.get("user-agent"),
       operation_result="success"
   )
   ```

**Response**:
```json
{
  "success": true,
  "revoked_at": "2024-01-20T16:45:00Z",
  "message": "Gmail access has been revoked successfully"
}
```

## Security Considerations

### Input Validation
- Validate all query parameters and request bodies
- Sanitize state parameters to prevent injection
- Validate redirect URIs against whitelist

### Rate Limiting
- Implement different limits for different endpoints
- Use sliding window rate limiting
- Track attempts per user and per IP

### Error Handling
- Don't expose sensitive information in error messages
- Log all security-relevant events
- Implement proper HTTP status codes

### Token Security
- Use AES-256-GCM for encryption
- Implement secure key derivation
- Store encryption keys separately from tokens
- Implement token rotation strategy

## Monitoring and Observability

### Metrics to Track
- OAuth flow completion rates
- Token refresh success/failure rates
- API call latencies
- Error rates by endpoint

### Logging Requirements
- Log all OAuth operations with correlation IDs
- Include request/response metadata
- Implement structured logging
- Ensure logs don't contain sensitive data

### Alerting Conditions
- High OAuth failure rates (>10%)
- Unusual token refresh patterns
- Security events (invalid state, expired codes)
- Rate limit violations
