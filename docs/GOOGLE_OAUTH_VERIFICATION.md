# OAuth App Configuration for Google Verification

## App Information
- **App Name**: PhishNet - Email Security Scanner
- **App Description**: An AI-powered email security platform that analyzes Gmail emails for phishing threats and malicious content to protect users from cybersecurity attacks.
- **App Category**: Security & Privacy
- **Developer**: PhishNet Team

## Redirect URIs Configuration

### Production URLs (Required for Verification)
- `https://phishnet-backend-iuoc.onrender.com/api/test/oauth/callback`
- `https://phishnet-tau.vercel.app/auth/callback`

### Development URLs (For Testing)
- `http://localhost:8001/api/test/oauth/callback`
- `http://localhost:3000/auth/callback`

## OAuth Scopes Requested

### 1. `openid` (Non-sensitive)
**Purpose**: Basic OAuth 2.0 authentication
**Justification**: Required for secure user authentication

### 2. `email` (Non-sensitive)
**Purpose**: Access user's primary email address
**Justification**: Used to identify and associate Gmail account with PhishNet user profile

### 3. `profile` (Non-sensitive)
**Purpose**: Access user's basic profile information (name, profile picture)
**Justification**: Used to personalize the user interface and display user information

### 4. `https://www.googleapis.com/auth/gmail.readonly` (Sensitive - Requires Verification)
**Purpose**: Read-only access to Gmail messages and metadata
**Justification**: 
- **Security Analysis**: Read email headers, sender information, and content to detect phishing attempts
- **Threat Detection**: Analyze links, attachments, and email patterns for malicious indicators
- **Read-Only Access**: No modification, deletion, or sending of emails - purely for security analysis
- **User Protection**: Helps users identify and avoid phishing attacks, malware, and other email threats

## Security Measures

### Data Protection
- All Gmail data is processed in real-time and not permanently stored
- OAuth tokens are encrypted at rest using industry-standard encryption
- JWT tokens used for session management with proper expiration
- All API communications use HTTPS/TLS encryption

### Privacy Compliance
- Users can revoke access at any time through Google Account settings
- No sharing of Gmail data with third parties
- Data processing limited to security analysis only
- Transparent privacy policy explaining data usage

### Access Controls
- Per-user token isolation - users only see their own emails
- Automatic token refresh with secure storage
- Proper error handling and token revocation
- CORS protection for production domains

## App Branding Requirements

### Logo and Icons
- High-resolution app logo (minimum 512x512 px)
- Favicon and various icon sizes for different platforms
- Consistent branding across OAuth consent screen

### App Domain Verification
- Domain ownership verification for phishnet-tau.vercel.app
- SSL certificate validation
- Proper domain configuration

## Legal Documents Required

### 1. Privacy Policy
- Clear explanation of data collection and usage
- Gmail data processing procedures
- User rights and data retention policies
- Contact information for privacy inquiries

### 2. Terms of Service
- Service usage agreement
- User responsibilities and limitations
- Liability disclaimers
- Service availability terms

### 3. OAuth Scope Justification Document
- Detailed explanation of why Gmail read-only access is necessary
- Security use case documentation
- User benefit explanation
- Data handling procedures

## Verification Checklist

- [ ] All redirect URIs properly configured in Google Cloud Console
- [ ] Privacy Policy published and accessible
- [ ] Terms of Service published and accessible
- [ ] App branding materials prepared
- [ ] Domain verification completed
- [ ] OAuth scope justification documented
- [ ] Security measures documented
- [ ] Test with limited users completed
- [ ] Production readiness verified

## Post-Verification Benefits

1. **No Security Warnings**: Users will see professional consent screen without warnings
2. **Unlimited Users**: No longer limited to 100 test users
3. **Production Ready**: App appears legitimate and trustworthy
4. **Better User Experience**: Professional branding on consent screen
5. **Compliance**: Meets Google's security and privacy requirements