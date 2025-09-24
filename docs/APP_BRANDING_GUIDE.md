# PhishNet App Branding and Domain Verification Guide

## Overview
This guide covers the app branding requirements and domain verification process for Google OAuth verification of PhishNet.

## App Branding Requirements

### 1. Application Name
- **Primary Name**: PhishNet Email Security Scanner
- **Short Name**: PhishNet
- **Description**: AI-powered email security platform that analyzes Gmail for phishing threats

### 2. Application Logo/Icon Requirements

#### Google OAuth Console Requirements:
- **Format**: PNG or JPG
- **Size**: 120x120 pixels (minimum), 1024x1024 pixels (recommended)
- **Style**: Professional, clean, recognizable
- **Content**: Should represent email security/protection

#### Suggested Logo Elements:
- Shield icon (security/protection)
- Email envelope symbol
- Net/mesh pattern (representing "PhishNet")
- Blue/green color scheme (trust, security)
- Clear, readable at small sizes

### 3. App Screenshots
**Required for verification:**
- Login/OAuth consent screen
- Main dashboard showing email analysis
- Security report/results page
- User settings/preferences

### 4. Homepage URL
- **Production**: https://phishnet-tau.vercel.app
- **Status**: Must be accessible and professional
- **Requirements**: 
  - Working HTTPS
  - Professional design
  - Clear description of service
  - Links to privacy policy and terms of service

## Domain Verification Process

### 1. Domain Ownership Verification

#### For Vercel Deployment (phishnet-tau.vercel.app):
1. **Google Search Console**:
   - Add property for https://phishnet-tau.vercel.app
   - Verify domain ownership through HTML file upload or DNS record
   - Ensure site is indexed and accessible

2. **OAuth Console Domain Verification**:
   - In Google Cloud Console → OAuth consent screen
   - Add phishnet-tau.vercel.app to authorized domains
   - Upload domain verification file if required

### 2. Authorized Redirect URIs

#### Production Configuration:
```
https://phishnet-tau.vercel.app/api/auth/google/callback
https://phishnet-tau.vercel.app/auth/callback
```

#### Development Configuration:
```
http://localhost:3000/api/auth/google/callback
http://localhost:3000/auth/callback
http://localhost:8000/api/auth/google/callback
```

### 3. Privacy Policy and Terms Links
- **Privacy Policy**: https://phishnet-tau.vercel.app/docs/privacy-policy.html
- **Terms of Service**: https://phishnet-tau.vercel.app/docs/terms-of-service.html
- **Status**: Must be publicly accessible without authentication

## Google OAuth Console Configuration

### 1. OAuth Consent Screen Setup

#### Application Type: External
#### Application Information:
- **App name**: PhishNet Email Security Scanner
- **User support email**: support@phishnet.app
- **App logo**: [Upload 120x120 PNG logo]
- **App domain**: phishnet-tau.vercel.app
- **Authorized domains**: phishnet-tau.vercel.app

#### Developer Contact Information:
- **Email**: developer@phishnet.app
- **Additional emails**: security@phishnet.app

#### Links:
- **App homepage**: https://phishnet-tau.vercel.app
- **App privacy policy**: https://phishnet-tau.vercel.app/docs/privacy-policy.html
- **App terms of service**: https://phishnet-tau.vercel.app/docs/terms-of-service.html

### 2. Scopes Configuration

#### Requested Scopes:
1. **openid** - OpenID Connect authentication
2. **email** - User email address for account identification
3. **profile** - Basic profile information
4. **https://www.googleapis.com/auth/gmail.readonly** - Read-only Gmail access

#### Scope Justifications:
- **Gmail Read-only**: Essential for email security analysis and phishing detection
- **Email/Profile**: Required for user identification and account management
- **OpenID**: Standard authentication protocol

### 3. Test Users Configuration
- Add test Gmail accounts for verification testing
- Include developer and reviewer accounts
- Maximum 100 test users before verification

## Verification Submission Checklist

### Pre-Submission Requirements:
- [ ] Application logo uploaded (120x120 minimum)
- [ ] Domain ownership verified in Google Search Console
- [ ] Privacy policy accessible at public URL
- [ ] Terms of service accessible at public URL
- [ ] All redirect URIs configured correctly
- [ ] App description clearly explains Gmail usage
- [ ] Contact email addresses set up and monitored

### Documentation Required:
- [ ] Detailed explanation of Gmail data usage
- [ ] Security measures documentation
- [ ] Data retention and deletion policies
- [ ] Scope-specific justifications
- [ ] Video demonstration of app functionality
- [ ] Screenshots of key app features

### Technical Requirements:
- [ ] HTTPS enforced on all domains
- [ ] OAuth flow working correctly
- [ ] Error handling implemented
- [ ] Rate limiting configured
- [ ] Logging and monitoring in place

## Post-Verification Benefits

### Eliminated Security Warnings:
- Remove "Google hasn't verified this app" warning
- Remove "This app isn't verified" message
- Eliminate "Advanced" button requirement

### Increased User Limits:
- Remove 100 test user limitation
- Allow unlimited production users
- Enable public app distribution

### Enhanced Trust:
- Professional appearance during OAuth flow
- Verified checkmark in consent screen
- Increased user confidence and adoption

## Support and Troubleshooting

### Common Verification Issues:
1. **Domain Verification Failure**
   - Ensure DNS records are properly configured
   - Verify domain ownership in Google Search Console
   - Check HTTPS certificate validity

2. **Policy Documentation Issues**
   - Ensure privacy policy is comprehensive
   - Include specific Gmail data processing details
   - Make sure terms of service cover all app functionality

3. **Scope Justification Problems**
   - Provide clear business justification for Gmail access
   - Explain security benefits to users
   - Document data processing limitations

### Contact Information:
- **Technical Support**: developer@phishnet.app
- **Legal Questions**: legal@phishnet.app
- **General Inquiries**: support@phishnet.app

## Timeline Expectations

### Verification Process:
- **Submission**: 1-2 days to prepare complete application
- **Review Period**: 7-14 days for Google review
- **Feedback**: Additional 3-7 days if revisions needed
- **Approval**: 1-2 days for final approval and activation

### Preparation Steps:
1. Complete all branding materials (1 day)
2. Set up domain verification (1 day)
3. Test OAuth flow thoroughly (1 day)
4. Prepare documentation and submit (1 day)

---

**Next Steps**: 
1. Create and upload app logo
2. Verify domain ownership
3. Complete OAuth console configuration
4. Submit for verification review