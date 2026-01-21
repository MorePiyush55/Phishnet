# PhishNet E2E OAuth Tests

Automated end-to-end tests for the PhishNet OAuth authentication flow using Playwright.

## 🎯 Purpose

This test suite automates the complete OAuth flow to:
- Test the integration between the Vercel frontend and Render backend
- Diagnose authentication callback issues
- Capture detailed logs and screenshots for debugging
- Verify endpoint registration and routing

## 📋 Prerequisites

- Node.js 18+ installed
- npm or yarn package manager
- Google account credentials for testing (`propam5553@gmail.com`)

## 🚀 Setup

### 1. Install Dependencies

```bash
cd tests/e2e
npm install
```

### 2. Install Playwright Browsers

```bash
npx playwright install chromium
```

### 3. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your test credentials
# IMPORTANT: Add the password for propam5553@gmail.com
```

Edit `.env`:
```env
DASHBOARD_URL=https://phishnet-tau.vercel.app
BACKEND_URL=https://phishnet-backend-iuoc.onrender.com
GOOGLE_TEST_EMAIL=propam5553@gmail.com
GOOGLE_TEST_PASSWORD=YOUR_PASSWORD_HERE  # ⚠️ Add the actual password
```

## 🧪 Running Tests

### Run All Tests

```bash
npm test
```

### Run OAuth Flow Test Only

```bash
npm run test:oauth
```

### Run in Headed Mode (See Browser)

```bash
npm run test:headed
```

### Debug Mode (Step Through)

```bash
npm run test:debug
```

### Run Specific Test

```bash
npx playwright test oauth-flow.spec.ts --grep "Complete OAuth flow"
```

## 📊 Test Results

After running tests, results are saved in:

- **Screenshots**: `test-results/screenshots/`
  - `00-dashboard-loaded.png` - Initial dashboard
  - `01-google-login-page.png` - Google login screen
  - `02-password-page.png` - Password entry
  - `03-consent-screen.png` - Permission consent
  - `04-unsafe-warning.png` - Unsafe app warning
  - `06-callback-page.png` - Final callback page
  - `error-*.png` - Error screenshots

- **Callback Results**: `test-results/callback-results.json`
  ```json
  {
    "timestamp": "2026-01-20T...",
    "callbackUrl": "https://...",
    "response": { ... },
    "success": true/false
  }
  ```

- **HTML Report**: `test-results/html-report/index.html`
  ```bash
  npm run report
  ```

## 🔍 What the Tests Do

### Test 1: Complete OAuth Flow
1. Navigate to PhishNet dashboard (`https://phishnet-tau.vercel.app/`)
2. Click "Connect Google Account" button
3. Enter Google credentials (`propam5553@gmail.com`)
4. Accept all OAuth permissions
5. Handle "unsafe app" warning and continue
6. Capture the callback URL and response
7. Verify the callback was successful

### Test 2: Verify Callback Endpoint
- Directly tests if `/api/v1/auth/gmail/callback` endpoint exists
- Distinguishes between:
  - ❌ 404 Not Found (endpoint not registered)
  - ✅ 400/422 (endpoint exists, missing parameters)

### Test 3: Debug Routes
- Lists all registered routes in the backend
- Checks if the callback route is properly registered
- Shows any router loading errors

## 🐛 Troubleshooting

### "Connect Google Account button not found"

The test tries multiple selectors. If it fails:
1. Check `00-dashboard-loaded.png` screenshot
2. Inspect the actual button selector in the dashboard
3. Add the selector to `connectButtonSelectors` in the test

### "Callback endpoint returned Not Found"

This means the route is not registered. Check:
1. `test-results/callback-results.json` for the exact URL
2. Run the "Debug: List all available routes" test
3. Verify `backend/app/main.py` includes the auth router
4. Check `backend/app/api/v1/auth.py` has the callback endpoint

### Google Login Issues

If Google login fails:
1. Check screenshots in `test-results/screenshots/`
2. Verify credentials in `.env`
3. Google may require manual verification for new devices
4. Try running in headed mode: `npm run test:headed`

### Timeout Errors

OAuth flows can be slow. Adjust timeouts in `playwright.config.ts`:
```typescript
timeout: 180 * 1000, // 3 minutes
```

## 📝 Test Output Example

```
[Step 1] Navigating to dashboard...
[Step 1] Dashboard loaded successfully

[Step 2] Looking for "Connect Google Account" button...
[Step 2] Found button with selector: button:has-text("Connect Google Account")
[Step 2] Clicked "Connect Google Account" button

[Step 3] Handling Google login...
[OAuth] Logging in with email: propam5553@gmail.com
[OAuth] Email entered
[OAuth] Password entered

[Step 4] Accepting permissions...
[OAuth] Found permission button: button:has-text("Continue")

[Step 5] Handling unsafe warning...
[OAuth] Found element: button:has-text("Advanced")

[Step 6] Capturing callback URL and response...
[OAuth] Callback URL: https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback?state=...

================================================================================
CALLBACK RESULTS
================================================================================
Callback URL: https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback?state=...
Response: { "detail": "Not Found" }
================================================================================

❌ CALLBACK FAILED: Received "Not Found" error
```

## 🔒 Security Notes

- ⚠️ **Never commit `.env` file** - It contains credentials
- The `.env` file is already in `.gitignore`
- Use a dedicated test account, not a personal account
- Rotate test credentials regularly

## 📚 Additional Resources

- [Playwright Documentation](https://playwright.dev)
- [Playwright Test API](https://playwright.dev/docs/api/class-test)
- [PhishNet Backend API Docs](https://phishnet-backend-iuoc.onrender.com/docs)

## 🤝 Contributing

When adding new tests:
1. Follow the existing pattern with detailed logging
2. Add screenshots at each major step
3. Include error handling and debugging output
4. Update this README with new test descriptions
