import { test, expect } from '@playwright/test';
import { OAuthHelper, setupConsoleLogging } from './helpers/oauth-helpers';
import * as fs from 'fs';
import * as path from 'path';

// Load environment variables
const DASHBOARD_URL = process.env.DASHBOARD_URL || 'https://phishnet-tau.vercel.app';
const BACKEND_URL = process.env.BACKEND_URL || 'https://phishnet-backend-iuoc.onrender.com';
const GOOGLE_EMAIL = process.env.GOOGLE_TEST_EMAIL || '';
const GOOGLE_PASSWORD = process.env.GOOGLE_TEST_PASSWORD || '';

test.describe('PhishNet OAuth Flow', () => {
    test.beforeEach(async ({ page }) => {
        // Setup console logging
        setupConsoleLogging(page);

        // Create screenshots directory
        const screenshotsDir = path.join(__dirname, '..', '..', 'test-results', 'screenshots');
        if (!fs.existsSync(screenshotsDir)) {
            fs.mkdirSync(screenshotsDir, { recursive: true });
        }

        console.log('='.repeat(80));
        console.log('Starting PhishNet OAuth Flow Test');
        console.log('='.repeat(80));
        console.log(`Dashboard URL: ${DASHBOARD_URL}`);
        console.log(`Backend URL: ${BACKEND_URL}`);
        console.log(`Test Email: ${GOOGLE_EMAIL}`);
        console.log('='.repeat(80));
    });

    test('Complete OAuth flow from dashboard to callback', async ({ page, context }) => {
        const oauthHelper = new OAuthHelper(page);

        // Validate environment variables
        if (!GOOGLE_EMAIL || !GOOGLE_PASSWORD) {
            throw new Error('GOOGLE_TEST_EMAIL and GOOGLE_TEST_PASSWORD must be set in .env file');
        }

        try {
            // Step 1: Navigate to dashboard
            console.log('\n[Step 1] Navigating to dashboard...');
            await page.goto(DASHBOARD_URL, { waitUntil: 'networkidle' });
            await page.screenshot({
                path: 'test-results/screenshots/00-dashboard-loaded.png',
                fullPage: true
            });
            console.log('[Step 1] Dashboard loaded successfully');

            // Step 2: Find and click "Connect Google Account" button
            console.log('\n[Step 2] Looking for "Connect Google Account" button...');

            // Try multiple possible selectors for the connect button
            const connectButtonSelectors = [
                'button:has-text("Connect Google Account")',
                'button:has-text("Connect Gmail")',
                'button:has-text("Sign in with Google")',
                'a:has-text("Connect Google Account")',
                'a:has-text("Connect Gmail")',
                '[data-testid="connect-google"]',
                '.connect-google-btn',
                '#connect-google'
            ];

            let buttonFound = false;
            for (const selector of connectButtonSelectors) {
                try {
                    const button = page.locator(selector).first();
                    if (await button.isVisible({ timeout: 3000 })) {
                        console.log(`[Step 2] Found button with selector: ${selector}`);
                        await button.click();
                        buttonFound = true;
                        console.log('[Step 2] Clicked "Connect Google Account" button');
                        break;
                    }
                } catch (e) {
                    // Try next selector
                    continue;
                }
            }

            if (!buttonFound) {
                console.error('[Step 2] Could not find "Connect Google Account" button');
                await page.screenshot({
                    path: 'test-results/screenshots/error-no-connect-button.png',
                    fullPage: true
                });
                throw new Error('Connect Google Account button not found');
            }

            // Wait for navigation to Google OAuth
            await page.waitForTimeout(2000);

            // Step 3: Handle Google login
            console.log('\n[Step 3] Handling Google login...');
            await oauthHelper.loginToGoogle(GOOGLE_EMAIL, GOOGLE_PASSWORD);

            // Step 4: Accept permissions
            console.log('\n[Step 4] Accepting permissions...');
            await oauthHelper.acceptPermissions();

            // Step 5: Handle unsafe warning
            console.log('\n[Step 5] Handling unsafe warning (if present)...');
            await oauthHelper.handleUnsafeWarning();

            // Step 6: Capture callback
            console.log('\n[Step 6] Capturing callback URL and response...');
            const callbackData = await oauthHelper.captureCallback();

            // Log results
            console.log('\n' + '='.repeat(80));
            console.log('CALLBACK RESULTS');
            console.log('='.repeat(80));
            console.log('Callback URL:', callbackData.url);
            console.log('Response:', JSON.stringify(callbackData.response, null, 2));
            console.log('='.repeat(80));

            // Save results to file
            const resultsPath = path.join(__dirname, '..', '..', 'test-results', 'callback-results.json');
            fs.writeFileSync(resultsPath, JSON.stringify({
                timestamp: new Date().toISOString(),
                callbackUrl: callbackData.url,
                response: callbackData.response,
                success: callbackData.response?.detail !== 'Not Found'
            }, null, 2));
            console.log(`\nResults saved to: ${resultsPath}`);

            // Verify callback was successful
            if (callbackData.response?.detail === 'Not Found') {
                console.error('\n❌ CALLBACK FAILED: Received "Not Found" error');
                console.error('This indicates the callback endpoint is not properly registered');
                throw new Error('Callback endpoint returned "Not Found"');
            } else {
                console.log('\n✅ CALLBACK SUCCESSFUL');
            }

        } catch (error) {
            console.error('\n' + '='.repeat(80));
            console.error('TEST FAILED');
            console.error('='.repeat(80));
            await oauthHelper.logError('oauth-flow-test', error);
            throw error;
        }
    });

    test('Verify callback endpoint exists', async ({ request }) => {
        console.log('\n[Endpoint Check] Verifying callback endpoint...');

        // Try to access the callback endpoint directly (should return error but not 404)
        const callbackUrl = `${BACKEND_URL}/api/v1/auth/gmail/callback`;
        console.log(`[Endpoint Check] Testing URL: ${callbackUrl}`);

        try {
            const response = await request.get(callbackUrl);
            console.log(`[Endpoint Check] Status: ${response.status()}`);
            console.log(`[Endpoint Check] Status Text: ${response.statusText()}`);

            const body = await response.text();
            console.log(`[Endpoint Check] Response: ${body}`);

            // 404 means endpoint doesn't exist (BAD)
            // 400/422 means endpoint exists but missing parameters (GOOD)
            if (response.status() === 404) {
                console.error('❌ Endpoint does not exist (404 Not Found)');
                throw new Error('Callback endpoint not found - route may not be registered');
            } else {
                console.log('✅ Endpoint exists (non-404 response)');
            }

        } catch (error) {
            console.error('[Endpoint Check] Error:', error);
            throw error;
        }
    });

    test('Debug: List all available routes', async ({ request }) => {
        console.log('\n[Debug] Fetching available routes...');

        try {
            // Try to get router errors endpoint
            const debugUrl = `${BACKEND_URL}/debug/router-errors`;
            console.log(`[Debug] Testing URL: ${debugUrl}`);

            const response = await request.get(debugUrl);
            const data = await response.json();

            console.log('\n[Debug] Router Errors:', JSON.stringify(data.errors, null, 2));
            console.log('\n[Debug] Loaded Routes:');
            data.loaded_routes.forEach((route: string) => {
                console.log(`  - ${route}`);
            });

            // Check if our callback route is in the list
            const hasCallback = data.loaded_routes.some((route: string) =>
                route.includes('/api/v1/auth/gmail/callback')
            );

            if (hasCallback) {
                console.log('\n✅ Callback route is registered');
            } else {
                console.log('\n❌ Callback route is NOT registered');
                console.log('Available auth routes:');
                data.loaded_routes
                    .filter((route: string) => route.includes('/auth'))
                    .forEach((route: string) => console.log(`  - ${route}`));
            }

        } catch (error) {
            console.log('[Debug] Could not fetch route information:', error);
        }
    });
});
