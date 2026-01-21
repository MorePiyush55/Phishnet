import { Page, expect } from '@playwright/test';

/**
 * Helper class for Google OAuth automation
 */
export class OAuthHelper {
    constructor(private page: Page) { }

    /**
     * Perform Google login
     */
    async loginToGoogle(email: string, password: string) {
        console.log(`[OAuth] Logging in with email: ${email}`);

        try {
            // Wait for Google login page
            await this.page.waitForURL(/accounts\.google\.com/, { timeout: 15000 });
            console.log('[OAuth] Google login page loaded');

            // Take screenshot of login page
            await this.page.screenshot({
                path: 'test-results/screenshots/01-google-login-page.png',
                fullPage: true
            });

            // Enter email
            const emailInput = this.page.locator('input[type="email"]');
            await emailInput.waitFor({ state: 'visible', timeout: 10000 });
            await emailInput.fill(email);
            console.log('[OAuth] Email entered');

            // Click Next button
            await this.page.click('button:has-text("Next"), #identifierNext');
            console.log('[OAuth] Clicked Next after email');

            // Wait for password page
            await this.page.waitForTimeout(2000);
            await this.page.screenshot({
                path: 'test-results/screenshots/02-password-page.png',
                fullPage: true
            });

            // Enter password
            const passwordInput = this.page.locator('input[type="password"]');
            await passwordInput.waitFor({ state: 'visible', timeout: 10000 });
            await passwordInput.fill(password);
            console.log('[OAuth] Password entered');

            // Click Next button
            await this.page.click('button:has-text("Next"), #passwordNext');
            console.log('[OAuth] Clicked Next after password');

            // Wait for navigation
            await this.page.waitForTimeout(3000);

        } catch (error) {
            console.error('[OAuth] Error during Google login:', error);
            await this.page.screenshot({
                path: 'test-results/screenshots/error-google-login.png',
                fullPage: true
            });
            throw error;
        }
    }

    /**
     * Accept all Google OAuth permissions
     */
    async acceptPermissions() {
        console.log('[OAuth] Accepting permissions');

        try {
            // Wait for consent screen
            await this.page.waitForTimeout(2000);
            await this.page.screenshot({
                path: 'test-results/screenshots/03-consent-screen.png',
                fullPage: true
            });

            // Look for various permission buttons
            const continueSelectors = [
                'button:has-text("Continue")',
                'button:has-text("Allow")',
                'button[id*="submit"]',
                '#submit_approve_access',
                'button[type="submit"]'
            ];

            for (const selector of continueSelectors) {
                try {
                    const button = this.page.locator(selector).first();
                    if (await button.isVisible({ timeout: 3000 })) {
                        console.log(`[OAuth] Found permission button: ${selector}`);
                        await button.click();
                        console.log('[OAuth] Clicked permission button');
                        break;
                    }
                } catch (e) {
                    // Try next selector
                    continue;
                }
            }

            // Wait for navigation
            await this.page.waitForTimeout(3000);

        } catch (error) {
            console.error('[OAuth] Error accepting permissions:', error);
            await this.page.screenshot({
                path: 'test-results/screenshots/error-permissions.png',
                fullPage: true
            });
            throw error;
        }
    }

    /**
     * Handle "unsafe" warning and continue
     */
    async handleUnsafeWarning() {
        console.log('[OAuth] Checking for unsafe warning');

        try {
            await this.page.waitForTimeout(2000);
            await this.page.screenshot({
                path: 'test-results/screenshots/04-unsafe-warning.png',
                fullPage: true
            });

            // Look for "Advanced" or "Continue anyway" links
            const advancedSelectors = [
                'button:has-text("Advanced")',
                'a:has-text("Advanced")',
                'button:has-text("Continue")',
                'a:has-text("Continue anyway")',
                'a:has-text("Go to")'
            ];

            for (const selector of advancedSelectors) {
                try {
                    const element = this.page.locator(selector).first();
                    if (await element.isVisible({ timeout: 3000 })) {
                        console.log(`[OAuth] Found element: ${selector}`);
                        await element.click();
                        console.log('[OAuth] Clicked on element');

                        // Wait and look for "Continue" or "Proceed" button
                        await this.page.waitForTimeout(1000);
                        const proceedSelectors = [
                            'button:has-text("Continue")',
                            'button:has-text("Proceed")',
                            'a:has-text("Continue")',
                            'a:has-text("Proceed")'
                        ];

                        for (const proceedSelector of proceedSelectors) {
                            try {
                                const proceedBtn = this.page.locator(proceedSelector).first();
                                if (await proceedBtn.isVisible({ timeout: 2000 })) {
                                    await proceedBtn.click();
                                    console.log('[OAuth] Clicked proceed button');
                                    break;
                                }
                            } catch (e) {
                                continue;
                            }
                        }
                        break;
                    }
                } catch (e) {
                    continue;
                }
            }

            await this.page.waitForTimeout(2000);

        } catch (error) {
            console.log('[OAuth] No unsafe warning found or error handling it:', error);
            await this.page.screenshot({
                path: 'test-results/screenshots/05-after-unsafe-handling.png',
                fullPage: true
            });
        }
    }

    /**
     * Capture and log callback URL and response
     */
    async captureCallback(): Promise<{ url: string; response: any }> {
        console.log('[OAuth] Waiting for callback');

        try {
            // Wait for callback URL
            await this.page.waitForURL(/\/api\/v1\/auth\/gmail\/callback/, { timeout: 30000 });

            const callbackUrl = this.page.url();
            console.log('[OAuth] Callback URL:', callbackUrl);

            // Parse URL parameters
            const url = new URL(callbackUrl);
            const params = {
                state: url.searchParams.get('state'),
                code: url.searchParams.get('code'),
                scope: url.searchParams.get('scope'),
                authuser: url.searchParams.get('authuser'),
                prompt: url.searchParams.get('prompt')
            };
            console.log('[OAuth] Callback parameters:', JSON.stringify(params, null, 2));

            // Take screenshot of callback page
            await this.page.screenshot({
                path: 'test-results/screenshots/06-callback-page.png',
                fullPage: true
            });

            // Try to get response body
            let responseBody: any = null;
            try {
                const content = await this.page.content();
                console.log('[OAuth] Page content:', content);

                // Try to parse as JSON if it looks like JSON
                if (content.includes('{') && content.includes('}')) {
                    const jsonMatch = content.match(/\{[^]*\}/);
                    if (jsonMatch) {
                        responseBody = JSON.parse(jsonMatch[0]);
                        console.log('[OAuth] Response body:', JSON.stringify(responseBody, null, 2));
                    }
                }
            } catch (e) {
                console.log('[OAuth] Could not parse response body:', e);
            }

            return {
                url: callbackUrl,
                response: responseBody
            };

        } catch (error) {
            console.error('[OAuth] Error capturing callback:', error);
            await this.page.screenshot({
                path: 'test-results/screenshots/error-callback.png',
                fullPage: true
            });

            // Log current URL and page content for debugging
            console.log('[OAuth] Current URL:', this.page.url());
            const content = await this.page.content();
            console.log('[OAuth] Page content:', content);

            throw error;
        }
    }

    /**
     * Log detailed error information
     */
    async logError(context: string, error: any) {
        console.error(`[OAuth Error - ${context}]:`, error);

        try {
            const timestamp = new Date().toISOString().replace(/:/g, '-');
            await this.page.screenshot({
                path: `test-results/screenshots/error-${context}-${timestamp}.png`,
                fullPage: true
            });

            console.log(`[OAuth] Current URL: ${this.page.url()}`);
            console.log(`[OAuth] Page title: ${await this.page.title()}`);

            const content = await this.page.content();
            console.log(`[OAuth] Page content length: ${content.length} characters`);

        } catch (screenshotError) {
            console.error('[OAuth] Could not capture error screenshot:', screenshotError);
        }
    }
}

/**
 * Wait for element with custom timeout and logging
 */
export async function waitForElement(
    page: Page,
    selector: string,
    timeout: number = 10000
): Promise<boolean> {
    try {
        await page.waitForSelector(selector, { timeout, state: 'visible' });
        console.log(`[Helper] Element found: ${selector}`);
        return true;
    } catch (error) {
        console.log(`[Helper] Element not found: ${selector}`);
        return false;
    }
}

/**
 * Log page console messages
 */
export function setupConsoleLogging(page: Page) {
    page.on('console', msg => {
        console.log(`[Browser Console - ${msg.type()}]:`, msg.text());
    });

    page.on('pageerror', error => {
        console.error('[Browser Error]:', error);
    });

    page.on('requestfailed', request => {
        console.error('[Request Failed]:', request.url(), request.failure()?.errorText);
    });
}
