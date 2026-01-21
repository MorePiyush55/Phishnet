import { defineConfig, devices } from '@playwright/test';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

export default defineConfig({
    testDir: './tests',

    // Maximum time one test can run
    timeout: 120 * 1000, // 2 minutes for OAuth flows

    // Test execution settings
    fullyParallel: false, // Run tests sequentially for OAuth
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: 1, // Single worker for OAuth tests

    // Reporter configuration
    reporter: [
        ['html', { outputFolder: 'test-results/html-report' }],
        ['json', { outputFile: 'test-results/results.json' }],
        ['list']
    ],

    // Shared settings for all projects
    use: {
        // Base URL for the application
        baseURL: process.env.DASHBOARD_URL || 'https://phishnet-tau.vercel.app',

        // Collect trace on failure
        trace: 'on-first-retry',

        // Screenshot on failure
        screenshot: 'only-on-failure',

        // Video on failure
        video: 'retain-on-failure',

        // Navigation timeout
        navigationTimeout: 30 * 1000,

        // Action timeout
        actionTimeout: 15 * 1000,
    },

    // Configure projects for different browsers
    projects: [
        {
            name: 'chromium',
            use: {
                ...devices['Desktop Chrome'],
                // Google OAuth works best with Chrome
                viewport: { width: 1280, height: 720 },
            },
        },
    ],

    // Output folder for test artifacts
    outputDir: 'test-results/artifacts',
});
