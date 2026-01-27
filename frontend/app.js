/**
 * PhishNet Frontend - Backend Integration
 * Handles OAuth authentication and dashboard access
 */

// Configuration
const CONFIG = {
    // Use environment variable or default to production backend
    BACKEND_URL: 'https://phishnet-backend-iuoc.onrender.com',

    // OAuth endpoints
    AUTH_ENDPOINT: '/auth/google',
    CALLBACK_ENDPOINT: '/auth/callback',
    DASHBOARD_URL: '/dashboard.html',

    // Storage keys
    TOKEN_KEY: 'phishnet_access_token',
    USER_KEY: 'phishnet_user'
};

/**
 * Initialize the application
 */
function init() {
    console.log('PhishNet Frontend initialized');
    console.log('Backend URL:', CONFIG.BACKEND_URL);

    // Check if user is already authenticated
    checkAuthStatus();

    // Set up event listeners
    setupEventListeners();

    // Handle OAuth callback if present
    handleOAuthCallback();
}

/**
 * Check if user is authenticated
 */
function checkAuthStatus() {
    const token = localStorage.getItem(CONFIG.TOKEN_KEY);
    const user = localStorage.getItem(CONFIG.USER_KEY);

    if (token && user) {
        console.log('User is authenticated:', JSON.parse(user));
        updateUIForAuthenticatedUser(JSON.parse(user));
    } else {
        console.log('User is not authenticated');
    }
}

/**
 * Update UI for authenticated users
 */
function updateUIForAuthenticatedUser(user) {
    const authButton = document.getElementById('auth-button');
    if (authButton) {
        authButton.textContent = user.email ? `Connected: ${user.email}` : 'Go to Dashboard';
        authButton.classList.remove('bg-primary', 'text-background-dark');
        authButton.classList.add('bg-emerald-500', 'text-white'); // Success state style
        authButton.onclick = () => {
            // Already connected explanation
            showNotification(`Active Protection: ${user.email}`, 'success');
        };
    }

    // Update all CTA buttons
    const ctaButtons = [
        document.getElementById('hero-cta'),
        document.getElementById('cta-button')
    ];

    ctaButtons.forEach(button => {
        if (button) {
            button.textContent = 'Open Dashboard';
            button.onclick = () => {
                window.location.href = CONFIG.DASHBOARD_URL;
            };
        }
    });
}

/**
 * Set up event listeners for authentication buttons
 */
function setupEventListeners() {
    // Main auth button in navigation
    const authButton = document.getElementById('auth-button');
    if (authButton && !authButton.onclick) {
        authButton.addEventListener('click', handleAuthClick);
    }

    // Hero CTA button
    const heroCTA = document.getElementById('hero-cta');
    if (heroCTA && !heroCTA.onclick) {
        heroCTA.addEventListener('click', handleAuthClick);
    }

    // Final CTA button
    const ctaButton = document.getElementById('cta-button');
    if (ctaButton && !ctaButton.onclick) {
        ctaButton.addEventListener('click', handleAuthClick);
    }
}

/**
 * Handle authentication button clicks
 */
function handleAuthClick(event) {
    event.preventDefault();

    // Check if already authenticated
    const token = localStorage.getItem(CONFIG.TOKEN_KEY);
    if (token) {
        // Redirect to dashboard
        window.location.href = CONFIG.DASHBOARD_URL;
        return;
    }

    // Start OAuth flow
    initiateOAuth();
}

/**
 * Initiate OAuth flow with Google
 */
function initiateOAuth() {
    console.log('Initiating OAuth flow...');

    // Store the current URL to return after authentication
    sessionStorage.setItem('phishnet_return_url', window.location.href);

    // Redirect to backend OAuth endpoint
    const authUrl = `${CONFIG.BACKEND_URL}${CONFIG.AUTH_ENDPOINT}`;
    console.log('Redirecting to:', authUrl);

    window.location.href = authUrl;
}

/**
 * Handle OAuth callback
 * The backend should redirect here with the access token
 */
function handleOAuthCallback() {
    // Check if we're on the callback URL
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    const error = urlParams.get('error');
    const oauth_success = urlParams.get('oauth_success');
    const gmail_email = urlParams.get('gmail_email');

    if (error) {
        console.error('OAuth error:', error);
        showNotification('Authentication failed. Please try again.', 'error');
        return;
    }

    // Handle "Nuclear/Zero-Dependency" Auth Flow
    // DEBUG: Alert to confirm parsing
    if (window.location.search.includes('oauth_success')) {
        //alert("DEBUG: OAuth Params Found: " + window.location.search);
        console.log("DEBUG: Params detected");
    }

    if (oauth_success === 'true' && gmail_email) {
        console.log('OAuth success detected:', gmail_email);
        // Alert removed for better UX
        // alert("Success! Connected: " + gmail_email + "\nRedirecting to Dashboard...");

        // Create a simulated user session
        const user = {
            email: gmail_email,
            name: gmail_email.split('@')[0],
            is_active: true
        };

        localStorage.setItem(CONFIG.USER_KEY, JSON.stringify(user));
        localStorage.setItem(CONFIG.TOKEN_KEY, 'simulated_access_token');

        // Clean up URL
        window.history.replaceState({}, document.title, window.location.pathname);

        showNotification(`Successfully connected ${gmail_email}! Redirecting...`, 'success');

        // Update UI immediately (fallback)
        updateUIForAuthenticatedUser(user);

        // Auto-redirect to dashboard
        setTimeout(() => {
            window.location.href = CONFIG.DASHBOARD_URL;
        }, 1500);
        return;
    }

    if (token) {
        console.log('OAuth callback received with token');

        // Store the token
        localStorage.setItem(CONFIG.TOKEN_KEY, token);

        // Fetch user information
        fetchUserInfo(token);

        // Clean up URL
        window.history.replaceState({}, document.title, window.location.pathname);

        // Show success message
        showNotification('Successfully authenticated! Redirecting to dashboard...', 'success');

        // Redirect to dashboard after a short delay
        setTimeout(() => {
            window.location.href = CONFIG.DASHBOARD_URL;
        }, 1500);
    }
}

/**
 * Fetch user information from backend
 */
async function fetchUserInfo(token) {
    try {
        const response = await fetch(`${CONFIG.BACKEND_URL}/api/v2/user/me`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.ok) {
            const user = await response.json();
            localStorage.setItem(CONFIG.USER_KEY, JSON.stringify(user));
            console.log('User info fetched:', user);
        } else {
            console.error('Failed to fetch user info:', response.status);
        }
    } catch (error) {
        console.error('Error fetching user info:', error);
    }
}

/**
 * Show notification to user
 */
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `fixed top-24 right-6 z-50 glass px-6 py-4 rounded-xl shadow-lg transform transition-all duration-300 ${type === 'error' ? 'border-red-500/50' : 'border-primary/50'
        }`;
    notification.style.border = '1px solid';

    notification.innerHTML = `
        <div class="flex items-center gap-3">
            <span class="material-symbols-outlined ${type === 'error' ? 'text-red-500' : 'text-primary'}">
                ${type === 'error' ? 'error' : 'check_circle'}
            </span>
            <p class="text-sm font-medium">${message}</p>
        </div>
    `;

    document.body.appendChild(notification);

    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 100);

    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.transform = 'translateX(400px)';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

/**
 * Logout function
 */
function logout() {
    localStorage.removeItem(CONFIG.TOKEN_KEY);
    localStorage.removeItem(CONFIG.USER_KEY);
    sessionStorage.removeItem('phishnet_return_url');
    window.location.href = '/';
}

// Make logout available globally
window.phishnetLogout = logout;

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
