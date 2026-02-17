/**
 * Production configuration for PhishNet Frontend
 * Optimized for Vercel deployment with Render backend
 */

// Environment detection
export const isProduction = import.meta.env.PROD;
export const isDevelopment = import.meta.env.DEV;

// API Configuration
export const API_CONFIG = {
  // Primary backend URL (Render)
  baseURL: import.meta.env.VITE_API_URL || 'https://your-render-app.onrender.com',
  
  // Timeout configuration
  timeout: 30000, // 30 seconds
  
  // Retry configuration
  maxRetries: 3,
  retryDelay: 1000, // 1 second base delay
  
  // Rate limiting
  defaultRateLimit: {
    maxRequests: 10,
    windowMs: 60000, // 1 minute
  },
  
  // Specific endpoint rate limits
  rateLimits: {
    '/auth/start': { maxRequests: 3, windowMs: 300000 }, // 3 per 5 minutes
    '/auth/revoke': { maxRequests: 2, windowMs: 60000 }, // 2 per minute
    '/api/scan/trigger': { maxRequests: 2, windowMs: 300000 }, // 2 per 5 minutes
    '/api/user/status': { maxRequests: 20, windowMs: 60000 }, // 20 per minute
    '/api/scan/history': { maxRequests: 10, windowMs: 60000 }, // 10 per minute
  }
};

// Authentication Configuration
export const AUTH_CONFIG = {
  // OAuth flow settings
  stateStorageKey: 'oauth_state',
  csrfTokenKey: 'csrf_token',
  
  // Session management
  sessionTimeout: 3600000, // 1 hour in milliseconds
  refreshThreshold: 300000, // 5 minutes before expiry
  
  // Storage preferences
  useSecureStorage: isProduction,
  storagePrefix: 'phishnet_',
};

// UI Configuration
export const UI_CONFIG = {
  // Animation and UX
  animationDuration: 300,
  toastDuration: 5000,
  
  // Pagination
  defaultPageSize: 20,
  maxPageSize: 100,
  
  // Refresh intervals
  statusRefreshInterval: 30000, // 30 seconds
  historyRefreshInterval: 60000, // 1 minute
  
  // Error handling
  maxErrorsDisplayed: 5,
  errorAutoRemoveDelay: 10000, // 10 seconds
};

// Real-time Configuration
export const REALTIME_CONFIG = {
  // WebSocket settings
  wsUrl: import.meta.env.VITE_WS_URL || 
         (API_CONFIG.baseURL.replace('https:', 'wss:').replace('http:', 'ws:') + '/ws'),
  
  // Connection management
  reconnectAttempts: 5,
  reconnectDelay: 2000,
  heartbeatInterval: 30000,
  
  // Event handlers
  events: {
    scan_complete: 'scan:complete',
    connection_status: 'connection:status',
    rate_limit: 'rate:limit',
    auth_logout: 'auth:logout',
  }
};

// Security Configuration
export const SECURITY_CONFIG = {
  // Content Security Policy
  csp: {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", 'https://accounts.google.com'],
    'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    'font-src': ["'self'", 'https://fonts.gstatic.com'],
    'img-src': ["'self'", 'data:', 'https:'],
    'connect-src': ["'self'", API_CONFIG.baseURL, REALTIME_CONFIG.wsUrl],
    'frame-src': ["'none'"],
    'object-src': ["'none'"],
  },
  
  // Security headers
  headers: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  },
  
  // HTTPS enforcement
  enforceHttps: isProduction,
  hstsMaxAge: 31536000, // 1 year
};

// Performance Configuration
export const PERFORMANCE_CONFIG = {
  // Caching
  cacheTimeout: 300000, // 5 minutes
  maxCacheSize: 50, // Max cached items
  
  // Bundle optimization
  chunkSizeWarning: 500000, // 500KB
  
  // Resource hints
  preconnectDomains: [
    'https://accounts.google.com',
    'https://www.googleapis.com',
    API_CONFIG.baseURL,
  ],
  
  // Lazy loading
  lazyLoadThreshold: '100px',
  enableVirtualization: true,
};

// Analytics and Monitoring
export const MONITORING_CONFIG = {
  // Error tracking
  enableErrorTracking: isProduction,
  errorSampleRate: 1.0,
  
  // Performance monitoring
  enablePerformanceTracking: isProduction,
  performanceSampleRate: 0.1, // 10%
  
  // User analytics
  enableAnalytics: isProduction,
  analyticsId: import.meta.env.VITE_ANALYTICS_ID,
  
  // Feature flags
  featureFlags: {
    realTimeUpdates: true,
    enhancedSecurity: true,
    advancedAnalytics: isProduction,
    debugMode: isDevelopment,
  }
};

// Export consolidated configuration
export const CONFIG = {
  api: API_CONFIG,
  auth: AUTH_CONFIG,
  ui: UI_CONFIG,
  realtime: REALTIME_CONFIG,
  security: SECURITY_CONFIG,
  performance: PERFORMANCE_CONFIG,
  monitoring: MONITORING_CONFIG,
  environment: {
    isProduction,
    isDevelopment,
    version: import.meta.env.VITE_APP_VERSION || '1.0.0',
    buildTime: import.meta.env.VITE_BUILD_TIME || new Date().toISOString(),
  }
};

// Production optimizations
if (isProduction) {
  // Disable console logs in production
  if (typeof console !== 'undefined') {
    console.log = () => {};
    console.warn = () => {};
    console.debug = () => {};
    // Keep console.error for critical issues
  }
  
  // Enable service worker for caching
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js')
        .then(registration => {
          console.info('SW registered: ', registration);
        })
        .catch(registrationError => {
          console.error('SW registration failed: ', registrationError);
        });
    });
  }
}

export default CONFIG;