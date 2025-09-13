import axios, { AxiosResponse } from 'axios';

// Base API configuration
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true, // Include httpOnly cookies
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add CSRF token
api.interceptors.request.use(
  (config) => {
    const csrfToken = getCsrfToken();
    if (csrfToken) {
      config.headers['X-CSRF-Token'] = csrfToken;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Enhanced response interceptor with retry logic
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      // Try to refresh session before redirecting
      try {
        await api.post('/auth/refresh');
        return api(originalRequest);
      } catch (refreshError) {
        // Clear auth state and redirect
        localStorage.removeItem('phishnet_auth');
        sessionStorage.clear();
        window.location.href = '/login';
      }
    }
    
    // Handle rate limiting with backoff
    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after'];
      if (retryAfter && !originalRequest._retryAfter) {
        originalRequest._retryAfter = true;
        await new Promise(resolve => setTimeout(resolve, parseInt(retryAfter) * 1000));
        return api(originalRequest);
      }
    }
    
    return Promise.reject(error);
  }
);

// Enhanced CSRF token management with fallback
function getCsrfToken(): string | null {
  // Try cookie first
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'csrf_token') {
      return decodeURIComponent(value);
    }
  }
  
  // Fallback to meta tag (common in production)
  const metaTag = document.querySelector('meta[name="csrf-token"]');
  if (metaTag) {
    return metaTag.getAttribute('content');
  }
  
  return null;
}

export interface UserStatus {
  user_id: number;
  email: string;
  display_name: string;
  google_sub: string;
  status: 'connected' | 'disconnected' | 'expired';
  connected_at?: string;
  scopes: string[];
  last_scan_at?: string;
  is_watch_active: boolean;
  permissions: string[];
}

export interface ScanResult {
  id: number;
  msg_id: string;
  verdict: 'safe' | 'suspicious' | 'malicious' | 'unknown';
  score: number;
  sender: string;
  subject: string;
  scanned_at: string;
  details: Record<string, any>;
}

export interface ScanHistory {
  results: ScanResult[];
  total: number;
  page: number;
  has_more: boolean;
}

export interface OAuthStartResponse {
  oauth_url: string;
  state: string;
}

export interface RevokeResponse {
  success: boolean;
  message: string;
}

export interface ScanTriggerResponse {
  job_id: string;
  message: string;
  estimated_time_seconds: number;
}

// Connection monitoring for offline/online states
export class ConnectionMonitor {
  private static isOnline = navigator.onLine;
  private static listeners: ((online: boolean) => void)[] = [];

  static init() {
    window.addEventListener('online', () => {
      this.isOnline = true;
      this.notifyListeners(true);
    });
    
    window.addEventListener('offline', () => {
      this.isOnline = false;
      this.notifyListeners(false);
    });
  }

  static addListener(callback: (online: boolean) => void) {
    this.listeners.push(callback);
  }

  static removeListener(callback: (online: boolean) => void) {
    this.listeners = this.listeners.filter(cb => cb !== callback);
  }

  private static notifyListeners(online: boolean) {
    this.listeners.forEach(callback => callback(online));
  }

  static get online() {
    return this.isOnline;
  }
}

// OAuth Service with production enhancements
export class OAuthService {
  private static reconnectAttempts = 0;
  private static maxReconnectAttempts = 3;
  private static reconnectDelay = 1000;

  /**
   * Clear all authentication-related data
   */
  private static clearStoredSession(): void {
    // Clear all authentication-related data
    localStorage.removeItem('oauth_state');
    localStorage.removeItem('csrf_token');
    sessionStorage.removeItem('oauth_state');
    
    // Clear rate limiting data for auth endpoints
    RateLimiter.clearRateLimit('/auth/start');
    RateLimiter.clearRateLimit('/api/user/status');
    RateLimiter.clearRateLimit('/auth/revoke');
    RateLimiter.clearRateLimit('/api/scan/trigger');
    
    // Clear any other session data
    sessionStorage.clear();
  }

  /**
   * Enhanced error handler with retry logic
   */
  private static async handleApiError(error: any, originalRequest?: any): Promise<any> {
    // Handle network errors with retry logic
    if (!error.response && originalRequest && this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
      
      console.log(`Network error, retrying in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      
      await new Promise(resolve => setTimeout(resolve, delay));
      
      try {
        const response = await api.request(originalRequest);
        this.reconnectAttempts = 0; // Reset on success
        return response.data;
      } catch (retryError) {
        return this.handleApiError(retryError);
      }
    }

    // Reset reconnection attempts on response
    if (error.response) {
      this.reconnectAttempts = 0;
    }

    // Handle authentication errors
    if (error.response?.status === 401) {
      this.clearStoredSession();
      window.dispatchEvent(new CustomEvent('auth:logout'));
      throw new Error('Session expired. Please login again.');
    }

    // Handle rate limiting
    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after'];
      const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : 60000;
      
      const message = `Too many requests. Please wait ${Math.ceil(waitTime / 1000)} seconds.`;
      window.dispatchEvent(new CustomEvent('auth:rate-limited', { 
        detail: { message, waitTime } 
      }));
      
      throw new Error(message);
    }

    // Enhanced error logging
    const errorDetails = {
      url: originalRequest?.url,
      method: originalRequest?.method,
      status: error.response?.status,
      message: error.message,
      data: error.response?.data
    };
    console.error('API Error:', errorDetails);

    throw new Error(`API Error: ${error.response?.data?.detail || error.message}`);
  }

  /**
   * Start OAuth flow - redirects to Google
   */
  static async startOAuth(): Promise<void> {
    try {
      // Check rate limit
      if (!RateLimiter.canMakeRequest('/auth/start')) {
        const waitTime = RateLimiter.getTimeUntilNextRequest('/auth/start');
        throw new Error(`Rate limit exceeded. Wait ${Math.ceil(waitTime / 1000)} seconds.`);
      }

      const response: AxiosResponse<OAuthStartResponse> = await api.get('/auth/start');
      
      // Store state for verification (optional extra security)
      sessionStorage.setItem('oauth_state', response.data.state);
      
      // Redirect to Google OAuth
      window.location.href = response.data.oauth_url;
    } catch (error: any) {
      return await this.handleApiError(error, { url: '/auth/start', method: 'get' });
    }
  }

  /**
   * Get current user OAuth status
   */
  static async getUserStatus(): Promise<UserStatus> {
    try {
      // Check rate limit
      if (!RateLimiter.canMakeRequest('/api/user/status')) {
        const waitTime = RateLimiter.getTimeUntilNextRequest('/api/user/status');
        throw new Error(`Rate limit exceeded. Wait ${Math.ceil(waitTime / 1000)} seconds.`);
      }

      const response: AxiosResponse<UserStatus> = await api.get('/api/user/status');
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 404) {
        throw new Error('User not connected');
      }
      return await this.handleApiError(error, { url: '/api/user/status', method: 'get' });
    }
  }

  /**
   * Revoke OAuth access and disconnect Gmail
   */
  static async revokeAccess(): Promise<RevokeResponse> {
    try {
      // Check rate limit
      if (!RateLimiter.canMakeRequest('/auth/revoke')) {
        const waitTime = RateLimiter.getTimeUntilNextRequest('/auth/revoke');
        throw new Error(`Rate limit exceeded. Wait ${Math.ceil(waitTime / 1000)} seconds.`);
      }

      const response: AxiosResponse<RevokeResponse> = await api.post('/auth/revoke');
      
      // Clear local session data on successful revoke
      this.clearStoredSession();
      
      return response.data;
    } catch (error: any) {
      return await this.handleApiError(error, { url: '/auth/revoke', method: 'post' });
    }
  }

  /**
   * Trigger manual scan of recent emails
   */
  static async triggerScan(): Promise<ScanTriggerResponse> {
    try {
      // Check rate limit
      if (!RateLimiter.canMakeRequest('/api/scan/trigger')) {
        const waitTime = RateLimiter.getTimeUntilNextRequest('/api/scan/trigger');
        throw new Error(`Rate limit exceeded. Wait ${Math.ceil(waitTime / 1000)} seconds.`);
      }

      const response: AxiosResponse<ScanTriggerResponse> = await api.post('/api/scan/trigger');
      return response.data;
    } catch (error: any) {
      return await this.handleApiError(error, { url: '/api/scan/trigger', method: 'post' });
    }
  }

  /**
   * Get scan history with pagination
   */
  static async getScanHistory(page: number = 1, limit: number = 20): Promise<ScanHistory> {
    try {
      // Check rate limit
      if (!RateLimiter.canMakeRequest('/api/scan/history')) {
        const waitTime = RateLimiter.getTimeUntilNextRequest('/api/scan/history');
        throw new Error(`Rate limit exceeded. Wait ${Math.ceil(waitTime / 1000)} seconds.`);
      }

      const response: AxiosResponse<ScanHistory> = await api.get('/api/scan/history', {
        params: { page, limit }
      });
      return response.data;
    } catch (error: any) {
      return await this.handleApiError(error, { url: '/api/scan/history', method: 'get' });
    }
  }

  /**
   * Export user data (GDPR compliance)
   */
  static async exportUserData(): Promise<Blob> {
    try {
      // Check rate limit
      if (!RateLimiter.canMakeRequest('/api/user/export')) {
        const waitTime = RateLimiter.getTimeUntilNextRequest('/api/user/export');
        throw new Error(`Rate limit exceeded. Wait ${Math.ceil(waitTime / 1000)} seconds.`);
      }

      const response = await api.get('/api/user/export', {
        responseType: 'blob'
      });
      return response.data;
    } catch (error: any) {
      return await this.handleApiError(error, { url: '/api/user/export', method: 'get' });
    }
  }

  /**
   * Delete user account and all data
   */
  static async deleteAccount(): Promise<{ success: boolean; message: string }> {
    try {
      // Check rate limit
      if (!RateLimiter.canMakeRequest('/api/user/delete')) {
        const waitTime = RateLimiter.getTimeUntilNextRequest('/api/user/delete');
        throw new Error(`Rate limit exceeded. Wait ${Math.ceil(waitTime / 1000)} seconds.`);
      }

      const response = await api.delete('/api/user/delete');
      
      // Clear all data on successful account deletion
      this.clearStoredSession();
      
      return response.data;
    } catch (error: any) {
      return await this.handleApiError(error, { url: '/api/user/delete', method: 'delete' });
    }
  }

  /**
   * Enhanced authentication check with automatic retry
   */
  static async checkAuthStatus(): Promise<UserStatus | null> {
    try {
      // Don't check if offline
      if (!ConnectionMonitor.online) {
        throw new Error('No internet connection');
      }

      const status = await this.getUserStatus();
      
      // Dispatch auth status event for components
      window.dispatchEvent(new CustomEvent('auth:status-checked', { 
        detail: { status, authenticated: true }
      }));
      
      return status;
    } catch (error: any) {
      // Handle unauthenticated state gracefully
      if (error.message.includes('User not connected') || error.message.includes('Session expired')) {
        window.dispatchEvent(new CustomEvent('auth:status-checked', { 
          detail: { status: null, authenticated: false }
        }));
        return null;
      }
      
      // Re-throw other errors
      throw error;
    }
  }

  /**
   * Verify OAuth callback state (call this on your callback page)
   */
  static verifyOAuthCallback(): boolean {
    const urlParams = new URLSearchParams(window.location.search);
    const state = urlParams.get('state');
    const storedState = sessionStorage.getItem('oauth_state');
    
    // Clear stored state
    sessionStorage.removeItem('oauth_state');
    
    if (!state || !storedState || state !== storedState) {
      console.error('OAuth state mismatch - possible CSRF attack');
      return false;
    }
    
    return true;
  }
}

// Rate limiting helper with localStorage persistence
export class RateLimiter {
  private static getStorageKey(endpoint: string): string {
    return `rate_limit_${endpoint}`;
  }

  static canMakeRequest(endpoint: string, maxRequests: number = 5, windowMs: number = 60000): boolean {
    const now = Date.now();
    const storageKey = this.getStorageKey(endpoint);
    
    // Get requests from localStorage for persistence across page reloads
    const storedRequests = localStorage.getItem(storageKey);
    const requests: number[] = storedRequests ? JSON.parse(storedRequests) : [];
    
    // Remove old requests outside the window
    const validRequests = requests.filter(time => now - time < windowMs);
    
    if (validRequests.length >= maxRequests) {
      return false;
    }
    
    // Add current request
    validRequests.push(now);
    localStorage.setItem(storageKey, JSON.stringify(validRequests));
    
    return true;
  }

  static getTimeUntilNextRequest(endpoint: string, maxRequests: number = 5, windowMs: number = 60000): number {
    const now = Date.now();
    const storageKey = this.getStorageKey(endpoint);
    const storedRequests = localStorage.getItem(storageKey);
    const requests: number[] = storedRequests ? JSON.parse(storedRequests) : [];
    
    if (requests.length < maxRequests) {
      return 0;
    }
    
    const oldestRequest = Math.min(...requests);
    return Math.max(0, windowMs - (now - oldestRequest));
  }

  static clearRateLimit(endpoint: string): void {
    const storageKey = this.getStorageKey(endpoint);
    localStorage.removeItem(storageKey);
  }
}

// Initialize connection monitoring
ConnectionMonitor.init();

export default api;