import axios, { AxiosResponse, AxiosError } from 'axios';

// Types
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'bearer';
  expires_in: number;
  user: {
    id: number;
    username: string;
    email: string;
    role: string;
    is_active: boolean;
  };
}

export interface RefreshTokenResponse {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
}

export interface Email {
  id: number;
  sender: string;
  subject: string;
  timestamp: string;
  risk_score: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  recipient: string;
  status: 'quarantined' | 'analyzing' | 'safe' | 'pending';
  ai_verdict?: string;
  vt_score?: string;
  links_count: number;
  attachments_count: number;
  gmail_id?: string;
  thread_id?: string;
  body_text?: string;
  body_html?: string;
  headers?: Record<string, any>;
  ml_features?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface EmailsResponse {
  emails: Email[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface Link {
  id: number;
  email_id: number;
  url: string;
  domain: string;
  risk_score: number;
  status: 'safe' | 'suspicious' | 'malicious' | 'pending';
  redirect_chain?: string[];
  screenshot_url?: string;
  sandbox_report?: Record<string, any>;
  vt_report?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface AuditLog {
  id: number;
  user_id?: number;
  action: string;
  resource_type: string;
  resource_id?: number;
  details: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
  timestamp: string;
}

export interface SystemStats {
  emails_processed_today: number;
  emails_quarantined: number;
  active_threats: number;
  system_status: 'healthy' | 'degraded' | 'down';
  last_updated: string;
}

// Base API configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

class ApiService {
  private baseURL: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private refreshPromise: Promise<string> | null = null;
  private tokenExpiry: number | null = null;

  constructor() {
    this.baseURL = `${API_BASE_URL}/api/v1`;
    
    // Initialize axios defaults
    axios.defaults.baseURL = this.baseURL;
    
    // Load tokens from localStorage
    this.accessToken = localStorage.getItem('access_token');
    this.refreshToken = localStorage.getItem('refresh_token');
    const expiryStr = localStorage.getItem('token_expiry');
    this.tokenExpiry = expiryStr ? parseInt(expiryStr) : null;
    
    // Set up request interceptor
    axios.interceptors.request.use(
      (config) => {
        if (this.accessToken) {
          config.headers.Authorization = `Bearer ${this.accessToken}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );
    
    // Set up response interceptor for token refresh
    axios.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config as any;
        
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;
          
          try {
            const newToken = await this.silentRefresh();
            if (newToken && originalRequest) {
              originalRequest.headers.Authorization = `Bearer ${newToken}`;
              return axios(originalRequest);
            }
          } catch (refreshError) {
            // Refresh failed, redirect to login
            this.clearTokens();
            window.location.href = '/login';
            return Promise.reject(refreshError);
          }
        }
        
        return Promise.reject(error);
      }
    );
  }

  // Authentication methods
  async login(credentials: LoginRequest): Promise<LoginResponse> {
    const formData = new FormData();
    formData.append('username', credentials.username);
    formData.append('password', credentials.password);
    
    const response: AxiosResponse<LoginResponse> = await axios.post('/auth/login', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    
    const data = response.data;
    this.setTokens(data.access_token, data.refresh_token);
    
    return data;
  }

  async logout(): Promise<void> {
    try {
      if (this.refreshToken) {
        await axios.post('/auth/logout', { refresh_token: this.refreshToken });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      this.clearTokens();
    }
  }

  async silentRefresh(): Promise<string | null> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }
    
    // Prevent multiple concurrent refresh requests
    if (this.refreshPromise) {
      return this.refreshPromise;
    }
    
    this.refreshPromise = this.performRefresh();
    
    try {
      const token = await this.refreshPromise;
      return token;
    } finally {
      this.refreshPromise = null;
    }
  }

  private async performRefresh(): Promise<string> {
    const response: AxiosResponse<RefreshTokenResponse> = await axios.post('/auth/refresh', {
      refresh_token: this.refreshToken,
    });
    
    const data = response.data;
    this.setTokens(data.access_token, this.refreshToken!);
    
    return data.access_token;
  }

  private setTokens(accessToken: string, refreshToken: string): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    
    // Calculate expiry time (JWT tokens have exp claim, but we'll use current time + expires_in)
    // In a real implementation, you'd decode the JWT to get the actual expiry
    this.tokenExpiry = Math.floor(Date.now() / 1000) + 3600; // 1 hour default
    
    localStorage.setItem('access_token', accessToken);
    localStorage.setItem('refresh_token', refreshToken);
    localStorage.setItem('token_expiry', this.tokenExpiry.toString());
  }

  private clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiry = null;
    
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('token_expiry');
  }

  // Email API methods
  async getEmails(params: {
    page?: number;
    size?: number;
    search?: string;
    risk_level?: string;
    status?: string;
    time_range?: string;
    sort_by?: string;
    sort_order?: 'asc' | 'desc';
  } = {}): Promise<EmailsResponse> {
    const response: AxiosResponse<EmailsResponse> = await axios.get('/emails', {
      params: {
        page: 1,
        size: 20,
        ...params,
      },
    });
    
    return response.data;
  }

  async getEmail(id: number): Promise<Email> {
    const response: AxiosResponse<Email> = await axios.get(`/emails/${id}`);
    return response.data;
  }

  async updateEmailStatus(id: number, status: string, reason?: string): Promise<Email> {
    const response: AxiosResponse<Email> = await axios.patch(`/emails/${id}/status`, {
      status,
      reason,
    });
    return response.data;
  }

  async deleteEmail(id: number): Promise<void> {
    await axios.delete(`/emails/${id}`);
  }

  async bulkUpdateEmails(emailIds: number[], action: string, reason?: string): Promise<void> {
    await axios.post('/emails/bulk-action', {
      email_ids: emailIds,
      action,
      reason,
    });
  }

  // Link API methods
  async getEmailLinks(emailId: number): Promise<Link[]> {
    const response: AxiosResponse<Link[]> = await axios.get(`/emails/${emailId}/links`);
    return response.data;
  }

  async analyzeLink(linkId: number): Promise<Link> {
    const response: AxiosResponse<Link> = await axios.post(`/links/${linkId}/analyze`);
    return response.data;
  }

  async getLinkScreenshot(linkId: number): Promise<string> {
    const response: AxiosResponse<{ screenshot_url: string }> = await axios.post(`/links/${linkId}/screenshot`);
    return response.data.screenshot_url;
  }

  // Analysis API methods
  async reprocessEmail(emailId: number): Promise<Email> {
    const response: AxiosResponse<Email> = await axios.post(`/analysis/reprocess/${emailId}`);
    return response.data;
  }

  async getThreatIntel(query: string, source?: string): Promise<any> {
    const response = await axios.get('/analysis/threat-intel', {
      params: { query, source },
    });
    return response.data;
  }

  // Audit API methods
  async getAuditLogs(params: {
    page?: number;
    size?: number;
    user_id?: number;
    action?: string;
    resource_type?: string;
    start_date?: string;
    end_date?: string;
  } = {}): Promise<{ logs: AuditLog[]; total: number; page: number; size: number; pages: number }> {
    const response = await axios.get('/audits/logs', { params });
    return response.data;
  }

  // System API methods
  async getSystemStats(): Promise<SystemStats> {
    const response: AxiosResponse<SystemStats> = await axios.get('/system/stats');
    return response.data;
  }

  async getHealthStatus(): Promise<{ status: string; details: Record<string, any> }> {
    const response = await axios.get('/system/health');
    return response.data;
  }

  // Gmail OAuth API methods
  async getGmailStatus(): Promise<any> {
    const response = await axios.get('/auth/gmail/status');
    return response.data;
  }

  async getGmailScopes(): Promise<any> {
    const response = await axios.get('/auth/gmail/scopes');
    return response.data;
  }

  async startGmailOAuth(): Promise<any> {
    const response = await axios.post('/auth/gmail/start', {});
    return response.data;
  }

  async revokeGmailOAuth(): Promise<any> {
    const response = await axios.post('/auth/gmail/revoke', {});
    return response.data;
  }

  async triggerGmailScan(options: { force_scan?: boolean; days_back?: number }): Promise<any> {
    const response = await axios.post('/auth/gmail/scan', options);
    return response.data;
  }

  async setupGmailWatch(): Promise<any> {
    const response = await axios.post('/auth/gmail/watch/setup', {});
    return response.data;
  }

  async stopGmailWatch(): Promise<any> {
    const response = await axios.post('/auth/gmail/watch/stop', {});
    return response.data;
  }

  async getGmailMessages(query?: string, maxResults?: number): Promise<any> {
    const params = new URLSearchParams();
    if (query) params.append('query', query);
    if (maxResults) params.append('max_results', maxResults.toString());
    
    const response = await axios.get(`/auth/gmail/messages?${params.toString()}`);
    return response.data;
  }

  async getGmailHealthCheck(): Promise<any> {
    const response = await axios.get('/auth/gmail/health');
    return response.data;
  }

  // Utility methods
  isAuthenticated(): boolean {
    return !!this.accessToken;
  }

  getAccessToken(): string | null {
    return this.accessToken;
  }

  getTokenExpiry(): number | null {
    return this.tokenExpiry;
  }

  // Enhanced methods for token management
  isTokenExpired(): boolean {
    if (!this.tokenExpiry) return true;
    return Date.now() / 1000 > this.tokenExpiry;
  }

  getTimeUntilExpiry(): number {
    if (!this.tokenExpiry) return 0;
    return Math.max(0, this.tokenExpiry - Math.floor(Date.now() / 1000));
  }
}

// Create singleton instance
export const apiService = new ApiService();
