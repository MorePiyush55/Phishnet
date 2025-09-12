import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import {
  ApiResponse,
  PaginatedResponse,
  ErrorResponse,
  ApiMethods,
  ApiConfig,
  LoginRequest,
  LoginResponse,
  LogoutRequest,
  RefreshTokenRequest,
  RefreshTokenResponse,
  User,
  Email,
  EmailBody,
  EmailListParams,
  EmailBulkActionRequest,
  EmailActionResponse,
  Link,
  LinkAnalysis,
  LinkAnalysisRequest,
  AuditLog,
  AuditLogParams,
  SystemStats,
  SystemHealth,
  ThreatIntelligence,
  ThreatIntelParams,
  Tenant,
  CreateUserRequest,
  UpdateUserRequest,
  UserListParams,
} from '../types/api';

// Default configuration
const DEFAULT_CONFIG: ApiConfig = {
  baseURL: '/api/v1',
  timeout: 30000,
  retryAttempts: 3,
  retryDelay: 1000,
};

// Custom error class for API errors
export class ApiError extends Error {
  public status: number;
  public code: string;
  public details?: any;
  public field?: string;

  constructor(error: ErrorResponse, status: number = 500) {
    super(error.error.message);
    this.name = 'ApiError';
    this.status = status;
    this.code = error.error.code;
    this.details = error.error.details;
    this.field = error.error.field;
  }
}

// Token management interface
interface TokenManager {
  getAccessToken(): string | null;
  getRefreshToken(): string | null;
  setTokens(accessToken: string, refreshToken: string, expiresIn: number): void;
  clearTokens(): void;
  isTokenExpired(): boolean;
  getTokenExpiry(): Date | null;
}

// Default token manager implementation
class LocalStorageTokenManager implements TokenManager {
  private readonly ACCESS_TOKEN_KEY = 'phishnet_access_token';
  private readonly REFRESH_TOKEN_KEY = 'phishnet_refresh_token';
  private readonly TOKEN_EXPIRY_KEY = 'phishnet_token_expiry';

  getAccessToken(): string | null {
    return localStorage.getItem(this.ACCESS_TOKEN_KEY);
  }

  getRefreshToken(): string | null {
    return localStorage.getItem(this.REFRESH_TOKEN_KEY);
  }

  setTokens(accessToken: string, refreshToken: string, expiresIn: number): void {
    const expiryTime = new Date(Date.now() + expiresIn * 1000);
    
    localStorage.setItem(this.ACCESS_TOKEN_KEY, accessToken);
    localStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
    localStorage.setItem(this.TOKEN_EXPIRY_KEY, expiryTime.toISOString());
  }

  clearTokens(): void {
    localStorage.removeItem(this.ACCESS_TOKEN_KEY);
    localStorage.removeItem(this.REFRESH_TOKEN_KEY);
    localStorage.removeItem(this.TOKEN_EXPIRY_KEY);
  }

  isTokenExpired(): boolean {
    const expiry = this.getTokenExpiry();
    if (!expiry) return true;
    
    // Consider token expired 5 minutes before actual expiry
    const bufferTime = 5 * 60 * 1000; // 5 minutes
    return new Date().getTime() > (expiry.getTime() - bufferTime);
  }

  getTokenExpiry(): Date | null {
    const expiryString = localStorage.getItem(this.TOKEN_EXPIRY_KEY);
    return expiryString ? new Date(expiryString) : null;
  }
}

// Typed API Client Class
export class TypedApiClient implements ApiMethods {
  private axiosInstance: AxiosInstance;
  private tokenManager: TokenManager;
  private config: ApiConfig;
  private refreshPromise: Promise<string> | null = null;

  constructor(config: Partial<ApiConfig> = {}, tokenManager?: TokenManager) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.tokenManager = tokenManager || new LocalStorageTokenManager();
    
    this.axiosInstance = axios.create({
      baseURL: this.config.baseURL,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    // Request interceptor for adding auth token
    this.axiosInstance.interceptors.request.use(
      (config) => {
        const token = this.tokenManager.getAccessToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for handling token refresh
    this.axiosInstance.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;

          try {
            const newToken = await this.handleTokenRefresh();
            originalRequest.headers!.Authorization = `Bearer ${newToken}`;
            return this.axiosInstance(originalRequest);
          } catch (refreshError) {
            this.tokenManager.clearTokens();
            // Redirect to login or emit auth event
            window.dispatchEvent(new CustomEvent('auth:logout'));
            return Promise.reject(refreshError);
          }
        }

        return Promise.reject(this.handleApiError(error));
      }
    );
  }

  private async handleTokenRefresh(): Promise<string> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.performTokenRefresh();
    
    try {
      const token = await this.refreshPromise;
      return token;
    } finally {
      this.refreshPromise = null;
    }
  }

  private async performTokenRefresh(): Promise<string> {
    const refreshToken = this.tokenManager.getRefreshToken();
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await axios.post<ApiResponse<RefreshTokenResponse>>(
        `${this.config.baseURL}/auth/refresh`,
        { refresh_token: refreshToken }
      );

      const { access_token, expires_in } = response.data.data;
      this.tokenManager.setTokens(access_token, refreshToken, expires_in);
      
      return access_token;
    } catch (error) {
      this.tokenManager.clearTokens();
      throw error;
    }
  }

  private handleApiError(error: AxiosError): Error {
    if (error.response?.data) {
      const errorData = error.response.data as ErrorResponse;
      return new ApiError(errorData, error.response.status);
    }
    
    return new Error(error.message || 'An unexpected error occurred');
  }

  private async retryRequest<T>(
    requestFn: () => Promise<AxiosResponse<T>>,
    attempts: number = this.config.retryAttempts
  ): Promise<AxiosResponse<T>> {
    try {
      return await requestFn();
    } catch (error) {
      if (attempts > 1 && this.shouldRetry(error as AxiosError)) {
        await this.delay(this.config.retryDelay);
        return this.retryRequest(requestFn, attempts - 1);
      }
      throw error;
    }
  }

  private shouldRetry(error: AxiosError): boolean {
    // Retry on network errors or 5xx server errors
    return !error.response || (error.response.status >= 500 && error.response.status < 600);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Authentication Methods
  async login(data: LoginRequest): Promise<ApiResponse<LoginResponse>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.post<ApiResponse<LoginResponse>>('/auth/login', data)
    );
    
    const { access_token, refresh_token, expires_in } = response.data.data;
    this.tokenManager.setTokens(access_token, refresh_token, expires_in);
    
    return response.data;
  }

  async logout(data: LogoutRequest): Promise<ApiResponse<void>> {
    try {
      const response = await this.axiosInstance.post<ApiResponse<void>>('/auth/logout', data);
      return response.data;
    } finally {
      this.tokenManager.clearTokens();
    }
  }

  async refreshToken(data: RefreshTokenRequest): Promise<ApiResponse<RefreshTokenResponse>> {
    const response = await this.axiosInstance.post<ApiResponse<RefreshTokenResponse>>('/auth/refresh', data);
    
    const { access_token, expires_in } = response.data.data;
    this.tokenManager.setTokens(access_token, data.refresh_token, expires_in);
    
    return response.data;
  }

  async getCurrentUser(): Promise<ApiResponse<User>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<ApiResponse<User>>('/auth/me')
    );
    return response.data;
  }

  // User Methods
  async getUsers(params?: UserListParams): Promise<PaginatedResponse<User>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<PaginatedResponse<User>>('/users', { params })
    );
    return response.data;
  }

  async getUser(id: number): Promise<ApiResponse<User>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<ApiResponse<User>>(`/users/${id}`)
    );
    return response.data;
  }

  async createUser(data: CreateUserRequest): Promise<ApiResponse<User>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.post<ApiResponse<User>>('/users', data)
    );
    return response.data;
  }

  async updateUser(id: number, data: UpdateUserRequest): Promise<ApiResponse<User>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.put<ApiResponse<User>>(`/users/${id}`, data)
    );
    return response.data;
  }

  async deleteUser(id: number): Promise<ApiResponse<void>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.delete<ApiResponse<void>>(`/users/${id}`)
    );
    return response.data;
  }

  // Email Methods
  async getEmails(params?: EmailListParams): Promise<PaginatedResponse<Email>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<PaginatedResponse<Email>>('/emails', { params })
    );
    return response.data;
  }

  async getEmail(id: string): Promise<ApiResponse<Email>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<ApiResponse<Email>>(`/emails/${id}`)
    );
    return response.data;
  }

  async getEmailBody(id: string): Promise<ApiResponse<EmailBody>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<ApiResponse<EmailBody>>(`/emails/${id}/body`)
    );
    return response.data;
  }

  async bulkEmailAction(data: EmailBulkActionRequest): Promise<ApiResponse<EmailActionResponse>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.post<ApiResponse<EmailActionResponse>>('/emails/bulk-action', data)
    );
    return response.data;
  }

  async reprocessEmail(id: string): Promise<ApiResponse<Email>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.post<ApiResponse<Email>>(`/emails/${id}/reprocess`)
    );
    return response.data;
  }

  // Link Methods
  async getEmailLinks(emailId: string): Promise<ApiResponse<Link[]>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<ApiResponse<Link[]>>(`/emails/${emailId}/links`)
    );
    return response.data;
  }

  async analyzeLink(linkId: string, params?: LinkAnalysisRequest): Promise<ApiResponse<LinkAnalysis>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.post<ApiResponse<LinkAnalysis>>(`/links/${linkId}/analyze`, params)
    );
    return response.data;
  }

  async getLinkScreenshot(linkId: string): Promise<ApiResponse<{ screenshot_url: string }>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.post<ApiResponse<{ screenshot_url: string }>>(`/links/${linkId}/screenshot`)
    );
    return response.data;
  }

  // Audit Methods
  async getAuditLogs(params?: AuditLogParams): Promise<PaginatedResponse<AuditLog>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<PaginatedResponse<AuditLog>>('/audit/logs', { params })
    );
    return response.data;
  }

  // System Methods
  async getSystemStats(): Promise<ApiResponse<SystemStats>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<ApiResponse<SystemStats>>('/system/stats')
    );
    return response.data;
  }

  async getSystemHealth(): Promise<ApiResponse<SystemHealth>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<ApiResponse<SystemHealth>>('/system/health')
    );
    return response.data;
  }

  // Threat Intelligence Methods
  async getThreatIntelligence(params?: ThreatIntelParams): Promise<ApiResponse<ThreatIntelligence>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<ApiResponse<ThreatIntelligence>>('/threat-intel', { params })
    );
    return response.data;
  }

  // Tenant Methods
  async getTenants(): Promise<ApiResponse<Tenant[]>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<ApiResponse<Tenant[]>>('/tenants')
    );
    return response.data;
  }

  async getTenant(id: string): Promise<ApiResponse<Tenant>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.get<ApiResponse<Tenant>>(`/tenants/${id}`)
    );
    return response.data;
  }

  async updateTenant(id: string, data: Partial<Tenant>): Promise<ApiResponse<Tenant>> {
    const response = await this.retryRequest(() =>
      this.axiosInstance.put<ApiResponse<Tenant>>(`/tenants/${id}`, data)
    );
    return response.data;
  }

  // Utility Methods
  public isAuthenticated(): boolean {
    return !!this.tokenManager.getAccessToken() && !this.tokenManager.isTokenExpired();
  }

  public getTokenExpiry(): Date | null {
    return this.tokenManager.getTokenExpiry();
  }

  public clearAuth(): void {
    this.tokenManager.clearTokens();
  }

  public setTokenManager(tokenManager: TokenManager): void {
    this.tokenManager = tokenManager;
  }

  public getAxiosInstance(): AxiosInstance {
    return this.axiosInstance;
  }
}

// Create and export singleton instance
export const typedApiClient = new TypedApiClient();

// Export hook for using typed API client
export const useTypedApi = () => {
  return typedApiClient;
};

// Export types for external use
export type { TokenManager };
export { LocalStorageTokenManager };
