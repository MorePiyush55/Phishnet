import { typedApiClient } from './typedApiClient';
import { 
  LoginRequest, 
  LoginResponse,
  RefreshTokenRequest,
  EmailListParams,
  EmailBulkActionRequest
} from '../types/api';

/**
 * Enhanced API Service that wraps the typed API client
 * Maintains backward compatibility while providing type safety
 */
class EnhancedApiService {
  // Authentication methods
  async login(username: string, password: string): Promise<LoginResponse> {
    const response = await typedApiClient.login({ username, password });
    return response.data;
  }

  async logout(): Promise<void> {
    const refreshToken = typedApiClient.getTokenExpiry();
    if (refreshToken) {
      await typedApiClient.logout({ refresh_token: refreshToken.toString() });
    }
  }

  async refreshToken(): Promise<string> {
    const refreshToken = localStorage.getItem('phishnet_refresh_token');
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await typedApiClient.refreshToken({ refresh_token: refreshToken });
    return response.data.access_token;
  }

  // Token management
  getAccessToken(): string | null {
    return localStorage.getItem('phishnet_access_token');
  }

  getTokenExpiry(): Date | null {
    return typedApiClient.getTokenExpiry();
  }

  isTokenExpired(): boolean {
    return !typedApiClient.isAuthenticated();
  }

  setTokens(accessToken: string, refreshToken: string, expiresIn: number): void {
    const expiryTime = new Date(Date.now() + expiresIn * 1000);
    localStorage.setItem('phishnet_access_token', accessToken);
    localStorage.setItem('phishnet_refresh_token', refreshToken);
    localStorage.setItem('phishnet_token_expiry', expiryTime.toISOString());
  }

  clearTokens(): void {
    typedApiClient.clearAuth();
  }

  // Email methods with backward compatibility
  async getEmails(params?: EmailListParams) {
    const response = await typedApiClient.getEmails(params);
    // Transform to match old format if needed
    return {
      emails: response.data,
      pagination: response.pagination,
    };
  }

  async getEmail(id: string) {
    const response = await typedApiClient.getEmail(id);
    return response.data;
  }

  async getEmailBody(id: string) {
    const response = await typedApiClient.getEmailBody(id);
    return response.data;
  }

  async bulkEmailAction(data: EmailBulkActionRequest) {
    const response = await typedApiClient.bulkEmailAction(data);
    return response.data;
  }

  async reprocessEmail(id: string) {
    const response = await typedApiClient.reprocessEmail(id);
    return response.data;
  }

  // Link methods
  async getEmailLinks(emailId: string) {
    const response = await typedApiClient.getEmailLinks(emailId);
    return response.data;
  }

  async analyzeLink(linkId: string, params?: any) {
    const response = await typedApiClient.analyzeLink(linkId, params);
    return response.data;
  }

  async getLinkScreenshot(linkId: string) {
    const response = await typedApiClient.getLinkScreenshot(linkId);
    return response.data;
  }

  // User methods
  async getCurrentUser() {
    const response = await typedApiClient.getCurrentUser();
    return response.data;
  }

  async getUsers(params?: any) {
    const response = await typedApiClient.getUsers(params);
    return {
      users: response.data,
      pagination: response.pagination,
    };
  }

  async createUser(data: any) {
    const response = await typedApiClient.createUser(data);
    return response.data;
  }

  async updateUser(id: number, data: any) {
    const response = await typedApiClient.updateUser(id, data);
    return response.data;
  }

  async deleteUser(id: number) {
    await typedApiClient.deleteUser(id);
  }

  // Audit methods
  async getAuditLogs(params?: any) {
    const response = await typedApiClient.getAuditLogs(params);
    return {
      logs: response.data,
      pagination: response.pagination,
    };
  }

  // System methods
  async getSystemStats() {
    const response = await typedApiClient.getSystemStats();
    return response.data;
  }

  async getSystemHealth() {
    const response = await typedApiClient.getSystemHealth();
    return response.data;
  }

  // Threat intelligence methods
  async getThreatIntelligence(params?: any) {
    const response = await typedApiClient.getThreatIntelligence(params);
    return response.data;
  }

  // Tenant methods
  async getTenants() {
    const response = await typedApiClient.getTenants();
    return response.data;
  }

  async getTenant(id: string) {
    const response = await typedApiClient.getTenant(id);
    return response.data;
  }

  async updateTenant(id: string, data: any) {
    const response = await typedApiClient.updateTenant(id, data);
    return response.data;
  }

  // Utility methods
  isAuthenticated(): boolean {
    return typedApiClient.isAuthenticated();
  }

  // Direct access to typed client for advanced usage
  getTypedClient() {
    return typedApiClient;
  }

  // Axios instance for custom requests
  getAxiosInstance() {
    return typedApiClient.getAxiosInstance();
  }
}

// Create singleton instance
export const enhancedApiService = new EnhancedApiService();

// Export both for compatibility
export { enhancedApiService as apiService };
export default enhancedApiService;
