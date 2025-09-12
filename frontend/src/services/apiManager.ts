import { typedApiClient, TypedApiClient } from './typedApiClient';
import { enhancedApiService } from './enhancedApiService';
import { 
  useApi, 
  useEmails, 
  useEmail, 
  useCurrentUser, 
  useSystemStats,
  useApiMutation,
  usePaginatedApi,
  useRealTimeData,
  useCachedApi
} from '../hooks/useTypedApi';
import type { 
  ApiResponse, 
  PaginatedResponse, 
  Email, 
  User, 
  SystemStats,
  LoginRequest,
  LoginResponse,
  EmailListParams,
  ApiMethods
} from '../types/api';

/**
 * Comprehensive API Service Manager
 * Provides unified access to all API functionality with full TypeScript support
 */
export class ApiServiceManager {
  private typedClient: TypedApiClient;
  private enhancedService: typeof enhancedApiService;

  constructor() {
    this.typedClient = typedApiClient;
    this.enhancedService = enhancedApiService;
  }

  // Typed client access
  get client(): ApiMethods {
    return this.typedClient;
  }

  // Enhanced service access (backward compatibility)
  get service() {
    return this.enhancedService;
  }

  // Authentication shortcuts
  auth = {
    login: (credentials: LoginRequest) => this.typedClient.login(credentials),
    logout: () => this.enhancedService.logout(),
    refresh: () => this.enhancedService.refreshToken(),
    getCurrentUser: () => this.typedClient.getCurrentUser(),
    isAuthenticated: () => this.typedClient.isAuthenticated(),
    clearAuth: () => this.typedClient.clearAuth(),
  };

  // Email shortcuts
  emails = {
    list: (params?: EmailListParams) => this.typedClient.getEmails(params),
    get: (id: string) => this.typedClient.getEmail(id),
    getBody: (id: string) => this.typedClient.getEmailBody(id),
    getLinks: (emailId: string) => this.typedClient.getEmailLinks(emailId),
    bulkAction: (data: any) => this.typedClient.bulkEmailAction(data),
    reprocess: (id: string) => this.typedClient.reprocessEmail(id),
  };

  // User shortcuts
  users = {
    list: (params?: any) => this.typedClient.getUsers(params),
    get: (id: number) => this.typedClient.getUser(id),
    create: (data: any) => this.typedClient.createUser(data),
    update: (id: number, data: any) => this.typedClient.updateUser(id, data),
    delete: (id: number) => this.typedClient.deleteUser(id),
  };

  // System shortcuts
  system = {
    stats: () => this.typedClient.getSystemStats(),
    health: () => this.typedClient.getSystemHealth(),
  };

  // Audit shortcuts
  audit = {
    logs: (params?: any) => this.typedClient.getAuditLogs(params),
  };

  // Link analysis shortcuts
  links = {
    analyze: (linkId: string, params?: any) => this.typedClient.analyzeLink(linkId, params),
    screenshot: (linkId: string) => this.typedClient.getLinkScreenshot(linkId),
  };

  // Threat intelligence shortcuts
  threatIntel = {
    get: (params?: any) => this.typedClient.getThreatIntelligence(params),
  };

  // Tenant shortcuts
  tenants = {
    list: () => this.typedClient.getTenants(),
    get: (id: string) => this.typedClient.getTenant(id),
    update: (id: string, data: any) => this.typedClient.updateTenant(id, data),
  };

  // Utility methods
  utils = {
    getAxiosInstance: () => this.typedClient.getAxiosInstance(),
    isAuthenticated: () => this.typedClient.isAuthenticated(),
    getTokenExpiry: () => this.typedClient.getTokenExpiry(),
  };
}

// Create singleton instance
export const apiManager = new ApiServiceManager();

// Re-export hooks for convenience
export {
  useApi,
  useEmails,
  useEmail,
  useCurrentUser,
  useSystemStats,
  useApiMutation,
  usePaginatedApi,
  useRealTimeData,
  useCachedApi,
};

// Re-export types
export type {
  ApiResponse,
  PaginatedResponse,
  Email,
  User,
  SystemStats,
  LoginRequest,
  LoginResponse,
  EmailListParams,
  ApiMethods,
};

// Re-export clients for advanced usage
export { typedApiClient, enhancedApiService };

// Default export for primary usage
export default apiManager;

/**
 * Usage Examples:
 * 
 * // Simple API calls
 * const response = await apiManager.emails.list({ status: 'malicious' });
 * const user = await apiManager.auth.getCurrentUser();
 * 
 * // Using React hooks
 * const { data: emails, loading, error } = useEmails({ status: 'suspicious' });
 * const { data: user } = useCurrentUser();
 * 
 * // Using mutations
 * const bulkAction = useApiMutation();
 * await bulkAction.mutate(
 *   (data) => apiManager.emails.bulkAction(data),
 *   { email_ids: ['1', '2'], action: 'quarantine' }
 * );
 * 
 * // Direct typed client access
 * const stats = await apiManager.client.getSystemStats();
 * 
 * // Enhanced service for backward compatibility
 * const emails = await apiManager.service.getEmails();
 */
