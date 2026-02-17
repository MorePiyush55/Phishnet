// API Response Types
export interface ApiResponse<T = any> {
  data: T;
  message?: string;
  success: boolean;
  timestamp: string;
}

export interface PaginatedResponse<T = any> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
    offset: number;
  };
  message?: string;
  success: boolean;
  timestamp: string;
}

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: any;
    field?: string;
  };
  success: false;
  timestamp: string;
}

// Authentication Types
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'bearer';
  expires_in: number;
  user: User;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

export interface RefreshTokenResponse {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
}

export interface LogoutRequest {
  refresh_token: string;
}

// User Types
export interface User {
  id: number;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'user';
  is_active: boolean;
  tenant_id: string;
  permissions?: string[];
  created_at: string;
  updated_at: string;
  last_login?: string;
  preferences?: UserPreferences;
}

export interface UserPreferences {
  theme: 'light' | 'dark' | 'auto';
  language: string;
  timezone: string;
  notifications: {
    email: boolean;
    push: boolean;
    sms: boolean;
  };
  dashboard: {
    defaultView: 'list' | 'grid' | 'compact';
    itemsPerPage: number;
    autoRefresh: boolean;
    refreshInterval: number;
  };
}

export interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
  role: 'admin' | 'analyst' | 'user';
  tenant_id: string;
}

export interface UpdateUserRequest {
  username?: string;
  email?: string;
  role?: 'admin' | 'analyst' | 'user';
  is_active?: boolean;
  preferences?: Partial<UserPreferences>;
}

// Email Types
export interface Email {
  id: string;
  message_id: string;
  gmail_id?: string;
  thread_id?: string;
  sender: string;
  recipient: string;
  subject: string;
  received_at: string;
  status: 'scanning' | 'safe' | 'suspicious' | 'malicious' | 'quarantined';
  confidence_score: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  tenant_id: string;
  has_attachments: boolean;
  attachments_count: number;
  links_count: number;
  preview?: string;
  ai_verdict?: string;
  vt_score?: string;
  created_at: string;
  updated_at: string;
  analysis?: EmailAnalysis;
  body?: EmailBody;
  headers?: EmailHeaders;
}

export interface EmailBody {
  id: string;
  email_id: string;
  html_content?: string;
  text_content?: string;
  size_bytes: number;
  attachments: EmailAttachment[];
  created_at: string;
}

export interface EmailAttachment {
  id: string;
  email_id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  is_safe: boolean;
  scan_result?: AttachmentScanResult;
  created_at: string;
}

export interface AttachmentScanResult {
  status: 'safe' | 'suspicious' | 'malicious';
  confidence: number;
  threats: string[];
  scanner: string;
  scanned_at: string;
}

export interface EmailHeaders {
  [key: string]: string | string[];
}

export interface EmailAnalysis {
  id: string;
  email_id: string;
  analyzer_results: AnalyzerResult[];
  final_verdict: 'safe' | 'suspicious' | 'malicious';
  confidence_score: number;
  processing_time_ms: number;
  created_at: string;
  updated_at: string;
}

export interface AnalyzerResult {
  analyzer_name: string;
  version: string;
  verdict: 'safe' | 'suspicious' | 'malicious';
  confidence: number;
  reasoning: string;
  evidence: any;
  processing_time_ms: number;
  metadata?: any;
}

// Email Query Parameters
export interface EmailListParams {
  page?: number;
  limit?: number;
  status?: Email['status'] | Email['status'][];
  sender?: string;
  recipient?: string;
  subject?: string;
  date_from?: string;
  date_to?: string;
  risk_level?: Email['risk_level'] | Email['risk_level'][];
  has_attachments?: boolean;
  tenant_id?: string;
  sort_by?: 'received_at' | 'created_at' | 'confidence_score' | 'risk_level';
  sort_order?: 'asc' | 'desc';
  search?: string;
}

export interface EmailBulkActionRequest {
  email_ids: string[];
  action: 'quarantine' | 'restore' | 'whitelist' | 'delete';
  reason?: string;
  notify_users?: boolean;
}

export interface EmailActionResponse {
  success: boolean;
  processed_count: number;
  failed_count: number;
  errors: Array<{
    email_id: string;
    error: string;
  }>;
}

// Link Analysis Types
export interface Link {
  id: string;
  email_id: string;
  url: string;
  display_text: string;
  position: number;
  redirect_chain?: RedirectChain[];
  analysis?: LinkAnalysis;
  screenshot_url?: string;
  is_safe: boolean;
  created_at: string;
  updated_at: string;
}

export interface RedirectChain {
  step: number;
  url: string;
  status_code: number;
  headers: Record<string, string>;
  response_time_ms: number;
  is_final: boolean;
  geolocation?: {
    country: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
  };
  ssl_info?: {
    is_secure: boolean;
    certificate: any;
    issuer: string;
    expires_at: string;
  };
}

export interface LinkAnalysis {
  id: string;
  link_id: string;
  verdict: 'safe' | 'suspicious' | 'malicious';
  confidence: number;
  reputation_score: number;
  blacklist_matches: string[];
  threat_categories: string[];
  screenshot_available: boolean;
  final_url: string;
  redirect_count: number;
  analysis_engines: Array<{
    name: string;
    verdict: string;
    confidence: number;
    details: any;
  }>;
  created_at: string;
}

export interface LinkAnalysisRequest {
  force_refresh?: boolean;
  include_screenshot?: boolean;
  max_redirects?: number;
}

// Audit Types
export interface AuditLog {
  id: string;
  user_id?: number;
  user_email?: string;
  tenant_id: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  details: any;
  ip_address: string;
  user_agent: string;
  timestamp: string;
  status: 'success' | 'failure' | 'partial';
}

export interface AuditLogParams {
  page?: number;
  limit?: number;
  user_id?: number;
  tenant_id?: string;
  action?: string;
  resource_type?: string;
  status?: AuditLog['status'];
  date_from?: string;
  date_to?: string;
  search?: string;
  sort_by?: 'timestamp' | 'action' | 'user_email';
  sort_order?: 'asc' | 'desc';
}

// System Types
export interface SystemStats {
  emails: {
    total: number;
    today: number;
    by_status: Record<Email['status'], number>;
    by_risk_level: Record<Email['risk_level'], number>;
  };
  users: {
    total: number;
    active: number;
    by_role: Record<User['role'], number>;
  };
  processing: {
    queue_size: number;
    average_processing_time_ms: number;
    last_processed_at?: string;
  };
  system: {
    uptime_seconds: number;
    version: string;
    deployment_id: string;
    health_status: 'healthy' | 'warning' | 'critical';
  };
}

export interface SystemHealth {
  status: 'healthy' | 'warning' | 'critical';
  services: Array<{
    name: string;
    status: 'up' | 'down' | 'degraded';
    response_time_ms?: number;
    last_check: string;
    details?: any;
  }>;
  dependencies: Array<{
    name: string;
    status: 'up' | 'down' | 'degraded';
    last_check: string;
    details?: any;
  }>;
  timestamp: string;
}

// Tenant Types
export interface Tenant {
  id: string;
  name: string;
  domain: string;
  is_active: boolean;
  settings: TenantSettings;
  created_at: string;
  updated_at: string;
}

export interface TenantSettings {
  max_users: number;
  max_emails_per_day: number;
  retention_days: number;
  features: {
    advanced_analysis: boolean;
    link_analysis: boolean;
    attachment_scanning: boolean;
    custom_rules: boolean;
    api_access: boolean;
    webhook_notifications: boolean;
  };
  integrations: {
    gmail: {
      enabled: boolean;
      client_id?: string;
      domain?: string;
    };
    slack: {
      enabled: boolean;
      webhook_url?: string;
    };
    teams: {
      enabled: boolean;
      webhook_url?: string;
    };
  };
}

// Threat Intelligence Types
export interface ThreatIntelligence {
  indicators: Array<{
    type: 'domain' | 'ip' | 'url' | 'hash' | 'email';
    value: string;
    threat_level: 'low' | 'medium' | 'high' | 'critical';
    categories: string[];
    first_seen: string;
    last_seen: string;
    confidence: number;
    sources: string[];
  }>;
  feeds: Array<{
    name: string;
    status: 'active' | 'inactive' | 'error';
    last_updated: string;
    indicator_count: number;
  }>;
  summary: {
    total_indicators: number;
    by_type: Record<string, number>;
    by_threat_level: Record<string, number>;
    last_updated: string;
  };
}

export interface ThreatIntelParams {
  indicator_type?: string;
  threat_level?: string;
  search?: string;
  page?: number;
  limit?: number;
}

// Webhook Types
export interface WebhookEvent {
  id: string;
  event_type: string;
  data: any;
  tenant_id: string;
  created_at: string;
  delivered_at?: string;
  attempts: number;
  status: 'pending' | 'delivered' | 'failed';
  error_message?: string;
}

export interface WebhookSubscription {
  id: string;
  tenant_id: string;
  url: string;
  events: string[];
  is_active: boolean;
  secret: string;
  created_at: string;
  updated_at: string;
  last_delivery?: string;
  failure_count: number;
}

// Configuration Types
export interface ApiConfig {
  baseURL: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
}

// Request/Response Interceptor Types
export interface RequestInterceptor {
  onFulfilled?: (config: any) => any;
  onRejected?: (error: any) => any;
}

export interface ResponseInterceptor {
  onFulfilled?: (response: any) => any;
  onRejected?: (error: any) => any;
}

// API Client Method Types
export interface ApiMethods {
  // Authentication
  login(data: LoginRequest): Promise<ApiResponse<LoginResponse>>;
  logout(data: LogoutRequest): Promise<ApiResponse<void>>;
  refreshToken(data: RefreshTokenRequest): Promise<ApiResponse<RefreshTokenResponse>>;
  getCurrentUser(): Promise<ApiResponse<User>>;
  
  // Users
  getUsers(params?: UserListParams): Promise<PaginatedResponse<User>>;
  getUser(id: number): Promise<ApiResponse<User>>;
  createUser(data: CreateUserRequest): Promise<ApiResponse<User>>;
  updateUser(id: number, data: UpdateUserRequest): Promise<ApiResponse<User>>;
  deleteUser(id: number): Promise<ApiResponse<void>>;
  
  // Emails
  getEmails(params?: EmailListParams): Promise<PaginatedResponse<Email>>;
  getEmail(id: string): Promise<ApiResponse<Email>>;
  getEmailBody(id: string): Promise<ApiResponse<EmailBody>>;
  bulkEmailAction(data: EmailBulkActionRequest): Promise<ApiResponse<EmailActionResponse>>;
  reprocessEmail(id: string): Promise<ApiResponse<Email>>;
  
  // Links
  getEmailLinks(emailId: string): Promise<ApiResponse<Link[]>>;
  analyzeLink(linkId: string, params?: LinkAnalysisRequest): Promise<ApiResponse<LinkAnalysis>>;
  getLinkScreenshot(linkId: string): Promise<ApiResponse<{ screenshot_url: string }>>;
  
  // Audit Logs
  getAuditLogs(params?: AuditLogParams): Promise<PaginatedResponse<AuditLog>>;
  
  // System
  getSystemStats(): Promise<ApiResponse<SystemStats>>;
  getSystemHealth(): Promise<ApiResponse<SystemHealth>>;
  
  // Threat Intelligence
  getThreatIntelligence(params?: ThreatIntelParams): Promise<ApiResponse<ThreatIntelligence>>;
  
  // Tenants
  getTenants(): Promise<ApiResponse<Tenant[]>>;
  getTenant(id: string): Promise<ApiResponse<Tenant>>;
  updateTenant(id: string, data: Partial<Tenant>): Promise<ApiResponse<Tenant>>;
}

export interface UserListParams {
  page?: number;
  limit?: number;
  role?: User['role'];
  is_active?: boolean;
  tenant_id?: string;
  search?: string;
  sort_by?: 'username' | 'email' | 'created_at' | 'last_login';
  sort_order?: 'asc' | 'desc';
}
