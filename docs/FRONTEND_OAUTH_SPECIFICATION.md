# Frontend OAuth2 Integration Technical Specification

## Overview

This document provides detailed technical specifications for implementing the frontend OAuth2 components for Gmail integration in PhishNet.

## Component Architecture

The frontend OAuth2 integration consists of:
1. **GmailConnect** - Main connection management component
2. **GmailConsentModal** - Detailed consent and permission disclosure
3. **GmailStatus** - Status dashboard and controls
4. **OAuthService** - API communication layer
5. **OAuth Hooks** - React hooks for state management

## Component Specifications

### 1. GmailConnect Component

**File**: `frontend/src/components/Gmail/GmailConnect.tsx`

**Purpose**: Main Gmail connection interface with status display and controls

**Props Interface**:
```typescript
interface GmailConnectProps {
  className?: string;
  onConnectionChange?: (connected: boolean) => void;
  showAdvancedControls?: boolean;
}
```

**State Management**:
```typescript
interface GmailConnectionState {
  isConnected: boolean;
  isConnecting: boolean;
  connectionStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  userEmail?: string;
  lastScan?: Date;
  connectionDate?: Date;
  grantedScopes: string[];
  error?: string;
}
```

**Component Structure**:
```tsx
const GmailConnect: React.FC<GmailConnectProps> = ({ 
  className, 
  onConnectionChange, 
  showAdvancedControls = false 
}) => {
  // State and hooks
  const [connectionState, setConnectionState] = useState<GmailConnectionState>({
    isConnected: false,
    isConnecting: false,
    connectionStatus: 'disconnected',
    grantedScopes: []
  });
  
  const [showConsentModal, setShowConsentModal] = useState(false);
  const { gmailStatus, initiateConnection, revokeConnection } = useGmailOAuth();

  // Effects for status polling
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const status = await oauthService.getGmailStatus();
        setConnectionState(prev => ({
          ...prev,
          isConnected: status.connected,
          userEmail: status.email_address,
          lastScan: status.last_scan ? new Date(status.last_scan) : undefined,
          connectionDate: status.connection_date ? new Date(status.connection_date) : undefined,
          grantedScopes: status.granted_scopes || [],
          connectionStatus: status.connected ? 'connected' : 'disconnected'
        }));
      } catch (error) {
        setConnectionState(prev => ({
          ...prev,
          connectionStatus: 'error',
          error: 'Failed to check connection status'
        }));
      }
    };

    checkStatus();
    // Poll every 30 seconds when component is mounted
    const interval = setInterval(checkStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  // Event handlers
  const handleConnectClick = () => {
    setShowConsentModal(true);
  };

  const handleConsentApproved = async () => {
    setShowConsentModal(false);
    setConnectionState(prev => ({ ...prev, isConnecting: true, connectionStatus: 'connecting' }));
    
    try {
      const authUrl = await initiateConnection();
      // Redirect to Google OAuth
      window.location.href = authUrl;
    } catch (error) {
      setConnectionState(prev => ({
        ...prev,
        isConnecting: false,
        connectionStatus: 'error',
        error: 'Failed to initiate connection'
      }));
    }
  };

  const handleDisconnect = async () => {
    try {
      await revokeConnection();
      setConnectionState(prev => ({
        ...prev,
        isConnected: false,
        connectionStatus: 'disconnected',
        userEmail: undefined,
        lastScan: undefined,
        connectionDate: undefined,
        grantedScopes: []
      }));
      onConnectionChange?.(false);
    } catch (error) {
      setConnectionState(prev => ({
        ...prev,
        error: 'Failed to disconnect Gmail'
      }));
    }
  };

  // Render logic based on connection status
  const renderConnectionControls = () => {
    switch (connectionStatus) {
      case 'connected':
        return (
          <div className="space-y-4">
            <div className="flex items-center space-x-2 text-green-600">
              <CheckCircleIcon className="h-5 w-5" />
              <span>Connected as {userEmail}</span>
            </div>
            
            <div className="text-sm text-gray-600">
              <p>Connected: {connectionDate?.toLocaleDateString()}</p>
              {lastScan && <p>Last scan: {lastScan.toLocaleString()}</p>}
            </div>

            {showAdvancedControls && (
              <div className="space-y-2">
                <button
                  onClick={handleManualScan}
                  className="w-full bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
                >
                  Scan Now
                </button>
                
                <button
                  onClick={handleDisconnect}
                  className="w-full bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700"
                >
                  Disconnect Gmail
                </button>
              </div>
            )}
          </div>
        );

      case 'connecting':
        return (
          <div className="flex items-center space-x-2 text-blue-600">
            <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div>
            <span>Connecting to Gmail...</span>
          </div>
        );

      case 'error':
        return (
          <div className="space-y-4">
            <div className="flex items-center space-x-2 text-red-600">
              <ExclamationTriangleIcon className="h-5 w-5" />
              <span>Connection Error</span>
            </div>
            <p className="text-sm text-gray-600">{error}</p>
            <button
              onClick={handleConnectClick}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
            >
              Try Again
            </button>
          </div>
        );

      default: // disconnected
        return (
          <div className="space-y-4">
            <div className="text-center">
              <EnvelopeIcon className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-2 text-sm font-medium text-gray-900">
                Gmail Not Connected
              </h3>
              <p className="mt-1 text-sm text-gray-500">
                Connect your Gmail to enable real-time phishing analysis
              </p>
            </div>
            
            <button
              onClick={handleConnectClick}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
            >
              Connect Gmail
            </button>
          </div>
        );
    }
  };

  return (
    <div className={`bg-white rounded-lg shadow p-6 ${className}`}>
      <h2 className="text-lg font-medium text-gray-900 mb-4">
        Gmail Integration
      </h2>
      
      {renderConnectionControls()}
      
      {/* Consent Modal */}
      <GmailConsentModal
        isOpen={showConsentModal}
        onClose={() => setShowConsentModal(false)}
        onApprove={handleConsentApproved}
      />
    </div>
  );
};
```

### 2. GmailConsentModal Component

**File**: `frontend/src/components/Gmail/GmailConsentModal.tsx`

**Purpose**: Detailed consent and permission disclosure modal

**Props Interface**:
```typescript
interface GmailConsentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onApprove: () => void;
}
```

**Component Implementation**:
```tsx
const GmailConsentModal: React.FC<GmailConsentModalProps> = ({
  isOpen,
  onClose,
  onApprove
}) => {
  const [consentChecks, setConsentChecks] = useState({
    readEmails: false,
    modifyEmails: false,
    dataProcessing: false,
    privacyPolicy: false
  });

  const allConsentsGiven = Object.values(consentChecks).every(Boolean);

  const handleConsentChange = (key: keyof typeof consentChecks) => {
    setConsentChecks(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const handleApprove = () => {
    if (allConsentsGiven) {
      // Track consent in analytics
      analytics.track('Gmail OAuth Consent Given', {
        timestamp: new Date().toISOString(),
        consents: consentChecks
      });
      onApprove();
    }
  };

  return (
    <Transition show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" />
        </Transition.Child>

        <div className="fixed inset-0 z-10 overflow-y-auto">
          <div className="flex min-h-full items-end justify-center p-4 text-center sm:items-center sm:p-0">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
              enterTo="opacity-100 translate-y-0 sm:scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 translate-y-0 sm:scale-100"
              leaveTo="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
            >
              <Dialog.Panel className="relative transform overflow-hidden rounded-lg bg-white px-4 pb-4 pt-5 text-left shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-lg sm:p-6">
                <div>
                  <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-blue-100">
                    <ShieldCheckIcon className="h-6 w-6 text-blue-600" />
                  </div>
                  <div className="mt-3 text-center sm:mt-5">
                    <Dialog.Title as="h3" className="text-lg font-semibold leading-6 text-gray-900">
                      Connect Gmail for Phishing Protection
                    </Dialog.Title>
                    <div className="mt-2">
                      <p className="text-sm text-gray-500">
                        PhishNet will analyze your emails to detect phishing attempts and protect you from security threats.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="mt-6 space-y-4">
                  <h4 className="text-sm font-medium text-gray-900">
                    Permissions Required:
                  </h4>
                  
                  <div className="space-y-3">
                    <label className="flex items-start space-x-3">
                      <input
                        type="checkbox"
                        checked={consentChecks.readEmails}
                        onChange={() => handleConsentChange('readEmails')}
                        className="mt-1 h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                      />
                      <div className="flex-1">
                        <p className="text-sm font-medium text-gray-900">
                          Read and analyze email content
                        </p>
                        <p className="text-xs text-gray-500">
                          PhishNet will scan incoming emails to detect phishing attempts, malicious links, and suspicious attachments.
                        </p>
                      </div>
                    </label>

                    <label className="flex items-start space-x-3">
                      <input
                        type="checkbox"
                        checked={consentChecks.modifyEmails}
                        onChange={() => handleConsentChange('modifyEmails')}
                        className="mt-1 h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                      />
                      <div className="flex-1">
                        <p className="text-sm font-medium text-gray-900">
                          Apply labels and quarantine malicious emails
                        </p>
                        <p className="text-xs text-gray-500">
                          When phishing is detected, PhishNet can automatically label emails as suspicious or move them to a quarantine folder.
                        </p>
                      </div>
                    </label>

                    <label className="flex items-start space-x-3">
                      <input
                        type="checkbox"
                        checked={consentChecks.dataProcessing}
                        onChange={() => handleConsentChange('dataProcessing')}
                        className="mt-1 h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                      />
                      <div className="flex-1">
                        <p className="text-sm font-medium text-gray-900">
                          Data processing and analysis
                        </p>
                        <p className="text-xs text-gray-500">
                          Email metadata and content will be processed for threat analysis. We never share your personal information with third parties.
                        </p>
                      </div>
                    </label>

                    <label className="flex items-start space-x-3">
                      <input
                        type="checkbox"
                        checked={consentChecks.privacyPolicy}
                        onChange={() => handleConsentChange('privacyPolicy')}
                        className="mt-1 h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                      />
                      <div className="flex-1">
                        <p className="text-sm font-medium text-gray-900">
                          Privacy Policy and Terms
                        </p>
                        <p className="text-xs text-gray-500">
                          I have read and agree to the{' '}
                          <a href="/privacy" target="_blank" className="text-blue-600 hover:text-blue-800">
                            Privacy Policy
                          </a>{' '}
                          and{' '}
                          <a href="/terms" target="_blank" className="text-blue-600 hover:text-blue-800">
                            Terms of Service
                          </a>.
                        </p>
                      </div>
                    </label>
                  </div>
                </div>

                <div className="mt-6 bg-yellow-50 border border-yellow-200 rounded-md p-4">
                  <div className="flex">
                    <ExclamationTriangleIcon className="h-5 w-5 text-yellow-400" />
                    <div className="ml-3">
                      <p className="text-sm text-yellow-800">
                        <strong>Your Privacy:</strong> You can revoke access at any time from your account settings or directly from your Google account.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="mt-5 sm:mt-6 sm:grid sm:grid-flow-row-dense sm:grid-cols-2 sm:gap-3">
                  <button
                    type="button"
                    onClick={handleApprove}
                    disabled={!allConsentsGiven}
                    className={`inline-flex w-full justify-center rounded-md px-3 py-2 text-sm font-semibold text-white shadow-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 sm:col-start-2 ${
                      allConsentsGiven
                        ? 'bg-blue-600 hover:bg-blue-500 focus-visible:outline-blue-600'
                        : 'bg-gray-300 cursor-not-allowed'
                    }`}
                  >
                    Connect to Gmail
                  </button>
                  <button
                    type="button"
                    onClick={onClose}
                    className="mt-3 inline-flex w-full justify-center rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50 sm:col-start-1 sm:mt-0"
                  >
                    Cancel
                  </button>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  );
};
```

### 3. GmailStatus Component

**File**: `frontend/src/components/Gmail/GmailStatus.tsx`

**Purpose**: Detailed status dashboard and management controls

**Component Implementation**:
```tsx
interface GmailStatusProps {
  className?: string;
}

const GmailStatus: React.FC<GmailStatusProps> = ({ className }) => {
  const [status, setStatus] = useState<GmailConnectionStatus | null>(null);
  const [scanning, setScanning] = useState(false);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [showAuditLogs, setShowAuditLogs] = useState(false);

  // Load status and audit logs
  useEffect(() => {
    const loadData = async () => {
      try {
        const [statusData, auditData] = await Promise.all([
          oauthService.getGmailStatus(),
          oauthService.getAuditLogs({ limit: 10 })
        ]);
        setStatus(statusData);
        setAuditLogs(auditData);
      } catch (error) {
        console.error('Failed to load Gmail status:', error);
      }
    };

    loadData();
  }, []);

  const handleManualScan = async () => {
    setScanning(true);
    try {
      await gmailService.triggerManualScan();
      // Refresh status after scan
      const newStatus = await oauthService.getGmailStatus();
      setStatus(newStatus);
    } catch (error) {
      console.error('Failed to trigger scan:', error);
    } finally {
      setScanning(false);
    }
  };

  if (!status) {
    return <div className="animate-pulse bg-gray-200 h-32 rounded"></div>;
  }

  return (
    <div className={`bg-white rounded-lg shadow ${className}`}>
      <div className="px-6 py-4 border-b border-gray-200">
        <h3 className="text-lg font-medium text-gray-900">Gmail Integration Status</h3>
      </div>
      
      <div className="p-6 space-y-6">
        {/* Connection Status */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-sm font-medium text-gray-900 mb-3">Connection Details</h4>
            <dl className="space-y-2">
              <div className="flex justify-between">
                <dt className="text-sm text-gray-500">Status</dt>
                <dd className={`text-sm font-medium ${status.connected ? 'text-green-600' : 'text-red-600'}`}>
                  {status.connected ? 'Connected' : 'Disconnected'}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-sm text-gray-500">Email</dt>
                <dd className="text-sm text-gray-900">{status.email_address || 'N/A'}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-sm text-gray-500">Connected</dt>
                <dd className="text-sm text-gray-900">
                  {status.connection_date ? new Date(status.connection_date).toLocaleDateString() : 'N/A'}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-sm text-gray-500">Last Token Refresh</dt>
                <dd className="text-sm text-gray-900">
                  {status.last_token_refresh ? new Date(status.last_token_refresh).toLocaleString() : 'N/A'}
                </dd>
              </div>
            </dl>
          </div>

          <div>
            <h4 className="text-sm font-medium text-gray-900 mb-3">Scanning Activity</h4>
            <dl className="space-y-2">
              <div className="flex justify-between">
                <dt className="text-sm text-gray-500">Last Scan</dt>
                <dd className="text-sm text-gray-900">
                  {status.last_scan ? new Date(status.last_scan).toLocaleString() : 'Never'}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-sm text-gray-500">Total Emails Scanned</dt>
                <dd className="text-sm text-gray-900">{status.total_emails_scanned || 0}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-sm text-gray-500">API Access</dt>
                <dd className={`text-sm font-medium ${status.api_access_valid ? 'text-green-600' : 'text-red-600'}`}>
                  {status.api_access_valid ? 'Valid' : 'Invalid'}
                </dd>
              </div>
            </dl>
          </div>
        </div>

        {/* Granted Scopes */}
        <div>
          <h4 className="text-sm font-medium text-gray-900 mb-3">Granted Permissions</h4>
          <div className="space-y-2">
            {status.granted_scopes?.map((scope, index) => (
              <div key={index} className="flex items-center space-x-2">
                <CheckCircleIcon className="h-4 w-4 text-green-500" />
                <span className="text-sm text-gray-700">
                  {scope.includes('readonly') ? 'Read emails' : 'Modify emails'}
                </span>
              </div>
            )) || <span className="text-sm text-gray-500">No permissions granted</span>}
          </div>
        </div>

        {/* Action Buttons */}
        {status.connected && (
          <div className="flex space-x-3">
            <button
              onClick={handleManualScan}
              disabled={scanning}
              className="flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
            >
              {scanning ? (
                <>
                  <div className="animate-spin -ml-1 mr-2 h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                  Scanning...
                </>
              ) : (
                <>
                  <MagnifyingGlassIcon className="-ml-1 mr-2 h-4 w-4" />
                  Scan Now
                </>
              )}
            </button>
            
            <button
              onClick={() => setShowAuditLogs(!showAuditLogs)}
              className="flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              <ClipboardDocumentListIcon className="-ml-1 mr-2 h-4 w-4" />
              {showAuditLogs ? 'Hide' : 'Show'} Activity Log
            </button>
          </div>
        )}

        {/* Audit Logs */}
        {showAuditLogs && auditLogs.length > 0 && (
          <div>
            <h4 className="text-sm font-medium text-gray-900 mb-3">Recent Activity</h4>
            <div className="bg-gray-50 rounded-md p-4 max-h-60 overflow-y-auto">
              <div className="space-y-2">
                {auditLogs.map((log, index) => (
                  <div key={index} className="flex justify-between items-center text-xs">
                    <span className="text-gray-600">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                    <span className="text-gray-800">{log.operation_type}</span>
                    <span className={`font-medium ${
                      log.result === 'success' ? 'text-green-600' : 'text-red-600'
                    }`}>
                      {log.result}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
```

### 4. OAuth Service Layer

**File**: `frontend/src/services/oauthService.ts`

**Purpose**: Handle all OAuth-related API communications

```typescript
interface GmailConnectionStatus {
  connected: boolean;
  email_address?: string;
  connection_date?: string;
  last_token_refresh?: string;
  granted_scopes?: string[];
  api_access_valid: boolean;
  last_scan?: string;
  total_emails_scanned?: number;
}

interface AuditLog {
  timestamp: string;
  operation_type: string;
  result: 'success' | 'failure';
  details?: string;
}

class OAuthService {
  private baseUrl: string;
  
  constructor() {
    this.baseUrl = process.env.REACT_APP_API_BASE_URL || '';
  }

  private async makeRequest<T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> {
    const token = localStorage.getItem('accessToken');
    
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(error.detail || `HTTP ${response.status}`);
    }

    return response.json();
  }

  async initiateGmailOAuth(): Promise<{ authorization_url: string; state: string }> {
    return this.makeRequest('/api/v1/oauth/gmail/initiate', {
      method: 'POST',
    });
  }

  async getGmailStatus(): Promise<GmailConnectionStatus> {
    return this.makeRequest('/api/v1/oauth/gmail/status');
  }

  async refreshGmailToken(): Promise<{ success: boolean; token_refreshed_at: string }> {
    return this.makeRequest('/api/v1/oauth/gmail/refresh', {
      method: 'POST',
    });
  }

  async revokeGmailAccess(): Promise<{ success: boolean; revoked_at: string }> {
    return this.makeRequest('/api/v1/oauth/gmail/revoke', {
      method: 'DELETE',
    });
  }

  async getAuditLogs(params: { limit?: number; offset?: number } = {}): Promise<AuditLog[]> {
    const queryParams = new URLSearchParams();
    if (params.limit) queryParams.append('limit', params.limit.toString());
    if (params.offset) queryParams.append('offset', params.offset.toString());

    return this.makeRequest(`/api/v1/oauth/gmail/audit?${queryParams}`);
  }

  async triggerManualScan(): Promise<{ scan_id: string; status: string }> {
    return this.makeRequest('/api/v1/gmail/scan/trigger', {
      method: 'POST',
    });
  }
}

export const oauthService = new OAuthService();
export default oauthService;
```

### 5. React Hooks for OAuth

**File**: `frontend/src/hooks/useGmailOAuth.ts`

```typescript
import { useState, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import oauthService, { GmailConnectionStatus } from '../services/oauthService';

export const useGmailOAuth = () => {
  const queryClient = useQueryClient();

  // Query for Gmail status
  const {
    data: gmailStatus,
    isLoading: isLoadingStatus,
    error: statusError,
    refetch: refetchStatus
  } = useQuery<GmailConnectionStatus>({
    queryKey: ['gmail-status'],
    queryFn: () => oauthService.getGmailStatus(),
    refetchInterval: 30000, // Refetch every 30 seconds
    retry: (failureCount, error: any) => {
      // Don't retry on auth errors
      if (error?.message?.includes('401')) return false;
      return failureCount < 2;
    },
  });

  // Mutation for initiating OAuth
  const initiateConnectionMutation = useMutation({
    mutationFn: () => oauthService.initiateGmailOAuth(),
    onSuccess: (data) => {
      // Store state for validation when user returns
      sessionStorage.setItem('oauth_state', data.state);
    },
  });

  // Mutation for revoking access
  const revokeConnectionMutation = useMutation({
    mutationFn: () => oauthService.revokeGmailAccess(),
    onSuccess: () => {
      // Invalidate and refetch status
      queryClient.invalidateQueries({ queryKey: ['gmail-status'] });
    },
  });

  // Mutation for manual token refresh
  const refreshTokenMutation = useMutation({
    mutationFn: () => oauthService.refreshGmailToken(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gmail-status'] });
    },
  });

  // Convenience functions
  const initiateConnection = useCallback(async (): Promise<string> => {
    const result = await initiateConnectionMutation.mutateAsync();
    return result.authorization_url;
  }, [initiateConnectionMutation]);

  const revokeConnection = useCallback(async (): Promise<void> => {
    await revokeConnectionMutation.mutateAsync();
  }, [revokeConnectionMutation]);

  const refreshToken = useCallback(async (): Promise<void> => {
    await refreshTokenMutation.mutateAsync();
  }, [refreshTokenMutation]);

  // Handle OAuth callback return
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const status = urlParams.get('status');
    const error = urlParams.get('error');

    if (status === 'success') {
      // Clear OAuth state from session
      sessionStorage.removeItem('oauth_state');
      // Refetch status to get updated connection info
      refetchStatus();
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
    } else if (status === 'error') {
      console.error('OAuth error:', error);
      // Handle error state
      sessionStorage.removeItem('oauth_state');
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, [refetchStatus]);

  return {
    // Data
    gmailStatus,
    isConnected: gmailStatus?.connected || false,
    
    // Loading states
    isLoadingStatus,
    isConnecting: initiateConnectionMutation.isPending,
    isRevoking: revokeConnectionMutation.isPending,
    isRefreshing: refreshTokenMutation.isPending,
    
    // Errors
    statusError,
    connectionError: initiateConnectionMutation.error,
    revokeError: revokeConnectionMutation.error,
    refreshError: refreshTokenMutation.error,
    
    // Actions
    initiateConnection,
    revokeConnection,
    refreshToken,
    refetchStatus,
  };
};
```

## Integration with Existing App

### App.tsx Updates

Add OAuth callback route to handle returns from Google:

```tsx
// Add to routes in App.tsx
<Route 
  path="/oauth/callback" 
  element={
    <RequireAuth>
      <OAuthCallback />
    </RequireAuth>
  } 
/>
```

### Dashboard Integration

Add Gmail components to the main dashboard:

```tsx
// In SOCDashboard.tsx
import { GmailConnect, GmailStatus } from './Gmail';

// Add to dashboard layout
<div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
  <GmailConnect showAdvancedControls={true} />
  <GmailStatus />
</div>
```

This frontend implementation provides a complete, user-friendly interface for managing Gmail OAuth2 integration with proper error handling, loading states, and security considerations.
