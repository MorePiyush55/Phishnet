/**
 * Gmail OAuth Connection Component
 * Handles Gmail connection flow with comprehensive UX and security
 */

import React, { useState, useEffect, useCallback } from 'react';
import { 
  Mail, 
  Shield, 
  Eye, 
  CheckCircle, 
  AlertCircle, 
  XCircle,
  RefreshCw,
  Loader2,
  ExternalLink 
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { apiService } from '../services/apiService';

interface GmailStatus {
  connected: boolean;
  status: string;
  gmail_email?: string;
  scopes_granted: string[];
  connection_date?: string;
  last_scan?: string;
  last_token_refresh?: string;
  monitoring_enabled: boolean;
}

interface ScopeInfo {
  scope: string;
  description: string;
  purpose: string;
}

const SCOPE_INFORMATION: Record<string, ScopeInfo> = {
  'https://www.googleapis.com/auth/gmail.readonly': {
    scope: 'gmail.readonly',
    description: 'Read your email messages and metadata',
    purpose: 'Analyze incoming emails for phishing threats'
  },
  'https://www.googleapis.com/auth/gmail.modify': {
    scope: 'gmail.modify',
    description: 'Label and quarantine suspicious emails',
    purpose: 'Automatically quarantine detected phishing emails'
  },
  'https://www.googleapis.com/auth/userinfo.email': {
    scope: 'userinfo.email', 
    description: 'Access your email address',
    purpose: 'Verify your Gmail account identity'
  }
};

export const GmailOAuthManager: React.FC = () => {
  const [status, setStatus] = useState<GmailStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [watchSetup, setWatchSetup] = useState(false);
  const [watchEnabled, setWatchEnabled] = useState(false);
  const [showConsentModal, setShowConsentModal] = useState(false);
  const [scopeDetails, setScopeDetails] = useState<any>(null);
  const [notification, setNotification] = useState<{type: 'success' | 'error' | 'info', message: string} | null>(null);
  
  const { user, isAuthenticated } = useAuth();

  // Show notification
  const showNotification = (type: 'success' | 'error' | 'info', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 5000);
  };

  // Fetch Gmail connection status
  const fetchStatus = useCallback(async () => {
    if (!isAuthenticated) return;
    
    try {
      const response = await apiService.getGmailStatus();
      setStatus(response);
    } catch (error) {
      console.error('Error fetching Gmail status:', error);
      showNotification('error', 'Failed to load Gmail connection status');
    } finally {
      setLoading(false);
    }
  }, [isAuthenticated]);

  // Fetch OAuth scope information
  const fetchScopeDetails = useCallback(async () => {
    try {
      const response = await apiService.getGmailScopes();
      setScopeDetails(response);
    } catch (error) {
      console.error('Error fetching scope details:', error);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    fetchScopeDetails();
    
    // Check for OAuth callback results in URL params
    const urlParams = new URLSearchParams(window.location.search);
    const oauthSuccess = urlParams.get('oauth_success');
    const oauthError = urlParams.get('oauth_error');
    const gmailEmail = urlParams.get('gmail_email');
    
    if (oauthSuccess === 'true') {
      showNotification('success', `Gmail account ${gmailEmail} connected successfully!`);
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
      fetchStatus(); // Refresh status
    } else if (oauthError) {
      let errorMessage = 'Failed to connect Gmail account';
      switch (oauthError) {
        case 'access_denied':
          errorMessage = 'You denied access to your Gmail account';
          break;
        case 'invalid_state':
          errorMessage = 'Security validation failed. Please try again.';
          break;
        case 'processing_failed':
          errorMessage = 'Failed to process OAuth callback';
          break;
        default:
          errorMessage = `OAuth error: ${oauthError}`;
      }
      
      showNotification('error', errorMessage);
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, [fetchStatus, fetchScopeDetails]);

  // Start OAuth flow
  const handleConnect = async () => {
    setConnecting(true);
    try {
      const response = await apiService.startGmailOAuth();
      
      if (response.success && response.authorization_url) {
        // Redirect to Google OAuth
        window.location.href = response.authorization_url;
      } else {
        throw new Error(response.message || 'Failed to start OAuth flow');
      }
    } catch (error) {
      console.error('Error starting OAuth flow:', error);
      showNotification('error', error instanceof Error ? error.message : 'Failed to start Gmail connection');
    } finally {
      setConnecting(false);
    }
  };

  // Revoke OAuth access
  const handleDisconnect = async () => {
    setDisconnecting(true);
    try {
      const response = await apiService.revokeGmailOAuth();
      
      if (response.success) {
        showNotification('success', 'Gmail account disconnected successfully');
        fetchStatus(); // Refresh status
      } else {
        throw new Error(response.message || 'Failed to disconnect');
      }
    } catch (error) {
      console.error('Error disconnecting Gmail:', error);
      showNotification('error', error instanceof Error ? error.message : 'Failed to disconnect Gmail');
    } finally {
      setDisconnecting(false);
    }
  };

  // Trigger manual scan
  const handleManualScan = async () => {
    setScanning(true);
    try {
      const response = await apiService.triggerGmailScan({
        force_scan: false,
        days_back: 7
      });
      
      if (response.success) {
        showNotification('success', `Manual scan initiated. ${response.estimated_completion}`);
      } else {
        throw new Error(response.message || 'Failed to start scan');
      }
    } catch (error) {
      console.error('Error starting manual scan:', error);
      showNotification('error', error instanceof Error ? error.message : 'Failed to start manual scan');
    } finally {
      setScanning(false);
    }
  };

  // Setup Gmail watch for real-time monitoring
  const handleSetupWatch = async () => {
    setWatchSetup(true);
    try {
      const response = await apiService.setupGmailWatch();
      
      if (response.status === 'success') {
        setWatchEnabled(true);
        showNotification('success', 'Real-time monitoring enabled successfully!');
        fetchStatus(); // Refresh status
      } else {
        throw new Error(response.message || 'Failed to setup watch');
      }
    } catch (error) {
      console.error('Error setting up Gmail watch:', error);
      showNotification('error', error instanceof Error ? error.message : 'Failed to enable real-time monitoring');
    } finally {
      setWatchSetup(false);
    }
  };

  // Stop Gmail watch
  const handleStopWatch = async () => {
    setWatchSetup(true);
    try {
      const response = await apiService.stopGmailWatch();
      
      if (response.status === 'success') {
        setWatchEnabled(false);
        showNotification('success', 'Real-time monitoring disabled');
        fetchStatus(); // Refresh status
      } else {
        throw new Error(response.message || 'Failed to stop watch');
      }
    } catch (error) {
      console.error('Error stopping Gmail watch:', error);
      showNotification('error', error instanceof Error ? error.message : 'Failed to disable real-time monitoring');
    } finally {
      setWatchSetup(false);
    }
  };

  // Status badge component
  const StatusBadge = ({ status }: { status: string }) => {
    const getBadgeClasses = (status: string) => {
      switch (status) {
        case 'connected':
          return 'bg-green-100 text-green-800 border-green-200';
        case 'error':
        case 'expired':
          return 'bg-red-100 text-red-800 border-red-200';
        default:
          return 'bg-gray-100 text-gray-800 border-gray-200';
      }
    };
    
    const getIcon = (status: string) => {
      switch (status) {
        case 'connected':
          return <CheckCircle className="w-3 h-3 mr-1" />;
        case 'error':
        case 'expired':
          return <AlertCircle className="w-3 h-3 mr-1" />;
        default:
          return <XCircle className="w-3 h-3 mr-1" />;
      }
    };
    
    return (
      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border ${getBadgeClasses(status)}`}>
        {getIcon(status)}
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    );
  };

  // Consent modal component
  const ConsentModal = () => {
    if (!showConsentModal) return null;
    
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-6 max-w-2xl mx-4 max-h-96 overflow-y-auto">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5" />
            <h3 className="text-lg font-semibold">Gmail Access Permissions</h3>
          </div>
          
          <p className="text-gray-600 mb-4">
            PhishNet requests the following permissions to protect your email:
          </p>
          
          <div className="space-y-4 mb-6">
            {scopeDetails?.required_scopes?.map((scope: string) => {
              const info = SCOPE_INFORMATION[scope];
              return (
                <div key={scope} className="border rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <Eye className="w-5 h-5 text-blue-500 mt-0.5" />
                    <div className="flex-1">
                      <h4 className="font-medium">{info?.description || scope}</h4>
                      <p className="text-sm text-gray-600 mt-1">
                        {info?.purpose || 'Used for email security analysis'}
                      </p>
                    </div>
                  </div>
                </div>
              );
            })}
            
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-start gap-2">
                <Shield className="w-4 h-4 text-blue-600 mt-0.5" />
                <div>
                  <strong className="text-blue-900">Privacy Guarantee:</strong>
                  <p className="text-sm text-blue-800 mt-1">
                    PhishNet only analyzes email content for security threats. 
                    We never store your email content permanently or share it with third parties.
                  </p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="flex gap-3">
            <button 
              onClick={() => {
                setShowConsentModal(false);
                handleConnect();
              }}
              className="flex-1 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center justify-center"
              disabled={connecting}
            >
              {connecting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Connecting...
                </>
              ) : (
                <>
                  <CheckCircle className="w-4 h-4 mr-2" />
                  Grant Access
                </>
              )}
            </button>
            <button 
              onClick={() => setShowConsentModal(false)}
              className="flex-1 bg-gray-200 text-gray-800 px-4 py-2 rounded-lg hover:bg-gray-300"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <div className="flex items-center justify-center py-8">
          <Loader2 className="w-6 h-6 animate-spin mr-2" />
          Loading Gmail connection status...
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Notification */}
      {notification && (
        <div className={`p-4 rounded-lg ${
          notification.type === 'success' ? 'bg-green-50 text-green-800 border border-green-200' :
          notification.type === 'error' ? 'bg-red-50 text-red-800 border border-red-200' :
          'bg-blue-50 text-blue-800 border border-blue-200'
        }`}>
          {notification.message}
        </div>
      )}

      {/* Main Gmail OAuth Card */}
      <div className="bg-white rounded-lg shadow-sm border">
        {/* Header */}
        <div className="p-6 border-b">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Mail className="w-6 h-6 text-blue-600" />
              <div>
                <h3 className="text-lg font-semibold">Gmail Protection</h3>
                <p className="text-sm text-gray-600">
                  Connect your Gmail for real-time phishing protection
                </p>
              </div>
            </div>
            <StatusBadge status={status?.status || 'disconnected'} />
          </div>
        </div>
        
        {/* Content */}
        <div className="p-6 space-y-4">
          {status?.connected ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-green-600" />
                <span className="font-medium">Connected to {status.gmail_email}</span>
              </div>
              
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-600">Connected:</span>
                  <div className="font-medium">
                    {status.connection_date ? 
                      new Date(status.connection_date).toLocaleDateString() : 
                      'Unknown'
                    }
                  </div>
                </div>
                <div>
                  <span className="text-gray-600">Last Scan:</span>
                  <div className="font-medium">
                    {status.last_scan ? 
                      new Date(status.last_scan).toLocaleDateString() : 
                      'Never'
                    }
                  </div>
                </div>
              </div>
              
              <div>
                <span className="text-gray-600 text-sm">Monitoring:</span>
                <div className="flex items-center gap-2 mt-1">
                  {status.monitoring_enabled ? (
                    <>
                      <CheckCircle className="w-4 h-4 text-green-600" />
                      <span className="text-sm font-medium">Active</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="w-4 h-4 text-gray-400" />
                      <span className="text-sm">Inactive</span>
                    </>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
              <div className="flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-orange-600 mt-0.5" />
                <div>
                  <p className="text-orange-800">
                    Connect your Gmail account to enable real-time phishing protection and email scanning.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
        
        {/* Footer */}
        <div className="p-6 border-t bg-gray-50 flex gap-3">
          {status?.connected ? (
            <>
              <button 
                onClick={handleManualScan}
                disabled={scanning}
                className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center"
              >
                {scanning ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Scan Now
                  </>
                )}
              </button>
              <button 
                onClick={handleDisconnect}
                disabled={disconnecting}
                className="bg-gray-200 text-gray-800 px-4 py-2 rounded-lg hover:bg-gray-300 disabled:opacity-50 flex items-center"
              >
                {disconnecting ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Disconnecting...
                  </>
                ) : (
                  <>
                    <XCircle className="w-4 h-4 mr-2" />
                    Disconnect
                  </>
                )}
              </button>
            </>
          ) : (
            <button 
              onClick={() => setShowConsentModal(true)}
              disabled={connecting}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center justify-center"
            >
              {connecting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Connecting...
                </>
              ) : (
                <>
                  <Mail className="w-4 h-4 mr-2" />
                  Connect Gmail
                </>
              )}
            </button>
          )}
        </div>
      </div>
      
      <ConsentModal />
    </div>
  );
};

export default GmailOAuthManager;
