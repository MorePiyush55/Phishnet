import React, { useState, useEffect, useCallback } from 'react';
import { 
  Mail, 
  RefreshCw, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  ExternalLink,
  Shield,
  Tag,
  RotateCw,
  Activity,
  Globe,
  Wifi,
  WifiOff
} from 'lucide-react';
import { OAuthService } from '../services/oauthService';

interface GmailIntegrationStatus {
  connected: boolean;
  email: string;
  last_sync: string;
  sync_enabled: boolean;
  permissions: string[];
  quota_remaining: number;
  webhook_active: boolean;
}

interface GmailAction {
  action_type: 'quarantine' | 'restore' | 'label' | 'move';
  email_id: string;
  gmail_thread_id?: string;
  gmail_message_id?: string;
  target_label?: string;
  reason?: string;
}

interface RealTimeSyncEvent {
  type: 'email_quarantined' | 'email_restored' | 'label_updated' | 'sync_status';
  email_id: string;
  gmail_thread_id?: string;
  status: string;
  timestamp: string;
  details?: any;
}

export interface GmailIntegrationProps {
  emailId?: string;
  onActionComplete?: (action: GmailAction, success: boolean) => void;
  className?: string;
}

export const GmailIntegration: React.FC<GmailIntegrationProps> = ({
  emailId,
  onActionComplete,
  className = ''
}) => {
  const [syncEvents, setSyncEvents] = useState<RealTimeSyncEvent[]>([]);
  const [isConnecting, setIsConnecting] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('disconnected');

  // Mock Gmail status data
  const [gmailStatus, setGmailStatus] = useState<{
    connected: boolean;
    email: string;
    last_sync: string;
    sync_enabled: boolean;
    permissions: string[];
    quota_remaining: number;
    webhook_active: boolean;
  }>({
    connected: false,
    email: '',
    last_sync: new Date().toISOString(),
    sync_enabled: false,
    permissions: [],
    quota_remaining: 1000,
    webhook_active: false
  });

  const [statusLoading, setStatusLoading] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [gmailActionLoading, setGmailActionLoading] = useState(false);
  const [gmailActionError, setGmailActionError] = useState<string | null>(null);

  const refreshStatus = () => {
    setStatusLoading(true);
    // Simulate API call
    setTimeout(() => {
      setGmailStatus(prev => ({
        ...prev,
        last_sync: new Date().toISOString()
      }));
      setStatusLoading(false);
    }, 1000);
  };

  // Initialize status on mount
  useEffect(() => {
    refreshStatus();
  }, []);

  // Real-time sync monitoring
  useEffect(() => {
    if (!gmailStatus?.webhook_active) return;

    // Mock WebSocket simulation for real-time updates
    const interval = setInterval(() => {
      const syncEvent: RealTimeSyncEvent = {
        type: 'sync_status',
        email_id: 'mock',
        status: 'connected',
        timestamp: new Date().toISOString(),
        details: {}
      };
      setSyncEvents(prev => [syncEvent, ...prev.slice(0, 49)]);
      setConnectionStatus('connected');
    }, 5000);

    return () => {
      clearInterval(interval);
      setConnectionStatus('disconnected');
    };
  }, [gmailStatus?.webhook_active]);

  const handleGmailConnect = async () => {
    try {
      setIsConnecting(true);
      
      // Use the proper OAuth service
      await OAuthService.startOAuth();
    } catch (error) {
      console.error('Gmail connection failed:', error);
    } finally {
      setIsConnecting(false);
    }
  };

  const handleQuarantineEmail = async () => {
    if (!emailId) return;

    try {
      const action: GmailAction = {
        action_type: 'quarantine',
        email_id: emailId,
        target_label: 'PHISHNET_QUARANTINED',
        reason: 'Detected as phishing by PhishNet'
      };

      // Mock API call - will be replaced with real API
      console.log('Quarantining email:', action);

      onActionComplete?.(action, true);
      refreshStatus();
      
      return { success: true };
    } catch (error) {
      console.error('Gmail quarantine failed:', error);
      onActionComplete?.(emailId ? { action_type: 'quarantine', email_id: emailId } : {} as any, false);
      throw error;
    }
  };

  const handleRestoreEmail = async () => {
    if (!emailId) return;

    try {
      const action: GmailAction = {
        action_type: 'restore',
        email_id: emailId,
        target_label: 'INBOX',
        reason: 'Restored by PhishNet analysis'
      };

      // Mock API call - will be replaced with real API
      console.log('Restoring email:', action);

      onActionComplete?.(action, true);
      refreshStatus();
      
      return { success: true };
    } catch (error) {
      console.error('Gmail restore failed:', error);
      onActionComplete?.(emailId ? { action_type: 'restore', email_id: emailId } : {} as any, false);
      throw error;
    }
  };

  const handleManualSync = async () => {
    try {
      // Mock API call - will be replaced with real API
      console.log('Starting manual Gmail sync');
      refreshStatus();
    } catch (error) {
      console.error('Manual sync failed:', error);
    }
  };

  const getConnectionStatusColor = () => {
    switch (connectionStatus) {
      case 'connected': return 'text-green-600 bg-green-50';
      case 'connecting': return 'text-yellow-600 bg-yellow-50';
      case 'disconnected': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getConnectionIcon = () => {
    switch (connectionStatus) {
      case 'connected': return <Wifi className="h-4 w-4" />;
      case 'connecting': return <Activity className="h-4 w-4 animate-spin" />;
      case 'disconnected': return <WifiOff className="h-4 w-4" />;
      default: return <Activity className="h-4 w-4" />;
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Connection Status */}
      <div className="bg-white border rounded-lg p-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <Mail className="h-6 w-6 text-blue-600" />
            <div>
              <h3 className="text-lg font-semibold">Gmail Integration</h3>
              <p className="text-sm text-gray-600">Real-time sync and action capabilities</p>
            </div>
          </div>
          <div className={`flex items-center space-x-2 px-3 py-2 rounded-full ${getConnectionStatusColor()}`}>
            {getConnectionIcon()}
            <span className="text-sm font-medium capitalize">{connectionStatus}</span>
          </div>
        </div>

        {statusLoading ? (
          <div className="flex items-center space-x-2 text-gray-600">
            <Activity className="h-4 w-4 animate-spin" />
            <span>Loading Gmail status...</span>
          </div>
        ) : statusError ? (
          <div className="bg-red-50 border border-red-200 rounded p-3">
            <div className="flex items-center space-x-2 text-red-700">
              <AlertTriangle className="h-4 w-4" />
              <span>Error loading Gmail status</span>
            </div>
            <p className="text-red-600 text-sm mt-1">{statusError}</p>
          </div>
        ) : gmailStatus ? (
          <div className="space-y-4">
            {/* Status Overview */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-3 bg-gray-50 rounded">
                <div className={`text-2xl font-bold ${gmailStatus.connected ? 'text-green-600' : 'text-red-600'}`}>
                  {gmailStatus.connected ? '✓' : '✗'}
                </div>
                <div className="text-sm text-gray-600">Connected</div>
              </div>
              <div className="text-center p-3 bg-gray-50 rounded">
                <div className={`text-2xl font-bold ${gmailStatus.sync_enabled ? 'text-green-600' : 'text-gray-600'}`}>
                  {gmailStatus.sync_enabled ? '✓' : '⏸'}
                </div>
                <div className="text-sm text-gray-600">Sync Active</div>
              </div>
              <div className="text-center p-3 bg-gray-50 rounded">
                <div className="text-2xl font-bold text-blue-600">
                  {gmailStatus.quota_remaining || 0}
                </div>
                <div className="text-sm text-gray-600">API Quota</div>
              </div>
              <div className="text-center p-3 bg-gray-50 rounded">
                <div className={`text-2xl font-bold ${gmailStatus.webhook_active ? 'text-green-600' : 'text-gray-600'}`}>
                  {gmailStatus.webhook_active ? '🔄' : '⏹'}
                </div>
                <div className="text-sm text-gray-600">Real-time</div>
              </div>
            </div>

            {/* Account Info */}
            {gmailStatus.connected && (
              <div className="p-3 bg-blue-50 border border-blue-200 rounded">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Globe className="h-4 w-4 text-blue-600" />
                    <span className="text-blue-900 font-medium">{gmailStatus.email}</span>
                  </div>
                  <div className="text-blue-700 text-sm">
                    Last sync: {new Date(gmailStatus.last_sync).toLocaleString()}
                  </div>
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="flex flex-wrap gap-2">
              {!gmailStatus.connected ? (
                <button
                  onClick={handleGmailConnect}
                  disabled={isConnecting}
                  className="flex items-center space-x-2 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
                >
                  <Mail className="h-4 w-4" />
                  <span>{isConnecting ? 'Connecting...' : 'Connect Gmail'}</span>
                </button>
              ) : (
                <>
                  <button
                    onClick={handleManualSync}
                    disabled={gmailActionLoading}
                    className="flex items-center space-x-2 px-3 py-2 bg-green-500 text-white rounded hover:bg-green-600 disabled:opacity-50"
                  >
                    <RefreshCw className="h-4 w-4" />
                    <span>Manual Sync</span>
                  </button>
                  
                  {emailId && (
                    <>
                      <button
                        onClick={handleQuarantineEmail}
                        disabled={gmailActionLoading}
                        className="flex items-center space-x-2 px-3 py-2 bg-red-500 text-white rounded hover:bg-red-600 disabled:opacity-50"
                      >
                        <Shield className="h-4 w-4" />
                        <span>Quarantine in Gmail</span>
                      </button>
                      
                      <button
                        onClick={handleRestoreEmail}
                        disabled={gmailActionLoading}
                        className="flex items-center space-x-2 px-3 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
                      >
                        <Tag className="h-4 w-4" />
                        <span>Restore to Inbox</span>
                      </button>
                    </>
                  )}
                </>
              )}
            </div>
          </div>
        ) : null}
      </div>

      {/* Real-time Event Feed */}
      {syncEvents.length > 0 && (
        <div className="bg-white border rounded-lg">
          <div className="border-b p-4">
            <div className="flex items-center justify-between">
              <h4 className="text-lg font-semibold">Real-time Sync Events</h4>
              <span className="text-sm text-gray-500">{syncEvents.length} recent events</span>
            </div>
          </div>
          <div className="max-h-64 overflow-y-auto">
            {syncEvents.map((event, index) => (
              <div key={index} className="border-b p-3 hover:bg-gray-50">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className={`p-1 rounded ${
                      event.type === 'email_quarantined' ? 'bg-red-100 text-red-600' :
                      event.type === 'email_restored' ? 'bg-green-100 text-green-600' :
                      event.type === 'label_updated' ? 'bg-blue-100 text-blue-600' :
                      'bg-gray-100 text-gray-600'
                    }`}>
                      {event.type === 'email_quarantined' ? <Shield className="h-3 w-3" /> :
                       event.type === 'email_restored' ? <CheckCircle className="h-3 w-3" /> :
                       event.type === 'label_updated' ? <Tag className="h-3 w-3" /> :
                       <RotateCw className="h-3 w-3" />}
                    </div>
                    <div>
                      <div className="text-sm font-medium">
                        {event.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      </div>
                      <div className="text-xs text-gray-500">
                        Email: {event.email_id}
                        {event.gmail_thread_id && ` • Thread: ${event.gmail_thread_id}`}
                      </div>
                    </div>
                  </div>
                  <div className="text-xs text-gray-500">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </div>
                </div>
                <div className="mt-2 text-sm text-gray-700">
                  Status: <span className="font-medium">{event.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Gmail Action Status */}
      {gmailActionLoading && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-center space-x-2 text-blue-700">
            <Activity className="h-4 w-4 animate-spin" />
            <span>Executing Gmail action...</span>
          </div>
        </div>
      )}

      {gmailActionError && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center space-x-2 text-red-700">
            <AlertTriangle className="h-4 w-4" />
            <span>Gmail action failed</span>
          </div>
          <p className="text-red-600 text-sm mt-1">{gmailActionError}</p>
        </div>
      )}
    </div>
  );
};

// Real-time sync status indicator component
export interface GmailSyncIndicatorProps {
  className?: string;
  showDetails?: boolean;
}

export const GmailSyncIndicator: React.FC<GmailSyncIndicatorProps> = ({
  className = '',
  showDetails = false
}) => {
  const [syncStatus, setSyncStatus] = useState<'synced' | 'syncing' | 'error' | 'offline'>('offline');
  const [lastSync, setLastSync] = useState<Date | null>(null);

  // Monitor sync status
  useEffect(() => {
    const eventSource = new EventSource('/api/v1/integrations/gmail/sync-status');
    
    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setSyncStatus(data.status);
        if (data.last_sync) {
          setLastSync(new Date(data.last_sync));
        }
      } catch (error) {
        setSyncStatus('error');
      }
    };

    eventSource.onerror = () => {
      setSyncStatus('offline');
    };

    return () => {
      eventSource.close();
    };
  }, []);

  const getStatusColor = () => {
    switch (syncStatus) {
      case 'synced': return 'text-green-600 bg-green-50';
      case 'syncing': return 'text-blue-600 bg-blue-50';
      case 'error': return 'text-red-600 bg-red-50';
      case 'offline': return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusIcon = () => {
    switch (syncStatus) {
      case 'synced': return <CheckCircle className="h-3 w-3" />;
      case 'syncing': return <Activity className="h-3 w-3 animate-spin" />;
      case 'error': return <AlertTriangle className="h-3 w-3" />;
      case 'offline': return <WifiOff className="h-3 w-3" />;
    }
  };

  if (!showDetails) {
    return (
      <div className={`flex items-center space-x-1 px-2 py-1 rounded ${getStatusColor()} ${className}`}>
        {getStatusIcon()}
        <span className="text-xs font-medium">Gmail</span>
      </div>
    );
  }

  return (
    <div className={`p-2 rounded border ${getStatusColor().replace('bg-', 'border-').replace('-50', '-200')} ${className}`}>
      <div className="flex items-center space-x-2">
        {getStatusIcon()}
        <span className="text-sm font-medium">Gmail Sync</span>
        <span className="text-xs capitalize">{syncStatus}</span>
      </div>
      {lastSync && (
        <div className="text-xs mt-1">
          Last sync: {lastSync.toLocaleTimeString()}
        </div>
      )}
    </div>
  );
};

export default GmailIntegration;
