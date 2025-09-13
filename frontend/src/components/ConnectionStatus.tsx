import React, { useState, useEffect } from 'react';
import { 
  Mail, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  Shield, 
  Settings,
  Download,
  Trash2,
  RefreshCw,
  Zap,
  Eye,
  Calendar
} from 'lucide-react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { OAuthService, UserStatus, ScanHistory, RateLimiter } from '../services/oauthService';

interface ConnectionStatusProps {
  className?: string;
}

export const ConnectionStatus: React.FC<ConnectionStatusProps> = ({ className = '' }) => {
  const queryClient = useQueryClient();
  const [showDisconnectConfirm, setShowDisconnectConfirm] = useState(false);
  const [showDataExport, setShowDataExport] = useState(false);
  const [nextScanTime, setNextScanTime] = useState<number>(0);

  // Query user status
  const { data: userStatus, isLoading: statusLoading, error: statusError } = useQuery<UserStatus>({
    queryKey: ['userStatus'],
    queryFn: OAuthService.getUserStatus,
    refetchInterval: 30000, // Refresh every 30 seconds
    retry: 2
  });

  // Query scan history
  const { data: scanHistory, isLoading: historyLoading } = useQuery<ScanHistory>({
    queryKey: ['scanHistory'],
    queryFn: () => OAuthService.getScanHistory(1, 10),
    enabled: !!userStatus?.status && userStatus.status === 'connected',
    refetchInterval: 60000 // Refresh every minute
  });

  // Disconnect mutation
  const disconnectMutation = useMutation({
    mutationFn: OAuthService.revokeAccess,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['userStatus'] });
      setShowDisconnectConfirm(false);
    }
  });

  // Scan trigger mutation
  const scanMutation = useMutation({
    mutationFn: OAuthService.triggerScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scanHistory'] });
    }
  });

  // Update scan countdown
  useEffect(() => {
    const updateCountdown = () => {
      const remaining = RateLimiter.getTimeUntilNextRequest('scan_trigger', 2, 300000); // 2 scans per 5 minutes
      setNextScanTime(remaining);
    };

    updateCountdown();
    const interval = setInterval(updateCountdown, 1000);
    return () => clearInterval(interval);
  }, [scanMutation.data]);

  const handleScanNow = () => {
    if (!RateLimiter.canMakeRequest('scan_trigger', 2, 300000)) {
      return; // Rate limited
    }
    scanMutation.mutate();
  };

  const handleDisconnect = () => {
    disconnectMutation.mutate();
  };

  const handleExportData = async () => {
    try {
      const blob = await OAuthService.exportUserData();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `phishnet-data-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setShowDataExport(false);
    } catch (error) {
      console.error('Export failed:', error);
    }
  };

  if (statusLoading) {
    return (
      <div className={`bg-white rounded-lg border border-gray-200 p-6 ${className}`}>
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="h-6 bg-gray-200 rounded w-3/4 mb-2"></div>
          <div className="h-4 bg-gray-200 rounded w-1/2"></div>
        </div>
      </div>
    );
  }

  if (statusError || !userStatus) {
    return (
      <div className={`bg-white rounded-lg border border-red-200 p-6 ${className}`}>
        <div className="flex items-center gap-3 text-red-600">
          <AlertTriangle className="h-5 w-5" />
          <span>Failed to load connection status</span>
        </div>
      </div>
    );
  }

  const formatLastScan = (timestamp?: string) => {
    if (!timestamp) return 'Never';
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)} minutes ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
    return date.toLocaleDateString();
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected': return 'text-green-600 bg-green-50 border-green-200';
      case 'expired': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      default: return 'text-red-600 bg-red-50 border-red-200';
    }
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'safe': return 'text-green-600 bg-green-50';
      case 'suspicious': return 'text-yellow-600 bg-yellow-50';
      case 'malicious': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  return (
    <>
      <div className={`bg-white rounded-lg border border-gray-200 ${className}`}>
        {/* Header */}
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Mail className="h-6 w-6 text-blue-600" />
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Gmail Connection</h3>
                <p className="text-sm text-gray-600">Security monitoring status</p>
              </div>
            </div>
            
            <div className={`px-3 py-1 rounded-full border text-sm font-medium ${getStatusColor(userStatus.status)}`}>
              {userStatus.status === 'connected' && <CheckCircle2 className="h-4 w-4 inline mr-1" />}
              {userStatus.status === 'expired' && <Clock className="h-4 w-4 inline mr-1" />}
              {userStatus.status === 'disconnected' && <AlertTriangle className="h-4 w-4 inline mr-1" />}
              {userStatus.status.charAt(0).toUpperCase() + userStatus.status.slice(1)}
            </div>
          </div>
        </div>

        {/* Connection Details */}
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium text-gray-700">Connected Account</label>
              <p className="text-gray-900">{userStatus.email}</p>
              <p className="text-sm text-gray-500">{userStatus.display_name}</p>
            </div>
            
            <div>
              <label className="text-sm font-medium text-gray-700">Connected Since</label>
              <p className="text-gray-900">
                {userStatus.connected_at 
                  ? new Date(userStatus.connected_at).toLocaleDateString()
                  : 'Unknown'
                }
              </p>
            </div>
          </div>

          {/* Scopes */}
          <div>
            <label className="text-sm font-medium text-gray-700 mb-2 block">Granted Permissions</label>
            <div className="flex flex-wrap gap-2">
              {userStatus.scopes.map((scope) => (
                <span
                  key={scope}
                  className="px-2 py-1 bg-blue-50 text-blue-700 text-xs rounded-md border border-blue-200"
                >
                  {scope.replace('https://www.googleapis.com/auth/', '')}
                </span>
              ))}
            </div>
          </div>

          {/* Last Scan Info */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium text-gray-700">Last Scan</label>
              <p className="text-gray-900">{formatLastScan(userStatus.last_scan_at)}</p>
            </div>
            
            <div>
              <label className="text-sm font-medium text-gray-700">Watch Status</label>
              <div className="flex items-center gap-2">
                {userStatus.is_watch_active ? (
                  <span className="text-green-600 flex items-center gap-1">
                    <Eye className="h-4 w-4" />
                    Active
                  </span>
                ) : (
                  <span className="text-yellow-600 flex items-center gap-1">
                    <AlertTriangle className="h-4 w-4" />
                    Inactive
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex gap-3 pt-4 border-t border-gray-200">
            <button
              onClick={handleScanNow}
              disabled={scanMutation.isPending || nextScanTime > 0}
              className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {scanMutation.isPending ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <Zap className="h-4 w-4" />
              )}
              {nextScanTime > 0 
                ? `Scan in ${Math.ceil(nextScanTime / 1000)}s`
                : 'Scan Now'
              }
            </button>

            <button
              onClick={() => setShowDataExport(true)}
              className="border border-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-50 flex items-center gap-2"
            >
              <Download className="h-4 w-4" />
              Export Data
            </button>

            <button
              onClick={() => setShowDisconnectConfirm(true)}
              className="border border-red-300 text-red-700 px-4 py-2 rounded-md hover:bg-red-50 flex items-center gap-2"
            >
              <Trash2 className="h-4 w-4" />
              Disconnect
            </button>
          </div>

          {/* Scan History */}
          {scanHistory && scanHistory.results.length > 0 && (
            <div className="pt-4 border-t border-gray-200">
              <h4 className="text-sm font-medium text-gray-700 mb-3 flex items-center gap-2">
                <Calendar className="h-4 w-4" />
                Recent Scans ({scanHistory.total} total)
              </h4>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {scanHistory.results.map((result) => (
                  <div
                    key={result.id}
                    className="flex items-center justify-between p-3 border border-gray-200 rounded-md"
                  >
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 truncate">
                        {result.subject}
                      </p>
                      <p className="text-xs text-gray-500">
                        From: {result.sender} • {formatLastScan(result.scanned_at)}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-600">
                        Score: {(result.score * 100).toFixed(0)}%
                      </span>
                      <span className={`px-2 py-1 text-xs rounded-full ${getVerdictColor(result.verdict)}`}>
                        {result.verdict}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Disconnect Confirmation Modal */}
      {showDisconnectConfirm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md mx-4">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="h-6 w-6 text-red-600" />
              <h3 className="text-lg font-semibold">Disconnect Gmail</h3>
            </div>
            
            <p className="text-gray-600 mb-4">
              This will revoke PhishNet's access to your Gmail account and stop all monitoring. 
              You can reconnect anytime.
            </p>

            <div className="flex gap-3">
              <button
                onClick={() => setShowDisconnectConfirm(false)}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleDisconnect}
                disabled={disconnectMutation.isPending}
                className="flex-1 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50"
              >
                {disconnectMutation.isPending ? 'Disconnecting...' : 'Disconnect'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Data Export Modal */}
      {showDataExport && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md mx-4">
            <div className="flex items-center gap-3 mb-4">
              <Download className="h-6 w-6 text-blue-600" />
              <h3 className="text-lg font-semibold">Export Your Data</h3>
            </div>
            
            <p className="text-gray-600 mb-4">
              Download all your PhishNet data including scan history, connection logs, 
              and account information in JSON format.
            </p>

            <div className="flex gap-3">
              <button
                onClick={() => setShowDataExport(false)}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleExportData}
                className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
              >
                Download
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default ConnectionStatus;