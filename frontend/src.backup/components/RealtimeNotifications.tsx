import React, { useState, useEffect } from 'react';
import { 
  Bell, 
  CheckCircle2, 
  AlertTriangle, 
  Shield, 
  X, 
  Wifi, 
  WifiOff,
  RefreshCw
} from 'lucide-react';
import { useRealtimeConnection, ScanUpdate, ConnectionStatusUpdate } from '../hooks/useRealtimeUpdates';
import { useQueryClient } from '@tanstack/react-query';

interface Notification {
  id: string;
  type: 'scan_completed' | 'scan_error' | 'connection_changed' | 'system';
  title: string;
  message: string;
  severity: 'info' | 'success' | 'warning' | 'error';
  timestamp: Date;
  autoHide?: boolean;
}

interface RealtimeNotificationsProps {
  className?: string;
  maxNotifications?: number;
}

export const RealtimeNotifications: React.FC<RealtimeNotificationsProps> = ({
  className = '',
  maxNotifications = 5
}) => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [isEnabled, setIsEnabled] = useState(true);
  const queryClient = useQueryClient();

  const handleScanUpdate = (update: ScanUpdate) => {
    const notification: Notification = {
      id: `scan-${Date.now()}`,
      type: update.type === 'scan_completed' ? 'scan_completed' : 'scan_error',
      title: '',
      message: '',
      severity: 'info',
      timestamp: new Date(update.timestamp),
      autoHide: true
    };

    switch (update.type) {
      case 'scan_started':
        notification.title = 'Scan Started';
        notification.message = 'Analyzing recent emails for threats...';
        notification.severity = 'info';
        break;
        
      case 'scan_completed':
        const result = update.data.result;
        if (result) {
          const verdictEmoji = {
            safe: '✅',
            suspicious: '⚠️',
            malicious: '🚨',
            unknown: '❓'
          };
          
          notification.title = `${verdictEmoji[result.verdict]} Email Scanned`;
          notification.message = `${result.subject} - ${result.verdict.toUpperCase()}`;
          notification.severity = result.verdict === 'malicious' ? 'error' : 
                                  result.verdict === 'suspicious' ? 'warning' : 'success';
        } else {
          notification.title = 'Scan Completed';
          notification.message = 'Email analysis finished successfully';
          notification.severity = 'success';
        }
        
        // Refresh scan history
        queryClient.invalidateQueries({ queryKey: ['scanHistory'] });
        break;
        
      case 'scan_error':
        notification.title = 'Scan Failed';
        notification.message = update.data.error || 'An error occurred during email analysis';
        notification.severity = 'error';
        break;
    }

    addNotification(notification);
  };

  const handleConnectionUpdate = (update: ConnectionStatusUpdate) => {
    const notification: Notification = {
      id: `connection-${Date.now()}`,
      type: 'connection_changed',
      title: 'Connection Status Changed',
      message: '',
      severity: 'info',
      timestamp: new Date(update.data.timestamp),
      autoHide: true
    };

    switch (update.data.status) {
      case 'connected':
        notification.title = '✅ Gmail Connected';
        notification.message = `Successfully connected to ${update.data.email}`;
        notification.severity = 'success';
        break;
        
      case 'disconnected':
        notification.title = '🔌 Gmail Disconnected';
        notification.message = 'Gmail monitoring has been disabled';
        notification.severity = 'warning';
        break;
        
      case 'expired':
        notification.title = '⏰ Connection Expired';
        notification.message = 'Please reconnect your Gmail account';
        notification.severity = 'error';
        break;
    }

    // Refresh user status
    queryClient.invalidateQueries({ queryKey: ['userStatus'] });
    addNotification(notification);
  };

  const handleConnectionError = (error: Error) => {
    const notification: Notification = {
      id: `error-${Date.now()}`,
      type: 'system',
      title: 'Connection Error',
      message: 'Lost connection to real-time updates',
      severity: 'warning',
      timestamp: new Date(),
      autoHide: false
    };

    addNotification(notification);
  };

  const { isConnected, connectionAttempts, reconnect } = useRealtimeConnection({
    enabled: isEnabled,
    onScanUpdate: handleScanUpdate,
    onConnectionUpdate: handleConnectionUpdate,
    onError: handleConnectionError
  });

  const addNotification = (notification: Notification) => {
    setNotifications(prev => {
      const newNotifications = [notification, ...prev].slice(0, maxNotifications);
      
      // Auto-hide notification after 5 seconds if enabled
      if (notification.autoHide) {
        setTimeout(() => {
          removeNotification(notification.id);
        }, 5000);
      }
      
      return newNotifications;
    });
  };

  const removeNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  const clearAllNotifications = () => {
    setNotifications([]);
  };

  const getSeverityStyles = (severity: Notification['severity']) => {
    switch (severity) {
      case 'success':
        return 'bg-green-50 border-green-200 text-green-800';
      case 'warning':
        return 'bg-yellow-50 border-yellow-200 text-yellow-800';
      case 'error':
        return 'bg-red-50 border-red-200 text-red-800';
      default:
        return 'bg-blue-50 border-blue-200 text-blue-800';
    }
  };

  const getSeverityIcon = (severity: Notification['severity']) => {
    switch (severity) {
      case 'success':
        return <CheckCircle2 className="h-4 w-4 text-green-600" />;
      case 'warning':
        return <AlertTriangle className="h-4 w-4 text-yellow-600" />;
      case 'error':
        return <AlertTriangle className="h-4 w-4 text-red-600" />;
      default:
        return <Shield className="h-4 w-4 text-blue-600" />;
    }
  };

  return (
    <div className={`${className}`}>
      {/* Connection Status Indicator */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          {isConnected ? (
            <Wifi className="h-4 w-4 text-green-600" />
          ) : (
            <WifiOff className="h-4 w-4 text-red-600" />
          )}
          <span className="text-sm text-gray-600">
            {isConnected ? 'Real-time updates active' : 'Connection lost'}
          </span>
          {connectionAttempts > 0 && (
            <span className="text-xs text-gray-500">
              (Attempt {connectionAttempts})
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {!isConnected && (
            <button
              onClick={reconnect}
              className="text-xs text-blue-600 hover:text-blue-700 flex items-center gap-1"
            >
              <RefreshCw className="h-3 w-3" />
              Reconnect
            </button>
          )}
          
          <button
            onClick={() => setIsEnabled(!isEnabled)}
            className="text-xs text-gray-600 hover:text-gray-700"
          >
            {isEnabled ? 'Disable' : 'Enable'}
          </button>
        </div>
      </div>

      {/* Notifications */}
      {notifications.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-medium text-gray-700 flex items-center gap-2">
              <Bell className="h-4 w-4" />
              Recent Updates ({notifications.length})
            </h4>
            
            {notifications.length > 0 && (
              <button
                onClick={clearAllNotifications}
                className="text-xs text-gray-500 hover:text-gray-700"
              >
                Clear all
              </button>
            )}
          </div>

          <div className="space-y-2 max-h-80 overflow-y-auto">
            {notifications.map((notification) => (
              <div
                key={notification.id}
                className={`p-3 rounded-md border ${getSeverityStyles(notification.severity)} relative`}
              >
                <button
                  onClick={() => removeNotification(notification.id)}
                  className="absolute top-2 right-2 text-gray-400 hover:text-gray-600"
                >
                  <X className="h-3 w-3" />
                </button>

                <div className="flex items-start gap-2 pr-6">
                  {getSeverityIcon(notification.severity)}
                  
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium">{notification.title}</p>
                    <p className="text-xs mt-1">{notification.message}</p>
                    <p className="text-xs text-gray-500 mt-1">
                      {notification.timestamp.toLocaleTimeString()}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Empty state */}
      {notifications.length === 0 && isEnabled && (
        <div className="text-center py-8 text-gray-500">
          <Bell className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No recent updates</p>
          <p className="text-xs">You'll see notifications for scans and connection changes here</p>
        </div>
      )}
    </div>
  );
};

export default RealtimeNotifications;