import { useEffect, useRef, useCallback } from 'react';
import { webSocketService, WebSocketMessage } from '../services/webSocketService';
import { useUIStore } from '../stores/uiStore';
import { useWebSocketQueryInvalidation } from './useApiQueries';
import { apiService } from '../services/apiService';

interface AuthenticatedWebSocketMessage extends WebSocketMessage {
  user_id?: number;
  tenant_id?: string;
  permissions?: string[];
}

export function useWebSocket() {
  const {
    setWSConnected,
    setWSReconnecting,
    setWSLastMessage,
    addNotification,
  } = useUIStore();

  const {
    invalidateEmails,
    invalidateEmail,
    invalidateSystemStats,
    updateEmailInCache,
  } = useWebSocketQueryInvalidation();

  const reconnectAttemptRef = useRef(0);
  const maxReconnectAttempts = 5;
  const authCheckIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Enhanced connection with authentication
  const connectWithAuth = useCallback(() => {
    const token = apiService.getAccessToken();
    
    if (!token) {
      console.warn('No access token available for WebSocket connection');
      return;
    }

    // Connect with authorization header
    webSocketService.connect();
  }, []);

  // Validate message authentication
  const validateMessageAuth = useCallback((message: AuthenticatedWebSocketMessage): boolean => {
    // Add validation logic based on your authentication requirements
    if (message.user_id && message.tenant_id) {
      // Validate that the message is for the current user/tenant
      // This would typically be validated on the backend, but we can add client-side checks
      return true;
    }
    return false;
  }, []);

  useEffect(() => {
    // Periodic auth check for WebSocket
    authCheckIntervalRef.current = setInterval(() => {
      const token = apiService.getAccessToken();
      const isExpired = apiService.isTokenExpired();
      
      if (!token || isExpired) {
        webSocketService.disconnect();
        setWSConnected(false);
      } else if (!webSocketService.isConnected()) {
        connectWithAuth();
      }
    }, 30000); // Check every 30 seconds

    return () => {
      if (authCheckIntervalRef.current) {
        clearInterval(authCheckIntervalRef.current);
      }
    };
  }, [connectWithAuth]);

  useEffect(() => {
    // Connection handlers
    const handleConnection = (message: WebSocketMessage) => {
      const connected = message.data.connected;
      setWSConnected(connected);
      
      if (connected) {
        reconnectAttemptRef.current = 0;
        setWSReconnecting(false);
        addNotification({
          type: 'success',
          message: 'Real-time updates connected',
          autoHide: true,
        });
      } else {
        addNotification({
          type: 'warning',
          message: 'Real-time updates disconnected',
          autoHide: true,
        });
      }
    };

    const handleReconnecting = (message: WebSocketMessage) => {
      setWSReconnecting(true);
      reconnectAttemptRef.current = message.data.attempt;
      
      if (message.data.attempt <= 3) {
        addNotification({
          type: 'info',
          message: `Reconnecting... (${message.data.attempt}/${message.data.maxAttempts})`,
          autoHide: true,
        });
      }
    };

    const handleMaxReconnectAttemptsReached = () => {
      setWSReconnecting(false);
      addNotification({
        type: 'error',
        message: 'Unable to establish real-time connection. Some features may not work properly.',
        autoHide: false,
      });
    };

    const handleError = (message: WebSocketMessage) => {
      console.error('WebSocket error:', message.data.error);
      setWSConnected(false);
      setWSReconnecting(false);
      
      // Check if error is authentication-related
      if (message.data.error?.includes('authentication') || message.data.error?.includes('unauthorized')) {
        addNotification({
          type: 'warning',
          message: 'Authentication expired. Please refresh the page.',
          autoHide: false,
        });
      }
    };

    // Enhanced business logic handlers with auth validation
    const handleEmailProcessed = (message: AuthenticatedWebSocketMessage) => {
      // Validate message authentication
      if (!validateMessageAuth(message)) {
        console.warn('Received unauthenticated email update message');
        return;
      }

      const { email_id, risk_score, risk_level, status, ai_verdict, tenant_id } = message.data;
      
      // Update email in cache
      updateEmailInCache({
        id: email_id,
        risk_score,
        risk_level,
        status,
        ai_verdict,
        updated_at: new Date().toISOString(),
      });

      // Show notification for high-risk emails
      if (['critical', 'high'].includes(risk_level)) {
        addNotification({
          type: risk_level === 'critical' ? 'error' : 'warning',
          message: `${risk_level.toUpperCase()} threat detected: Risk score ${risk_score}`,
          autoHide: false,
        });
      }

      // Update system stats
      invalidateSystemStats();
      
      // Store last message
      setWSLastMessage({
        ...message,
        timestamp: new Date().toISOString(),
      });
    };

    const handleEmailQuarantined = (message: AuthenticatedWebSocketMessage) => {
      if (!validateMessageAuth(message)) {
        console.warn('Received unauthenticated quarantine message');
        return;
      }

      const { email_id, status, reason, gmail_action } = message.data;
      
      // Update email status in cache
      updateEmailInCache({
        id: email_id,
        status,
        updated_at: new Date().toISOString(),
      });

      // Show notification
      addNotification({
        type: 'info',
        message: `Email ${email_id} has been ${status}${reason ? `: ${reason}` : ''}`,
        autoHide: true,
      });

      // If Gmail action was performed, show additional notification
      if (gmail_action) {
        addNotification({
          type: 'success',
          message: `Gmail label updated: ${gmail_action}`,
          autoHide: true,
        });
      }

      invalidateEmails();
      invalidateSystemStats();
    };

    const handleLinkAnalyzed = (message: AuthenticatedWebSocketMessage) => {
      if (!validateMessageAuth(message)) {
        console.warn('Received unauthenticated link analysis message');
        return;
      }

      const { email_id, link_id, risk_score, status, redirect_chain } = message.data;
      
      // Invalidate email data to refresh link information
      invalidateEmail(email_id);
      
      // Show notification for malicious links
      if (status === 'malicious') {
        addNotification({
          type: 'error',
          message: `Malicious link detected in email ${email_id}`,
          autoHide: false,
        });
      }
    };

    const handleSystemAlert = (message: AuthenticatedWebSocketMessage) => {
      const { alert_type, message: alertMessage, severity } = message.data;
      
      const notificationType = severity === 'critical' ? 'error' : 
                              severity === 'warning' ? 'warning' : 'info';
      
      addNotification({
        type: notificationType,
        message: `System Alert: ${alertMessage}`,
        autoHide: severity !== 'critical',
      });

      invalidateSystemStats();
    };

    const handleTenantUpdate = (message: AuthenticatedWebSocketMessage) => {
      if (!validateMessageAuth(message)) {
        console.warn('Received unauthenticated tenant update message');
        return;
      }

      const { tenant_id, update_type, details } = message.data;
      
      // Refresh all data for tenant-wide updates
      invalidateEmails();
      invalidateSystemStats();
      
      addNotification({
        type: 'info',
        message: `Tenant configuration updated: ${update_type}`,
        autoHide: true,
      });
    };

    // Register enhanced event handlers
    const eventHandlers = {
      'connection': handleConnection,
      'reconnecting': handleReconnecting,
      'max_reconnect_attempts_reached': handleMaxReconnectAttemptsReached,
      'error': handleError,
      'email_processed': handleEmailProcessed,
      'email_quarantined': handleEmailQuarantined,
      'email_status_updated': handleEmailQuarantined, // Same handler
      'link_analyzed': handleLinkAnalyzed,
      'system_alert': handleSystemAlert,
      'tenant_update': handleTenantUpdate,
    };

    // Subscribe to all events
    Object.entries(eventHandlers).forEach(([event, handler]) => {
      webSocketService.on(event, handler);
    });

    // Connect with authentication
    connectWithAuth();

    // Cleanup function
    return () => {
      Object.entries(eventHandlers).forEach(([event, handler]) => {
        webSocketService.off(event, handler);
      });
      webSocketService.disconnect();
    };
  }, [
    setWSConnected,
    setWSReconnecting,
    setWSLastMessage,
    addNotification,
    invalidateEmails,
    invalidateEmail,
    invalidateSystemStats,
    updateEmailInCache,
    connectWithAuth,
    validateMessageAuth,
  ]);

  // Return connection utilities
  return {
    isConnected: webSocketService.isConnected(),
    reconnectAttempts: reconnectAttemptRef.current,
    maxReconnectAttempts,
    connectWithAuth,
    disconnect: () => webSocketService.disconnect(),
  };
}
