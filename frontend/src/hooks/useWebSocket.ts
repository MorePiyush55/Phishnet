import { useEffect, useRef } from 'react';
import { webSocketService, WebSocketMessage } from '../services/webSocketService';
import { useUIStore } from '../stores/uiStore';
import { useWebSocketQueryInvalidation } from './useApiQueries';

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
    };

    // Business logic handlers
    const handleEmailProcessed = (message: WebSocketMessage) => {
      const { email_id, risk_score, risk_level, status, ai_verdict } = message.data;
      
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
      
      setWSLastMessage(message);
    };

    const handleEmailUpdated = (message: WebSocketMessage) => {
      const { email_id, status, updated_by, reason } = message.data;
      
      // Update email in cache
      updateEmailInCache({
        id: email_id,
        status,
        updated_at: new Date().toISOString(),
      });

      // Show notification if updated by another user
      if (updated_by && updated_by !== 'current_user') { // Replace with actual current user check
        addNotification({
          type: 'info',
          message: `Email ${email_id} ${status} by ${updated_by}${reason ? `: ${reason}` : ''}`,
          autoHide: true,
        });
      }

      setWSLastMessage(message);
    };

    const handleThreatDetected = (message: WebSocketMessage) => {
      const { email_id, threat_type, severity, indicators } = message.data;
      
      // Invalidate email to get latest threat information
      invalidateEmail(email_id);
      
      // Show critical alert
      addNotification({
        type: 'error',
        message: `${threat_type} detected in email ${email_id} (${severity}): ${indicators.join(', ')}`,
        autoHide: false,
      });

      setWSLastMessage(message);
    };

    const handleSystemAlert = (message: WebSocketMessage) => {
      const { alert_type, message: alertMessage, component } = message.data;
      
      addNotification({
        type: alert_type === 'error' ? 'error' : alert_type === 'warning' ? 'warning' : 'info',
        message: `${component ? `[${component}] ` : ''}${alertMessage}`,
        autoHide: alert_type === 'info',
      });

      setWSLastMessage(message);
    };

    const handleUserAction = (message: WebSocketMessage) => {
      const { action, user, target, details } = message.data;
      
      // Invalidate relevant queries based on action
      if (target?.type === 'email') {
        if (action === 'bulk_update') {
          invalidateEmails();
        } else {
          invalidateEmail(target.id);
        }
      }

      // Show notification for significant actions by other users
      if (user !== 'current_user' && ['quarantine', 'delete', 'bulk_update'].includes(action)) {
        addNotification({
          type: 'info',
          message: `${user} performed ${action} on ${target?.type || 'resource'} ${target?.id || ''}`,
          autoHide: true,
        });
      }

      setWSLastMessage(message);
    };

    // Generic message handler for debugging
    const handleMessage = (message: WebSocketMessage) => {
      console.log('WebSocket message:', message);
    };

    // Register event handlers
    webSocketService.on('connection', handleConnection);
    webSocketService.on('reconnecting', handleReconnecting);
    webSocketService.on('maxReconnectAttemptsReached', handleMaxReconnectAttemptsReached);
    webSocketService.on('error', handleError);
    webSocketService.on('email_processed', handleEmailProcessed);
    webSocketService.on('email_updated', handleEmailUpdated);
    webSocketService.on('threat_detected', handleThreatDetected);
    webSocketService.on('system_alert', handleSystemAlert);
    webSocketService.on('user_action', handleUserAction);
    webSocketService.on('message', handleMessage);

    // Connect WebSocket
    webSocketService.connect().catch((error) => {
      console.error('Failed to connect WebSocket:', error);
      setWSConnected(false);
      addNotification({
        type: 'warning',
        message: 'Unable to connect to real-time updates',
        autoHide: true,
      });
    });

    // Cleanup function
    return () => {
      webSocketService.off('connection', handleConnection);
      webSocketService.off('reconnecting', handleReconnecting);
      webSocketService.off('maxReconnectAttemptsReached', handleMaxReconnectAttemptsReached);
      webSocketService.off('error', handleError);
      webSocketService.off('email_processed', handleEmailProcessed);
      webSocketService.off('email_updated', handleEmailUpdated);
      webSocketService.off('threat_detected', handleThreatDetected);
      webSocketService.off('system_alert', handleSystemAlert);
      webSocketService.off('user_action', handleUserAction);
      webSocketService.off('message', handleMessage);
      
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
  ]);

  return {
    isConnected: webSocketService.isConnected(),
    send: (message: any) => webSocketService.send(message),
    reconnect: () => webSocketService.connect(),
  };
}

// Hook for components that need to react to specific WebSocket events
export function useWebSocketEvent(
  eventType: string,
  handler: (message: WebSocketMessage) => void,
  dependencies: any[] = []
) {
  useEffect(() => {
    webSocketService.on(eventType, handler);
    
    return () => {
      webSocketService.off(eventType, handler);
    };
  }, dependencies);
}
