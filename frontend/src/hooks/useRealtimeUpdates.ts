import { useEffect, useRef, useState, useCallback } from 'react';

export interface ScanUpdate {
  type: 'scan_started' | 'scan_completed' | 'scan_error' | 'connection_status';
  data: {
    job_id?: string;
    user_id?: number;
    status?: string;
    progress?: number;
    result?: {
      msg_id: string;
      verdict: 'safe' | 'suspicious' | 'malicious' | 'unknown';
      score: number;
      sender: string;
      subject: string;
      scanned_at: string;
    };
    error?: string;
    message?: string;
  };
  timestamp: string;
}

export interface ConnectionStatusUpdate {
  type: 'oauth_status_changed';
  data: {
    user_id: number;
    status: 'connected' | 'disconnected' | 'expired';
    email?: string;
    timestamp: string;
  };
}

type EventUpdate = ScanUpdate | ConnectionStatusUpdate;

interface UseRealtimeUpdatesOptions {
  enabled?: boolean;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
  onScanUpdate?: (update: ScanUpdate) => void;
  onConnectionUpdate?: (update: ConnectionStatusUpdate) => void;
  onError?: (error: Error) => void;
}

export const useRealtimeUpdates = ({
  enabled = true,
  reconnectInterval = 5000,
  maxReconnectAttempts = 10,
  onScanUpdate,
  onConnectionUpdate,
  onError
}: UseRealtimeUpdatesOptions = {}) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<EventUpdate | null>(null);
  const [connectionAttempts, setConnectionAttempts] = useState(0);
  
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const connect = useCallback(() => {
    if (!enabled || eventSourceRef.current) return;

    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
      const eventSource = new EventSource(`${baseUrl}/api/events/stream`, {
        withCredentials: true
      });

      eventSource.onopen = () => {
        console.log('SSE connection opened');
        setIsConnected(true);
        setConnectionAttempts(0);
      };

      eventSource.onmessage = (event) => {
        try {
          const update: EventUpdate = JSON.parse(event.data);
          setLastUpdate(update);

          // Route updates to appropriate handlers
          if (update.type.startsWith('scan_')) {
            onScanUpdate?.(update as ScanUpdate);
          } else if (update.type === 'oauth_status_changed') {
            onConnectionUpdate?.(update as ConnectionStatusUpdate);
          }
        } catch (error) {
          console.error('Error parsing SSE message:', error);
          onError?.(new Error('Failed to parse server update'));
        }
      };

      eventSource.onerror = (error) => {
        console.error('SSE connection error:', error);
        setIsConnected(false);
        eventSource.close();
        eventSourceRef.current = null;

        // Attempt reconnection if under max attempts
        if (connectionAttempts < maxReconnectAttempts) {
          setConnectionAttempts(prev => prev + 1);
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        } else {
          onError?.(new Error('Max reconnection attempts reached'));
        }
      };

      eventSourceRef.current = eventSource;
    } catch (error) {
      console.error('Failed to create SSE connection:', error);
      onError?.(error as Error);
    }
  }, [enabled, connectionAttempts, maxReconnectAttempts, reconnectInterval, onScanUpdate, onConnectionUpdate, onError]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }

    setIsConnected(false);
    setConnectionAttempts(0);
  }, []);

  const reconnect = useCallback(() => {
    disconnect();
    setConnectionAttempts(0);
    connect();
  }, [disconnect, connect]);

  useEffect(() => {
    if (enabled) {
      connect();
    } else {
      disconnect();
    }

    return () => {
      disconnect();
    };
  }, [enabled, connect, disconnect]);

  return {
    isConnected,
    lastUpdate,
    connectionAttempts,
    reconnect,
    disconnect
  };
};

// WebSocket fallback hook (if SSE is not supported)
export const useWebSocketUpdates = ({
  enabled = true,
  reconnectInterval = 5000,
  maxReconnectAttempts = 10,
  onScanUpdate,
  onConnectionUpdate,
  onError
}: UseRealtimeUpdatesOptions = {}) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<EventUpdate | null>(null);
  const [connectionAttempts, setConnectionAttempts] = useState(0);
  
  const websocketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const connect = useCallback(() => {
    if (!enabled || websocketRef.current) return;

    try {
      const baseUrl = import.meta.env.VITE_WS_BASE_URL || 'ws://localhost:8000';
      const websocket = new WebSocket(`${baseUrl}/api/events/ws`);

      websocket.onopen = () => {
        console.log('WebSocket connection opened');
        setIsConnected(true);
        setConnectionAttempts(0);
      };

      websocket.onmessage = (event) => {
        try {
          const update: EventUpdate = JSON.parse(event.data);
          setLastUpdate(update);

          // Route updates to appropriate handlers
          if (update.type.startsWith('scan_')) {
            onScanUpdate?.(update as ScanUpdate);
          } else if (update.type === 'oauth_status_changed') {
            onConnectionUpdate?.(update as ConnectionStatusUpdate);
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
          onError?.(new Error('Failed to parse server update'));
        }
      };

      websocket.onclose = () => {
        console.log('WebSocket connection closed');
        setIsConnected(false);
        websocketRef.current = null;

        // Attempt reconnection if under max attempts
        if (connectionAttempts < maxReconnectAttempts) {
          setConnectionAttempts(prev => prev + 1);
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        } else {
          onError?.(new Error('Max reconnection attempts reached'));
        }
      };

      websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
        onError?.(new Error('WebSocket connection error'));
      };

      websocketRef.current = websocket;
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      onError?.(error as Error);
    }
  }, [enabled, connectionAttempts, maxReconnectAttempts, reconnectInterval, onScanUpdate, onConnectionUpdate, onError]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (websocketRef.current) {
      websocketRef.current.close();
      websocketRef.current = null;
    }

    setIsConnected(false);
    setConnectionAttempts(0);
  }, []);

  const reconnect = useCallback(() => {
    disconnect();
    setConnectionAttempts(0);
    connect();
  }, [disconnect, connect]);

  useEffect(() => {
    if (enabled) {
      connect();
    } else {
      disconnect();
    }

    return () => {
      disconnect();
    };
  }, [enabled, connect, disconnect]);

  return {
    isConnected,
    lastUpdate,
    connectionAttempts,
    reconnect,
    disconnect
  };
};

// Main hook that tries SSE first, falls back to WebSocket
export const useRealtimeConnection = (options: UseRealtimeUpdatesOptions = {}) => {
  const [useWebSocket, setUseWebSocket] = useState(false);

  // Try SSE first
  const sseConnection = useRealtimeUpdates({
    ...options,
    enabled: options.enabled && !useWebSocket,
    onError: (error) => {
      console.warn('SSE failed, trying WebSocket:', error);
      setUseWebSocket(true);
      options.onError?.(error);
    }
  });

  // Fallback to WebSocket
  const wsConnection = useWebSocketUpdates({
    ...options,
    enabled: options.enabled && useWebSocket
  });

  return useWebSocket ? wsConnection : sseConnection;
};