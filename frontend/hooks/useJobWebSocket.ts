/**
 * WebSocket Hook for Real-time Job Updates
 * Manages WebSocket connections for job status notifications
 */

import { useState, useEffect, useRef, useCallback } from 'react';

interface JobUpdate {
  type: 'status_update' | 'progress_update' | 'job_completed' | 'job_failed' | 'connection_established' | 'error';
  job_id?: string;
  status?: string;
  progress?: number;
  result?: any;
  error?: string;
  message?: string;
  timestamp: string;
}

interface UseJobWebSocketOptions {
  url: string;
  jobId?: string;
  onUpdate?: (update: JobUpdate) => void;
  onError?: (error: Error) => void;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

interface UseJobWebSocketReturn {
  isConnected: boolean;
  lastUpdate: JobUpdate | null;
  connectionError: Error | null;
  reconnectCount: number;
  sendMessage: (message: any) => void;
  disconnect: () => void;
  reconnect: () => void;
}

export const useJobWebSocket = ({
  url,
  jobId,
  onUpdate,
  onError,
  reconnectInterval = 3000,
  maxReconnectAttempts = 5
}: UseJobWebSocketOptions): UseJobWebSocketReturn => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<JobUpdate | null>(null);
  const [connectionError, setConnectionError] = useState<Error | null>(null);
  const [reconnectCount, setReconnectCount] = useState(0);
  
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttemptsRef = useRef(0);

  const connect = useCallback(() => {
    try {
      // Build WebSocket URL with job ID if provided
      const wsUrl = jobId ? `${url}/jobs/${jobId}` : url;
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('WebSocket connected');
        setIsConnected(true);
        setConnectionError(null);
        reconnectAttemptsRef.current = 0;
        setReconnectCount(0);
      };

      ws.onmessage = (event) => {
        try {
          const update: JobUpdate = JSON.parse(event.data);
          setLastUpdate(update);
          onUpdate?.(update);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
          onError?.(new Error('Failed to parse WebSocket message'));
        }
      };

      ws.onclose = (event) => {
        console.log('WebSocket disconnected:', event.code, event.reason);
        setIsConnected(false);
        wsRef.current = null;

        // Attempt to reconnect if not a normal closure
        if (
          event.code !== 1000 && 
          reconnectAttemptsRef.current < maxReconnectAttempts
        ) {
          reconnectAttemptsRef.current++;
          setReconnectCount(reconnectAttemptsRef.current);
          
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log(`Attempting to reconnect (${reconnectAttemptsRef.current}/${maxReconnectAttempts})`);
            connect();
          }, reconnectInterval);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        const wsError = new Error('WebSocket connection error');
        setConnectionError(wsError);
        onError?.(wsError);
      };

      wsRef.current = ws;
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      const connectionError = new Error('Failed to create WebSocket connection');
      setConnectionError(connectionError);
      onError?.(connectionError);
    }
  }, [url, jobId, onUpdate, onError, reconnectInterval, maxReconnectAttempts]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.close(1000, 'Manual disconnect');
    }

    wsRef.current = null;
    setIsConnected(false);
    reconnectAttemptsRef.current = maxReconnectAttempts; // Prevent auto-reconnect
  }, [maxReconnectAttempts]);

  const reconnect = useCallback(() => {
    disconnect();
    reconnectAttemptsRef.current = 0;
    setReconnectCount(0);
    setTimeout(connect, 1000);
  }, [disconnect, connect]);

  const sendMessage = useCallback((message: any) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket is not connected');
    }
  }, []);

  // Initialize connection
  useEffect(() => {
    connect();
    
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  // Ping to keep connection alive
  useEffect(() => {
    if (!isConnected) return;

    const pingInterval = setInterval(() => {
      sendMessage({ type: 'ping' });
    }, 30000); // Ping every 30 seconds

    return () => clearInterval(pingInterval);
  }, [isConnected, sendMessage]);

  return {
    isConnected,
    lastUpdate,
    connectionError,
    reconnectCount,
    sendMessage,
    disconnect,
    reconnect
  };
};

// Hook for system-wide status updates
export const useSystemWebSocket = (
  url: string,
  onUpdate?: (update: any) => void
) => {
  return useJobWebSocket({
    url: `${url}/system`,
    onUpdate,
    reconnectInterval: 5000,
    maxReconnectAttempts: 10
  });
};

// Hook for multiple job tracking
interface UseJobsWebSocketOptions {
  baseUrl: string;
  jobIds: string[];
  onJobUpdate?: (jobId: string, update: JobUpdate) => void;
  onError?: (error: Error) => void;
}

export const useJobsWebSocket = ({
  baseUrl,
  jobIds,
  onJobUpdate,
  onError
}: UseJobsWebSocketOptions) => {
  const [connections, setConnections] = useState<Map<string, boolean>>(new Map());
  const [lastUpdates, setLastUpdates] = useState<Map<string, JobUpdate>>(new Map());
  const connectionsRef = useRef<Map<string, WebSocket>>(new Map());

  const updateConnectionStatus = useCallback((jobId: string, connected: boolean) => {
    setConnections(prev => new Map(prev.set(jobId, connected)));
  }, []);

  const updateLastUpdate = useCallback((jobId: string, update: JobUpdate) => {
    setLastUpdates(prev => new Map(prev.set(jobId, update)));
    onJobUpdate?.(jobId, update);
  }, [onJobUpdate]);

  // Create connections for new job IDs
  useEffect(() => {
    const newJobIds = jobIds.filter(id => !connectionsRef.current.has(id));
    const removedJobIds = Array.from(connectionsRef.current.keys()).filter(id => !jobIds.includes(id));

    // Remove connections for jobs no longer tracked
    removedJobIds.forEach(jobId => {
      const ws = connectionsRef.current.get(jobId);
      if (ws) {
        ws.close();
        connectionsRef.current.delete(jobId);
        updateConnectionStatus(jobId, false);
      }
    });

    // Add connections for new jobs
    newJobIds.forEach(jobId => {
      try {
        const ws = new WebSocket(`${baseUrl}/jobs/${jobId}`);
        
        ws.onopen = () => {
          updateConnectionStatus(jobId, true);
        };

        ws.onmessage = (event) => {
          try {
            const update: JobUpdate = JSON.parse(event.data);
            updateLastUpdate(jobId, update);
          } catch (error) {
            console.error(`Failed to parse message for job ${jobId}:`, error);
          }
        };

        ws.onclose = () => {
          updateConnectionStatus(jobId, false);
          connectionsRef.current.delete(jobId);
        };

        ws.onerror = (error) => {
          console.error(`WebSocket error for job ${jobId}:`, error);
          onError?.(new Error(`WebSocket error for job ${jobId}`));
        };

        connectionsRef.current.set(jobId, ws);
      } catch (error) {
        console.error(`Failed to create WebSocket for job ${jobId}:`, error);
        onError?.(new Error(`Failed to create WebSocket for job ${jobId}`));
      }
    });

    // Cleanup on unmount
    return () => {
      connectionsRef.current.forEach(ws => ws.close());
      connectionsRef.current.clear();
    };
  }, [jobIds, baseUrl, onError, updateConnectionStatus, updateLastUpdate]);

  return {
    connections: Object.fromEntries(connections),
    lastUpdates: Object.fromEntries(lastUpdates),
    connectedCount: Array.from(connections.values()).filter(Boolean).length
  };
};

// Utility function to get WebSocket URL from current location
export const getWebSocketUrl = (): string => {
  if (typeof window !== 'undefined') {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    return `${protocol}//${host}/ws`;
  }
  return 'ws://localhost:8000/ws';
};