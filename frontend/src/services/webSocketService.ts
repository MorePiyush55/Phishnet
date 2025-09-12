export interface WebSocketMessage {
  type: 'email_processed' | 'email_updated' | 'threat_detected' | 'system_alert' | 'user_action';
  data: any;
  timestamp: string;
}

export interface EmailProcessedEvent {
  type: 'email_processed';
  data: {
    email_id: number;
    risk_score: number;
    risk_level: string;
    status: string;
    ai_verdict?: string;
  };
}

export interface EmailUpdatedEvent {
  type: 'email_updated';
  data: {
    email_id: number;
    status: string;
    updated_by?: string;
    reason?: string;
  };
}

export interface ThreatDetectedEvent {
  type: 'threat_detected';
  data: {
    email_id: number;
    threat_type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    indicators: string[];
  };
}

export interface SystemAlertEvent {
  type: 'system_alert';
  data: {
    alert_type: 'error' | 'warning' | 'info';
    message: string;
    component?: string;
  };
}

export type WebSocketEventHandler = (message: WebSocketMessage) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectInterval = 1000; // Start with 1 second
  private maxReconnectInterval = 30000; // Max 30 seconds
  private reconnectTimer: NodeJS.Timeout | null = null;
  private eventHandlers: Map<string, WebSocketEventHandler[]> = new Map();
  private isConnecting = false;
  private shouldReconnect = true;

  constructor(private url: string, private getAccessToken: () => string | null) {}

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }

      if (this.isConnecting) {
        reject(new Error('Connection already in progress'));
        return;
      }

      const token = this.getAccessToken();
      if (!token) {
        reject(new Error('No access token available'));
        return;
      }

      this.isConnecting = true;
      const wsUrl = `${this.url}?token=${encodeURIComponent(token)}`;
      
      try {
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
          console.log('WebSocket connected');
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          this.reconnectInterval = 1000;
          this.emit('connection', { connected: true });
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const message: WebSocketMessage = JSON.parse(event.data);
            this.handleMessage(message);
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };

        this.ws.onclose = (event) => {
          console.log('WebSocket disconnected:', event.code, event.reason);
          this.isConnecting = false;
          this.ws = null;
          this.emit('connection', { connected: false });

          if (this.shouldReconnect && event.code !== 1000) {
            this.scheduleReconnect();
          }
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.isConnecting = false;
          this.emit('error', { error });
          reject(error);
        };

      } catch (error) {
        this.isConnecting = false;
        reject(error);
      }
    });
  }

  disconnect(): void {
    this.shouldReconnect = false;
    
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      this.ws.close(1000, 'Manual disconnect');
      this.ws = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      this.emit('maxReconnectAttemptsReached', {});
      return;
    }

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    this.reconnectAttempts++;
    console.log(`Scheduling reconnect attempt ${this.reconnectAttempts} in ${this.reconnectInterval}ms`);
    
    this.emit('reconnecting', { 
      attempt: this.reconnectAttempts, 
      maxAttempts: this.maxReconnectAttempts,
      delay: this.reconnectInterval 
    });

    this.reconnectTimer = setTimeout(async () => {
      try {
        await this.connect();
      } catch (error) {
        console.error('Reconnection failed:', error);
        
        // Exponential backoff with jitter
        this.reconnectInterval = Math.min(
          this.reconnectInterval * 2 + Math.random() * 1000,
          this.maxReconnectInterval
        );
        
        this.scheduleReconnect();
      }
    }, this.reconnectInterval);
  }

  private handleMessage(message: WebSocketMessage): void {
    console.log('WebSocket message received:', message);
    
    // Emit to type-specific handlers
    this.emit(message.type, message);
    
    // Emit to generic message handlers
    this.emit('message', message);
  }

  // Event handler methods
  on(eventType: string, handler: WebSocketEventHandler): void {
    if (!this.eventHandlers.has(eventType)) {
      this.eventHandlers.set(eventType, []);
    }
    this.eventHandlers.get(eventType)!.push(handler);
  }

  off(eventType: string, handler: WebSocketEventHandler): void {
    const handlers = this.eventHandlers.get(eventType);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }

  private emit(eventType: string, data: any): void {
    const handlers = this.eventHandlers.get(eventType);
    if (handlers) {
      handlers.forEach(handler => {
        try {
          handler({ type: eventType as any, data, timestamp: new Date().toISOString() });
        } catch (error) {
          console.error('Error in WebSocket event handler:', error);
        }
      });
    }
  }

  // Utility methods
  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  getReadyState(): number | null {
    return this.ws?.readyState ?? null;
  }

  send(message: any): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket not connected, cannot send message');
    }
  }
}

// Create singleton instance
const WS_URL = (typeof window !== 'undefined' && window.location.protocol === 'https:') 
  ? 'wss://localhost:8000/api/v1/ws' 
  : 'ws://localhost:8000/api/v1/ws';

export const webSocketService = new WebSocketService(
  WS_URL,
  () => localStorage.getItem('access_token')
);
