import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { 
  Activity, 
  CheckCircle, 
  AlertCircle, 
  Clock, 
  Zap,
  TrendingUp,
  Mail,
  Database
} from 'lucide-react';

interface RealTimeMetrics {
  active_syncs: number;
  messages_per_minute: number;
  api_quota_usage: number;
  processing_queue_size: number;
  success_rate: number;
  avg_processing_time: number;
}

interface SyncEvent {
  timestamp: string;
  event_type: 'sync_started' | 'sync_completed' | 'sync_paused' | 'message_processed' | 'error';
  user_id?: number;
  message?: string;
  details?: any;
}

const SyncProgressTracker: React.FC = () => {
  const [metrics, setMetrics] = useState<RealTimeMetrics>({
    active_syncs: 0,
    messages_per_minute: 0,
    api_quota_usage: 0,
    processing_queue_size: 0,
    success_rate: 0,
    avg_processing_time: 0
  });
  const [recentEvents, setRecentEvents] = useState<SyncEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  // Simulate real-time updates (in production, use WebSocket or Server-Sent Events)
  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        // Simulate fetching real-time metrics
        const mockMetrics: RealTimeMetrics = {
          active_syncs: Math.floor(Math.random() * 5) + 1,
          messages_per_minute: Math.floor(Math.random() * 100) + 20,
          api_quota_usage: Math.random() * 100,
          processing_queue_size: Math.floor(Math.random() * 500),
          success_rate: 95 + Math.random() * 5,
          avg_processing_time: 0.1 + Math.random() * 0.5
        };
        
        setMetrics(mockMetrics);
        setIsConnected(true);

        // Simulate recent events
        const mockEvents: SyncEvent[] = [
          {
            timestamp: new Date(Date.now() - Math.random() * 60000).toISOString(),
            event_type: 'message_processed' as const,
            message: '10 messages processed successfully'
          },
          {
            timestamp: new Date(Date.now() - Math.random() * 120000).toISOString(),
            event_type: 'sync_started' as const,
            user_id: 123,
            message: 'Initial sync started for user@example.com'
          },
          {
            timestamp: new Date(Date.now() - Math.random() * 180000).toISOString(),
            event_type: 'sync_completed' as const,
            user_id: 456,
            message: 'Sync completed: 2,500 messages processed'
          }
        ].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        
        setRecentEvents(mockEvents);

      } catch (error) {
        setIsConnected(false);
        console.error('Failed to fetch metrics:', error);
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, []);

  const getEventIcon = (eventType: string) => {
    switch (eventType) {
      case 'sync_started':
        return <Activity className="h-4 w-4 text-blue-500" />;
      case 'sync_completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'sync_paused':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'message_processed':
        return <Mail className="h-4 w-4 text-purple-500" />;
      case 'error':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      default:
        return <Activity className="h-4 w-4 text-gray-500" />;
    }
  };

  const getQuotaColor = (usage: number) => {
    if (usage < 50) return 'text-green-600';
    if (usage < 80) return 'text-yellow-600';
    return 'text-red-600';
  };

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    
    return date.toLocaleDateString();
  };

  return (
    <div className="space-y-6">
      {/* Connection Status */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Sync Progress Tracker</h2>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-sm text-gray-600">
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Real-time Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Active Syncs */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Syncs</CardTitle>
            <Activity className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{metrics.active_syncs}</div>
            <p className="text-xs text-gray-600">Currently running</p>
          </CardContent>
        </Card>

        {/* Messages per Minute */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Processing Rate</CardTitle>
            <TrendingUp className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{metrics.messages_per_minute}</div>
            <p className="text-xs text-gray-600">messages/minute</p>
          </CardContent>
        </Card>

        {/* API Quota Usage */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">API Quota</CardTitle>
            <Zap className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${getQuotaColor(metrics.api_quota_usage)}`}>
              {metrics.api_quota_usage.toFixed(1)}%
            </div>
            <Progress value={metrics.api_quota_usage} className="h-1 mt-2" />
          </CardContent>
        </Card>

        {/* Processing Queue */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Queue Size</CardTitle>
            <Database className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{metrics.processing_queue_size.toLocaleString()}</div>
            <p className="text-xs text-gray-600">pending messages</p>
          </CardContent>
        </Card>

        {/* Success Rate */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">
              {metrics.success_rate.toFixed(1)}%
            </div>
            <p className="text-xs text-gray-600">last 24 hours</p>
          </CardContent>
        </Card>

        {/* Avg Processing Time */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Processing</CardTitle>
            <Clock className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{metrics.avg_processing_time.toFixed(2)}s</div>
            <p className="text-xs text-gray-600">per message</p>
          </CardContent>
        </Card>
      </div>

      {/* Recent Events */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Recent Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {recentEvents.length > 0 ? (
              recentEvents.map((event, index) => (
                <div key={index} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                  <div className="flex-shrink-0 mt-0.5">
                    {getEventIcon(event.event_type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-xs">
                        {event.event_type.replace('_', ' ')}
                      </Badge>
                      <span className="text-xs text-gray-500">
                        {formatTime(event.timestamp)}
                      </span>
                    </div>
                    <p className="text-sm mt-1">{event.message}</p>
                    {event.user_id && (
                      <p className="text-xs text-gray-600 mt-1">
                        User ID: {event.user_id}
                      </p>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <Activity className="h-8 w-8 mx-auto mb-2 text-gray-400" />
                <p>No recent activity</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* System Health Summary */}
      <Card>
        <CardHeader>
          <CardTitle>System Health</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 bg-green-500 rounded-full" />
              <div>
                <div className="font-medium">Gmail API</div>
                <div className="text-sm text-gray-600">Operational</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 bg-green-500 rounded-full" />
              <div>
                <div className="font-medium">Sync Engine</div>
                <div className="text-sm text-gray-600">Healthy</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 bg-yellow-500 rounded-full" />
              <div>
                <div className="font-medium">Queue Processing</div>
                <div className="text-sm text-gray-600">
                  {metrics.processing_queue_size > 1000 ? 'High Load' : 'Normal'}
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default SyncProgressTracker;