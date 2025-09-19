import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  Mail, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Clock,
  TrendingUp,
  Users,
  Database,
  Wifi,
  WifiOff,
  Download,
  Trash2,
  Settings,
  Eye,
  RefreshCw
} from 'lucide-react';

// API configuration
const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';
const WS_BASE = import.meta.env.VITE_WS_BASE_URL || 'ws://localhost:8000/api/v1';

// Types
interface ScanResult {
  id: string;
  gmail_message_id: string;
  sender_domain: string;
  status: string;
  created_at: string;
  completed_at?: string;
  threat_result?: {
    threat_level: string;
    threat_score: number;
    confidence: number;
    explanation: string;
    recommendations: string[];
    phishing_indicators: string[];
    component_scores: {
      link_analysis: number;
      content_analysis: number;
      sender_reputation: number;
      llm_analysis: number;
    };
  };
}

interface DashboardStats {
  scan_stats: {
    total_scans: number;
    recent_scans: number;
    threat_distribution: Record<string, number>;
  };
  recent_threats: Array<{
    id: string;
    sender_domain: string;
    threat_level: string;
    threat_score: number;
    created_at: string;
  }>;
  quarantine_stats: {
    total_quarantined: number;
    auto_quarantined: number;
    manual_actions: number;
    false_positives: number;
  };
}

interface WebSocketMessage {
  type: string;
  data: any;
  timestamp: string;
}

// Custom hooks
const useWebSocket = (userId: string) => {
  const [socket, setSocket] = useState<WebSocket | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');
  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;

  const connect = useCallback(() => {
    if (socket?.readyState === WebSocket.OPEN) {
      return;
    }

    setConnectionStatus('connecting');
    const ws = new WebSocket(`${WS_BASE}/ws/${userId}`);

    ws.onopen = () => {
      setConnectionStatus('connected');
      reconnectAttempts.current = 0;
      console.log('WebSocket connected');
    };

    ws.onmessage = (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data);
        setMessages(prev => [...prev.slice(-50), message]); // Keep last 50 messages
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    ws.onclose = () => {
      setConnectionStatus('disconnected');
      setSocket(null);
      
      // Auto-reconnect with exponential backoff
      if (reconnectAttempts.current < maxReconnectAttempts) {
        const delay = Math.pow(2, reconnectAttempts.current) * 1000;
        reconnectAttempts.current++;
        console.log(`Reconnecting in ${delay}ms (attempt ${reconnectAttempts.current})`);
        setTimeout(connect, delay);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    setSocket(ws);
  }, [userId]);

  const disconnect = useCallback(() => {
    if (socket) {
      socket.close();
      setSocket(null);
      setConnectionStatus('disconnected');
    }
  }, [socket]);

  useEffect(() => {
    connect();
    return disconnect;
  }, [connect, disconnect]);

  return { connectionStatus, messages, connect, disconnect };
};

const useAPI = () => {
  const [loading, setLoading] = useState(false);
  
  const apiCall = async (endpoint: string, options: RequestInit = {}) => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
          ...options.headers,
        },
        ...options,
      });
      
      if (!response.ok) {
        throw new Error(`API Error: ${response.status}`);
      }
      
      return await response.json();
    } finally {
      setLoading(false);
    }
  };

  return { apiCall, loading };
};

// Components
const ThreatLevelBadge: React.FC<{ level: string; score?: number }> = ({ level, score }) => {
  const getVariant = () => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      case 'safe': return 'outline';
      default: return 'outline';
    }
  };

  const getIcon = () => {
    switch (level?.toLowerCase()) {
      case 'critical':
      case 'high':
        return <XCircle className="w-4 h-4" />;
      case 'medium':
        return <AlertTriangle className="w-4 h-4" />;
      case 'low':
      case 'safe':
        return <CheckCircle className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
    }
  };

  return (
    <Badge variant={getVariant()} className="flex items-center gap-1">
      {getIcon()}
      {level} {score && `(${score}%)`}
    </Badge>
  );
};

const ConnectionStatus: React.FC<{ status: 'connecting' | 'connected' | 'disconnected' }> = ({ status }) => {
  const getIcon = () => {
    switch (status) {
      case 'connected':
        return <Wifi className="w-4 h-4 text-green-500" />;
      case 'connecting':
        return <RefreshCw className="w-4 h-4 animate-spin text-yellow-500" />;
      case 'disconnected':
        return <WifiOff className="w-4 h-4 text-red-500" />;
    }
  };

  return (
    <div className="flex items-center gap-2">
      {getIcon()}
      <span className="text-sm capitalize">{status}</span>
    </div>
  );
};

const StatsCard: React.FC<{ title: string; value: number; icon: React.ReactNode; trend?: number }> = ({ 
  title, 
  value, 
  icon, 
  trend 
}) => (
  <Card>
    <CardContent className="flex items-center p-6">
      <div className="flex items-center space-x-4">
        <div className="p-2 bg-primary/10 rounded-lg">
          {icon}
        </div>
        <div>
          <p className="text-2xl font-bold">{value.toLocaleString()}</p>
          <p className="text-sm text-muted-foreground">{title}</p>
          {trend !== undefined && (
            <div className="flex items-center text-xs">
              <TrendingUp className="w-3 h-3 mr-1" />
              <span className={trend > 0 ? 'text-green-500' : 'text-red-500'}>
                {trend > 0 ? '+' : ''}{trend}% this month
              </span>
            </div>
          )}
        </div>
      </div>
    </CardContent>
  </Card>
);

const ThreatDistributionChart: React.FC<{ distribution: Record<string, number> }> = ({ distribution }) => {
  const total = Object.values(distribution).reduce((sum, count) => sum + count, 0);
  
  return (
    <div className="space-y-3">
      {Object.entries(distribution).map(([level, count]) => {
        const percentage = total > 0 ? (count / total) * 100 : 0;
        return (
          <div key={level} className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ThreatLevelBadge level={level} />
              <span className="text-sm">{count} emails</span>
            </div>
            <Progress value={percentage} className="w-20" />
          </div>
        );
      })}
    </div>
  );
};

const RecentThreatsTable: React.FC<{ threats: DashboardStats['recent_threats'] }> = ({ threats }) => (
  <div className="space-y-2">
    {threats.length === 0 ? (
      <div className="text-center py-8 text-muted-foreground">
        <Shield className="w-12 h-12 mx-auto mb-2" />
        <p>No recent threats detected</p>
      </div>
    ) : (
      threats.map((threat) => (
        <Card key={threat.id} className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Mail className="w-4 h-4" />
              <div>
                <p className="font-medium">{threat.sender_domain}</p>
                <p className="text-xs text-muted-foreground">
                  {new Date(threat.created_at).toLocaleString()}
                </p>
              </div>
            </div>
            <ThreatLevelBadge 
              level={threat.threat_level} 
              score={Math.round(threat.threat_score)} 
            />
          </div>
        </Card>
      ))
    )}
  </div>
);

const ScanHistoryTable: React.FC<{ scans: ScanResult[]; onViewDetails: (scanId: string) => void }> = ({ 
  scans, 
  onViewDetails 
}) => (
  <div className="space-y-2">
    {scans.map((scan) => (
      <Card key={scan.id} className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Mail className="w-4 h-4" />
            <div>
              <p className="font-medium">{scan.sender_domain}</p>
              <p className="text-xs text-muted-foreground">
                {new Date(scan.created_at).toLocaleString()}
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {scan.threat_result && (
              <ThreatLevelBadge 
                level={scan.threat_result.threat_level}
                score={Math.round(scan.threat_result.threat_score)} 
              />
            )}
            <Button variant="outline" size="sm" onClick={() => onViewDetails(scan.id)}>
              <Eye className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </Card>
    ))}
  </div>
);

// Main Dashboard Component
const PhishNetDashboard: React.FC = () => {
  const [dashboardStats, setDashboardStats] = useState<DashboardStats | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [gmailConnected, setGmailConnected] = useState(false);
  const { apiCall, loading } = useAPI();
  
  // Mock user ID for demo - in real app, get from auth
  const userId = "1";
  const { connectionStatus, messages } = useWebSocket(userId);

  // Load dashboard data
  const loadDashboardData = async () => {
    try {
      const [statsResponse, scansResponse] = await Promise.all([
        apiCall('/dashboard/stats'),
        apiCall('/scans?limit=10')
      ]);
      
      setDashboardStats(statsResponse);
      setScanHistory(scansResponse.scans || []);
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    }
  };

  // Initialize Gmail OAuth
  const initializeGmailAuth = async () => {
    try {
      const response = await apiCall('/auth/gmail/init', { method: 'POST' });
      window.open(response.authorization_url, '_blank');
    } catch (error) {
      console.error('Gmail OAuth error:', error);
    }
  };

  // View scan details
  const viewScanDetails = async (scanId: string) => {
    try {
      const response = await apiCall(`/scans/${scanId}`);
      setSelectedScan(response);
    } catch (error) {
      console.error('Error loading scan details:', error);
    }
  };

  // Export user data
  const exportUserData = async () => {
    try {
      const response = await apiCall('/privacy/export');
      const blob = new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `phishnet-data-export-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export error:', error);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  // Handle WebSocket messages
  useEffect(() => {
    const latestMessage = messages[messages.length - 1];
    if (latestMessage) {
      switch (latestMessage.type) {
        case 'scan_completed':
        case 'threat_detected':
        case 'quarantine_action':
          loadDashboardData(); // Refresh data
          break;
      }
    }
  }, [messages]);

  if (!dashboardStats) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <RefreshCw className="w-8 h-8 animate-spin" />
        <span className="ml-2">Loading dashboard...</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-2">
                <Shield className="w-8 h-8 text-blue-600" />
                PhishNet Dashboard
              </h1>
              <p className="text-gray-600 mt-1">Real-time email threat monitoring and analysis</p>
            </div>
            <div className="flex items-center space-x-4">
              <ConnectionStatus status={connectionStatus} />
              {!gmailConnected && (
                <Button onClick={initializeGmailAuth} className="flex items-center gap-2">
                  <Mail className="w-4 h-4" />
                  Connect Gmail
                </Button>
              )}
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatsCard
            title="Total Scans"
            value={dashboardStats.scan_stats.total_scans}
            icon={<Database className="w-6 h-6 text-blue-600" />}
          />
          <StatsCard
            title="This Month"
            value={dashboardStats.scan_stats.recent_scans}
            icon={<TrendingUp className="w-6 h-6 text-green-600" />}
          />
          <StatsCard
            title="Quarantined"
            value={dashboardStats.quarantine_stats.total_quarantined}
            icon={<Shield className="w-6 h-6 text-orange-600" />}
          />
          <StatsCard
            title="Auto Actions"
            value={dashboardStats.quarantine_stats.auto_quarantined}
            icon={<Settings className="w-6 h-6 text-purple-600" />}
          />
        </div>

        {/* Main Content */}
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="scans">Scan History</TabsTrigger>
            <TabsTrigger value="threats">Threats</TabsTrigger>
            <TabsTrigger value="privacy">Privacy</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Threat Distribution</CardTitle>
                </CardHeader>
                <CardContent>
                  <ThreatDistributionChart distribution={dashboardStats.scan_stats.threat_distribution} />
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Recent High-Risk Threats</CardTitle>
                </CardHeader>
                <CardContent>
                  <RecentThreatsTable threats={dashboardStats.recent_threats} />
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="scans" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Scan History</CardTitle>
              </CardHeader>
              <CardContent>
                <ScanHistoryTable 
                  scans={scanHistory} 
                  onViewDetails={viewScanDetails}
                />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="threats" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Threat Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    Advanced threat analysis with multi-component scoring including 
                    link analysis, content analysis, sender reputation, and LLM analysis.
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="privacy" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Data Export</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground mb-4">
                    Export all your data in compliance with GDPR data portability rights.
                  </p>
                  <Button onClick={exportUserData} className="flex items-center gap-2">
                    <Download className="w-4 h-4" />
                    Export My Data
                  </Button>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Data Deletion</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground mb-4">
                    Request deletion of your data in compliance with GDPR right to erasure.
                  </p>
                  <Button variant="destructive" className="flex items-center gap-2">
                    <Trash2 className="w-4 h-4" />
                    Request Deletion
                  </Button>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default PhishNetDashboard;
