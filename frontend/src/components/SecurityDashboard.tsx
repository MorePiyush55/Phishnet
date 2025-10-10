import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  CircularProgress,
  Alert,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  Chip,
  List,
  ListItem,
  ListItemText,
  Divider,
  LinearProgress
} from '@mui/material';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';
import {
  Security,
  Email,
  Report,
  TrendingUp,
  TrendingDown,
  Warning,
  CheckCircle,
  Error,
  Speed,
  Analytics,
  Shield
} from '@mui/icons-material';

interface DashboardMetrics {
  threat_overview: ThreatOverview;
  email_analysis: EmailAnalysis;
  incident_summary: IncidentSummary;
  threat_intelligence: ThreatIntelligence;
  real_time_alerts: RealTimeAlert[];
  performance_metrics: PerformanceMetrics;
  trend_analysis: TrendAnalysis;
  timestamp: string;
}

interface ThreatOverview {
  total_threats_detected: number;
  phishing_emails_blocked: number;
  malicious_urls_found: number;
  suspicious_attachments: number;
  threat_score_average: number;
  risk_distribution: Record<string, number>;
  top_threat_types: Array<{ indicator: string; count: number }>;
}

interface EmailAnalysis {
  total_emails_analyzed: number;
  phishing_detection_rate: number;
  false_positive_rate: number;
  processing_time_avg_ms: number;
  accuracy_score: number;
  volume_trends: Array<{ time: string; count: number }>;
}

interface IncidentSummary {
  active_incidents: number;
  resolved_incidents: number;
  average_resolution_time: number;
  escalated_incidents: number;
  incident_severity_breakdown: Record<string, number>;
  response_time_metrics: Record<string, number>;
}

interface ThreatIntelligence {
  ioc_count: number;
  feed_sources: string[];
  reputation_scores: Record<string, number>;
  new_threats_24h: number;
  threat_actor_tracking: Array<{ actor: string; activity: number }>;
}

interface RealTimeAlert {
  alert_id: string;
  severity: string;
  threat_type: string;
  description: string;
  source: string;
  timestamp: string;
  status: string;
}

interface PerformanceMetrics {
  api_response_time: number;
  analysis_throughput: number;
  system_availability: number;
  resource_utilization: Record<string, number>;
  error_rates: Record<string, number>;
}

interface TrendAnalysis {
  threat_trends: {
    data: Array<{ timestamp: string; value: number }>;
    direction: string;
    forecast: Array<{ timestamp: string; predicted_value: number; confidence: number }>;
  };
  email_trends: {
    data: Array<{ timestamp: string; value: number }>;
    direction: string;
  };
  incident_trends: {
    data: Array<{ timestamp: string; value: number }>;
    direction: string;
  };
  summary: {
    overall_trend: string;
    risk_level: string;
  };
}

const SecurityDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState('24h');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchDashboardMetrics = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/analytics/dashboard?time_range=${timeRange}&include_trends=true`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch dashboard metrics');
      }
      
      const data = await response.json();
      setMetrics(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardMetrics();
  }, [timeRange]);

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(fetchDashboardMetrics, 30000); // Refresh every 30 seconds
      return () => clearInterval(interval);
    }
  }, [autoRefresh, timeRange]);

  const getSeverityColor = (severity: string): string => {
    switch (severity.toLowerCase()) {
      case 'critical': return '#f44336';
      case 'high': return '#ff9800';
      case 'medium': return '#ffeb3b';
      case 'low': return '#4caf50';
      default: return '#9e9e9e';
    }
  };

  const getTrendIcon = (direction: string) => {
    switch (direction) {
      case 'increasing': return <TrendingUp color="error" />;
      case 'decreasing': return <TrendingDown color="success" />;
      default: return <TrendingUp color="action" />;
    }
  };

  const formatNumber = (num: number): string => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
  };

  if (loading && !metrics) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={60} />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ margin: 2 }}>
        Error loading dashboard: {error}
        <Button onClick={fetchDashboardMetrics} sx={{ ml: 2 }}>
          Retry
        </Button>
      </Alert>
    );
  }

  if (!metrics) {
    return <Alert severity="warning">No data available</Alert>;
  }

  const riskDistributionData = Object.entries(metrics.threat_overview.risk_distribution).map(
    ([risk, count]) => ({ name: risk, value: count, fill: getSeverityColor(risk) })
  );

  const severityDistributionData = Object.entries(metrics.incident_summary.incident_severity_breakdown).map(
    ([severity, count]) => ({ name: severity, value: count, fill: getSeverityColor(severity) })
  );

  return (
    <Box sx={{ p: 3 }}>
      {/* Header Controls */}
      <Box sx={{ display: 'flex', justifyContent: 'between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Security color="primary" />
          PhishNet Security Operations Dashboard
        </Typography>
        
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Time Range</InputLabel>
            <Select value={timeRange} onChange={(e) => setTimeRange(e.target.value)} label="Time Range">
              <MenuItem value="1h">1 Hour</MenuItem>
              <MenuItem value="24h">24 Hours</MenuItem>
              <MenuItem value="7d">7 Days</MenuItem>
              <MenuItem value="30d">30 Days</MenuItem>
            </Select>
          </FormControl>
          
          <Button
            variant={autoRefresh ? "contained" : "outlined"}
            onClick={() => setAutoRefresh(!autoRefresh)}
            size="small"
          >
            Auto Refresh: {autoRefresh ? 'ON' : 'OFF'}
          </Button>
          
          <Button variant="outlined" onClick={fetchDashboardMetrics} size="small">
            Refresh Now
          </Button>
        </Box>
      </Box>

      {/* Key Metrics Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="h6">
                    Threats Detected
                  </Typography>
                  <Typography variant="h4">
                    {formatNumber(metrics.threat_overview.total_threats_detected)}
                  </Typography>
                </Box>
                <Warning color="error" sx={{ fontSize: 40 }} />
              </Box>
              <Box sx={{ mt: 1 }}>
                {getTrendIcon(metrics.trend_analysis.threat_trends.direction)}
                <Typography variant="body2" color="textSecondary" component="span" sx={{ ml: 1 }}>
                  {metrics.trend_analysis.threat_trends.direction}
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="h6">
                    Emails Analyzed
                  </Typography>
                  <Typography variant="h4">
                    {formatNumber(metrics.email_analysis.total_emails_analyzed)}
                  </Typography>
                </Box>
                <Email color="primary" sx={{ fontSize: 40 }} />
              </Box>
              <Box sx={{ mt: 1 }}>
                <Typography variant="body2" color="textSecondary">
                  Accuracy: {(metrics.email_analysis.accuracy_score * 100).toFixed(1)}%
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="h6">
                    Active Incidents
                  </Typography>
                  <Typography variant="h4">
                    {metrics.incident_summary.active_incidents}
                  </Typography>
                </Box>
                <Report color="warning" sx={{ fontSize: 40 }} />
              </Box>
              <Box sx={{ mt: 1 }}>
                <Typography variant="body2" color="textSecondary">
                  Avg Resolution: {metrics.incident_summary.average_resolution_time.toFixed(1)}h
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="h6">
                    System Health
                  </Typography>
                  <Typography variant="h4">
                    {metrics.performance_metrics.system_availability.toFixed(1)}%
                  </Typography>
                </Box>
                <CheckCircle color="success" sx={{ fontSize: 40 }} />
              </Box>
              <Box sx={{ mt: 1 }}>
                <Typography variant="body2" color="textSecondary">
                  API Response: {metrics.performance_metrics.api_response_time.toFixed(0)}ms
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Threat Trends Chart */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Threat Detection Trends
              </Typography>
              <Box sx={{ height: 300 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={metrics.trend_analysis.threat_trends.data}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                    />
                    <YAxis />
                    <Tooltip 
                      labelFormatter={(value) => new Date(value).toLocaleString()}
                    />
                    <Legend />
                    <Line 
                      type="monotone" 
                      dataKey="value" 
                      stroke="#8884d8" 
                      strokeWidth={2}
                      name="Threats Detected"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} lg={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Risk Distribution
              </Typography>
              <Box sx={{ height: 300 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={riskDistributionData}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {riskDistributionData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Real-time Alerts and Performance */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Real-time Security Alerts
              </Typography>
              <List sx={{ maxHeight: 400, overflow: 'auto' }}>
                {metrics.real_time_alerts.slice(0, 10).map((alert, index) => (
                  <React.Fragment key={alert.alert_id}>
                    <ListItem>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Chip 
                              label={alert.severity} 
                              size="small" 
                              sx={{ bgcolor: getSeverityColor(alert.severity), color: 'white' }}
                            />
                            <Typography variant="body1">{alert.description}</Typography>
                          </Box>
                        }
                        secondary={
                          <Box>
                            <Typography variant="body2" color="textSecondary">
                              {alert.threat_type} • {new Date(alert.timestamp).toLocaleTimeString()}
                            </Typography>
                          </Box>
                        }
                      />
                    </ListItem>
                    {index < metrics.real_time_alerts.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Performance
              </Typography>
              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" gutterBottom>
                  CPU Usage: {metrics.performance_metrics.resource_utilization.cpu}%
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={metrics.performance_metrics.resource_utilization.cpu} 
                  sx={{ mb: 2 }}
                />
                
                <Typography variant="body2" gutterBottom>
                  Memory Usage: {metrics.performance_metrics.resource_utilization.memory}%
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={metrics.performance_metrics.resource_utilization.memory} 
                  sx={{ mb: 2 }}
                />
                
                <Typography variant="body2" gutterBottom>
                  Disk Usage: {metrics.performance_metrics.resource_utilization.disk}%
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={metrics.performance_metrics.resource_utilization.disk} 
                />
              </Box>
              
              <Box sx={{ mt: 3 }}>
                <Typography variant="body2" color="textSecondary">
                  Analysis Throughput: {metrics.performance_metrics.analysis_throughput} emails/hour
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Error Rate: {(metrics.performance_metrics.error_rates.api_errors * 100).toFixed(2)}%
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Incident Management and Threat Intelligence */}
      <Grid container spacing={3}>
        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Incident Severity Breakdown
              </Typography>
              <Box sx={{ height: 250 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityDistributionData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="value" fill="#8884d8" />
                  </BarChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Threat Intelligence Summary
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'between' }}>
                  <Typography variant="body1">Total IOCs:</Typography>
                  <Typography variant="body1" fontWeight="bold">
                    {formatNumber(metrics.threat_intelligence.ioc_count)}
                  </Typography>
                </Box>
                
                <Box sx={{ display: 'flex', justifyContent: 'between' }}>
                  <Typography variant="body1">Feed Sources:</Typography>
                  <Typography variant="body1" fontWeight="bold">
                    {metrics.threat_intelligence.feed_sources.length}
                  </Typography>
                </Box>
                
                <Box sx={{ display: 'flex', justifyContent: 'between' }}>
                  <Typography variant="body1">New Threats (24h):</Typography>
                  <Chip 
                    label={metrics.threat_intelligence.new_threats_24h} 
                    color={metrics.threat_intelligence.new_threats_24h > 50 ? "error" : "success"}
                    size="small"
                  />
                </Box>
                
                <Divider />
                
                <Typography variant="subtitle2" gutterBottom>
                  Active Feed Sources:
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {metrics.threat_intelligence.feed_sources.slice(0, 5).map((source, index) => (
                    <Chip key={index} label={source} size="small" variant="outlined" />
                  ))}
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Last Updated */}
      <Box sx={{ mt: 3, textAlign: 'center' }}>
        <Typography variant="caption" color="textSecondary">
          Last updated: {new Date(metrics.timestamp).toLocaleString()}
        </Typography>
      </Box>
    </Box>
  );
};

export default SecurityDashboard;