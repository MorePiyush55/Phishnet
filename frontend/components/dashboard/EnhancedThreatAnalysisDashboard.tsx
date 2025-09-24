/**
 * Enhanced Threat Analysis Dashboard
 * 
 * Integrates all enhanced UX components for comprehensive threat analysis:
 * - Enhanced redirect chain visualization
 * - Screenshot evidence viewer
 * - Threat action panel
 * - Enhanced audit history
 * - Real-time updates and notifications
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  RefreshCw,
  Eye,
  History,
  Settings,
  Bell,
  Download,
  Share2,
  BarChart3,
  Activity,
  Globe,
  Lock,
  Zap
} from 'lucide-react';

// Import our enhanced components
import EnhancedRedirectChainVisualization, { RedirectChain, RedirectHop } from '../threat/EnhancedRedirectChainVisualization';
import ScreenshotEvidenceViewer, { ScreenshotEvidence } from '../threat/ScreenshotEvidenceViewer';
import ThreatActionPanel, { ThreatAnalysisResult } from '../threat/ThreatActionPanel';
import EnhancedAuditHistory, { AuditEntry } from '../audit/EnhancedAuditHistory';

interface EnhancedThreatAnalysisResult {
  // Basic analysis data
  url: string;
  domain: string;
  final_url: string;
  threat_score: number;
  threat_level: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  analysis_id: string;
  timestamp: string;
  
  // Enhanced analysis data
  redirect_chain: RedirectChain;
  screenshots: ScreenshotEvidence[];
  
  // Explanation and insights
  explanation: {
    reasoning: string;
    confidence_band: {
      lower_bound: number;
      upper_bound: number;
      confidence_level: number;
    };
    top_signals: Array<{
      name: string;
      description: string;
      component: string;
      contribution: number;
      evidence: string[];
    }>;
    component_breakdown: Record<string, number>;
    risk_factors: string[];
  };
  
  // Real-time status
  status: 'analyzing' | 'completed' | 'error';
  progress: number;
  
  // Privacy and compliance
  privacy_assessment: {
    pii_detected: boolean;
    consent_required: boolean;
    retention_period: string;
    data_categories: string[];
  };
  
  // Metadata
  metadata: {
    processing_time_ms: number;
    version: string;
    user_id?: string;
    organization_id?: string;
  };
}

interface EnhancedThreatAnalysisDashboardProps {
  analysisResult?: EnhancedThreatAnalysisResult;
  onAnalyze?: (url: string, options?: any) => Promise<EnhancedThreatAnalysisResult>;
  onAction?: (action: string, params?: any) => Promise<void>;
  userRole?: 'user' | 'admin' | 'analyst' | 'compliance';
  organizationId?: string;
  showPrivacyCompliance?: boolean;
}

const RealTimeStatusBar: React.FC<{
  status: string;
  progress: number;
  lastUpdate: string;
  onRefresh?: () => void;
}> = ({ status, progress, lastUpdate, onRefresh }) => {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'analyzing': return 'text-blue-600 bg-blue-100';
      case 'completed': return 'text-green-600 bg-green-100';
      case 'error': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };
  
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'analyzing': return <RefreshCw className="w-4 h-4 animate-spin" />;
      case 'completed': return <CheckCircle className="w-4 h-4" />;
      case 'error': return <AlertTriangle className="w-4 h-4" />;
      default: return <Activity className="w-4 h-4" />;
    }
  };
  
  return (
    <Card className="border-l-4 border-l-blue-500">
      <CardContent className="p-4">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <div className={`p-1 rounded ${getStatusColor(status)}`}>
              {getStatusIcon(status)}
            </div>
            <span className="font-semibold capitalize">{status.replace('_', ' ')}</span>
            {status === 'analyzing' && (
              <Badge variant="outline" className="animate-pulse">
                Processing...
              </Badge>
            )}
          </div>
          
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <span>Last update: {new Date(lastUpdate).toLocaleTimeString()}</span>
            {onRefresh && (
              <Button variant="ghost" size="sm" onClick={onRefresh}>
                <RefreshCw className="w-3 h-3" />
              </Button>
            )}
          </div>
        </div>
        
        {status === 'analyzing' && (
          <div className="space-y-2">
            <Progress value={progress} className="h-2" />
            <div className="text-xs text-gray-600 text-center">
              {progress.toFixed(1)}% complete
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

const ThreatOverviewCard: React.FC<{
  result: EnhancedThreatAnalysisResult;
}> = ({ result }) => {
  const getThreatColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'border-red-500 bg-red-50';
      case 'HIGH': return 'border-orange-500 bg-orange-50';
      case 'MEDIUM': return 'border-yellow-500 bg-yellow-50';
      case 'LOW': return 'border-blue-500 bg-blue-50';
      case 'SAFE': return 'border-green-500 bg-green-50';
      default: return 'border-gray-500 bg-gray-50';
    }
  };
  
  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH':
        return <AlertTriangle className="w-6 h-6 text-red-600" />;
      case 'MEDIUM':
        return <Shield className="w-6 h-6 text-yellow-600" />;
      case 'LOW':
        return <Eye className="w-6 h-6 text-blue-600" />;
      case 'SAFE':
        return <CheckCircle className="w-6 h-6 text-green-600" />;
      default:
        return <Shield className="w-6 h-6 text-gray-600" />;
    }
  };
  
  return (
    <Card className={`border-2 ${getThreatColor(result.threat_level)}`}>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            {getThreatIcon(result.threat_level)}
            <div>
              <CardTitle className="text-lg">Threat Assessment</CardTitle>
              <div className="text-sm text-gray-600 mt-1">
                Analysis ID: {result.analysis_id}
              </div>
            </div>
          </div>
          
          <Badge 
            variant={
              result.threat_level === 'CRITICAL' || result.threat_level === 'HIGH' 
                ? 'destructive' 
                : result.threat_level === 'MEDIUM' 
                ? 'warning' 
                : 'secondary'
            }
            className="text-sm"
          >
            {result.threat_level} ({(result.threat_score * 100).toFixed(1)}%)
          </Badge>
        </div>
      </CardHeader>
      
      <CardContent>
        <div className="space-y-4">
          {/* URL Info */}
          <div>
            <h4 className="text-sm font-semibold mb-2">Target URL</h4>
            <div className="space-y-1">
              <div className="text-sm">
                <span className="text-gray-500">Original:</span>
                <div className="font-mono text-xs bg-gray-100 p-2 rounded mt-1 break-all">
                  {result.url}
                </div>
              </div>
              {result.final_url !== result.url && (
                <div className="text-sm">
                  <span className="text-gray-500">Final:</span>
                  <div className="font-mono text-xs bg-gray-100 p-2 rounded mt-1 break-all">
                    {result.final_url}
                  </div>
                </div>
              )}
            </div>
          </div>
          
          {/* Key Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-xl font-bold text-blue-600">
                {result.redirect_chain.total_redirects}
              </div>
              <div className="text-xs text-gray-600">Redirects</div>
            </div>
            
            <div className="text-center">
              <div className="text-xl font-bold text-purple-600">
                {result.screenshots.length}
              </div>
              <div className="text-xs text-gray-600">Screenshots</div>
            </div>
            
            <div className="text-center">
              <div className="text-xl font-bold text-green-600">
                {(result.explanation.confidence_band.confidence_level * 100).toFixed(0)}%
              </div>
              <div className="text-xs text-gray-600">Confidence</div>
            </div>
            
            <div className="text-center">
              <div className="text-xl font-bold text-orange-600">
                {result.redirect_chain.chain_analysis.geographic_hops}
              </div>
              <div className="text-xs text-gray-600">Countries</div>
            </div>
          </div>
          
          {/* Risk Factors */}
          <div>
            <h4 className="text-sm font-semibold mb-2">Risk Factors</h4>
            <div className="flex flex-wrap gap-1">
              {result.explanation.risk_factors.slice(0, 5).map((factor, index) => (
                <Badge key={index} variant="outline" className="text-xs">
                  {factor}
                </Badge>
              ))}
              {result.explanation.risk_factors.length > 5 && (
                <Badge variant="outline" className="text-xs">
                  +{result.explanation.risk_factors.length - 5} more
                </Badge>
              )}
            </div>
          </div>
          
          {/* Privacy Assessment */}
          {result.privacy_assessment.pii_detected && (
            <Alert>
              <Lock className="h-4 w-4" />
              <AlertDescription>
                <strong>Privacy Notice:</strong> Personal information detected. 
                {result.privacy_assessment.consent_required && ' User consent required for processing.'}
              </AlertDescription>
            </Alert>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

const NotificationCenter: React.FC<{
  notifications: Array<{
    id: string;
    type: 'info' | 'warning' | 'error' | 'success';
    title: string;
    message: string;
    timestamp: string;
  }>;
  onDismiss: (id: string) => void;
}> = ({ notifications, onDismiss }) => {
  if (notifications.length === 0) return null;
  
  return (
    <div className="space-y-2">
      {notifications.map(notification => {
        const getNotificationVariant = (type: string) => {
          switch (type) {
            case 'error': return 'destructive';
            case 'warning': return 'warning';
            case 'success': return 'success';
            default: return 'default';
          }
        };
        
        return (
          <Alert key={notification.id} variant={getNotificationVariant(notification.type)}>
            <Bell className="h-4 w-4" />
            <div className="flex-1">
              <div className="flex justify-between items-start">
                <div>
                  <div className="font-semibold">{notification.title}</div>
                  <AlertDescription>{notification.message}</AlertDescription>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onDismiss(notification.id)}
                  className="text-xs"
                >
                  ×
                </Button>
              </div>
              <div className="text-xs text-gray-500 mt-1">
                {new Date(notification.timestamp).toLocaleTimeString()}
              </div>
            </div>
          </Alert>
        );
      })}
    </div>
  );
};

const EnhancedThreatAnalysisDashboard: React.FC<EnhancedThreatAnalysisDashboardProps> = ({ 
  analysisResult,
  onAnalyze,
  onAction,
  userRole = 'user',
  organizationId,
  showPrivacyCompliance = false
}) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedScreenshot, setSelectedScreenshot] = useState(0);
  const [notifications, setNotifications] = useState<Array<{
    id: string;
    type: 'info' | 'warning' | 'error' | 'success';
    title: string;
    message: string;
    timestamp: string;
  }>>([]);
  
  // Mock audit entries - in real app, these would come from API
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  
  useEffect(() => {
    // Set up real-time updates if analysis is in progress
    if (analysisResult?.status === 'analyzing') {
      const interval = setInterval(() => {
        // In real app, this would fetch status updates
        console.log('Checking analysis status...');
      }, 5000);
      
      return () => clearInterval(interval);
    }
  }, [analysisResult?.status]);
  
  const handleAction = useCallback(async (action: string, params: any = {}) => {
    try {
      if (onAction) {
        await onAction(action, params);
        
        // Add success notification
        setNotifications(prev => [...prev, {
          id: Date.now().toString(),
          type: 'success',
          title: 'Action Completed',
          message: `Successfully ${action.replace('_', ' ')} for ${analysisResult?.domain}`,
          timestamp: new Date().toISOString()
        }]);
      }
    } catch (error) {
      // Add error notification
      setNotifications(prev => [...prev, {
        id: Date.now().toString(),
        type: 'error',
        title: 'Action Failed',
        message: error.message,
        timestamp: new Date().toISOString()
      }]);
    }
  }, [onAction, analysisResult]);
  
  const dismissNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };
  
  const handleScreenshotSelect = (screenshot: ScreenshotEvidence, index: number) => {
    setSelectedScreenshot(index);
  };
  
  const handleHopSelect = (hop: RedirectHop, index: number) => {
    // Auto-switch to screenshots tab if hop has screenshot
    if (hop.screenshot && analysisResult?.screenshots) {
      const screenshotIndex = analysisResult.screenshots.findIndex(s => s.hop_index === index);
      if (screenshotIndex !== -1) {
        setSelectedScreenshot(screenshotIndex);
        setActiveTab('screenshots');
      }
    }
  };
  
  const handleScreenshotView = (screenshot: { url: string; timestamp: string }) => {
    // Open full-screen screenshot viewer
    console.log('Opening screenshot:', screenshot);
  };
  
  if (!analysisResult) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <Shield className="w-12 h-12 mx-auto text-gray-400 mb-4" />
          <p className="text-gray-600">No analysis results to display</p>
          <p className="text-sm text-gray-500 mt-2">
            Run a threat analysis to see detailed results here
          </p>
        </CardContent>
      </Card>
    );
  }
  
  const tabs = [
    { key: 'overview', label: 'Overview', icon: BarChart3 },
    { key: 'redirects', label: 'Redirect Chain', icon: Globe },
    { key: 'screenshots', label: 'Evidence', icon: Eye },
    { key: 'actions', label: 'Actions', icon: Zap },
    { key: 'history', label: 'Audit Log', icon: History }
  ].filter(tab => {
    // Filter tabs based on user role and data availability
    if (tab.key === 'history' && userRole === 'user') {
      return false; // Regular users might not see audit logs
    }
    if (tab.key === 'screenshots' && analysisResult.screenshots.length === 0) {
      return false; // Hide screenshots tab if no screenshots
    }
    return true;
  });
  
  return (
    <div className="space-y-6">
      {/* Notifications */}
      <NotificationCenter 
        notifications={notifications}
        onDismiss={dismissNotification}
      />
      
      {/* Status Bar */}
      <RealTimeStatusBar
        status={analysisResult.status}
        progress={analysisResult.progress}
        lastUpdate={analysisResult.timestamp}
        onRefresh={() => {
          // Trigger status refresh
          console.log('Refreshing analysis status...');
        }}
      />
      
      {/* Main Dashboard */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Overview Sidebar */}
        <div className="lg:col-span-1">
          <ThreatOverviewCard result={analysisResult} />
        </div>
        
        {/* Main Content */}
        <div className="lg:col-span-2">
          <Card>
            <CardContent className="p-0">
              <Tabs value={activeTab} onValueChange={setActiveTab}>
                <div className="border-b p-4">
                  <TabsList className="grid w-full" style={{ gridTemplateColumns: `repeat(${tabs.length}, minmax(0, 1fr))` }}>
                    {tabs.map(tab => {
                      const Icon = tab.icon;
                      return (
                        <TabsTrigger key={tab.key} value={tab.key} className="flex items-center gap-1">
                          <Icon className="w-3 h-3" />
                          <span className="hidden sm:inline">{tab.label}</span>
                        </TabsTrigger>
                      );
                    })}
                  </TabsList>
                </div>
                
                <div className="p-4">
                  <TabsContent value="overview">
                    <div className="space-y-6">
                      {/* Analysis Reasoning */}
                      <div>
                        <h3 className="text-lg font-semibold mb-3">Analysis Reasoning</h3>
                        <Alert>
                          <Shield className="h-4 w-4" />
                          <AlertDescription>
                            {analysisResult.explanation.reasoning}
                          </AlertDescription>
                        </Alert>
                      </div>
                      
                      {/* Top Signals */}
                      <div>
                        <h3 className="text-lg font-semibold mb-3">Top Risk Signals</h3>
                        <div className="space-y-3">
                          {analysisResult.explanation.top_signals.slice(0, 3).map((signal, index) => (
                            <Card key={index} className="border-l-4 border-l-red-400">
                              <CardContent className="p-3">
                                <div className="flex justify-between items-start">
                                  <div>
                                    <div className="font-semibold text-sm">{signal.description}</div>
                                    <div className="text-xs text-gray-600 mt-1">
                                      Component: {signal.component}
                                    </div>
                                  </div>
                                  <Badge variant="destructive" className="text-xs">
                                    {(signal.contribution * 100).toFixed(1)}%
                                  </Badge>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </div>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="redirects">
                    <EnhancedRedirectChainVisualization
                      redirectChain={analysisResult.redirect_chain}
                      onHopSelect={handleHopSelect}
                      onScreenshotView={handleScreenshotView}
                    />
                  </TabsContent>
                  
                  <TabsContent value="screenshots">
                    <ScreenshotEvidenceViewer
                      screenshots={analysisResult.screenshots}
                      selectedIndex={selectedScreenshot}
                      onScreenshotSelect={handleScreenshotSelect}
                      showTimeline={true}
                      allowExport={true}
                    />
                  </TabsContent>
                  
                  <TabsContent value="actions">
                    <ThreatActionPanel
                      analysisResult={{
                        url: analysisResult.url,
                        threat_score: analysisResult.threat_score,
                        threat_level: analysisResult.threat_level,
                        domain: analysisResult.domain,
                        final_url: analysisResult.final_url,
                        analysis_id: analysisResult.analysis_id,
                        timestamp: analysisResult.timestamp
                      }}
                      onAction={handleAction}
                      userRole={userRole}
                      organizationId={organizationId}
                    />
                  </TabsContent>
                  
                  <TabsContent value="history">
                    <EnhancedAuditHistory
                      entries={auditEntries}
                      userRole={userRole}
                      showPrivacyCompliance={showPrivacyCompliance}
                      organizationId={organizationId}
                      onLoadMore={async (filters) => {
                        // Load more audit entries based on filters
                        console.log('Loading more audit entries with filters:', filters);
                        return [];
                      }}
                      onExport={async (filters) => {
                        // Export audit entries
                        console.log('Exporting audit entries with filters:', filters);
                      }}
                    />
                  </TabsContent>
                </div>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default EnhancedThreatAnalysisDashboard;
export type { EnhancedThreatAnalysisResult, EnhancedThreatAnalysisDashboardProps };