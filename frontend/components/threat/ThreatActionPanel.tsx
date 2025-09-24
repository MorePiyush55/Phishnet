/**
 * Threat Action Panel Component
 * 
 * Provides actionable security options for threat analysis results:
 * - Block/Allow domain controls
 * - Report to security services
 * - Share threat intelligence
 * - Export analysis reports
 * - Create custom rules
 * - Schedule re-analysis
 */

import React, { useState, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Shield, 
  AlertTriangle, 
  Ban, 
  CheckCircle, 
  Share2, 
  Download,
  Flag,
  Clock,
  Settings,
  FileText,
  Mail,
  Globe,
  Lock,
  Unlock,
  RefreshCw,
  Eye,
  BarChart3,
  Users,
  Bell,
  Archive
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface ThreatAnalysisResult {
  url: string;
  threat_score: number;
  threat_level: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  domain: string;
  final_url: string;
  analysis_id: string;
  timestamp: string;
}

interface ThreatActionPanelProps {
  analysisResult: ThreatAnalysisResult;
  onAction?: (action: string, params?: any) => Promise<void>;
  userRole?: 'user' | 'admin' | 'analyst';
  organizationId?: string;
}

interface ActionHistory {
  action: string;
  timestamp: string;
  user: string;
  status: 'success' | 'pending' | 'failed';
  details?: string;
}

const QuickActions: React.FC<{
  threat: ThreatAnalysisResult;
  onAction: (action: string, params?: any) => Promise<void>;
  disabled?: boolean;
}> = ({ threat, onAction, disabled = false }) => {
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState<string | null>(null);
  
  const handleQuickAction = async (actionType: string, params: any = {}) => {
    setIsLoading(actionType);
    try {
      await onAction(actionType, { url: threat.url, domain: threat.domain, ...params });
      toast({
        title: "Action completed",
        description: `Successfully ${actionType.replace('_', ' ')} ${threat.domain}`,
      });
    } catch (error) {
      toast({
        title: "Action failed",
        description: `Failed to ${actionType.replace('_', ' ')}: ${error.message}`,
        variant: "destructive",
      });
    } finally {
      setIsLoading(null);
    }
  };
  
  const getQuickActions = () => {
    const actions = [];
    
    // Block/Allow actions based on threat level
    if (threat.threat_score >= 0.7) {
      actions.push({
        key: 'block_domain',
        label: 'Block Domain',
        icon: Ban,
        variant: 'destructive' as const,
        description: 'Block access to this domain'
      });
    } else {
      actions.push({
        key: 'allow_domain',
        label: 'Mark Safe',
        icon: CheckCircle,
        variant: 'success' as const,
        description: 'Mark this domain as safe'
      });
    }
    
    // Report action for suspicious/malicious content
    if (threat.threat_score >= 0.5) {
      actions.push({
        key: 'report_threat',
        label: 'Report Threat',
        icon: Flag,
        variant: 'secondary' as const,
        description: 'Report to threat intelligence services'
      });
    }
    
    // Always available actions
    actions.push({
      key: 'share_analysis',
      label: 'Share Analysis',
      icon: Share2,
      variant: 'outline' as const,
      description: 'Share this analysis with your team'
    });
    
    actions.push({
      key: 'export_report',
      label: 'Export Report',
      icon: Download,
      variant: 'outline' as const,
      description: 'Export detailed analysis report'
    });
    
    return actions;
  };
  
  return (
    <div className="space-y-4">
      <h4 className="text-sm font-semibold">Quick Actions</h4>
      <div className="grid grid-cols-2 gap-2">
        {getQuickActions().map((action) => {
          const Icon = action.icon;
          const isActionLoading = isLoading === action.key;
          
          return (
            <Button
              key={action.key}
              variant={action.variant}
              size="sm"
              className="justify-start h-auto p-3"
              disabled={disabled || isActionLoading}
              onClick={() => handleQuickAction(action.key)}
            >
              <div className="flex items-center gap-2">
                {isActionLoading ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Icon className="w-4 h-4" />
                )}
                <div className="text-left">
                  <div className="font-medium">{action.label}</div>
                  <div className="text-xs opacity-70">{action.description}</div>
                </div>
              </div>
            </Button>
          );
        })}
      </div>
    </div>
  );
};

const DomainManagement: React.FC<{
  domain: string;
  onAction: (action: string, params?: any) => Promise<void>;
}> = ({ domain, onAction }) => {
  const [blocklistReason, setBlocklistReason] = useState('');
  const [allowlistReason, setAllowlistReason] = useState('');
  const [customRule, setCustomRule] = useState({
    type: 'domain',
    pattern: domain,
    action: 'block',
    description: ''
  });
  
  const handleBlocklist = async () => {
    await onAction('add_to_blocklist', {
      domain,
      reason: blocklistReason,
      type: 'domain'
    });
    setBlocklistReason('');
  };
  
  const handleAllowlist = async () => {
    await onAction('add_to_allowlist', {
      domain,
      reason: allowlistReason,
      type: 'domain'
    });
    setAllowlistReason('');
  };
  
  const handleCustomRule = async () => {
    await onAction('create_custom_rule', customRule);
    setCustomRule({
      type: 'domain',
      pattern: domain,
      action: 'block',
      description: ''
    });
  };
  
  return (
    <div className="space-y-6">
      <div>
        <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Ban className="w-4 h-4" />
          Block Domain
        </h4>
        <div className="space-y-3">
          <div>
            <Label htmlFor="blocklist-reason">Reason for blocking</Label>
            <Textarea
              id="blocklist-reason"
              placeholder="Enter reason for blocking this domain..."
              value={blocklistReason}
              onChange={(e) => setBlocklistReason(e.target.value)}
              rows={2}
            />
          </div>
          <Button 
            variant="destructive" 
            onClick={handleBlocklist}
            disabled={!blocklistReason.trim()}
            className="w-full"
          >
            Add to Blocklist
          </Button>
        </div>
      </div>
      
      <div>
        <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <CheckCircle className="w-4 h-4" />
          Allow Domain
        </h4>
        <div className="space-y-3">
          <div>
            <Label htmlFor="allowlist-reason">Reason for allowing</Label>
            <Textarea
              id="allowlist-reason"
              placeholder="Enter reason for allowing this domain..."
              value={allowlistReason}
              onChange={(e) => setAllowlistReason(e.target.value)}
              rows={2}
            />
          </div>
          <Button 
            variant="success" 
            onClick={handleAllowlist}
            disabled={!allowlistReason.trim()}
            className="w-full"
          >
            Add to Allowlist
          </Button>
        </div>
      </div>
      
      <div>
        <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Settings className="w-4 h-4" />
          Custom Rule
        </h4>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Rule Type</Label>
              <Select value={customRule.type} onValueChange={(value) => setCustomRule({...customRule, type: value})}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="domain">Domain</SelectItem>
                  <SelectItem value="url_pattern">URL Pattern</SelectItem>
                  <SelectItem value="content_type">Content Type</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Action</Label>
              <Select value={customRule.action} onValueChange={(value) => setCustomRule({...customRule, action: value})}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="block">Block</SelectItem>
                  <SelectItem value="allow">Allow</SelectItem>
                  <SelectItem value="warn">Warn Only</SelectItem>
                  <SelectItem value="monitor">Monitor</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <div>
            <Label>Pattern</Label>
            <Input
              value={customRule.pattern}
              onChange={(e) => setCustomRule({...customRule, pattern: e.target.value})}
              placeholder="Enter pattern to match..."
            />
          </div>
          
          <div>
            <Label>Description</Label>
            <Textarea
              value={customRule.description}
              onChange={(e) => setCustomRule({...customRule, description: e.target.value})}
              placeholder="Describe this rule..."
              rows={2}
            />
          </div>
          
          <Button 
            onClick={handleCustomRule}
            disabled={!customRule.pattern.trim() || !customRule.description.trim()}
            className="w-full"
          >
            Create Rule
          </Button>
        </div>
      </div>
    </div>
  );
};

const ReportingPanel: React.FC<{
  threat: ThreatAnalysisResult;
  onAction: (action: string, params?: any) => Promise<void>;
}> = ({ threat, onAction }) => {
  const [reportData, setReportData] = useState({
    service: 'phishtank',
    category: 'phishing',
    confidence: threat.threat_score,
    description: '',
    evidence: '',
    contact_info: ''
  });
  
  const [shareData, setShareData] = useState({
    recipients: '',
    message: '',
    include_screenshots: true,
    include_full_analysis: true,
    urgency: 'normal'
  });
  
  const handleReport = async () => {
    await onAction('submit_threat_report', {
      ...reportData,
      url: threat.url,
      analysis_id: threat.analysis_id
    });
    setReportData({
      ...reportData,
      description: '',
      evidence: ''
    });
  };
  
  const handleShare = async () => {
    await onAction('share_analysis', {
      ...shareData,
      analysis_id: threat.analysis_id,
      recipients: shareData.recipients.split(',').map(r => r.trim())
    });
    setShareData({
      ...shareData,
      recipients: '',
      message: ''
    });
  };
  
  return (
    <div className="space-y-6">
      <div>
        <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Flag className="w-4 h-4" />
          Report to Security Services
        </h4>
        
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Service</Label>
              <Select value={reportData.service} onValueChange={(value) => setReportData({...reportData, service: value})}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="phishtank">PhishTank</SelectItem>
                  <SelectItem value="urlvoid">URLVoid</SelectItem>
                  <SelectItem value="virustotal">VirusTotal</SelectItem>
                  <SelectItem value="safebrowsing">Google Safe Browsing</SelectItem>
                  <SelectItem value="internal">Internal Security Team</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Category</Label>
              <Select value={reportData.category} onValueChange={(value) => setReportData({...reportData, category: value})}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="phishing">Phishing</SelectItem>
                  <SelectItem value="malware">Malware</SelectItem>
                  <SelectItem value="spam">Spam</SelectItem>
                  <SelectItem value="fraud">Fraud</SelectItem>
                  <SelectItem value="suspicious">Suspicious Activity</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <div>
            <Label>Description</Label>
            <Textarea
              value={reportData.description}
              onChange={(e) => setReportData({...reportData, description: e.target.value})}
              placeholder="Describe the threat and why you're reporting it..."
              rows={3}
            />
          </div>
          
          <div>
            <Label>Supporting Evidence</Label>
            <Textarea
              value={reportData.evidence}
              onChange={(e) => setReportData({...reportData, evidence: e.target.value})}
              placeholder="Include any additional evidence or context..."
              rows={2}
            />
          </div>
          
          <Button 
            onClick={handleReport}
            disabled={!reportData.description.trim()}
            className="w-full"
          >
            Submit Report
          </Button>
        </div>
      </div>
      
      <div>
        <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Share2 className="w-4 h-4" />
          Share with Team
        </h4>
        
        <div className="space-y-3">
          <div>
            <Label>Recipients (email addresses)</Label>
            <Input
              value={shareData.recipients}
              onChange={(e) => setShareData({...shareData, recipients: e.target.value})}
              placeholder="user1@example.com, user2@example.com"
            />
          </div>
          
          <div className="grid grid-cols-2 gap-3">
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="include-screenshots"
                checked={shareData.include_screenshots}
                onChange={(e) => setShareData({...shareData, include_screenshots: e.target.checked})}
              />
              <Label htmlFor="include-screenshots">Include Screenshots</Label>
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="include-full-analysis"
                checked={shareData.include_full_analysis}
                onChange={(e) => setShareData({...shareData, include_full_analysis: e.target.checked})}
              />
              <Label htmlFor="include-full-analysis">Full Analysis</Label>
            </div>
          </div>
          
          <div>
            <Label>Urgency Level</Label>
            <Select value={shareData.urgency} onValueChange={(value) => setShareData({...shareData, urgency: value})}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="low">Low - For Review</SelectItem>
                <SelectItem value="normal">Normal - Informational</SelectItem>
                <SelectItem value="high">High - Requires Attention</SelectItem>
                <SelectItem value="critical">Critical - Immediate Action</SelectItem>
              </SelectContent>
            </Select>
          </div>
          
          <div>
            <Label>Message</Label>
            <Textarea
              value={shareData.message}
              onChange={(e) => setShareData({...shareData, message: e.target.value})}
              placeholder="Add a message for recipients..."
              rows={2}
            />
          </div>
          
          <Button 
            onClick={handleShare}
            disabled={!shareData.recipients.trim()}
            className="w-full"
          >
            Share Analysis
          </Button>
        </div>
      </div>
    </div>
  );
};

const MonitoringPanel: React.FC<{
  threat: ThreatAnalysisResult;
  onAction: (action: string, params?: any) => Promise<void>;
}> = ({ threat, onAction }) => {
  const [monitorConfig, setMonitorConfig] = useState({
    frequency: 'daily',
    notifications: true,
    threshold_change: 0.1,
    monitor_redirects: true,
    monitor_content: true,
    alert_contacts: ''
  });
  
  const handleSetupMonitoring = async () => {
    await onAction('setup_monitoring', {
      url: threat.url,
      domain: threat.domain,
      ...monitorConfig,
      alert_contacts: monitorConfig.alert_contacts.split(',').map(c => c.trim())
    });
  };
  
  const handleScheduleRescan = async (when: string) => {
    await onAction('schedule_rescan', {
      analysis_id: threat.analysis_id,
      url: threat.url,
      schedule: when
    });
  };
  
  return (
    <div className="space-y-6">
      <div>
        <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Eye className="w-4 h-4" />
          Continuous Monitoring
        </h4>
        
        <div className="space-y-3">
          <div>
            <Label>Monitor Frequency</Label>
            <Select value={monitorConfig.frequency} onValueChange={(value) => setMonitorConfig({...monitorConfig, frequency: value})}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="hourly">Hourly</SelectItem>
                <SelectItem value="daily">Daily</SelectItem>
                <SelectItem value="weekly">Weekly</SelectItem>
                <SelectItem value="monthly">Monthly</SelectItem>
              </SelectContent>
            </Select>
          </div>
          
          <div className="grid grid-cols-2 gap-3">
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="monitor-redirects"
                checked={monitorConfig.monitor_redirects}
                onChange={(e) => setMonitorConfig({...monitorConfig, monitor_redirects: e.target.checked})}
              />
              <Label htmlFor="monitor-redirects">Monitor Redirects</Label>
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="monitor-content"
                checked={monitorConfig.monitor_content}
                onChange={(e) => setMonitorConfig({...monitorConfig, monitor_content: e.target.checked})}
              />
              <Label htmlFor="monitor-content">Monitor Content</Label>
            </div>
          </div>
          
          <div>
            <Label>Alert Contacts</Label>
            <Input
              value={monitorConfig.alert_contacts}
              onChange={(e) => setMonitorConfig({...monitorConfig, alert_contacts: e.target.value})}
              placeholder="security@example.com, admin@example.com"
            />
          </div>
          
          <Button onClick={handleSetupMonitoring} className="w-full">
            <Bell className="w-4 h-4 mr-2" />
            Setup Monitoring
          </Button>
        </div>
      </div>
      
      <div>
        <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Clock className="w-4 h-4" />
          Schedule Re-analysis
        </h4>
        
        <div className="grid grid-cols-2 gap-2">
          <Button variant="outline" onClick={() => handleScheduleRescan('1_hour')}>
            In 1 Hour
          </Button>
          <Button variant="outline" onClick={() => handleScheduleRescan('1_day')}>
            In 1 Day
          </Button>
          <Button variant="outline" onClick={() => handleScheduleRescan('1_week')}>
            In 1 Week
          </Button>
          <Button variant="outline" onClick={() => handleScheduleRescan('1_month')}>
            In 1 Month
          </Button>
        </div>
      </div>
    </div>
  );
};

const ActionHistoryPanel: React.FC<{
  history: ActionHistory[];
  onRefresh?: () => void;
}> = ({ history, onRefresh }) => {
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'pending': return <Clock className="w-4 h-4 text-yellow-500" />;
      case 'failed': return <AlertTriangle className="w-4 h-4 text-red-500" />;
      default: return <Clock className="w-4 h-4 text-gray-500" />;
    }
  };
  
  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h4 className="text-sm font-semibold flex items-center gap-2">
          <Archive className="w-4 h-4" />
          Action History
        </h4>
        <Button variant="ghost" size="sm" onClick={onRefresh}>
          <RefreshCw className="w-4 h-4" />
        </Button>
      </div>
      
      <div className="space-y-2 max-h-64 overflow-y-auto">
        {history.length === 0 ? (
          <div className="text-center text-gray-500 py-4">
            No actions taken yet
          </div>
        ) : (
          history.map((entry, index) => (
            <div key={index} className="flex items-start gap-3 p-2 bg-gray-50 rounded">
              {getStatusIcon(entry.status)}
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium">
                  {entry.action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </div>
                <div className="text-xs text-gray-500">
                  {entry.user} • {new Date(entry.timestamp).toLocaleString()}
                </div>
                {entry.details && (
                  <div className="text-xs text-gray-600 mt-1">{entry.details}</div>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

const ThreatActionPanel: React.FC<ThreatActionPanelProps> = ({ 
  analysisResult, 
  onAction,
  userRole = 'user',
  organizationId
}) => {
  const [actionHistory, setActionHistory] = useState<ActionHistory[]>([]);
  const [activeTab, setActiveTab] = useState('quick');
  
  const handleAction = useCallback(async (action: string, params: any = {}) => {
    // Add to history immediately
    const historyEntry: ActionHistory = {
      action,
      timestamp: new Date().toISOString(),
      user: 'current_user', // This would come from auth context
      status: 'pending',
      details: `Action: ${action} on ${analysisResult.domain}`
    };
    
    setActionHistory(prev => [historyEntry, ...prev]);
    
    try {
      if (onAction) {
        await onAction(action, params);
      }
      
      // Update status to success
      setActionHistory(prev => 
        prev.map(entry => 
          entry.timestamp === historyEntry.timestamp 
            ? { ...entry, status: 'success' } 
            : entry
        )
      );
    } catch (error) {
      // Update status to failed
      setActionHistory(prev => 
        prev.map(entry => 
          entry.timestamp === historyEntry.timestamp 
            ? { ...entry, status: 'failed', details: error.message } 
            : entry
        )
      );
      throw error;
    }
  }, [analysisResult, onAction]);
  
  const tabs = [
    { key: 'quick', label: 'Quick Actions', icon: Zap },
    { key: 'domain', label: 'Domain Control', icon: Globe },
    { key: 'report', label: 'Report & Share', icon: Share2 },
    { key: 'monitor', label: 'Monitoring', icon: Eye },
    { key: 'history', label: 'History', icon: Archive }
  ].filter(tab => {
    // Filter tabs based on user role
    if (userRole === 'user') {
      return ['quick', 'report', 'history'].includes(tab.key);
    }
    return true; // Admin and analyst see all tabs
  });
  
  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="w-5 h-5" />
          Security Actions
        </CardTitle>
        <div className="flex items-center gap-2 text-sm text-gray-600">
          <Badge variant={analysisResult.threat_score >= 0.7 ? 'destructive' : 'secondary'}>
            {analysisResult.threat_level}
          </Badge>
          <span>{analysisResult.domain}</span>
        </div>
      </CardHeader>
      
      <CardContent>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
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
          
          <TabsContent value="quick" className="mt-4">
            <QuickActions 
              threat={analysisResult} 
              onAction={handleAction}
            />
          </TabsContent>
          
          {(userRole === 'admin' || userRole === 'analyst') && (
            <>
              <TabsContent value="domain" className="mt-4">
                <DomainManagement 
                  domain={analysisResult.domain}
                  onAction={handleAction}
                />
              </TabsContent>
              
              <TabsContent value="monitor" className="mt-4">
                <MonitoringPanel 
                  threat={analysisResult}
                  onAction={handleAction}
                />
              </TabsContent>
            </>
          )}
          
          <TabsContent value="report" className="mt-4">
            <ReportingPanel 
              threat={analysisResult}
              onAction={handleAction}
            />
          </TabsContent>
          
          <TabsContent value="history" className="mt-4">
            <ActionHistoryPanel 
              history={actionHistory}
              onRefresh={() => {
                // This would typically fetch from an API
                console.log('Refreshing action history...');
              }}
            />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default ThreatActionPanel;
export type { ThreatAnalysisResult, ThreatActionPanelProps, ActionHistory };