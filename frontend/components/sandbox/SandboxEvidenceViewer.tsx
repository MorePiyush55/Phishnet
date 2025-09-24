/**
 * Sandbox Evidence Display Components
 * 
 * React components for displaying sandbox analysis results including
 * screenshots, network logs, DOM dumps, and threat indicators.
 */

import React, { useState, useEffect, useMemo } from 'react';
import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Badge,
  Button,
  ScrollArea,
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
  Alert,
  AlertDescription,
  Progress
} from '@/components/ui';
import { 
  ChevronDown, 
  ChevronRight, 
  Download, 
  Eye, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Network,
  FileText,
  Image,
  Clock,
  Hash,
  Globe
} from 'lucide-react';

interface SandboxEvidence {
  job_id: string;
  session_id: string;
  status: string;
  created_at: string;
  completed_at?: string;
  target_url_hash: string;
  execution_time?: number;
  evidence: {
    screenshots: ScreenshotEvidence[];
    network_captures: NetworkCapture[];
    dom_dumps: DOMEvidence[];
    security_events: SecurityEvent[];
  };
  threat_analysis: ThreatAnalysis;
  metadata: {
    browser_version: string;
    user_agent: string;
    viewport_size: string;
    execution_environment: string;
  };
}

interface ScreenshotEvidence {
  filename: string;
  timestamp: string;
  file_hash: string;
  file_size: number;
  dimensions: string;
  description: string;
  threat_indicators: string[];
}

interface NetworkCapture {
  filename: string;
  timestamp: string;
  file_hash: string;
  file_size: number;
  packet_count: number;
  connections: NetworkConnection[];
  blocked_requests: BlockedRequest[];
  dns_queries: DNSQuery[];
}

interface DOMEvidence {
  filename: string;
  timestamp: string;
  file_hash: string;
  file_size: number;
  element_count: number;
  suspicious_elements: SuspiciousElement[];
  forms_detected: FormData[];
  scripts_detected: ScriptData[];
}

interface ThreatAnalysis {
  risk_score: number;
  threat_level: 'low' | 'medium' | 'high' | 'critical';
  indicators: ThreatIndicator[];
  recommendations: string[];
  iocs: IOC[];
}

interface ThreatIndicator {
  type: string;
  value: string;
  confidence: number;
  description: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
}

const SandboxEvidenceViewer: React.FC<{ evidenceData: SandboxEvidence }> = ({ 
  evidenceData 
}) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set());

  const toggleSection = (sectionId: string) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(sectionId)) {
      newExpanded.delete(sectionId);
    } else {
      newExpanded.add(sectionId);
    }
    setExpandedSections(newExpanded);
  };

  const formatFileSize = (bytes: number): string => {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    
    return `${size.toFixed(1)} ${units[unitIndex]}`;
  };

  const getThreatLevelColor = (level: string): string => {
    switch (level) {
      case 'low': return 'text-green-600';
      case 'medium': return 'text-yellow-600';
      case 'high': return 'text-orange-600';
      case 'critical': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-green-600" />;
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-600" />;
      case 'timeout':
        return <Clock className="h-5 w-5 text-yellow-600" />;
      default:
        return <AlertTriangle className="h-5 w-5 text-gray-600" />;
    }
  };

  return (
    <div className="w-full space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-6 w-6" />
                Sandbox Analysis Report
              </CardTitle>
              <div className="flex items-center gap-4 mt-2 text-sm text-gray-600">
                <span className="flex items-center gap-1">
                  {getStatusIcon(evidenceData.status)}
                  Status: {evidenceData.status}
                </span>
                <span>Job ID: {evidenceData.job_id}</span>
                <span>Session: {evidenceData.session_id}</span>
              </div>
            </div>
            <div className="text-right">
              <Badge 
                className={getThreatLevelColor(evidenceData.threat_analysis.threat_level)}
                variant="outline"
              >
                {evidenceData.threat_analysis.threat_level.toUpperCase()} RISK
              </Badge>
              <div className="text-sm text-gray-600 mt-1">
                Score: {evidenceData.threat_analysis.risk_score}/100
              </div>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="screenshots">Screenshots</TabsTrigger>
          <TabsTrigger value="network">Network</TabsTrigger>
          <TabsTrigger value="dom">DOM Analysis</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Execution Summary */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Execution Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Start Time:</span>
                  <span className="text-sm">{new Date(evidenceData.created_at).toLocaleString()}</span>
                </div>
                {evidenceData.completed_at && (
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Completion:</span>
                    <span className="text-sm">{new Date(evidenceData.completed_at).toLocaleString()}</span>
                  </div>
                )}
                {evidenceData.execution_time && (
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Duration:</span>
                    <span className="text-sm">{evidenceData.execution_time.toFixed(2)}s</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">URL Hash:</span>
                  <span className="text-sm font-mono text-xs">
                    {evidenceData.target_url_hash.substring(0, 16)}...
                  </span>
                </div>
              </CardContent>
            </Card>

            {/* Evidence Summary */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Evidence Collected</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Screenshots:</span>
                  <span className="text-sm">{evidenceData.evidence.screenshots.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Network Captures:</span>
                  <span className="text-sm">{evidenceData.evidence.network_captures.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">DOM Dumps:</span>
                  <span className="text-sm">{evidenceData.evidence.dom_dumps.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Security Events:</span>
                  <span className="text-sm">{evidenceData.evidence.security_events.length}</span>
                </div>
              </CardContent>
            </Card>

            {/* Threat Overview */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Threat Assessment</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Risk Level:</span>
                  <Badge 
                    className={getThreatLevelColor(evidenceData.threat_analysis.threat_level)}
                    variant="outline"
                  >
                    {evidenceData.threat_analysis.threat_level.toUpperCase()}
                  </Badge>
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Risk Score:</span>
                    <span className="text-sm">{evidenceData.threat_analysis.risk_score}/100</span>
                  </div>
                  <Progress 
                    value={evidenceData.threat_analysis.risk_score} 
                    className="h-2"
                  />
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Indicators:</span>
                  <span className="text-sm">{evidenceData.threat_analysis.indicators.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">IOCs:</span>
                  <span className="text-sm">{evidenceData.threat_analysis.iocs.length}</span>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Quick Threat Indicators */}
          {evidenceData.threat_analysis.indicators.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Key Threat Indicators</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {evidenceData.threat_analysis.indicators.slice(0, 6).map((indicator, index) => (
                    <Alert key={index} className="p-3">
                      <AlertTriangle className="h-4 w-4" />
                      <AlertDescription>
                        <div className="flex justify-between items-start">
                          <div>
                            <div className="font-medium">{indicator.type}</div>
                            <div className="text-sm text-gray-600">{indicator.description}</div>
                          </div>
                          <Badge variant="outline" className="ml-2">
                            {(indicator.confidence * 100).toFixed(0)}%
                          </Badge>
                        </div>
                      </AlertDescription>
                    </Alert>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Screenshots Tab */}
        <TabsContent value="screenshots" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {evidenceData.evidence.screenshots.map((screenshot, index) => (
              <Card key={index}>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Image className="h-4 w-4" />
                    {screenshot.description || `Screenshot ${index + 1}`}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {/* Screenshot placeholder - in real app, would show actual image */}
                  <div className="aspect-video bg-gray-100 rounded-lg flex items-center justify-center border-2 border-dashed border-gray-300">
                    <div className="text-center">
                      <Image className="h-12 w-12 mx-auto text-gray-400 mb-2" />
                      <p className="text-sm text-gray-500">Screenshot Preview</p>
                      <p className="text-xs text-gray-400">{screenshot.dimensions}</p>
                    </div>
                  </div>
                  
                  {/* Screenshot details */}
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-600">Timestamp:</span>
                      <span>{new Date(screenshot.timestamp).toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">File Size:</span>
                      <span>{formatFileSize(screenshot.file_size)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">File Hash:</span>
                      <span className="font-mono text-xs">
                        {screenshot.file_hash.substring(0, 16)}...
                      </span>
                    </div>
                  </div>

                  {/* Threat indicators for this screenshot */}
                  {screenshot.threat_indicators.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-sm font-medium">Threat Indicators:</h4>
                      <div className="flex flex-wrap gap-1">
                        {screenshot.threat_indicators.map((indicator, idx) => (
                          <Badge key={idx} variant="destructive" className="text-xs">
                            {indicator}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex gap-2 pt-2">
                    <Button size="sm" variant="outline" className="flex-1">
                      <Eye className="h-4 w-4 mr-1" />
                      View Full Size
                    </Button>
                    <Button size="sm" variant="outline" className="flex-1">
                      <Download className="h-4 w-4 mr-1" />
                      Download
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Network Tab */}
        <TabsContent value="network" className="space-y-4">
          {evidenceData.evidence.network_captures.map((capture, index) => (
            <Card key={index}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Network Capture {index + 1}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Capture summary */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-600">Packets:</span>
                    <div className="font-medium">{capture.packet_count}</div>
                  </div>
                  <div>
                    <span className="text-gray-600">Connections:</span>
                    <div className="font-medium">{capture.connections.length}</div>
                  </div>
                  <div>
                    <span className="text-gray-600">Blocked:</span>
                    <div className="font-medium text-red-600">{capture.blocked_requests.length}</div>
                  </div>
                  <div>
                    <span className="text-gray-600">DNS Queries:</span>
                    <div className="font-medium">{capture.dns_queries.length}</div>
                  </div>
                </div>

                {/* Connections */}
                <Collapsible>
                  <CollapsibleTrigger 
                    className="flex items-center gap-2 text-sm font-medium hover:bg-gray-50 p-2 rounded w-full text-left"
                    onClick={() => toggleSection(`connections-${index}`)}
                  >
                    {expandedSections.has(`connections-${index}`) ? 
                      <ChevronDown className="h-4 w-4" /> : 
                      <ChevronRight className="h-4 w-4" />
                    }
                    Network Connections ({capture.connections.length})
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2">
                    <ScrollArea className="h-32">
                      <div className="space-y-1">
                        {capture.connections.map((conn, connIdx) => (
                          <div key={connIdx} className="text-xs font-mono bg-gray-50 p-2 rounded">
                            {conn.source_ip}:{conn.source_port} → {conn.dest_ip}:{conn.dest_port} ({conn.protocol})
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </CollapsibleContent>
                </Collapsible>

                {/* Blocked requests */}
                {capture.blocked_requests.length > 0 && (
                  <Collapsible>
                    <CollapsibleTrigger 
                      className="flex items-center gap-2 text-sm font-medium hover:bg-gray-50 p-2 rounded w-full text-left"
                      onClick={() => toggleSection(`blocked-${index}`)}
                    >
                      {expandedSections.has(`blocked-${index}`) ? 
                        <ChevronDown className="h-4 w-4" /> : 
                        <ChevronRight className="h-4 w-4" />
                      }
                      Blocked Requests ({capture.blocked_requests.length})
                    </CollapsibleTrigger>
                    <CollapsibleContent className="mt-2">
                      <ScrollArea className="h-32">
                        <div className="space-y-1">
                          {capture.blocked_requests.map((req, reqIdx) => (
                            <div key={reqIdx} className="text-xs bg-red-50 border border-red-200 p-2 rounded">
                              <div className="font-medium text-red-800">{req.url}</div>
                              <div className="text-red-600">Reason: {req.block_reason}</div>
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </CollapsibleContent>
                  </Collapsible>
                )}
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        {/* DOM Analysis Tab */}
        <TabsContent value="dom" className="space-y-4">
          {evidenceData.evidence.dom_dumps.map((dom, index) => (
            <Card key={index}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="h-5 w-5" />
                  DOM Analysis {index + 1}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* DOM summary */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-600">Elements:</span>
                    <div className="font-medium">{dom.element_count}</div>
                  </div>
                  <div>
                    <span className="text-gray-600">Suspicious:</span>
                    <div className="font-medium text-orange-600">{dom.suspicious_elements.length}</div>
                  </div>
                  <div>
                    <span className="text-gray-600">Forms:</span>
                    <div className="font-medium">{dom.forms_detected.length}</div>
                  </div>
                  <div>
                    <span className="text-gray-600">Scripts:</span>
                    <div className="font-medium">{dom.scripts_detected.length}</div>
                  </div>
                </div>

                {/* Suspicious elements */}
                {dom.suspicious_elements.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Suspicious Elements</h4>
                    <div className="space-y-2">
                      {dom.suspicious_elements.map((element, elemIdx) => (
                        <Alert key={elemIdx} className="p-3">
                          <AlertTriangle className="h-4 w-4" />
                          <AlertDescription>
                            <div className="font-medium">{element.tag_name}</div>
                            <div className="text-sm text-gray-600">{element.reason}</div>
                            {element.attributes && (
                              <div className="text-xs font-mono bg-gray-100 p-1 mt-1 rounded">
                                {JSON.stringify(element.attributes)}
                              </div>
                            )}
                          </AlertDescription>
                        </Alert>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security" className="space-y-4">
          {/* Threat Analysis */}
          <Card>
            <CardHeader>
              <CardTitle>Threat Analysis</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-medium">Overall Risk Assessment</h3>
                  <p className="text-sm text-gray-600">
                    Risk Score: {evidenceData.threat_analysis.risk_score}/100
                  </p>
                </div>
                <Badge 
                  className={getThreatLevelColor(evidenceData.threat_analysis.threat_level)}
                  variant="outline"
                  size="lg"
                >
                  {evidenceData.threat_analysis.threat_level.toUpperCase()}
                </Badge>
              </div>

              <Progress 
                value={evidenceData.threat_analysis.risk_score} 
                className="h-3"
              />

              {/* Recommendations */}
              {evidenceData.threat_analysis.recommendations.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium mb-2">Recommendations</h4>
                  <ul className="list-disc list-inside space-y-1 text-sm">
                    {evidenceData.threat_analysis.recommendations.map((rec, index) => (
                      <li key={index} className="text-gray-700">{rec}</li>
                    ))}
                  </ul>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Security Events */}
          {evidenceData.evidence.security_events.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Security Events</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-64">
                  <div className="space-y-2">
                    {evidenceData.evidence.security_events.map((event, index) => (
                      <Alert key={index} className="p-3">
                        <Shield className="h-4 w-4" />
                        <AlertDescription>
                          <div className="flex justify-between items-start">
                            <div>
                              <div className="font-medium">{event.event_type}</div>
                              <div className="text-sm text-gray-600">{event.description}</div>
                              <div className="text-xs text-gray-500">
                                {new Date(event.timestamp).toLocaleString()}
                              </div>
                            </div>
                            <Badge variant={event.severity === 'high' ? 'destructive' : 'outline'}>
                              {event.severity}
                            </Badge>
                          </div>
                        </AlertDescription>
                      </Alert>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          )}

          {/* IOCs */}
          {evidenceData.threat_analysis.iocs.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Indicators of Compromise (IOCs)</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {evidenceData.threat_analysis.iocs.map((ioc, index) => (
                    <div key={index} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                      <div>
                        <span className="font-medium">{ioc.type}:</span>
                        <span className="ml-2 font-mono text-sm">{ioc.value}</span>
                      </div>
                      <Badge variant="outline">{ioc.confidence}% confidence</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SandboxEvidenceViewer;