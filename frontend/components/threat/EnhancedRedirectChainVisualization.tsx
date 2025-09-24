/**
 * Enhanced Redirect Chain Visualization Component
 * 
 * Provides advanced visualization of URL redirect chains with:
 * - Interactive flow diagram
 * - Threat indicators at each hop
 * - Screenshot evidence display
 * - Geographic routing visualization
 * - Timeline analysis
 */

import React, { useState, useEffect, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  ArrowRight, 
  AlertTriangle, 
  Shield, 
  Globe, 
  Clock, 
  Camera,
  MapPin,
  ExternalLink,
  Download,
  ZoomIn,
  Eye,
  Flag,
  Timer,
  Network,
  AlertOctagon
} from 'lucide-react';

interface RedirectHop {
  url: string;
  status_code: number;
  method: string;
  response_time_ms: number;
  headers: Record<string, string>;
  threat_indicators: {
    suspicious_domains: boolean;
    malicious_patterns: boolean;
    cloaking_detected: boolean;
    risk_score: number;
  };
  geolocation?: {
    country: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
  };
  screenshot?: {
    url: string;
    timestamp: string;
    thumbnail_url: string;
  };
  certificate?: {
    issuer: string;
    valid_from: string;
    valid_to: string;
    is_valid: boolean;
  };
}

interface RedirectChain {
  original_url: string;
  final_url: string;
  hops: RedirectHop[];
  total_redirects: number;
  total_time_ms: number;
  chain_analysis: {
    is_suspicious: boolean;
    risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    cloaking_attempts: number;
    geographic_hops: number;
    suspicious_patterns: string[];
  };
  metadata: {
    analysis_timestamp: string;
    user_agent: string;
    max_redirects_allowed: number;
  };
}

interface EnhancedRedirectChainProps {
  redirectChain: RedirectChain;
  onHopSelect?: (hop: RedirectHop, index: number) => void;
  onScreenshotView?: (screenshot: { url: string; timestamp: string }) => void;
}

const ThreatIndicatorBadge: React.FC<{ 
  indicators: RedirectHop['threat_indicators'];
  compact?: boolean;
}> = ({ indicators, compact = false }) => {
  const { risk_score, suspicious_domains, malicious_patterns, cloaking_detected } = indicators;
  
  const getRiskColor = (score: number) => {
    if (score >= 0.8) return 'bg-red-500';
    if (score >= 0.6) return 'bg-orange-500';
    if (score >= 0.4) return 'bg-yellow-500';
    return 'bg-green-500';
  };
  
  const getRiskLevel = (score: number) => {
    if (score >= 0.8) return 'CRITICAL';
    if (score >= 0.6) return 'HIGH';
    if (score >= 0.4) return 'MEDIUM';
    return 'LOW';
  };
  
  if (compact) {
    return (
      <Badge 
        variant={risk_score >= 0.6 ? 'destructive' : risk_score >= 0.4 ? 'warning' : 'success'}
        className="text-xs"
      >
        {getRiskLevel(risk_score)} ({(risk_score * 100).toFixed(0)}%)
      </Badge>
    );
  }
  
  return (
    <div className="flex flex-wrap gap-1">
      <Badge variant={risk_score >= 0.6 ? 'destructive' : 'secondary'} className="text-xs">
        <AlertTriangle className="w-3 h-3 mr-1" />
        Risk: {(risk_score * 100).toFixed(0)}%
      </Badge>
      {suspicious_domains && (
        <Badge variant="destructive" className="text-xs">
          <Globe className="w-3 h-3 mr-1" />
          Suspicious Domain
        </Badge>
      )}
      {malicious_patterns && (
        <Badge variant="destructive" className="text-xs">
          <Flag className="w-3 h-3 mr-1" />
          Malicious Patterns
        </Badge>
      )}
      {cloaking_detected && (
        <Badge variant="destructive" className="text-xs">
          <Eye className="w-3 h-3 mr-1" />
          Cloaking
        </Badge>
      )}
    </div>
  );
};

const HopCard: React.FC<{
  hop: RedirectHop;
  index: number;
  isFirst: boolean;
  isLast: boolean;
  onSelect: () => void;
  onScreenshotView: () => void;
}> = ({ hop, index, isFirst, isLast, onSelect, onScreenshotView }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  
  const getStatusColor = (code: number) => {
    if (code >= 200 && code < 300) return 'text-green-600';
    if (code >= 300 && code < 400) return 'text-blue-600';
    if (code >= 400 && code < 500) return 'text-yellow-600';
    return 'text-red-600';
  };
  
  const formatDomain = (url: string) => {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  };
  
  return (
    <Card 
      className={`transition-all duration-200 hover:shadow-md cursor-pointer ${
        hop.threat_indicators.risk_score >= 0.6 ? 'border-red-300 bg-red-50' : ''
      }`}
      onClick={() => setIsExpanded(!isExpanded)}
    >
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-xs">
              Hop {index + 1}
            </Badge>
            {hop.method !== 'GET' && (
              <Badge variant="secondary" className="text-xs">
                {hop.method}
              </Badge>
            )}
            <Badge variant="outline" className={`text-xs ${getStatusColor(hop.status_code)}`}>
              {hop.status_code}
            </Badge>
          </div>
          <ThreatIndicatorBadge indicators={hop.threat_indicators} compact />
        </div>
        
        <div className="space-y-2">
          <div className="font-mono text-sm break-all">
            <span className="text-gray-600">
              {formatDomain(hop.url)}
            </span>
          </div>
          
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {hop.response_time_ms}ms
            </span>
            
            {hop.geolocation && (
              <span className="flex items-center gap-1">
                <MapPin className="w-3 h-3" />
                {hop.geolocation.country}
              </span>
            )}
            
            {hop.screenshot && (
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2"
                onClick={(e) => {
                  e.stopPropagation();
                  onScreenshotView();
                }}
              >
                <Camera className="w-3 h-3" />
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      
      {isExpanded && (
        <CardContent className="pt-0">
          <div className="space-y-4">
            {/* Full URL */}
            <div>
              <h4 className="text-xs font-semibold text-gray-600 mb-1">Full URL</h4>
              <div className="font-mono text-xs bg-gray-100 p-2 rounded break-all">
                {hop.url}
              </div>
            </div>
            
            {/* Threat Analysis */}
            <div>
              <h4 className="text-xs font-semibold text-gray-600 mb-2">Threat Analysis</h4>
              <ThreatIndicatorBadge indicators={hop.threat_indicators} />
            </div>
            
            {/* Certificate Info */}
            {hop.certificate && (
              <div>
                <h4 className="text-xs font-semibold text-gray-600 mb-1">SSL Certificate</h4>
                <div className="text-xs">
                  <div className="flex items-center gap-2 mb-1">
                    <Shield className={`w-3 h-3 ${hop.certificate.is_valid ? 'text-green-500' : 'text-red-500'}`} />
                    <span className={hop.certificate.is_valid ? 'text-green-600' : 'text-red-600'}>
                      {hop.certificate.is_valid ? 'Valid' : 'Invalid'}
                    </span>
                  </div>
                  <div className="text-gray-600">
                    Issuer: {hop.certificate.issuer}
                  </div>
                </div>
              </div>
            )}
            
            {/* Screenshot Preview */}
            {hop.screenshot && (
              <div>
                <h4 className="text-xs font-semibold text-gray-600 mb-1">Screenshot Preview</h4>
                <div className="relative group">
                  <img 
                    src={hop.screenshot.thumbnail_url}
                    alt="Page screenshot"
                    className="w-full h-32 object-cover rounded border cursor-pointer"
                    onClick={(e) => {
                      e.stopPropagation();
                      onScreenshotView();
                    }}
                  />
                  <div className="absolute inset-0 bg-black bg-opacity-0 group-hover:bg-opacity-20 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-all duration-200">
                    <ZoomIn className="w-6 h-6 text-white" />
                  </div>
                </div>
              </div>
            )}
            
            {/* Actions */}
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={(e) => {
                  e.stopPropagation();
                  onSelect();
                }}
              >
                <ExternalLink className="w-3 h-3 mr-1" />
                Analyze
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={(e) => {
                  e.stopPropagation();
                  navigator.clipboard.writeText(hop.url);
                }}
              >
                Copy URL
              </Button>
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  );
};

const RedirectFlowDiagram: React.FC<{ hops: RedirectHop[]; onHopClick: (index: number) => void }> = ({ 
  hops, 
  onHopClick 
}) => {
  return (
    <div className="flex items-center gap-2 overflow-x-auto pb-4">
      {hops.map((hop, index) => (
        <React.Fragment key={index}>
          <div 
            className="flex-shrink-0 cursor-pointer"
            onClick={() => onHopClick(index)}
          >
            <div className="text-center">
              <div className={`
                w-12 h-12 rounded-full border-2 flex items-center justify-center text-xs font-semibold
                ${hop.threat_indicators.risk_score >= 0.6 
                  ? 'border-red-400 bg-red-100 text-red-700' 
                  : hop.threat_indicators.risk_score >= 0.4
                  ? 'border-yellow-400 bg-yellow-100 text-yellow-700'
                  : 'border-green-400 bg-green-100 text-green-700'
                }
                hover:scale-110 transition-transform duration-200
              `}>
                {index + 1}
              </div>
              <div className="text-xs text-gray-600 mt-1 max-w-16 truncate">
                {new URL(hop.url).hostname.split('.')[0]}
              </div>
            </div>
          </div>
          
          {index < hops.length - 1 && (
            <ArrowRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
          )}
        </React.Fragment>
      ))}
    </div>
  );
};

const GeographicRouting: React.FC<{ hops: RedirectHop[] }> = ({ hops }) => {
  const uniqueCountries = useMemo(() => {
    const countries = hops
      .filter(hop => hop.geolocation)
      .map(hop => hop.geolocation!.country);
    return [...new Set(countries)];
  }, [hops]);
  
  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold flex items-center gap-2">
        <Globe className="w-4 h-4" />
        Geographic Routing ({uniqueCountries.length} countries)
      </h4>
      
      <div className="space-y-2">
        {hops.filter(hop => hop.geolocation).map((hop, index) => (
          <div key={index} className="flex items-center justify-between p-2 bg-gray-50 rounded">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-xs">Hop {index + 1}</Badge>
              <MapPin className="w-3 h-3 text-gray-500" />
              <span className="text-sm">
                {hop.geolocation!.city}, {hop.geolocation!.country}
              </span>
            </div>
            <ThreatIndicatorBadge indicators={hop.threat_indicators} compact />
          </div>
        ))}
      </div>
    </div>
  );
};

const TimelineAnalysis: React.FC<{ hops: RedirectHop[]; totalTime: number }> = ({ 
  hops, 
  totalTime 
}) => {
  const maxTime = Math.max(...hops.map(hop => hop.response_time_ms));
  
  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold flex items-center gap-2">
        <Timer className="w-4 h-4" />
        Timeline Analysis (Total: {totalTime}ms)
      </h4>
      
      <div className="space-y-2">
        {hops.map((hop, index) => {
          const widthPercentage = (hop.response_time_ms / maxTime) * 100;
          const isSlowRequest = hop.response_time_ms > 2000;
          
          return (
            <div key={index} className="space-y-1">
              <div className="flex justify-between text-xs">
                <span>Hop {index + 1}</span>
                <span className={isSlowRequest ? 'text-orange-600 font-semibold' : ''}>
                  {hop.response_time_ms}ms
                  {isSlowRequest && ' (slow)'}
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div 
                  className={`h-2 rounded-full ${
                    isSlowRequest ? 'bg-orange-400' : 'bg-blue-400'
                  }`}
                  style={{ width: `${Math.max(widthPercentage, 2)}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const EnhancedRedirectChainVisualization: React.FC<EnhancedRedirectChainProps> = ({ 
  redirectChain, 
  onHopSelect, 
  onScreenshotView 
}) => {
  const [selectedHop, setSelectedHop] = useState<number>(0);
  const [activeTab, setActiveTab] = useState('chain');
  
  const handleHopSelect = (hop: RedirectHop, index: number) => {
    setSelectedHop(index);
    onHopSelect?.(hop, index);
  };
  
  const handleScreenshotView = (hop: RedirectHop) => {
    if (hop.screenshot) {
      onScreenshotView?.(hop.screenshot);
    }
  };
  
  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex justify-between items-start">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Network className="w-5 h-5" />
              Redirect Chain Analysis
            </CardTitle>
            <div className="text-sm text-gray-600 mt-1">
              {redirectChain.total_redirects} redirect(s) • {redirectChain.total_time_ms}ms total
            </div>
          </div>
          
          <Badge 
            variant={
              redirectChain.chain_analysis.risk_level === 'CRITICAL' ? 'destructive' :
              redirectChain.chain_analysis.risk_level === 'HIGH' ? 'destructive' :
              redirectChain.chain_analysis.risk_level === 'MEDIUM' ? 'warning' :
              'secondary'
            }
          >
            {redirectChain.chain_analysis.risk_level} Risk
          </Badge>
        </div>
        
        {/* Flow Diagram */}
        <div className="mt-4">
          <RedirectFlowDiagram 
            hops={redirectChain.hops}
            onHopClick={(index) => setSelectedHop(index)}
          />
        </div>
      </CardHeader>
      
      <CardContent>
        {/* Chain Analysis Alerts */}
        {redirectChain.chain_analysis.is_suspicious && (
          <Alert className="mb-4 border-orange-200 bg-orange-50">
            <AlertOctagon className="h-4 w-4" />
            <AlertDescription>
              <strong>Suspicious redirect chain detected:</strong>
              <ul className="mt-2 space-y-1 text-sm">
                {redirectChain.chain_analysis.suspicious_patterns.map((pattern, index) => (
                  <li key={index} className="flex items-center gap-2">
                    <ArrowRight className="w-3 h-3" />
                    {pattern}
                  </li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        )}
        
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="chain">Chain Details</TabsTrigger>
            <TabsTrigger value="geographic">Geographic</TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="summary">Summary</TabsTrigger>
          </TabsList>
          
          <TabsContent value="chain" className="space-y-4">
            {redirectChain.hops.map((hop, index) => (
              <HopCard
                key={index}
                hop={hop}
                index={index}
                isFirst={index === 0}
                isLast={index === redirectChain.hops.length - 1}
                onSelect={() => handleHopSelect(hop, index)}
                onScreenshotView={() => handleScreenshotView(hop)}
              />
            ))}
          </TabsContent>
          
          <TabsContent value="geographic">
            <GeographicRouting hops={redirectChain.hops} />
          </TabsContent>
          
          <TabsContent value="timeline">
            <TimelineAnalysis 
              hops={redirectChain.hops} 
              totalTime={redirectChain.total_time_ms} 
            />
          </TabsContent>
          
          <TabsContent value="summary" className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Card>
                <CardContent className="p-4">
                  <div className="text-2xl font-bold">{redirectChain.total_redirects}</div>
                  <div className="text-sm text-gray-600">Total Redirects</div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-4">
                  <div className="text-2xl font-bold">{redirectChain.chain_analysis.cloaking_attempts}</div>
                  <div className="text-sm text-gray-600">Cloaking Attempts</div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-4">
                  <div className="text-2xl font-bold">{redirectChain.chain_analysis.geographic_hops}</div>
                  <div className="text-sm text-gray-600">Geographic Hops</div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-4">
                  <div className="text-2xl font-bold">{redirectChain.total_time_ms}ms</div>
                  <div className="text-sm text-gray-600">Total Time</div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default EnhancedRedirectChainVisualization;
export type { RedirectHop, RedirectChain, EnhancedRedirectChainProps };