import React, { useState, useEffect, useRef } from 'react';
import { 
  ExternalLink, 
  Shield, 
  AlertTriangle, 
  CheckCircle,
  XCircle,
  Eye,
  Clock,
  ArrowRight,
  Globe,
  Server,
  Lock,
  Unlock,
  Info,
  ChevronDown,
  ChevronRight,
  Copy,
  ZoomIn,
  ZoomOut,
  RotateCcw
} from 'lucide-react';

interface RedirectHop {
  id: string;
  url: string;
  domain: string;
  status_code: number;
  method: 'GET' | 'POST' | 'REDIRECT';
  redirect_type?: 'http' | 'javascript' | 'meta' | 'html';
  response_time_ms: number;
  security_headers?: Record<string, string>;
  ssl_info?: {
    valid: boolean;
    issuer?: string;
    expires?: string;
  };
  risk_score: number;
  risk_factors: string[];
  timestamp: string;
  ip_address?: string;
  geolocation?: {
    country?: string;
    city?: string;
  };
}

interface RedirectChain {
  id: string;
  original_url: string;
  final_url: string;
  total_hops: number;
  total_time_ms: number;
  chain_risk_score: number;
  chain_status: 'safe' | 'suspicious' | 'malicious' | 'unknown';
  hops: RedirectHop[];
  analysis_timestamp: string;
  cloaking_detected: boolean;
  suspicious_patterns: string[];
}

interface RedirectChainVisualizationProps {
  chain: RedirectChain;
  showDetails?: boolean;
  compact?: boolean;
  interactive?: boolean;
  maxWidth?: string;
  maxHeight?: string;
}

const getRiskColor = (score: number): string => {
  if (score >= 80) return 'text-red-600 border-red-500 bg-red-50';
  if (score >= 60) return 'text-orange-600 border-orange-500 bg-orange-50';
  if (score >= 40) return 'text-yellow-600 border-yellow-500 bg-yellow-50';
  return 'text-green-600 border-green-500 bg-green-50';
};

const getStatusIcon = (statusCode: number) => {
  if (statusCode >= 200 && statusCode < 300) return <CheckCircle className="h-4 w-4 text-green-500" />;
  if (statusCode >= 300 && statusCode < 400) return <ArrowRight className="h-4 w-4 text-blue-500" />;
  if (statusCode >= 400 && statusCode < 500) return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
  if (statusCode >= 500) return <XCircle className="h-4 w-4 text-red-500" />;
  return <Clock className="h-4 w-4 text-gray-500" />;
};

const getMethodColor = (method: string): string => {
  switch (method) {
    case 'GET': return 'bg-blue-100 text-blue-800';
    case 'POST': return 'bg-green-100 text-green-800';
    case 'REDIRECT': return 'bg-purple-100 text-purple-800';
    default: return 'bg-gray-100 text-gray-800';
  }
};

const truncateUrl = (url: string, maxLength: number = 40): string => {
  if (url.length <= maxLength) return url;
  const start = url.substring(0, maxLength / 2);
  const end = url.substring(url.length - maxLength / 2);
  return `${start}...${end}`;
};

const copyToClipboard = (text: string) => {
  navigator.clipboard.writeText(text);
};

interface HopNodeProps {
  hop: RedirectHop;
  index: number;
  isFirst: boolean;
  isLast: boolean;
  expanded: boolean;
  onToggleExpanded: () => void;
  compact?: boolean;
}

const HopNode: React.FC<HopNodeProps> = ({
  hop,
  index,
  isFirst,
  isLast,
  expanded,
  onToggleExpanded,
  compact = false
}) => {
  const riskColorClass = getRiskColor(hop.risk_score);
  const statusIcon = getStatusIcon(hop.status_code);
  const methodColorClass = getMethodColor(hop.method);

  if (compact) {
    return (
      <div className={`inline-flex items-center px-2 py-1 rounded border ${riskColorClass} text-xs`}>
        {statusIcon}
        <span className="ml-1 font-mono">{hop.domain}</span>
        <span className="ml-1 text-gray-500">({hop.status_code})</span>
      </div>
    );
  }

  return (
    <div className="relative">
      {/* Connection line to previous hop */}
      {!isFirst && (
        <div className="absolute -top-4 left-1/2 w-px h-4 bg-gray-300 transform -translate-x-1/2"></div>
      )}
      
      {/* Connection line to next hop */}
      {!isLast && (
        <div className="absolute -bottom-4 left-1/2 w-px h-4 bg-gray-300 transform -translate-x-1/2"></div>
      )}

      <div className={`border-2 rounded-lg p-4 bg-white ${riskColorClass.split(' ')[1]} ${riskColorClass.split(' ')[2]}`}>
        {/* Header */}
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-1">
              <span className="text-sm font-bold text-gray-600">#{index + 1}</span>
              {statusIcon}
            </div>
            
            <div className={`px-2 py-1 rounded text-xs font-medium ${methodColorClass}`}>
              {hop.method}
            </div>
            
            {hop.redirect_type && (
              <div className="px-2 py-1 rounded text-xs bg-gray-100 text-gray-700">
                {hop.redirect_type}
              </div>
            )}
          </div>

          <div className="flex items-center space-x-2">
            <div className="text-right">
              <div className={`text-sm font-bold ${getRiskColor(hop.risk_score).split(' ')[0]}`}>
                {hop.risk_score}%
              </div>
              <div className="text-xs text-gray-500">
                {hop.response_time_ms}ms
              </div>
            </div>
            
            <button
              onClick={onToggleExpanded}
              className="p-1 hover:bg-gray-100 rounded"
            >
              {expanded ? (
                <ChevronDown className="h-4 w-4 text-gray-400" />
              ) : (
                <ChevronRight className="h-4 w-4 text-gray-400" />
              )}
            </button>
          </div>
        </div>

        {/* URL */}
        <div className="mb-2">
          <div className="flex items-center space-x-2">
            <Globe className="h-4 w-4 text-gray-400" />
            <span className="font-semibold text-gray-700">{hop.domain}</span>
            <button
              onClick={() => copyToClipboard(hop.url)}
              className="p-1 hover:bg-gray-100 rounded"
              title="Copy URL"
            >
              <Copy className="h-3 w-3 text-gray-400" />
            </button>
          </div>
          <div className="mt-1 text-xs text-gray-600 font-mono break-all">
            {hop.url}
          </div>
        </div>

        {/* Risk factors */}
        {hop.risk_factors.length > 0 && (
          <div className="mb-2">
            <div className="flex flex-wrap gap-1">
              {hop.risk_factors.slice(0, expanded ? undefined : 2).map((factor, i) => (
                <span
                  key={i}
                  className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-red-100 text-red-800"
                >
                  <AlertTriangle className="h-3 w-3 mr-1" />
                  {factor}
                </span>
              ))}
              {!expanded && hop.risk_factors.length > 2 && (
                <span className="text-xs text-gray-500">
                  +{hop.risk_factors.length - 2} more
                </span>
              )}
            </div>
          </div>
        )}

        {/* Expanded details */}
        {expanded && (
          <div className="space-y-3 mt-3 pt-3 border-t">
            {/* SSL Info */}
            {hop.ssl_info && (
              <div className="flex items-center space-x-2">
                {hop.ssl_info.valid ? (
                  <Lock className="h-4 w-4 text-green-500" />
                ) : (
                  <Unlock className="h-4 w-4 text-red-500" />
                )}
                <span className="text-sm">
                  SSL: {hop.ssl_info.valid ? 'Valid' : 'Invalid'}
                  {hop.ssl_info.issuer && ` (${hop.ssl_info.issuer})`}
                </span>
              </div>
            )}

            {/* IP and Geolocation */}
            {hop.ip_address && (
              <div className="flex items-center space-x-2">
                <Server className="h-4 w-4 text-gray-400" />
                <span className="text-sm font-mono">{hop.ip_address}</span>
                {hop.geolocation && (
                  <span className="text-sm text-gray-600">
                    ({hop.geolocation.city}, {hop.geolocation.country})
                  </span>
                )}
              </div>
            )}

            {/* Security Headers */}
            {hop.security_headers && Object.keys(hop.security_headers).length > 0 && (
              <div>
                <div className="text-sm font-medium text-gray-700 mb-1">Security Headers</div>
                <div className="bg-gray-50 rounded p-2 text-xs font-mono space-y-1">
                  {Object.entries(hop.security_headers).map(([header, value]) => (
                    <div key={header} className="flex justify-between">
                      <span className="text-gray-600">{header}:</span>
                      <span className="text-gray-900 truncate ml-2" title={value}>
                        {value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Timestamp */}
            <div className="flex items-center space-x-2 text-xs text-gray-500">
              <Clock className="h-3 w-3" />
              <span>{new Date(hop.timestamp).toLocaleString()}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export const RedirectChainVisualization: React.FC<RedirectChainVisualizationProps> = ({
  chain,
  showDetails = false,
  compact = false,
  interactive = true,
  maxWidth = '100%',
  maxHeight = '600px'
}) => {
  const [expandedHops, setExpandedHops] = useState<Set<string>>(new Set());
  const [scale, setScale] = useState(1);
  const containerRef = useRef<HTMLDivElement>(null);

  const toggleHopExpanded = (hopId: string) => {
    if (!interactive) return;
    
    const newExpanded = new Set(expandedHops);
    if (newExpanded.has(hopId)) {
      newExpanded.delete(hopId);
    } else {
      newExpanded.add(hopId);
    }
    setExpandedHops(newExpanded);
  };

  const chainRiskColor = getRiskColor(chain.chain_risk_score);

  if (compact) {
    return (
      <div className="flex items-center space-x-2 p-2 border rounded">
        <div className="flex items-center space-x-1">
          <ArrowRight className="h-4 w-4 text-gray-400" />
          <span className="text-sm font-medium">{chain.total_hops} hops</span>
        </div>
        
        <div className="flex space-x-1 overflow-x-auto">
          {chain.hops.map((hop, index) => (
            <HopNode
              key={hop.id}
              hop={hop}
              index={index}
              isFirst={index === 0}
              isLast={index === chain.hops.length - 1}
              expanded={false}
              onToggleExpanded={() => {}}
              compact={true}
            />
          ))}
        </div>
        
        <div className={`px-2 py-1 rounded text-xs font-medium ${chainRiskColor}`}>
          {chain.chain_risk_score}%
        </div>
      </div>
    );
  }

  return (
    <div 
      className="bg-white rounded-lg border"
      style={{ maxWidth, maxHeight }}
    >
      {/* Header */}
      <div className="border-b p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-3">
            <h3 className="text-lg font-semibold text-gray-900">
              Redirect Chain Analysis
            </h3>
            
            {chain.cloaking_detected && (
              <div className="flex items-center space-x-1 px-2 py-1 rounded bg-red-100 text-red-800 text-sm">
                <Eye className="h-4 w-4" />
                <span>Cloaking Detected</span>
              </div>
            )}
          </div>

          {interactive && (
            <div className="flex space-x-2">
              <button
                onClick={() => setScale(Math.max(0.5, scale - 0.1))}
                className="p-1 hover:bg-gray-100 rounded"
                title="Zoom Out"
              >
                <ZoomOut className="h-4 w-4 text-gray-600" />
              </button>
              <button
                onClick={() => setScale(Math.min(2, scale + 0.1))}
                className="p-1 hover:bg-gray-100 rounded"
                title="Zoom In"
              >
                <ZoomIn className="h-4 w-4 text-gray-600" />
              </button>
              <button
                onClick={() => setScale(1)}
                className="p-1 hover:bg-gray-100 rounded"
                title="Reset Zoom"
              >
                <RotateCcw className="h-4 w-4 text-gray-600" />
              </button>
            </div>
          )}
        </div>

        {/* Chain Summary */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <div className="text-gray-500">Total Hops</div>
            <div className="font-semibold">{chain.total_hops}</div>
          </div>
          <div>
            <div className="text-gray-500">Total Time</div>
            <div className="font-semibold">{chain.total_time_ms}ms</div>
          </div>
          <div>
            <div className="text-gray-500">Chain Risk</div>
            <div className={`font-semibold ${chainRiskColor.split(' ')[0]}`}>
              {chain.chain_risk_score}%
            </div>
          </div>
          <div>
            <div className="text-gray-500">Status</div>
            <div className={`font-semibold capitalize ${
              chain.chain_status === 'safe' ? 'text-green-600' :
              chain.chain_status === 'suspicious' ? 'text-yellow-600' :
              chain.chain_status === 'malicious' ? 'text-red-600' : 'text-gray-600'
            }`}>
              {chain.chain_status}
            </div>
          </div>
        </div>

        {/* Suspicious Patterns */}
        {chain.suspicious_patterns.length > 0 && (
          <div className="mt-3">
            <div className="text-sm text-gray-700 mb-2">Suspicious Patterns Detected:</div>
            <div className="flex flex-wrap gap-2">
              {chain.suspicious_patterns.map((pattern, index) => (
                <span
                  key={index}
                  className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-yellow-100 text-yellow-800"
                >
                  <AlertTriangle className="h-3 w-3 mr-1" />
                  {pattern}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Chain Visualization */}
      <div 
        ref={containerRef}
        className="p-4 overflow-auto"
        style={{ transform: `scale(${scale})`, transformOrigin: 'top left' }}
      >
        <div className="space-y-6">
          {chain.hops.map((hop, index) => (
            <div key={hop.id} className="flex flex-col items-center">
              <HopNode
                hop={hop}
                index={index}
                isFirst={index === 0}
                isLast={index === chain.hops.length - 1}
                expanded={expandedHops.has(hop.id)}
                onToggleExpanded={() => toggleHopExpanded(hop.id)}
              />
              
              {/* Connection arrow */}
              {index < chain.hops.length - 1 && (
                <div className="flex flex-col items-center my-2">
                  <ArrowRight className="h-6 w-6 text-gray-400" />
                  <div className="text-xs text-gray-500 mt-1">
                    {chain.hops[index + 1].response_time_ms}ms
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Analysis timestamp */}
      <div className="border-t p-3 text-xs text-gray-500 flex items-center justify-between">
        <div className="flex items-center space-x-1">
          <Info className="h-3 w-3" />
          <span>Analysis completed: {new Date(chain.analysis_timestamp).toLocaleString()}</span>
        </div>
        
        {interactive && (
          <div className="flex space-x-4">
            <button
              onClick={() => setExpandedHops(new Set(chain.hops.map(h => h.id)))}
              className="text-blue-600 hover:text-blue-800"
            >
              Expand All
            </button>
            <button
              onClick={() => setExpandedHops(new Set())}
              className="text-blue-600 hover:text-blue-800"
            >
              Collapse All
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

// Simplified redirect chain summary for email list view
export const RedirectChainSummary: React.FC<{
  hops: number;
  riskScore: number;
  cloakingDetected?: boolean;
  totalTime?: number;
}> = ({ hops, riskScore, cloakingDetected, totalTime }) => {
  const riskColor = getRiskColor(riskScore);
  
  return (
    <div className="flex items-center space-x-3 text-sm">
      <div className="flex items-center space-x-1">
        <ArrowRight className="h-4 w-4 text-gray-400" />
        <span>{hops} hops</span>
      </div>
      
      <div className={`px-2 py-1 rounded text-xs font-medium ${riskColor}`}>
        {riskScore}%
      </div>
      
      {cloakingDetected && (
        <div className="flex items-center space-x-1 text-red-600">
          <Eye className="h-3 w-3" />
          <span className="text-xs">Cloaking</span>
        </div>
      )}
      
      {totalTime && (
        <span className="text-gray-500 text-xs">{totalTime}ms</span>
      )}
    </div>
  );
};
