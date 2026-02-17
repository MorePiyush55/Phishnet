import React, { useState, useEffect, useMemo } from 'react';
import { useApi, useApiMutation } from '../hooks/useTypedApi';
import { apiManager } from '../services/apiManager';
import { Link, LinkAnalysis, LinkAnalysisRequest, RedirectChain } from '../types/api';
import { 
  Shield, 
  ExternalLink, 
  Eye, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  MousePointer,
  Globe,
  Lock,
  Unlock,
  Server,
  Activity,
  Camera,
  Download
} from 'lucide-react';

export interface SafeLinkAnalyzerProps {
  linkId: string;
  emailId?: string;
  onAction?: (action: 'analyze' | 'screenshot' | 'quarantine', linkId: string) => void;
  className?: string;
}

export const SafeLinkAnalyzer: React.FC<SafeLinkAnalyzerProps> = ({
  linkId,
  emailId,
  onAction,
  className = ''
}) => {
  const [analysisMode, setAnalysisMode] = useState<'quick' | 'deep' | 'screenshot'>('quick');
  const [showDetails, setShowDetails] = useState(false);
  const [link, setLink] = useState<Link | null>(null);

  // Since we don't have a getLink method, we'll fetch it through email links
  const { 
    data: emailLinks, 
    loading: linksLoading, 
    error: linksError,
    refresh: refreshLinks 
  } = useApi(() => emailId ? apiManager.emails.getLinks(emailId) : Promise.reject('No email ID'), {
    immediate: !!emailId
  });

  // Find the specific link from email links
  useEffect(() => {
    if (emailLinks && Array.isArray(emailLinks)) {
      const foundLink = emailLinks.find((l: Link) => l.id === linkId);
      setLink(foundLink || null);
    }
  }, [emailLinks, linkId]);

  // Analysis mutation
  const linkAnalysis = useApiMutation<LinkAnalysis, LinkAnalysisRequest>();
  
  // Screenshot mutation
  const screenshotMutation = useApiMutation<{ screenshot_url: string }, void>();

  const handleAnalyze = async (mode: 'quick' | 'deep' | 'screenshot') => {
    try {
      setAnalysisMode(mode);
      
      if (mode === 'screenshot') {
        const result = await screenshotMutation.mutate(
          () => apiManager.links.screenshot(linkId),
          undefined
        );
        onAction?.('screenshot', linkId);
        return result;
      } else {
        const params: LinkAnalysisRequest = {
          force_refresh: mode === 'deep',
          include_screenshot: true,
          max_redirects: mode === 'deep' ? 10 : 5
        };
        
        const result = await linkAnalysis.mutate(
          () => apiManager.links.analyze(linkId, params),
          params
        );

        onAction?.('analyze', linkId);
        await refreshLinks();
        
        return result;
      }
    } catch (error) {
      console.error('Analysis failed:', error);
      throw error;
    }
  };

  const getRiskColor = (verdict?: string) => {
    switch (verdict) {
      case 'safe': return 'text-green-600 bg-green-50 border-green-200';
      case 'suspicious': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'malicious': return 'text-red-600 bg-red-50 border-red-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getStatusIcon = (status?: string, isAnalyzing?: boolean) => {
    if (isAnalyzing) return <Clock className="h-4 w-4 animate-spin" />;
    
    switch (status) {
      case 'safe': return <CheckCircle className="h-4 w-4" />;
      case 'suspicious': return <AlertTriangle className="h-4 w-4" />;
      case 'malicious': return <AlertTriangle className="h-4 w-4" />;
      default: return <Activity className="h-4 w-4" />;
    }
  };

  if (linksLoading) {
    return (
      <div className={`flex items-center justify-center p-6 ${className}`}>
        <div className="flex items-center space-x-2">
          <Activity className="h-5 w-5 animate-pulse" />
          <span>Loading link analysis...</span>
        </div>
      </div>
    );
  }

  if (linksError || !link) {
    return (
      <div className={`bg-red-50 border border-red-200 rounded-lg p-4 ${className}`}>
        <div className="flex items-center space-x-2 text-red-700">
          <AlertTriangle className="h-5 w-5" />
          <span>Error loading link analysis</span>
        </div>
        <p className="text-red-600 text-sm mt-1">{linksError || 'Link not found'}</p>
      </div>
    );
  }

  const isAnalyzing = linkAnalysis.loading || screenshotMutation.loading;
  const verdict = link.analysis?.verdict;
  const isSafe = link.is_safe || verdict === 'safe';

  return (
    <div className={`bg-white border rounded-lg ${className}`}>
      {/* Header */}
      <div className="border-b p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-lg border ${getRiskColor(verdict)}`}>
              {getStatusIcon(verdict, isAnalyzing)}
            </div>
            <div>
              <h3 className="text-lg font-semibold">Link Analysis</h3>
              <p className="text-sm text-gray-600 break-all max-w-md">
                {link.url}
              </p>
              {link.display_text && link.display_text !== link.url && (
                <p className="text-xs text-gray-500">
                  Display: {link.display_text}
                </p>
              )}
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {verdict && (
              <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getRiskColor(verdict)}`}>
                {verdict.toUpperCase()}
              </span>
            )}
            {link.analysis && (
              <span className="text-sm text-gray-500">
                {Math.round(link.analysis.confidence * 100)}% confidence
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="p-4 border-b bg-gray-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <button
              onClick={() => handleAnalyze('quick')}
              disabled={isAnalyzing}
              className="flex items-center space-x-2 px-3 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
            >
              <Eye className="h-4 w-4" />
              <span>Quick Scan</span>
            </button>
            <button
              onClick={() => handleAnalyze('deep')}
              disabled={isAnalyzing}
              className="flex items-center space-x-2 px-3 py-2 bg-purple-500 text-white rounded hover:bg-purple-600 disabled:opacity-50"
            >
              <Activity className="h-4 w-4" />
              <span>Deep Analysis</span>
            </button>
            <button
              onClick={() => handleAnalyze('screenshot')}
              disabled={isAnalyzing}
              className="flex items-center space-x-2 px-3 py-2 bg-green-500 text-white rounded hover:bg-green-600 disabled:opacity-50"
            >
              <Camera className="h-4 w-4" />
              <span>Screenshot</span>
            </button>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setShowDetails(!showDetails)}
              className="flex items-center space-x-2 px-3 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300"
            >
              <MousePointer className="h-4 w-4" />
              <span>{showDetails ? 'Hide' : 'Show'} Details</span>
            </button>
          </div>
        </div>

        {isAnalyzing && (
          <div className="mt-3 flex items-center space-x-2 text-blue-600">
            <Activity className="h-4 w-4 animate-spin" />
            <span>Running {analysisMode} analysis...</span>
          </div>
        )}
      </div>

      {/* Analysis Results */}
      {showDetails && link.analysis && (
        <div className="p-4 border-b">
          <h4 className="font-medium text-gray-900 mb-3">Analysis Results</h4>
          
          {/* Threat Categories */}
          {link.analysis.threat_categories && link.analysis.threat_categories.length > 0 && (
            <div className="mb-4">
              <h5 className="text-sm font-medium text-gray-700 mb-2">Threat Categories</h5>
              <div className="flex flex-wrap gap-2">
                {link.analysis.threat_categories.map((category, index) => (
                  <span key={index} className="px-2 py-1 text-xs bg-red-100 text-red-700 rounded">
                    {category}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Blacklist Matches */}
          {link.analysis.blacklist_matches && link.analysis.blacklist_matches.length > 0 && (
            <div className="mb-4">
              <h5 className="text-sm font-medium text-gray-700 mb-2">Blacklist Matches</h5>
              <div className="space-y-1">
                {link.analysis.blacklist_matches.map((match, index) => (
                  <div key={index} className="flex items-center space-x-2 p-2 bg-red-50 rounded">
                    <AlertTriangle className="h-4 w-4 text-red-500" />
                    <span className="text-sm text-red-700">{match}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Analysis Engines */}
          {link.analysis.analysis_engines && link.analysis.analysis_engines.length > 0 && (
            <div className="mb-4">
              <h5 className="text-sm font-medium text-gray-700 mb-2">Analysis Engines</h5>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {link.analysis.analysis_engines.map((engine, index) => (
                  <div key={index} className="p-3 bg-gray-50 rounded">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{engine.name}</span>
                      <span className={`px-2 py-1 text-xs rounded ${getRiskColor(engine.verdict)}`}>
                        {engine.verdict}
                      </span>
                    </div>
                    <div className="text-xs text-gray-600 mt-1">
                      Confidence: {Math.round(engine.confidence * 100)}%
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Final URL */}
          {link.analysis.final_url && link.analysis.final_url !== link.url && (
            <div className="mb-4">
              <h5 className="text-sm font-medium text-gray-700 mb-2">Final URL</h5>
              <p className="text-sm bg-gray-50 p-2 rounded break-all">
                {link.analysis.final_url}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Redirect Chain */}
      {link.redirect_chain && link.redirect_chain.length > 0 && (
        <div className="p-4 border-b">
          <h4 className="font-medium text-gray-900 mb-3">
            Redirect Chain ({link.redirect_chain.length} hops)
          </h4>
          <div className="space-y-2">
            {link.redirect_chain.slice(0, showDetails ? undefined : 3).map((hop: RedirectChain, index: number) => (
              <div key={index} className="flex items-center space-x-3 p-2 bg-gray-50 rounded">
                <span className="text-sm font-mono text-gray-500 w-6">{hop.step}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm break-all">{hop.url}</p>
                  <div className="flex items-center space-x-2 mt-1">
                    <span className={`text-xs px-2 py-1 rounded ${
                      hop.status_code >= 200 && hop.status_code < 300 
                        ? 'bg-green-100 text-green-700'
                        : hop.status_code >= 300 && hop.status_code < 400
                        ? 'bg-yellow-100 text-yellow-700'
                        : 'bg-red-100 text-red-700'
                    }`}>
                      {hop.status_code}
                    </span>
                    <span className="text-xs text-gray-500">{hop.response_time_ms}ms</span>
                    {hop.ssl_info && (
                      <span className={`text-xs px-2 py-1 rounded flex items-center space-x-1 ${
                        hop.ssl_info.is_secure 
                          ? 'bg-green-100 text-green-700'
                          : 'bg-red-100 text-red-700'
                      }`}>
                        {hop.ssl_info.is_secure ? <Lock className="h-3 w-3" /> : <Unlock className="h-3 w-3" />}
                        <span>SSL</span>
                      </span>
                    )}
                    {hop.geolocation && (
                      <span className="text-xs text-gray-500">
                        📍 {hop.geolocation.country}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
            {!showDetails && link.redirect_chain.length > 3 && (
              <button
                onClick={() => setShowDetails(true)}
                className="text-sm text-blue-600 hover:text-blue-800"
              >
                Show {link.redirect_chain.length - 3} more hops...
              </button>
            )}
          </div>
        </div>
      )}

      {/* Screenshot */}
      {link.screenshot_url && (
        <div className="p-4 border-b">
          <h4 className="font-medium text-gray-900 mb-3">Screenshot</h4>
          <div className="border rounded-lg overflow-hidden">
            <img
              src={link.screenshot_url}
              alt="Link screenshot"
              className="w-full h-48 object-cover cursor-pointer hover:opacity-80"
              onClick={() => window.open(link.screenshot_url, '_blank')}
            />
          </div>
        </div>
      )}

      {/* Safe Action Button */}
      {isSafe && (
        <div className="p-4 bg-green-50">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 text-green-700">
              <CheckCircle className="h-5 w-5" />
              <span className="font-medium">Link verified as safe</span>
            </div>
            <button
              onClick={() => window.open(link.url, '_blank', 'noopener,noreferrer')}
              className="flex items-center space-x-2 px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600"
            >
              <ExternalLink className="h-4 w-4" />
              <span>Open Safely</span>
            </button>
          </div>
        </div>
      )}

      {/* Warning for unsafe links */}
      {verdict === 'malicious' && (
        <div className="p-4 bg-red-50">
          <div className="flex items-center space-x-2 text-red-700">
            <AlertTriangle className="h-5 w-5" />
            <span className="font-medium">⚠️ This link has been identified as malicious. Do not click!</span>
          </div>
        </div>
      )}

      {verdict === 'suspicious' && (
        <div className="p-4 bg-yellow-50">
          <div className="flex items-center space-x-2 text-yellow-700">
            <AlertTriangle className="h-5 w-5" />
            <span className="font-medium">⚠️ This link appears suspicious. Exercise caution.</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default SafeLinkAnalyzer;
