/**
 * Main Link Redirect Analysis Component
 * 
 * Provides comprehensive interface for URL analysis including redirect visualization,
 * threat assessment, cloaking detection, and security findings.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { 
  Search, 
  AlertCircle, 
  CheckCircle, 
  Clock, 
  RefreshCw,
  Download,
  Share2,
  ExternalLink,
  Zap,
  Globe,
  Activity
} from 'lucide-react';

import {
  TLSCertificateBadge,
  RedirectHopCard,
  CloakingAnalysisPanel,
  SecurityFindingsPanel,
  analyzeLink,
  quickScanLink,
  getThreatColor,
  getVerdictColor,
  formatDomain,
  copyToClipboard,
  LinkAnalysisResult,
  RedirectHop,
  CloakingAnalysis,
  SecurityFindings,
  AnalysisSummary
} from './LinkAnalysis';

// Analysis Options Component
const AnalysisOptions: React.FC<{
  options: any;
  onOptionsChange: (options: any) => void;
  disabled?: boolean;
}> = ({ options, onOptionsChange, disabled = false }) => {
  return (
    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 mb-4">
      <h3 className="text-sm font-medium text-gray-700 mb-3">Analysis Options</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="block text-xs text-gray-600 mb-1">Max Redirects</label>
          <select
            value={options.maxRedirects}
            onChange={(e) => onOptionsChange({...options, maxRedirects: parseInt(e.target.value)})}
            disabled={disabled}
            className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          >
            <option value={5}>5</option>
            <option value={10}>10</option>
            <option value={15}>15</option>
            <option value={20}>20</option>
          </select>
        </div>
        
        <div>
          <label className="block text-xs text-gray-600 mb-1">Timeout (seconds)</label>
          <select
            value={options.timeoutSeconds}
            onChange={(e) => onOptionsChange({...options, timeoutSeconds: parseInt(e.target.value)})}
            disabled={disabled}
            className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          >
            <option value={15}>15</option>
            <option value={30}>30</option>
            <option value={45}>45</option>
            <option value={60}>60</option>
          </select>
        </div>
        
        <div className="flex items-center">
          <input
            type="checkbox"
            id="includeCloaking"
            checked={options.includeCloaking}
            onChange={(e) => onOptionsChange({...options, includeCloaking: e.target.checked})}
            disabled={disabled}
            className="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded disabled:opacity-50"
          />
          <label htmlFor="includeCloaking" className="text-xs text-gray-600">
            Include Cloaking Detection
          </label>
        </div>
      </div>
    </div>
  );
};

// Analysis Summary Component
const AnalysisSummaryCard: React.FC<{ summary: AnalysisSummary; threatScore: number; verdict: string }> = ({ 
  summary, 
  threatScore, 
  verdict 
}) => {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      <div className="bg-white border border-gray-200 rounded-lg p-4 text-center">
        <div className="text-2xl font-bold text-gray-900">{summary.total_redirects}</div>
        <div className="text-sm text-gray-600">Total Redirects</div>
      </div>
      
      <div className="bg-white border border-gray-200 rounded-lg p-4 text-center">
        <div className={`text-2xl font-bold ${getThreatColor(threatScore).split(' ')[0]}`}>
          {Math.round(threatScore * 100)}%
        </div>
        <div className="text-sm text-gray-600">Threat Score</div>
      </div>
      
      <div className="bg-white border border-gray-200 rounded-lg p-4 text-center">
        <div className="text-2xl font-bold text-gray-900">{summary.unique_domains}</div>
        <div className="text-sm text-gray-600">Unique Domains</div>
      </div>
      
      <div className="bg-white border border-gray-200 rounded-lg p-4 text-center">
        <div className="text-2xl font-bold text-gray-900">{Math.round(summary.https_coverage * 100)}%</div>
        <div className="text-sm text-gray-600">HTTPS Coverage</div>
      </div>
    </div>
  );
};

// Main Component
const LinkRedirectAnalysis: React.FC = () => {
  const [url, setUrl] = useState('');
  const [analysisResult, setAnalysisResult] = useState<LinkAnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysisMode, setAnalysisMode] = useState<'quick' | 'comprehensive'>('comprehensive');
  const [analysisOptions, setAnalysisOptions] = useState({
    maxRedirects: 10,
    timeoutSeconds: 30,
    includeCloaking: true
  });

  // URL validation
  const isValidUrl = useCallback((urlString: string): boolean => {
    try {
      const urlObj = new URL(urlString);
      return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch {
      return false;
    }
  }, []);

  // Handle analysis
  const handleAnalysis = async () => {
    if (!url.trim()) {
      setError('Please enter a URL to analyze');
      return;
    }

    if (!isValidUrl(url)) {
      setError('Please enter a valid HTTP or HTTPS URL');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setAnalysisResult(null);

    try {
      let result;
      if (analysisMode === 'quick') {
        const quickResult = await quickScanLink(url);
        // Convert quick scan result to full format for display
        result = {
          ...quickResult,
          analysis_id: `quick_${Date.now()}`,
          original_url: url,
          explanation: `Quick scan completed in ${quickResult.analysis_time_ms}ms`,
          threat_indicators: quickResult.key_indicators,
          redirect_chain: [],
          cloaking_analysis: {
            cloaking_detected: quickResult.cloaking_detected,
            cloaking_confidence: 0,
            cloaking_indicators: [],
            browser_behavior: {},
            content_differences: {},
            js_behavior: {},
            cross_ua_differences: {}
          },
          security_findings: {
            ip_domain_mismatch: false,
            cert_hostname_mismatch: false,
            suspicious_tld: false,
            suspicious_patterns: [],
            domain_reputation: {},
            ssl_issues: []
          },
          analysis_summary: {
            total_redirects: quickResult.redirect_count,
            final_destination: quickResult.final_url,
            cloaking_detected: quickResult.cloaking_detected,
            cloaking_confidence: 0,
            threat_score: quickResult.threat_score,
            unique_domains: 1,
            https_coverage: quickResult.final_url.startsWith('https') ? 1 : 0,
            suspicious_patterns_count: quickResult.key_indicators.length,
            analysis_duration_ms: quickResult.analysis_time_ms
          },
          timing_analysis: {},
          analysis_metadata: {},
          timestamp: new Date().toISOString(),
          execution_time_ms: quickResult.analysis_time_ms,
          cached: false
        } as LinkAnalysisResult;
      } else {
        result = await analyzeLink(url, analysisOptions);
      }

      setAnalysisResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Handle Enter key press
  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isAnalyzing) {
      handleAnalysis();
    }
  };

  // Export analysis results
  const exportResults = () => {
    if (!analysisResult) return;
    
    const dataStr = JSON.stringify(analysisResult, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `link-analysis-${analysisResult.analysis_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Link Redirect Analysis</h1>
        <p className="text-gray-600">
          Comprehensive URL analysis with redirect tracking, cloaking detection, and security assessment
        </p>
      </div>

      {/* Input Section */}
      <div className="bg-white border border-gray-200 rounded-lg p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row gap-4">
          <div className="flex-1">
            <label htmlFor="url-input" className="block text-sm font-medium text-gray-700 mb-2">
              URL to Analyze
            </label>
            <div className="relative">
              <input
                id="url-input"
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="https://example.com"
                disabled={isAnalyzing}
                className="w-full px-4 py-3 pr-12 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:opacity-50"
              />
              <Globe className="absolute right-3 top-3 w-6 h-6 text-gray-400" />
            </div>
          </div>
          
          <div className="flex flex-col justify-end">
            <div className="flex gap-2 mb-2">
              <button
                onClick={() => setAnalysisMode(analysisMode === 'quick' ? 'comprehensive' : 'quick')}
                disabled={isAnalyzing}
                className="px-3 py-2 text-sm border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 transition-colors"
              >
                {analysisMode === 'quick' ? (
                  <>
                    <Activity className="w-4 h-4 inline mr-1" />
                    Quick
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4 inline mr-1" />
                    Comprehensive
                  </>
                )}
              </button>
            </div>
            
            <button
              onClick={handleAnalysis}
              disabled={isAnalyzing || !url.trim()}
              className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center"
            >
              {isAnalyzing ? (
                <>
                  <RefreshCw className="w-5 h-5 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Search className="w-5 h-5 mr-2" />
                  Analyze
                </>
              )}
            </button>
          </div>
        </div>

        {/* Analysis Options */}
        {analysisMode === 'comprehensive' && (
          <AnalysisOptions
            options={analysisOptions}
            onOptionsChange={setAnalysisOptions}
            disabled={isAnalyzing}
          />
        )}
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center">
          <AlertCircle className="w-5 h-5 text-red-600 mr-3" />
          <span className="text-red-700">{error}</span>
        </div>
      )}

      {/* Results */}
      {analysisResult && (
        <div className="space-y-6">
          {/* Results Header */}
          <div className="bg-white border border-gray-200 rounded-lg p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-4">
                <div className={`px-4 py-2 rounded-lg text-lg font-semibold ${getVerdictColor(analysisResult.verdict)}`}>
                  {analysisResult.verdict.toUpperCase()}
                </div>
                <div className="text-gray-600">
                  <Clock className="w-4 h-4 inline mr-1" />
                  {analysisResult.execution_time_ms}ms
                  {analysisResult.cached && <span className="ml-2 text-green-600">(Cached)</span>}
                </div>
              </div>
              
              <div className="flex gap-2">
                <button
                  onClick={exportResults}
                  className="px-3 py-2 text-gray-600 border border-gray-300 rounded-md hover:bg-gray-50 transition-colors"
                >
                  <Download className="w-4 h-4" />
                </button>
                <button
                  onClick={() => copyToClipboard(JSON.stringify(analysisResult, null, 2))}
                  className="px-3 py-2 text-gray-600 border border-gray-300 rounded-md hover:bg-gray-50 transition-colors"
                >
                  <Share2 className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <span className="text-sm font-medium text-gray-700">Original URL:</span>
                <div className="text-gray-900 break-all">{analysisResult.original_url}</div>
              </div>
              <div>
                <span className="text-sm font-medium text-gray-700">Final Destination:</span>
                <div className="text-gray-900 break-all flex items-center">
                  {analysisResult.final_url}
                  <ExternalLink 
                    className="w-4 h-4 ml-2 text-gray-400 cursor-pointer hover:text-blue-600" 
                    onClick={() => window.open(analysisResult.final_url, '_blank')}
                  />
                </div>
              </div>
            </div>

            {analysisResult.explanation && (
              <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-md">
                <p className="text-blue-800 text-sm">{analysisResult.explanation}</p>
              </div>
            )}
          </div>

          {/* Analysis Summary */}
          <AnalysisSummaryCard 
            summary={analysisResult.analysis_summary}
            threatScore={analysisResult.threat_score}
            verdict={analysisResult.verdict}
          />

          {/* Threat Indicators */}
          {analysisResult.threat_indicators.length > 0 && (
            <div className="bg-white border border-gray-200 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <AlertCircle className="w-5 h-5 mr-2 text-orange-600" />
                Threat Indicators
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {analysisResult.threat_indicators.map((indicator, idx) => (
                  <div key={idx} className="flex items-center p-2 bg-orange-50 border border-orange-200 rounded-md">
                    <div className="w-2 h-2 bg-orange-500 rounded-full mr-3"></div>
                    <span className="text-orange-800 text-sm">{indicator}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Redirect Chain */}
          {analysisResult.redirect_chain.length > 0 && (
            <div className="bg-white border border-gray-200 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <Activity className="w-5 h-5 mr-2 text-blue-600" />
                Redirect Chain ({analysisResult.redirect_chain.length} hops)
              </h3>
              <div className="space-y-4">
                {analysisResult.redirect_chain.map((hop, idx) => (
                  <RedirectHopCard 
                    key={idx}
                    hop={hop}
                    isLast={idx === analysisResult.redirect_chain.length - 1}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Cloaking Analysis */}
          <CloakingAnalysisPanel analysis={analysisResult.cloaking_analysis} />

          {/* Security Findings */}
          <SecurityFindingsPanel findings={analysisResult.security_findings} />
        </div>
      )}
    </div>
  );
};

export default LinkRedirectAnalysis;