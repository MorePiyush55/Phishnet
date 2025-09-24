/**
 * Enhanced Link Redirect Analysis Frontend Components
 * 
 * Provides comprehensive visualization for redirect chain analysis,
 * cloaking detection, TLS validation, and threat assessment.
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Activity, 
  Shield, 
  AlertTriangle, 
  ExternalLink, 
  Clock, 
  Lock,
  Unlock,
  Globe,
  Eye,
  EyeOff,
  RefreshCw,
  Download,
  Copy,
  Share2,
  Zap
} from 'lucide-react';

// Types for link analysis
interface TLSCertificate {
  subject: string;
  issuer: string;
  common_name: string;
  san_list: string[];
  not_before: string;
  not_after: string;
  is_valid: boolean;
  is_self_signed: boolean;
  is_expired: boolean;
  hostname_matches: boolean;
  fingerprint_sha256: string;
  serial_number: string;
  signature_algorithm: string;
  issuer_organization: string;
  validation_errors: string[];
}

interface RedirectHop {
  hop_number: number;
  url: string;
  method: string;
  status_code: number;
  redirect_type: string;
  location_header?: string;
  hostname: string;
  ip_address?: string;
  tls_certificate?: TLSCertificate;
  response_time_ms: number;
  content_hash: string;
  content_length: number;
  headers: Record<string, string>;
  meta_refresh_delay?: number;
  javascript_redirects: string[];
  suspicious_patterns: string[];
  timestamp: string;
  final_effective_url: string;
}

interface CloakingAnalysis {
  cloaking_detected: boolean;
  cloaking_confidence: number;
  cloaking_indicators: string[];
  browser_behavior: Record<string, any>;
  content_differences: Record<string, any>;
  js_behavior: Record<string, any>;
  cross_ua_differences: Record<string, any>;
}

interface SecurityFindings {
  ip_domain_mismatch: boolean;
  cert_hostname_mismatch: boolean;
  suspicious_tld: boolean;
  suspicious_patterns: string[];
  domain_reputation: Record<string, any>;
  ssl_issues: string[];
}

interface AnalysisSummary {
  total_redirects: number;
  final_destination: string;
  cloaking_detected: boolean;
  cloaking_confidence: number;
  threat_score: number;
  unique_domains: number;
  https_coverage: number;
  suspicious_patterns_count: number;
  analysis_duration_ms: number;
}

interface LinkAnalysisResult {
  analysis_id: string;
  original_url: string;
  final_url: string;
  threat_score: number;
  confidence: number;
  verdict: string;
  explanation: string;
  threat_indicators: string[];
  redirect_chain: RedirectHop[];
  cloaking_analysis: CloakingAnalysis;
  security_findings: SecurityFindings;
  analysis_summary: AnalysisSummary;
  timing_analysis: Record<string, number>;
  analysis_metadata: Record<string, any>;
  timestamp: string;
  execution_time_ms: number;
  cached: boolean;
}

// API Functions
const analyzeLink = async (url: string, options: any = {}): Promise<LinkAnalysisResult> => {
  const response = await fetch('/api/v1/redirect-analysis/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${localStorage.getItem('access_token')}`
    },
    body: JSON.stringify({
      url,
      include_cloaking_detection: options.includeCloaking ?? true,
      max_redirects: options.maxRedirects ?? 10,
      timeout_seconds: options.timeoutSeconds ?? 30,
      ...options
    })
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Analysis failed');
  }

  return response.json();
};

const quickScanLink = async (url: string) => {
  const response = await fetch('/api/v1/redirect-analysis/quick-scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${localStorage.getItem('access_token')}`
    },
    body: JSON.stringify({ url })
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Quick scan failed');
  }

  return response.json();
};

// Utility Functions
const getThreatColor = (score: number): string => {
  if (score >= 0.8) return 'text-red-600 bg-red-50 border-red-200';
  if (score >= 0.6) return 'text-orange-600 bg-orange-50 border-orange-200';
  if (score >= 0.3) return 'text-yellow-600 bg-yellow-50 border-yellow-200';
  return 'text-green-600 bg-green-50 border-green-200';
};

const getVerdictColor = (verdict: string): string => {
  switch (verdict.toLowerCase()) {
    case 'malicious': return 'text-red-600 bg-red-50 border-red-200';
    case 'suspicious': return 'text-orange-600 bg-orange-50 border-orange-200';
    case 'safe': return 'text-green-600 bg-green-50 border-green-200';
    default: return 'text-gray-600 bg-gray-50 border-gray-200';
  }
};

const formatDomain = (url: string): string => {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
};

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
};

// TLS Certificate Badge Component
const TLSCertificateBadge: React.FC<{ certificate?: TLSCertificate; className?: string }> = ({ 
  certificate, 
  className = '' 
}) => {
  if (!certificate) {
    return (
      <div className={`inline-flex items-center px-2 py-1 rounded-md text-xs border ${className}`}>
        <Unlock className="w-3 h-3 mr-1 text-gray-400" />
        <span className="text-gray-500">No TLS</span>
      </div>
    );
  }

  const isSecure = certificate.is_valid && !certificate.is_expired && certificate.hostname_matches;
  const bgColor = isSecure ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200';
  const textColor = isSecure ? 'text-green-700' : 'text-red-700';

  return (
    <div className={`inline-flex items-center px-2 py-1 rounded-md text-xs border ${bgColor} ${textColor} ${className}`}>
      {isSecure ? (
        <Lock className="w-3 h-3 mr-1" />
      ) : (
        <Unlock className="w-3 h-3 mr-1" />
      )}
      <span>
        {isSecure ? 'Valid TLS' : 'Invalid TLS'}
      </span>
      {certificate.validation_errors.length > 0 && (
        <AlertTriangle className="w-3 h-3 ml-1" />
      )}
    </div>
  );
};

// Redirect Hop Card Component
const RedirectHopCard: React.FC<{ hop: RedirectHop; isLast: boolean }> = ({ hop, isLast }) => {
  const [showDetails, setShowDetails] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const success = await copyToClipboard(hop.url);
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getStatusColor = (code: number): string => {
    if (code >= 200 && code < 300) return 'text-green-600 bg-green-50';
    if (code >= 300 && code < 400) return 'text-blue-600 bg-blue-50';
    if (code >= 400 && code < 500) return 'text-orange-600 bg-orange-50';
    return 'text-red-600 bg-red-50';
  };

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-3">
          <div className="flex items-center justify-center w-8 h-8 bg-blue-100 text-blue-600 rounded-full text-sm font-semibold">
            {hop.hop_number}
          </div>
          <div>
            <div className="font-medium text-gray-900 truncate max-w-md">
              {formatDomain(hop.url)}
            </div>
            <div className="text-sm text-gray-500">{hop.method} • {hop.redirect_type}</div>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          <div className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(hop.status_code)}`}>
            {hop.status_code}
          </div>
          <TLSCertificateBadge certificate={hop.tls_certificate} />
          <button
            onClick={handleCopy}
            className="p-1 text-gray-400 hover:text-gray-600 transition-colors"
            title="Copy URL"
          >
            {copied ? <span className="text-green-600 text-xs">✓</span> : <Copy className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Indicators */}
      <div className="flex flex-wrap gap-2 mb-3">
        {hop.suspicious_patterns.map((pattern, idx) => (
          <span key={idx} className="px-2 py-1 bg-red-50 text-red-700 text-xs rounded-md border border-red-200">
            {pattern}
          </span>
        ))}
        {hop.javascript_redirects.length > 0 && (
          <span className="px-2 py-1 bg-yellow-50 text-yellow-700 text-xs rounded-md border border-yellow-200">
            JS Redirect
          </span>
        )}
        {hop.meta_refresh_delay && (
          <span className="px-2 py-1 bg-blue-50 text-blue-700 text-xs rounded-md border border-blue-200">
            Meta Refresh ({hop.meta_refresh_delay}s)
          </span>
        )}
      </div>

      {/* Details Toggle */}
      <button
        onClick={() => setShowDetails(!showDetails)}
        className="text-sm text-blue-600 hover:text-blue-800 flex items-center"
      >
        {showDetails ? 'Hide Details' : 'Show Details'}
        <Activity className={`w-4 h-4 ml-1 transition-transform ${showDetails ? 'rotate-180' : ''}`} />
      </button>

      {/* Detailed Information */}
      {showDetails && (
        <div className="mt-4 space-y-3 border-t pt-3">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-medium text-gray-700">IP Address:</span>
              <div className="text-gray-600">{hop.ip_address || 'N/A'}</div>
            </div>
            <div>
              <span className="font-medium text-gray-700">Response Time:</span>
              <div className="text-gray-600">{hop.response_time_ms}ms</div>
            </div>
            <div>
              <span className="font-medium text-gray-700">Content Length:</span>
              <div className="text-gray-600">{hop.content_length.toLocaleString()} bytes</div>
            </div>
            <div>
              <span className="font-medium text-gray-700">Content Hash:</span>
              <div className="text-gray-600 font-mono text-xs">{hop.content_hash.slice(0, 16)}...</div>
            </div>
          </div>

          {/* Full URL */}
          <div>
            <span className="font-medium text-gray-700">Full URL:</span>
            <div className="text-gray-600 break-all text-sm bg-gray-50 p-2 rounded mt-1">
              {hop.url}
            </div>
          </div>

          {/* TLS Certificate Details */}
          {hop.tls_certificate && (
            <div>
              <span className="font-medium text-gray-700">TLS Certificate:</span>
              <div className="text-sm space-y-1 mt-1">
                <div><strong>Subject:</strong> {hop.tls_certificate.subject}</div>
                <div><strong>Issuer:</strong> {hop.tls_certificate.issuer_organization}</div>
                <div><strong>Valid Until:</strong> {new Date(hop.tls_certificate.not_after).toLocaleDateString()}</div>
                {hop.tls_certificate.validation_errors.length > 0 && (
                  <div className="text-red-600">
                    <strong>Errors:</strong> {hop.tls_certificate.validation_errors.join(', ')}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Connection line to next hop */}
      {!isLast && (
        <div className="flex justify-center mt-4">
          <div className="w-0.5 h-6 bg-gray-300"></div>
        </div>
      )}
    </div>
  );
};

// Cloaking Analysis Component
const CloakingAnalysisPanel: React.FC<{ analysis: CloakingAnalysis }> = ({ analysis }) => {
  return (
    <div className="bg-white border border-gray-200 rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 flex items-center">
          {analysis.cloaking_detected ? (
            <EyeOff className="w-5 h-5 mr-2 text-red-600" />
          ) : (
            <Eye className="w-5 h-5 mr-2 text-green-600" />
          )}
          Cloaking Analysis
        </h3>
        <div className={`px-3 py-1 rounded-md text-sm font-medium ${
          analysis.cloaking_detected 
            ? 'bg-red-50 text-red-700 border border-red-200' 
            : 'bg-green-50 text-green-700 border border-green-200'
        }`}>
          {analysis.cloaking_detected ? 'Cloaking Detected' : 'No Cloaking'}
        </div>
      </div>

      <div className="space-y-4">
        {/* Confidence Score */}
        <div>
          <div className="flex justify-between text-sm text-gray-600 mb-1">
            <span>Confidence</span>
            <span>{Math.round(analysis.cloaking_confidence * 100)}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div 
              className="h-2 rounded-full bg-gradient-to-r from-green-500 to-red-500"
              style={{ width: `${analysis.cloaking_confidence * 100}%` }}
            />
          </div>
        </div>

        {/* Indicators */}
        {analysis.cloaking_indicators.length > 0 && (
          <div>
            <h4 className="font-medium text-gray-700 mb-2">Cloaking Indicators</h4>
            <div className="space-y-1">
              {analysis.cloaking_indicators.map((indicator, idx) => (
                <div key={idx} className="flex items-center text-sm">
                  <AlertTriangle className="w-4 h-4 text-orange-500 mr-2" />
                  <span className="text-gray-700">{indicator}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Browser Behavior */}
        {Object.keys(analysis.browser_behavior).length > 0 && (
          <div>
            <h4 className="font-medium text-gray-700 mb-2">Browser Behavior</h4>
            <div className="bg-gray-50 p-3 rounded-md text-sm">
              <pre className="text-gray-600 whitespace-pre-wrap">
                {JSON.stringify(analysis.browser_behavior, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// Security Findings Component
const SecurityFindingsPanel: React.FC<{ findings: SecurityFindings }> = ({ findings }) => {
  const securityIssues = [
    { key: 'ip_domain_mismatch', label: 'IP/Domain Mismatch', value: findings.ip_domain_mismatch },
    { key: 'cert_hostname_mismatch', label: 'Certificate Hostname Mismatch', value: findings.cert_hostname_mismatch },
    { key: 'suspicious_tld', label: 'Suspicious TLD', value: findings.suspicious_tld }
  ];

  const hasIssues = securityIssues.some(issue => issue.value) || 
                   findings.suspicious_patterns.length > 0 || 
                   findings.ssl_issues.length > 0;

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 flex items-center">
          <Shield className={`w-5 h-5 mr-2 ${hasIssues ? 'text-red-600' : 'text-green-600'}`} />
          Security Findings
        </h3>
        <div className={`px-3 py-1 rounded-md text-sm font-medium ${
          hasIssues 
            ? 'bg-red-50 text-red-700 border border-red-200' 
            : 'bg-green-50 text-green-700 border border-green-200'
        }`}>
          {hasIssues ? 'Issues Found' : 'All Clear'}
        </div>
      </div>

      <div className="space-y-4">
        {/* Security Checks */}
        <div>
          <h4 className="font-medium text-gray-700 mb-2">Security Checks</h4>
          <div className="space-y-2">
            {securityIssues.map((issue) => (
              <div key={issue.key} className="flex items-center justify-between text-sm">
                <span className="text-gray-700">{issue.label}</span>
                <span className={`px-2 py-1 rounded text-xs ${
                  issue.value 
                    ? 'bg-red-50 text-red-700 border border-red-200' 
                    : 'bg-green-50 text-green-700 border border-green-200'
                }`}>
                  {issue.value ? 'Failed' : 'Passed'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Suspicious Patterns */}
        {findings.suspicious_patterns.length > 0 && (
          <div>
            <h4 className="font-medium text-gray-700 mb-2">Suspicious Patterns</h4>
            <div className="space-y-1">
              {findings.suspicious_patterns.map((pattern, idx) => (
                <div key={idx} className="flex items-center text-sm">
                  <AlertTriangle className="w-4 h-4 text-orange-500 mr-2" />
                  <span className="text-gray-700">{pattern}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* SSL Issues */}
        {findings.ssl_issues.length > 0 && (
          <div>
            <h4 className="font-medium text-gray-700 mb-2">SSL/TLS Issues</h4>
            <div className="space-y-1">
              {findings.ssl_issues.map((issue, idx) => (
                <div key={idx} className="flex items-center text-sm">
                  <Unlock className="w-4 h-4 text-red-500 mr-2" />
                  <span className="text-gray-700">{issue}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export { 
  TLSCertificateBadge, 
  RedirectHopCard, 
  CloakingAnalysisPanel, 
  SecurityFindingsPanel,
  analyzeLink,
  quickScanLink,
  getThreatColor,
  getVerdictColor,
  formatDomain,
  copyToClipboard
};

export type {
  TLSCertificate,
  RedirectHop,
  CloakingAnalysis,
  SecurityFindings,
  AnalysisSummary,
  LinkAnalysisResult
};