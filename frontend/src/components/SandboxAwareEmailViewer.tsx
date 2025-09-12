import React, { useState, useEffect, useMemo } from 'react';
import { useApi } from '../hooks/useTypedApi';
import { apiManager } from '../services/apiManager';
import SafeLinkAnalyzer from './SafeLinkAnalyzer';
import { LazyEmailBody } from './LazyEmailBody';
import { Email, Link } from '../types/api';
import { 
  Shield, 
  ExternalLink, 
  Eye, 
  AlertTriangle, 
  CheckCircle, 
  Lock,
  Unlock,
  Activity,
  Monitor,
  Link as LinkIcon,
  Mail,
  Server
} from 'lucide-react';

export interface SandboxAwareEmailViewerProps {
  emailId: string;
  onSafeAction?: (url: string) => void;
  onQuarantine?: (linkId: string) => void;
  className?: string;
}

export const SandboxAwareEmailViewer: React.FC<SandboxAwareEmailViewerProps> = ({
  emailId,
  onSafeAction,
  onQuarantine,
  className = ''
}) => {
  const [selectedLinkId, setSelectedLinkId] = useState<string | null>(null);
  const [sandboxMode, setSandboxMode] = useState<'preview' | 'safe_view' | 'analyzer'>('preview');
  const [showRawEmail, setShowRawEmail] = useState(false);

  // Fetch email data
  const { 
    data: email, 
    loading: emailLoading, 
    error: emailError 
  } = useApi(() => apiManager.emails.get(emailId), {
    immediate: true
  });

  // Fetch links in email
  const { 
    data: emailLinks, 
    loading: linksLoading, 
    error: linksError,
    refresh: refreshLinks 
  } = useApi(() => apiManager.emails.getLinks(emailId), {
    immediate: true
  });

  // Calculate risk summary
  const riskSummary = useMemo(() => {
    if (!emailLinks || !Array.isArray(emailLinks)) return null;
    
    const links = emailLinks as Link[];
    const totalLinks = links.length;
    const safeLinks = links.filter(link => link.is_safe || link.analysis?.verdict === 'safe').length;
    const suspiciousLinks = links.filter(link => link.analysis?.verdict === 'suspicious').length;
    const maliciousLinks = links.filter(link => link.analysis?.verdict === 'malicious').length;
    const unanalyzedLinks = totalLinks - safeLinks - suspiciousLinks - maliciousLinks;

    return {
      totalLinks,
      safeLinks,
      suspiciousLinks,
      maliciousLinks,
      unanalyzedLinks,
      overallRisk: maliciousLinks > 0 ? 'high' : suspiciousLinks > 0 ? 'medium' : safeLinks === totalLinks ? 'low' : 'unknown'
    };
  }, [emailLinks]);

  const handleLinkClick = (linkId: string, url: string) => {
    const link = emailLinks?.find((l: Link) => l.id === linkId);
    
    if (!link) return;

    if (link.is_safe || link.analysis?.verdict === 'safe') {
      // Safe link - can open directly or via callback
      onSafeAction?.(url);
    } else {
      // Unsafe or unknown link - show analyzer
      setSelectedLinkId(linkId);
      setSandboxMode('analyzer');
    }
  };

  const handleLinkAction = (action: 'analyze' | 'screenshot' | 'quarantine', linkId: string) => {
    if (action === 'quarantine') {
      onQuarantine?.(linkId);
    }
    // Refresh links after any action
    refreshLinks();
  };

  if (emailLoading) {
    return (
      <div className={`flex items-center justify-center p-8 ${className}`}>
        <div className="flex items-center space-x-2">
          <Activity className="h-5 w-5 animate-pulse" />
          <span>Loading email...</span>
        </div>
      </div>
    );
  }

  if (emailError || !email) {
    return (
      <div className={`bg-red-50 border border-red-200 rounded-lg p-4 ${className}`}>
        <div className="flex items-center space-x-2 text-red-700">
          <AlertTriangle className="h-5 w-5" />
          <span>Error loading email</span>
        </div>
        <p className="text-red-600 text-sm mt-1">{emailError}</p>
      </div>
    );
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Security Header */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-6 w-6 text-blue-600" />
            <div>
              <h3 className="font-semibold text-blue-900">Sandbox-Protected Email Viewer</h3>
              <p className="text-blue-700 text-sm">
                All links are analyzed for safety before allowing access
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setSandboxMode(sandboxMode === 'safe_view' ? 'preview' : 'safe_view')}
              className={`px-3 py-2 rounded text-sm font-medium ${
                sandboxMode === 'safe_view' 
                  ? 'bg-green-500 text-white' 
                  : 'bg-green-100 text-green-700'
              }`}
            >
              <Monitor className="h-4 w-4 inline mr-1" />
              {sandboxMode === 'safe_view' ? 'Exit Safe View' : 'Safe View'}
            </button>
            <button
              onClick={() => setShowRawEmail(!showRawEmail)}
              className="px-3 py-2 bg-gray-100 text-gray-700 rounded text-sm hover:bg-gray-200"
            >
              <Mail className="h-4 w-4 inline mr-1" />
              {showRawEmail ? 'Hide Raw' : 'Show Raw'}
            </button>
          </div>
        </div>
      </div>

      {/* Risk Summary */}
      {riskSummary && riskSummary.totalLinks > 0 && (
        <div className={`border rounded-lg p-4 ${
          riskSummary.overallRisk === 'high' 
            ? 'bg-red-50 border-red-200' 
            : riskSummary.overallRisk === 'medium'
            ? 'bg-yellow-50 border-yellow-200'
            : riskSummary.overallRisk === 'low'
            ? 'bg-green-50 border-green-200'
            : 'bg-gray-50 border-gray-200'
        }`}>
          <div className="flex items-center justify-between mb-3">
            <h4 className="font-medium text-gray-900">Link Security Analysis</h4>
            <span className={`px-2 py-1 text-xs font-medium rounded ${
              riskSummary.overallRisk === 'high' 
                ? 'bg-red-100 text-red-700' 
                : riskSummary.overallRisk === 'medium'
                ? 'bg-yellow-100 text-yellow-700'
                : riskSummary.overallRisk === 'low'
                ? 'bg-green-100 text-green-700'
                : 'bg-gray-100 text-gray-700'
            }`}>
              {riskSummary.overallRisk.toUpperCase()} RISK
            </span>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-700">{riskSummary.totalLinks}</div>
              <div className="text-sm text-gray-600">Total Links</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">{riskSummary.safeLinks}</div>
              <div className="text-sm text-gray-600">Safe</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-600">{riskSummary.suspiciousLinks}</div>
              <div className="text-sm text-gray-600">Suspicious</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-600">{riskSummary.maliciousLinks}</div>
              <div className="text-sm text-gray-600">Malicious</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-600">{riskSummary.unanalyzedLinks}</div>
              <div className="text-sm text-gray-600">Unanalyzed</div>
            </div>
          </div>
        </div>
      )}

      {/* Email Header */}
      <div className="bg-white border rounded-lg p-4">
        <div className="space-y-3">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">{email.subject}</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-medium text-gray-700">From:</span>
              <span className="ml-2 text-gray-900">{email.sender}</span>
            </div>
            <div>
              <span className="font-medium text-gray-700">To:</span>
              <span className="ml-2 text-gray-900">{email.recipient}</span>
            </div>
            <div>
              <span className="font-medium text-gray-700">Date:</span>
              <span className="ml-2 text-gray-900">{new Date(email.received_at).toLocaleString()}</span>
            </div>
            <div>
              <span className="font-medium text-gray-700">Status:</span>
              <span className={`ml-2 px-2 py-1 text-xs rounded ${
                email.status === 'safe' ? 'bg-green-100 text-green-700' :
                email.status === 'malicious' ? 'bg-red-100 text-red-700' :
                email.status === 'suspicious' ? 'bg-yellow-100 text-yellow-700' :
                'bg-gray-100 text-gray-700'
              }`}>
                {email.status}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Link Analysis Results */}
      {selectedLinkId && sandboxMode === 'analyzer' && (
        <div className="bg-white border rounded-lg">
          <div className="border-b p-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold">Link Analysis</h3>
              <button
                onClick={() => {
                  setSelectedLinkId(null);
                  setSandboxMode('preview');
                }}
                className="text-gray-500 hover:text-gray-700"
              >
                ✕
              </button>
            </div>
          </div>
          <SafeLinkAnalyzer
            linkId={selectedLinkId}
            emailId={emailId}
            onAction={handleLinkAction}
            className="p-0"
          />
        </div>
      )}

      {/* Email Body */}
      <div className="bg-white border rounded-lg">
        <div className="border-b p-4">
          <h3 className="text-lg font-semibold">Email Content</h3>
        </div>
        
        {sandboxMode === 'safe_view' ? (
          <SafeEmailBodyViewer
            email={email}
            links={emailLinks as Link[] || []}
            onLinkClick={handleLinkClick}
            className="p-4"
          />
        ) : (
          <LazyEmailBody
            emailId={emailId}
            enableSafeLinks={true}
            className="p-4"
          />
        )}
      </div>

      {/* Raw Email */}
      {showRawEmail && (
        <div className="bg-white border rounded-lg">
          <div className="border-b p-4">
            <h3 className="text-lg font-semibold">Raw Email Data</h3>
          </div>
          <div className="p-4">
            <pre className="bg-gray-50 p-4 rounded text-sm overflow-auto max-h-96">
              {JSON.stringify(email, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {/* All Links Table */}
      {emailLinks && Array.isArray(emailLinks) && emailLinks.length > 0 && (
        <div className="bg-white border rounded-lg">
          <div className="border-b p-4">
            <h3 className="text-lg font-semibold">All Links in Email</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">URL</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">Display Text</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">Status</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {(emailLinks as Link[]).map((link) => (
                  <tr key={link.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm">
                      <div className="max-w-md truncate">{link.url}</div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600">
                      <div className="max-w-32 truncate">{link.display_text}</div>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className={`px-2 py-1 text-xs rounded ${
                        link.is_safe || link.analysis?.verdict === 'safe' 
                          ? 'bg-green-100 text-green-700' 
                          : link.analysis?.verdict === 'malicious'
                          ? 'bg-red-100 text-red-700'
                          : link.analysis?.verdict === 'suspicious'
                          ? 'bg-yellow-100 text-yellow-700'
                          : 'bg-gray-100 text-gray-700'
                      }`}>
                        {link.analysis?.verdict || (link.is_safe ? 'safe' : 'unanalyzed')}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleLinkClick(link.id, link.url)}
                          className={`px-2 py-1 text-xs rounded ${
                            link.is_safe || link.analysis?.verdict === 'safe'
                              ? 'bg-green-500 text-white hover:bg-green-600'
                              : 'bg-blue-500 text-white hover:bg-blue-600'
                          }`}
                        >
                          {link.is_safe || link.analysis?.verdict === 'safe' ? (
                            <ExternalLink className="h-3 w-3" />
                          ) : (
                            <Shield className="h-3 w-3" />
                          )}
                        </button>
                        <button
                          onClick={() => {
                            setSelectedLinkId(link.id);
                            setSandboxMode('analyzer');
                          }}
                          className="px-2 py-1 text-xs bg-purple-500 text-white rounded hover:bg-purple-600"
                        >
                          <Eye className="h-3 w-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

// Safe email body viewer that strips/replaces dangerous content
interface SafeEmailBodyViewerProps {
  email: Email;
  links: Link[];
  onLinkClick: (linkId: string, url: string) => void;
  className?: string;
}

const SafeEmailBodyViewer: React.FC<SafeEmailBodyViewerProps> = ({
  email,
  links,
  onLinkClick,
  className = ''
}) => {
  // Replace links in content with safe placeholders
  const createSafeContent = (content: string) => {
    let safeContent = content;
    
    links.forEach(link => {
      const linkElement = `<a href="#" onclick="handleLinkClick('${link.id}', '${link.url}')" 
        class="text-blue-600 hover:text-blue-800 underline cursor-pointer
        ${link.is_safe || link.analysis?.verdict === 'safe' 
          ? 'border-green-200 bg-green-50' 
          : link.analysis?.verdict === 'malicious'
          ? 'border-red-200 bg-red-50'
          : link.analysis?.verdict === 'suspicious' 
          ? 'border-yellow-200 bg-yellow-50'
          : 'border-gray-200 bg-gray-50'
        } border rounded px-1"
        title="Link: ${link.url} (Status: ${link.analysis?.verdict || (link.is_safe ? 'safe' : 'unanalyzed')})"
      >
        ${link.display_text}
        ${link.is_safe || link.analysis?.verdict === 'safe' ? '✅' : 
          link.analysis?.verdict === 'malicious' ? '⚠️' :
          link.analysis?.verdict === 'suspicious' ? '⚠️' : '❓'}
      </a>`;
      
      // Replace the original link with our safe version
      safeContent = safeContent.replace(
        new RegExp(`<a[^>]*href=["']${link.url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["'][^>]*>.*?</a>`, 'gi'),
        linkElement
      );
    });

    return safeContent;
  };

  useEffect(() => {
    // Make handleLinkClick available globally for the onclick handlers
    (window as any).handleLinkClick = onLinkClick;
    
    return () => {
      delete (window as any).handleLinkClick;
    };
  }, [onLinkClick]);

  return (
    <div className={className}>
      <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded">
        <div className="flex items-center space-x-2 text-green-700">
          <Shield className="h-4 w-4" />
          <span className="text-sm font-medium">Safe View Mode</span>
        </div>
        <p className="text-green-600 text-sm mt-1">
          All links have been replaced with safe placeholders. Click any link to analyze it first.
        </p>
      </div>
      
      <div 
        className="prose max-w-none"
        dangerouslySetInnerHTML={{ 
          __html: email.body?.html_content 
            ? createSafeContent(email.body.html_content)
            : email.body?.text_content || 'No content available'
        }}
      />
    </div>
  );
};

export default SandboxAwareEmailViewer;
