import React, { 
  useState, 
  useEffect, 
  useRef, 
  useCallback,
  useMemo 
} from 'react';
import { Loader2, Eye, EyeOff, Download, FileText } from 'lucide-react';
import axios from 'axios';

export interface EmailBody {
  id: string;
  html_content?: string;
  text_content?: string;
  attachments?: EmailAttachment[];
  headers?: Record<string, string>;
  size_bytes?: number;
}

export interface EmailAttachment {
  id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  is_safe: boolean;
  scan_result?: {
    status: 'safe' | 'suspicious' | 'malicious';
    confidence: number;
    threats: string[];
  };
}

export interface LazyEmailBodyProps {
  emailId: string;
  onBodyLoad?: (body: EmailBody) => void;
  onError?: (error: string) => void;
  className?: string;
  autoLoad?: boolean;
  showPreview?: boolean;
  maxHeight?: number;
  enableSafeLinks?: boolean;
}

interface EmailBodyCache {
  [emailId: string]: {
    body: EmailBody;
    timestamp: number;
    size: number;
  };
}

// Cache configuration
const CACHE_MAX_SIZE = 50 * 1024 * 1024; // 50MB
const CACHE_MAX_ITEMS = 100;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Global cache instance
let emailBodyCache: EmailBodyCache = {};
let cacheSize = 0;

const cleanupCache = () => {
  const now = Date.now();
  const entries = Object.entries(emailBodyCache);
  
  // Remove expired entries
  const validEntries = entries.filter(([_, cache]) => 
    now - cache.timestamp < CACHE_TTL
  );
  
  // Sort by timestamp and keep only the most recent items
  validEntries.sort(([, a], [, b]) => b.timestamp - a.timestamp);
  
  const keptEntries = validEntries.slice(0, CACHE_MAX_ITEMS);
  
  // Rebuild cache
  emailBodyCache = {};
  cacheSize = 0;
  
  keptEntries.forEach(([id, cache]) => {
    emailBodyCache[id] = cache;
    cacheSize += cache.size;
  });
  
  // If still too large, remove oldest entries
  while (cacheSize > CACHE_MAX_SIZE && Object.keys(emailBodyCache).length > 0) {
    const oldest = Object.entries(emailBodyCache)
      .sort(([, a], [, b]) => a.timestamp - b.timestamp)[0];
    
    if (oldest) {
      cacheSize -= oldest[1].size;
      delete emailBodyCache[oldest[0]];
    }
  }
};

const getCachedBody = (emailId: string): EmailBody | null => {
  const cached = emailBodyCache[emailId];
  if (!cached) return null;
  
  const now = Date.now();
  if (now - cached.timestamp > CACHE_TTL) {
    delete emailBodyCache[emailId];
    cacheSize -= cached.size;
    return null;
  }
  
  return cached.body;
};

const setCachedBody = (emailId: string, body: EmailBody) => {
  const bodySize = JSON.stringify(body).length;
  
  // Clean up cache if needed
  if (cacheSize + bodySize > CACHE_MAX_SIZE || 
      Object.keys(emailBodyCache).length >= CACHE_MAX_ITEMS) {
    cleanupCache();
  }
  
  emailBodyCache[emailId] = {
    body,
    timestamp: Date.now(),
    size: bodySize
  };
  cacheSize += bodySize;
};

export const LazyEmailBody: React.FC<LazyEmailBodyProps> = ({
  emailId,
  onBodyLoad,
  onError,
  className = '',
  autoLoad = false,
  showPreview = true,
  maxHeight = 600,
  enableSafeLinks = false,
}) => {
  const [body, setBody] = useState<EmailBody | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showHtml, setShowHtml] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const abortControllerRef = useRef<AbortController | null>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  // Check cache first
  const cachedBody = useMemo(() => getCachedBody(emailId), [emailId]);

  const loadEmailBody = useCallback(async () => {
    if (loading) return;
    
    // Check cache first
    const cached = getCachedBody(emailId);
    if (cached) {
      setBody(cached);
      onBodyLoad?.(cached);
      return;
    }
    
    setLoading(true);
    setError(null);
    
    // Cancel previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    
    abortControllerRef.current = new AbortController();
    
    try {
      const response = await axios.get(`/api/v1/emails/${emailId}/body`, {
        signal: abortControllerRef.current.signal,
      });
      
      if (response.status === 200) {
        const emailBody = response.data;
        setBody(emailBody);
        setCachedBody(emailId, emailBody);
        onBodyLoad?.(emailBody);
      } else {
        throw new Error(`Failed to load email body: ${response.statusText}`);
      }
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        const errorMessage = err.message || 'Failed to load email body';
        setError(errorMessage);
        onError?.(errorMessage);
      }
    } finally {
      setLoading(false);
    }
  }, [emailId, loading, onBodyLoad, onError]);

  // Auto-load if requested
  useEffect(() => {
    if (autoLoad && !body && !loading && !error) {
      loadEmailBody();
    }
  }, [autoLoad, body, loading, error, loadEmailBody]);

  // Set cached body if available
  useEffect(() => {
    if (cachedBody && !body) {
      setBody(cachedBody);
      onBodyLoad?.(cachedBody);
    }
  }, [cachedBody, body, onBodyLoad]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const sanitizeHtml = (html: string): string => {
    if (!enableSafeLinks) {
      // Remove all links and make them safe
      return html
        .replace(/<a\s+[^>]*href=[^>]*>/gi, '<span class="text-blue-400 underline cursor-pointer" data-blocked-link="true">')
        .replace(/<\/a>/gi, '</span>')
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, 'blocked:')
        .replace(/on\w+\s*=/gi, 'data-blocked=');
    }
    return html;
  };

  const formatSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const handleAttachmentDownload = async (attachment: EmailAttachment) => {
    if (!attachment.is_safe) {
      alert('This attachment has been flagged as potentially unsafe and cannot be downloaded.');
      return;
    }
    
    try {
      const response = await axios.get(`/api/v1/emails/${emailId}/attachments/${attachment.id}/download`, {
        responseType: 'blob'
      });
      const blob = response.data;
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = attachment.filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Failed to download attachment:', err);
      alert('Failed to download attachment');
    }
  };

  const renderContent = () => {
    if (!body) return null;

    const content = showHtml && body.html_content ? body.html_content : body.text_content;
    if (!content) {
      return (
        <div className="p-4 text-gray-400 text-center">
          <FileText className="h-8 w-8 mx-auto mb-2" />
          <p>No content available</p>
        </div>
      );
    }

    if (showHtml && body.html_content) {
      const sanitizedHtml = sanitizeHtml(body.html_content);
      
      return (
        <div className="border border-gray-700 rounded">
          <iframe
            ref={iframeRef}
            srcDoc={sanitizedHtml}
            className="w-full bg-white"
            style={{ height: isExpanded ? 'auto' : maxHeight }}
            title="Email content"
            sandbox="allow-same-origin"
            onLoad={() => {
              if (iframeRef.current) {
                const iframe = iframeRef.current;
                const doc = iframe.contentDocument;
                if (doc) {
                  // Handle blocked links
                  const blockedLinks = doc.querySelectorAll('[data-blocked-link="true"]');
                  blockedLinks.forEach(link => {
                    link.addEventListener('click', (e) => {
                      e.preventDefault();
                      alert('Links are disabled for security. Use the redirect chain viewer to safely analyze links.');
                    });
                  });
                }
              }
            }}
          />
        </div>
      );
    }

    return (
      <div 
        className={`
          bg-gray-800 border border-gray-700 rounded p-4 font-mono text-sm whitespace-pre-wrap
          ${isExpanded ? '' : 'overflow-hidden'}
        `}
        style={{ maxHeight: isExpanded ? 'none' : maxHeight }}
      >
        {content}
      </div>
    );
  };

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          {!autoLoad && !body && (
            <button
              onClick={loadEmailBody}
              disabled={loading}
              className="flex items-center px-3 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Eye className="h-4 w-4 mr-2" />
              )}
              {loading ? 'Loading...' : 'Load Email Body'}
            </button>
          )}
          
          {body && body.html_content && (
            <button
              onClick={() => setShowHtml(!showHtml)}
              className="flex items-center px-3 py-2 bg-gray-600 hover:bg-gray-700 text-white text-sm rounded transition-colors"
            >
              {showHtml ? <EyeOff className="h-4 w-4 mr-2" /> : <Eye className="h-4 w-4 mr-2" />}
              {showHtml ? 'Show Text' : 'Show HTML'}
            </button>
          )}
          
          {body && (
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="flex items-center px-3 py-2 bg-gray-600 hover:bg-gray-700 text-white text-sm rounded transition-colors"
            >
              {isExpanded ? 'Collapse' : 'Expand'}
            </button>
          )}
        </div>
        
        {body?.size_bytes && (
          <span className="text-xs text-gray-400">
            Size: {formatSize(body.size_bytes)}
          </span>
        )}
      </div>

      {/* Loading state */}
      {loading && (
        <div className="flex items-center justify-center p-8">
          <Loader2 className="h-6 w-6 animate-spin text-blue-400 mr-2" />
          <span className="text-gray-400">Loading email body...</span>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="p-4 bg-red-900/20 border border-red-700 rounded text-red-400">
          <p>Error: {error}</p>
          <button
            onClick={() => {
              setError(null);
              loadEmailBody();
            }}
            className="mt-2 text-sm underline hover:no-underline"
          >
            Try again
          </button>
        </div>
      )}

      {/* Email content */}
      {body && !loading && !error && renderContent()}

      {/* Attachments */}
      {body?.attachments && body.attachments.length > 0 && (
        <div className="border-t border-gray-700 pt-4">
          <h4 className="text-sm font-medium text-gray-300 mb-3">
            Attachments ({body.attachments.length})
          </h4>
          <div className="space-y-2">
            {body.attachments.map((attachment) => (
              <div
                key={attachment.id}
                className={`
                  flex items-center justify-between p-3 rounded border
                  ${attachment.is_safe 
                    ? 'border-green-700 bg-green-900/20' 
                    : 'border-red-700 bg-red-900/20'
                  }
                `}
              >
                <div className="flex items-center space-x-3">
                  <FileText className="h-5 w-5 text-gray-400" />
                  <div>
                    <div className="text-sm font-medium text-white">
                      {attachment.filename}
                    </div>
                    <div className="text-xs text-gray-400">
                      {attachment.content_type} • {formatSize(attachment.size_bytes)}
                    </div>
                    {attachment.scan_result && (
                      <div className="text-xs mt-1">
                        <span className={`
                          ${attachment.scan_result.status === 'safe' ? 'text-green-400' : 
                            attachment.scan_result.status === 'suspicious' ? 'text-yellow-400' : 'text-red-400'}
                        `}>
                          {attachment.scan_result.status} ({Math.round(attachment.scan_result.confidence * 100)}%)
                        </span>
                        {attachment.scan_result.threats.length > 0 && (
                          <span className="text-red-400 ml-2">
                            Threats: {attachment.scan_result.threats.join(', ')}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
                
                <button
                  onClick={() => handleAttachmentDownload(attachment)}
                  disabled={!attachment.is_safe}
                  className={`
                    flex items-center px-3 py-1 text-xs rounded transition-colors
                    ${attachment.is_safe
                      ? 'bg-green-600 hover:bg-green-700 text-white'
                      : 'bg-gray-600 text-gray-400 cursor-not-allowed'
                    }
                  `}
                >
                  <Download className="h-3 w-3 mr-1" />
                  {attachment.is_safe ? 'Download' : 'Blocked'}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Cache info (development) */}
      {process.env.NODE_ENV === 'development' && (
        <div className="text-xs text-gray-500 mt-2">
          Cache: {Object.keys(emailBodyCache).length} items, {formatSize(cacheSize)}
        </div>
      )}
    </div>
  );
};

// Hook for managing email body cache
export const useEmailBodyCache = () => {
  const clearCache = useCallback(() => {
    emailBodyCache = {};
    cacheSize = 0;
  }, []);

  const getCacheStats = useCallback(() => ({
    itemCount: Object.keys(emailBodyCache).length,
    totalSize: cacheSize,
    maxSize: CACHE_MAX_SIZE,
    maxItems: CACHE_MAX_ITEMS,
  }), []);

  const preloadEmailBody = useCallback(async (emailId: string): Promise<EmailBody | null> => {
    const cached = getCachedBody(emailId);
    if (cached) return cached;
    
    try {
      const response = await axios.get(`/api/v1/emails/${emailId}/body`);
      if (response.status === 200) {
        const body = response.data;
        setCachedBody(emailId, body);
        return body;
      }
    } catch (err) {
      console.error('Failed to preload email body:', err);
    }
    
    return null;
  }, []);

  return {
    clearCache,
    getCacheStats,
    preloadEmailBody,
  };
};

export default LazyEmailBody;
