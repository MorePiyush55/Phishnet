/**
 * Safe Preview Mode Components
 * 
 * Sanitized content viewing components that allow analysts to safely examine
 * analyzed content without triggering malicious behavior or network requests.
 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
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
  Alert,
  AlertDescription,
  Switch,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Textarea,
  Separator
} from '@/components/ui';
import { 
  Eye, 
  EyeOff, 
  Shield, 
  AlertTriangle, 
  Download, 
  Copy,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Search,
  Filter,
  FileText,
  Code,
  Image as ImageIcon,
  Lock,
  Unlock,
  RefreshCw
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface SafePreviewProps {
  evidenceData: {
    screenshots: ScreenshotEvidence[];
    dom_dumps: DOMEvidence[];
    network_captures: NetworkCapture[];
  };
  jobId: string;
  sessionId: string;
}

interface SafetySettings {
  blockExternalImages: boolean;
  blockJavaScript: boolean;
  blockCSS: boolean;
  blockForms: boolean;
  blockIframes: boolean;
  blockObjects: boolean;
  sanitizeContent: boolean;
  showWarnings: boolean;
}

const SafePreviewViewer: React.FC<SafePreviewProps> = ({ 
  evidenceData, 
  jobId, 
  sessionId 
}) => {
  const [activeTab, setActiveTab] = useState('screenshots');
  const [selectedScreenshot, setSelectedScreenshot] = useState<number>(0);
  const [selectedDomDump, setSelectedDomDump] = useState<number>(0);
  const [zoomLevel, setZoomLevel] = useState(100);
  const [safetySettings, setSafetySettings] = useState<SafetySettings>({
    blockExternalImages: true,
    blockJavaScript: true,
    blockCSS: false,
    blockForms: true,
    blockIframes: true,
    blockObjects: true,
    sanitizeContent: true,
    showWarnings: true
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [highlightedElements, setHighlightedElements] = useState<string[]>([]);
  const [isPreviewLocked, setIsPreviewLocked] = useState(true);
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const { toast } = useToast();

  const sanitizeHTML = useCallback((html: string, settings: SafetySettings): string => {
    let sanitized = html;

    if (settings.sanitizeContent) {
      // Remove dangerous elements and attributes
      sanitized = sanitized.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '<!-- [REMOVED: script] -->');
      sanitized = sanitized.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '/* [REMOVED: event handler] */');
      sanitized = sanitized.replace(/javascript:/gi, '/* [REMOVED: javascript:] */');
      
      if (settings.blockJavaScript) {
        sanitized = sanitized.replace(/<script[^>]*>/gi, '<!-- [BLOCKED: script start] -->');
        sanitized = sanitized.replace(/<\/script>/gi, '<!-- [BLOCKED: script end] -->');
      }
      
      if (settings.blockExternalImages) {
        sanitized = sanitized.replace(/src\s*=\s*["']https?:\/\/[^"']*["']/gi, 
          'src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTIxIDlWN0gzVjlNMjEgOVYxOUgzVjlNMjEgOUgzTTkgMTMuNUw3IDE1LjVMOSAxNy41TTEzIDE3LjVMMTUgMTUuNUwxMyAxMy41TTExIDEzLjVIOSIgc3Ryb2tlPSIjNjY2NjY2IiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPgo8L3N2Zz4K" title="[BLOCKED: External Image]"');
      }
      
      if (settings.blockCSS) {
        sanitized = sanitized.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '<!-- [REMOVED: style] -->');
        sanitized = sanitized.replace(/style\s*=\s*["'][^"']*["']/gi, '/* [REMOVED: inline style] */');
      }
      
      if (settings.blockForms) {
        sanitized = sanitized.replace(/<form[^>]*>/gi, '<!-- [BLOCKED: form start] -->');
        sanitized = sanitized.replace(/<\/form>/gi, '<!-- [BLOCKED: form end] -->');
        sanitized = sanitized.replace(/<input[^>]*>/gi, '<!-- [BLOCKED: input] -->');
        sanitized = sanitized.replace(/<textarea[^>]*>[\s\S]*?<\/textarea>/gi, '<!-- [BLOCKED: textarea] -->');
      }
      
      if (settings.blockIframes) {
        sanitized = sanitized.replace(/<iframe[^>]*>[\s\S]*?<\/iframe>/gi, '<!-- [BLOCKED: iframe] -->');
      }
      
      if (settings.blockObjects) {
        sanitized = sanitized.replace(/<object[^>]*>[\s\S]*?<\/object>/gi, '<!-- [BLOCKED: object] -->');
        sanitized = sanitized.replace(/<embed[^>]*>/gi, '<!-- [BLOCKED: embed] -->');
      }
      
      // Remove all href attributes to prevent navigation
      sanitized = sanitized.replace(/href\s*=\s*["'][^"']*["']/gi, 'href="#" title="[BLOCKED: Navigation disabled in safe mode]"');
      
      // Add CSP meta tag
      const cspMeta = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'; font-src data:;">';
      sanitized = sanitized.replace(/<head>/i, '<head>' + cspMeta);
    }

    return sanitized;
  }, []);

  const highlightSearchResults = useCallback((content: string, term: string): string => {
    if (!term.trim()) return content;
    
    const regex = new RegExp(`(${term})`, 'gi');
    return content.replace(regex, '<mark style="background-color: yellow; padding: 2px;">$1</mark>');
  }, []);

  const loadSafeContent = useCallback((content: string) => {
    if (!iframeRef.current) return;
    
    const sanitizedContent = sanitizeHTML(content, safetySettings);
    const highlightedContent = highlightSearchResults(sanitizedContent, searchTerm);
    
    // Create a safe document
    const safeDocument = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
          <title>Safe Preview</title>
          <style>
            body { 
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
              margin: 20px; 
              line-height: 1.6;
              zoom: ${zoomLevel}%;
            }
            .safe-preview-warning {
              background: #fff3cd;
              border: 1px solid #ffeaa7;
              border-radius: 4px;
              padding: 12px;
              margin-bottom: 20px;
              color: #856404;
            }
            .blocked-element {
              background: #f8d7da;
              border: 1px solid #f5c6cb;
              padding: 8px;
              margin: 4px 0;
              border-radius: 4px;
              color: #721c24;
              font-family: monospace;
              font-size: 12px;
            }
            mark {
              background-color: yellow !important;
              padding: 2px !important;
            }
          </style>
        </head>
        <body>
          ${safetySettings.showWarnings ? `
            <div class="safe-preview-warning">
              ⚠️ <strong>Safe Preview Mode</strong> - This content has been sanitized and dangerous elements have been removed or blocked.
            </div>
          ` : ''}
          ${highlightedContent}
        </body>
      </html>
    `;
    
    const iframe = iframeRef.current;
    const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
    
    if (iframeDoc) {
      iframeDoc.open();
      iframeDoc.write(safeDocument);
      iframeDoc.close();
      
      // Disable all navigation and interaction
      iframeDoc.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        toast({
          title: "Navigation Blocked",
          description: "Navigation is disabled in safe preview mode",
          variant: "destructive"
        });
      });
    }
  }, [sanitizeHTML, highlightSearchResults, safetySettings, searchTerm, zoomLevel, toast]);

  const copyToClipboard = async (content: string) => {
    try {
      await navigator.clipboard.writeText(content);
      toast({
        title: "Copied",
        description: "Content copied to clipboard"
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to copy content",
        variant: "destructive"
      });
    }
  };

  const downloadContent = (content: string, filename: string, mimeType: string = 'text/html') => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const resetZoom = () => setZoomLevel(100);
  const zoomIn = () => setZoomLevel(prev => Math.min(prev + 25, 200));
  const zoomOut = () => setZoomLevel(prev => Math.max(prev - 25, 50));

  return (
    <div className="w-full space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="flex items-center gap-2">
                {isPreviewLocked ? (
                  <Lock className="h-5 w-5 text-green-600" />
                ) : (
                  <Unlock className="h-5 w-5 text-red-600" />
                )}
                Safe Preview Mode
              </CardTitle>
              <p className="text-sm text-gray-600 mt-1">
                Content is sanitized and safe for viewing. Malicious elements are blocked.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-green-600">
                <Shield className="h-3 w-3 mr-1" />
                Protected
              </Badge>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setIsPreviewLocked(!isPreviewLocked)}
              >
                {isPreviewLocked ? (
                  <>
                    <Lock className="h-4 w-4 mr-1" />
                    Locked
                  </>
                ) : (
                  <>
                    <Unlock className="h-4 w-4 mr-1" />
                    Unlocked
                  </>
                )}
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Safety Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Safety Settings</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium">Block JavaScript</label>
              <Switch
                checked={safetySettings.blockJavaScript}
                onCheckedChange={(checked) => 
                  setSafetySettings(prev => ({ ...prev, blockJavaScript: checked }))
                }
                disabled={isPreviewLocked}
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium">Block External Images</label>
              <Switch
                checked={safetySettings.blockExternalImages}
                onCheckedChange={(checked) => 
                  setSafetySettings(prev => ({ ...prev, blockExternalImages: checked }))
                }
                disabled={isPreviewLocked}
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium">Block Forms</label>
              <Switch
                checked={safetySettings.blockForms}
                onCheckedChange={(checked) => 
                  setSafetySettings(prev => ({ ...prev, blockForms: checked }))
                }
                disabled={isPreviewLocked}
              />
            </div>
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium">Sanitize Content</label>
              <Switch
                checked={safetySettings.sanitizeContent}
                onCheckedChange={(checked) => 
                  setSafetySettings(prev => ({ ...prev, sanitizeContent: checked }))
                }
                disabled={isPreviewLocked}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="screenshots">Screenshots</TabsTrigger>
          <TabsTrigger value="dom">DOM Content</TabsTrigger>
          <TabsTrigger value="source">Source Code</TabsTrigger>
        </TabsList>

        {/* Screenshots Tab */}
        <TabsContent value="screenshots" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle className="flex items-center gap-2">
                  <ImageIcon className="h-5 w-5" />
                  Screenshot Preview
                </CardTitle>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={zoomOut}>
                    <ZoomOut className="h-4 w-4" />
                  </Button>
                  <span className="text-sm w-16 text-center">{zoomLevel}%</span>
                  <Button variant="outline" size="sm" onClick={zoomIn}>
                    <ZoomIn className="h-4 w-4" />
                  </Button>
                  <Button variant="outline" size="sm" onClick={resetZoom}>
                    <RotateCcw className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Screenshot selector */}
              {evidenceData.screenshots.length > 1 && (
                <Select 
                  value={selectedScreenshot.toString()} 
                  onValueChange={(value) => setSelectedScreenshot(parseInt(value))}
                >
                  <SelectTrigger className="w-64">
                    <SelectValue placeholder="Select screenshot" />
                  </SelectTrigger>
                  <SelectContent>
                    {evidenceData.screenshots.map((screenshot, index) => (
                      <SelectItem key={index} value={index.toString()}>
                        {screenshot.description || `Screenshot ${index + 1}`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}

              {/* Screenshot display */}
              {evidenceData.screenshots[selectedScreenshot] && (
                <div className="border rounded-lg overflow-hidden">
                  <div 
                    className="bg-gray-100 flex items-center justify-center"
                    style={{ zoom: `${zoomLevel}%` }}
                  >
                    {/* Screenshot placeholder - in real app, would show actual image */}
                    <div className="aspect-video w-full max-w-4xl bg-white border-2 border-dashed border-gray-300 flex items-center justify-center">
                      <div className="text-center">
                        <ImageIcon className="h-24 w-24 mx-auto text-gray-400 mb-4" />
                        <p className="text-lg text-gray-500">Screenshot Preview</p>
                        <p className="text-sm text-gray-400">
                          {evidenceData.screenshots[selectedScreenshot].dimensions}
                        </p>
                        <p className="text-xs text-gray-400 mt-2">
                          {evidenceData.screenshots[selectedScreenshot].description}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Screenshot info */}
              {evidenceData.screenshots[selectedScreenshot] && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-600">Timestamp:</span>
                    <div>{new Date(evidenceData.screenshots[selectedScreenshot].timestamp).toLocaleString()}</div>
                  </div>
                  <div>
                    <span className="text-gray-600">File Size:</span>
                    <div>{(evidenceData.screenshots[selectedScreenshot].file_size / 1024).toFixed(1)} KB</div>
                  </div>
                  <div>
                    <span className="text-gray-600">Dimensions:</span>
                    <div>{evidenceData.screenshots[selectedScreenshot].dimensions}</div>
                  </div>
                  <div>
                    <span className="text-gray-600">Hash:</span>
                    <div className="font-mono text-xs">
                      {evidenceData.screenshots[selectedScreenshot].file_hash.substring(0, 12)}...
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* DOM Content Tab */}
        <TabsContent value="dom" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-5 w-5" />
                  DOM Content Preview
                </CardTitle>
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-2">
                    <Search className="h-4 w-4 text-gray-500" />
                    <input
                      type="text"
                      placeholder="Search content..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="border rounded px-2 py-1 text-sm w-48"
                    />
                  </div>
                  <Button variant="outline" size="sm" onClick={zoomOut}>
                    <ZoomOut className="h-4 w-4" />
                  </Button>
                  <span className="text-sm w-16 text-center">{zoomLevel}%</span>
                  <Button variant="outline" size="sm" onClick={zoomIn}>
                    <ZoomIn className="h-4 w-4" />
                  </Button>
                  <Button variant="outline" size="sm" onClick={resetZoom}>
                    <RotateCcw className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* DOM selector */}
              {evidenceData.dom_dumps.length > 1 && (
                <Select 
                  value={selectedDomDump.toString()} 
                  onValueChange={(value) => setSelectedDomDump(parseInt(value))}
                >
                  <SelectTrigger className="w-64">
                    <SelectValue placeholder="Select DOM dump" />
                  </SelectTrigger>
                  <SelectContent>
                    {evidenceData.dom_dumps.map((dump, index) => (
                      <SelectItem key={index} value={index.toString()}>
                        DOM Dump {index + 1} ({new Date(dump.timestamp).toLocaleTimeString()})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}

              {/* Safe iframe preview */}
              {evidenceData.dom_dumps[selectedDomDump] && (
                <div className="border rounded-lg overflow-hidden">
                  <Alert className="m-4">
                    <Shield className="h-4 w-4" />
                    <AlertDescription>
                      This content has been sanitized for safe viewing. JavaScript, forms, and external resources are blocked.
                    </AlertDescription>
                  </Alert>
                  
                  <iframe
                    ref={iframeRef}
                    className="w-full h-96 border-0"
                    sandbox="allow-same-origin"
                    style={{ zoom: `${zoomLevel}%` }}
                    title="Safe Preview"
                  />
                </div>
              )}

              {/* Actions */}
              {evidenceData.dom_dumps[selectedDomDump] && (
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => loadSafeContent(evidenceData.dom_dumps[selectedDomDump].content)}
                  >
                    <RefreshCw className="h-4 w-4 mr-1" />
                    Reload Preview
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyToClipboard(evidenceData.dom_dumps[selectedDomDump].content)}
                  >
                    <Copy className="h-4 w-4 mr-1" />
                    Copy HTML
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => downloadContent(
                      evidenceData.dom_dumps[selectedDomDump].content,
                      `dom_dump_${selectedDomDump + 1}.html`
                    )}
                  >
                    <Download className="h-4 w-4 mr-1" />
                    Download
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Source Code Tab */}
        <TabsContent value="source" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle className="flex items-center gap-2">
                  <Code className="h-5 w-5" />
                  Source Code View
                </CardTitle>
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-2">
                    <Search className="h-4 w-4 text-gray-500" />
                    <input
                      type="text"
                      placeholder="Search in source..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="border rounded px-2 py-1 text-sm w-48"
                    />
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Source selector */}
              {evidenceData.dom_dumps.length > 1 && (
                <Select 
                  value={selectedDomDump.toString()} 
                  onValueChange={(value) => setSelectedDomDump(parseInt(value))}
                >
                  <SelectTrigger className="w-64">
                    <SelectValue placeholder="Select source" />
                  </SelectTrigger>
                  <SelectContent>
                    {evidenceData.dom_dumps.map((dump, index) => (
                      <SelectItem key={index} value={index.toString()}>
                        Source {index + 1} ({new Date(dump.timestamp).toLocaleTimeString()})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}

              {/* Source code display */}
              {evidenceData.dom_dumps[selectedDomDump] && (
                <ScrollArea className="h-96 border rounded-lg">
                  <div className="p-4">
                    <pre className="text-sm font-mono whitespace-pre-wrap">
                      <code
                        dangerouslySetInnerHTML={{
                          __html: highlightSearchResults(
                            evidenceData.dom_dumps[selectedDomDump].content
                              .replace(/</g, '&lt;')
                              .replace(/>/g, '&gt;'),
                            searchTerm
                          )
                        }}
                      />
                    </pre>
                  </div>
                </ScrollArea>
              )}

              {/* Source actions */}
              {evidenceData.dom_dumps[selectedDomDump] && (
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyToClipboard(evidenceData.dom_dumps[selectedDomDump].content)}
                  >
                    <Copy className="h-4 w-4 mr-1" />
                    Copy Source
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => downloadContent(
                      evidenceData.dom_dumps[selectedDomDump].content,
                      `source_${selectedDomDump + 1}.html`,
                      'text/html'
                    )}
                  >
                    <Download className="h-4 w-4 mr-1" />
                    Download Source
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Security Warning */}
      <Alert>
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          <strong>Security Notice:</strong> This content has been analyzed in a secure sandbox environment. 
          Even in safe preview mode, exercise caution when examining potentially malicious content. 
          All external resources, scripts, and interactive elements have been disabled.
        </AlertDescription>
      </Alert>
    </div>
  );
};

export default SafePreviewViewer;