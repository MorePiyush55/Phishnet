/**
 * Screenshot Evidence Viewer Component
 * 
 * Displays captured screenshots from threat analysis with:
 * - Full-screen evidence modal
 * - Before/after comparison views
 * - Annotation and threat highlighting
 * - Evidence export capabilities
 * - Timeline scrubbing
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Camera, 
  ZoomIn, 
  ZoomOut, 
  Download, 
  Share2, 
  RotateCcw,
  Maximize2,
  X,
  ChevronLeft,
  ChevronRight,
  Clock,
  AlertTriangle,
  Eye,
  Target,
  Compare,
  FileImage,
  Calendar
} from 'lucide-react';

interface ScreenshotEvidence {
  id: string;
  url: string;
  thumbnail_url: string;
  full_url: string;
  timestamp: string;
  hop_index: number;
  threat_score: number;
  annotations?: {
    suspicious_elements: Array<{
      type: 'login_form' | 'download_button' | 'phishing_text' | 'fake_brand' | 'popup';
      coordinates: { x: number; y: number; width: number; height: number };
      description: string;
      confidence: number;
    }>;
    visual_similarity?: {
      matched_brand: string;
      similarity_score: number;
      template_url: string;
    };
  };
  metadata: {
    viewport: { width: number; height: number };
    user_agent: string;
    load_time_ms: number;
    page_size_bytes: number;
    final_url: string;
  };
}

interface ScreenshotEvidenceProps {
  screenshots: ScreenshotEvidence[];
  selectedIndex?: number;
  onScreenshotSelect?: (screenshot: ScreenshotEvidence, index: number) => void;
  showTimeline?: boolean;
  allowExport?: boolean;
}

const ThreatAnnotation: React.FC<{
  annotation: ScreenshotEvidence['annotations']['suspicious_elements'][0];
  isVisible: boolean;
  zoom: number;
  onToggle: () => void;
}> = ({ annotation, isVisible, zoom, onToggle }) => {
  const { coordinates, type, description, confidence } = annotation;
  
  const getTypeColor = (type: string) => {
    switch (type) {
      case 'login_form': return 'border-red-500 bg-red-500/20';
      case 'download_button': return 'border-orange-500 bg-orange-500/20';
      case 'phishing_text': return 'border-yellow-500 bg-yellow-500/20';
      case 'fake_brand': return 'border-purple-500 bg-purple-500/20';
      case 'popup': return 'border-blue-500 bg-blue-500/20';
      default: return 'border-gray-500 bg-gray-500/20';
    }
  };
  
  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'login_form': return '🔑';
      case 'download_button': return '⬇️';
      case 'phishing_text': return '⚠️';
      case 'fake_brand': return '🎭';
      case 'popup': return '📱';
      default: return '🔍';
    }
  };
  
  if (!isVisible) return null;
  
  return (
    <div
      className={`absolute border-2 cursor-pointer ${getTypeColor(type)}`}
      style={{
        left: `${coordinates.x * zoom}px`,
        top: `${coordinates.y * zoom}px`,
        width: `${coordinates.width * zoom}px`,
        height: `${coordinates.height * zoom}px`,
        transform: 'translate(0, 0)',
      }}
      onClick={onToggle}
      title={description}
    >
      <div className="absolute -top-6 left-0 bg-black text-white text-xs px-2 py-1 rounded whitespace-nowrap">
        {getTypeIcon(type)} {type.replace('_', ' ')} ({(confidence * 100).toFixed(0)}%)
      </div>
    </div>
  );
};

const ScreenshotViewer: React.FC<{
  screenshot: ScreenshotEvidence;
  isFullscreen?: boolean;
  showAnnotations?: boolean;
  onAnnotationToggle?: () => void;
}> = ({ screenshot, isFullscreen = false, showAnnotations = false, onAnnotationToggle }) => {
  const [zoom, setZoom] = useState(1);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  
  const handleZoomIn = () => setZoom(prev => Math.min(prev * 1.5, 4));
  const handleZoomOut = () => setZoom(prev => Math.max(prev / 1.5, 0.25));
  const handleReset = () => {
    setZoom(1);
    setPosition({ x: 0, y: 0 });
  };
  
  const handleMouseDown = (e: React.MouseEvent) => {
    if (zoom > 1) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - position.x, y: e.clientY - position.y });
    }
  };
  
  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      setPosition({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    }
  };
  
  const handleMouseUp = () => {
    setIsDragging(false);
  };
  
  return (
    <div className={`relative ${isFullscreen ? 'h-screen' : 'h-96'} overflow-hidden bg-gray-100 rounded-lg`}>
      {/* Toolbar */}
      <div className="absolute top-2 left-2 z-10 flex gap-2">
        <Button size="sm" variant="secondary" onClick={handleZoomIn}>
          <ZoomIn className="w-4 h-4" />
        </Button>
        <Button size="sm" variant="secondary" onClick={handleZoomOut}>
          <ZoomOut className="w-4 h-4" />
        </Button>
        <Button size="sm" variant="secondary" onClick={handleReset}>
          <RotateCcw className="w-4 h-4" />
        </Button>
        {screenshot.annotations?.suspicious_elements && (
          <Button 
            size="sm" 
            variant={showAnnotations ? "default" : "secondary"} 
            onClick={onAnnotationToggle}
          >
            <Target className="w-4 h-4" />
            Threats
          </Button>
        )}
      </div>
      
      {/* Zoom indicator */}
      <div className="absolute top-2 right-2 z-10 bg-black/70 text-white px-2 py-1 rounded text-sm">
        {(zoom * 100).toFixed(0)}%
      </div>
      
      {/* Screenshot container */}
      <div
        className="w-full h-full cursor-move"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <div
          className="relative"
          style={{
            transform: `translate(${position.x}px, ${position.y}px) scale(${zoom})`,
            transformOrigin: '0 0',
            transition: isDragging ? 'none' : 'transform 0.2s ease',
          }}
        >
          <img
            src={screenshot.full_url}
            alt={`Screenshot from ${screenshot.url}`}
            className="max-w-none"
            draggable={false}
          />
          
          {/* Annotations */}
          {showAnnotations && screenshot.annotations?.suspicious_elements?.map((annotation, index) => (
            <ThreatAnnotation
              key={index}
              annotation={annotation}
              isVisible={showAnnotations}
              zoom={zoom}
              onToggle={() => {}}
            />
          ))}
        </div>
      </div>
      
      {/* Metadata overlay */}
      <div className="absolute bottom-2 left-2 right-2 bg-black/70 text-white p-2 rounded text-sm">
        <div className="flex justify-between items-center">
          <div>
            <div className="font-semibold truncate">{new URL(screenshot.url).hostname}</div>
            <div className="text-gray-300 text-xs">
              {new Date(screenshot.timestamp).toLocaleString()}
            </div>
          </div>
          <Badge variant={screenshot.threat_score >= 0.7 ? 'destructive' : 'secondary'}>
            {(screenshot.threat_score * 100).toFixed(0)}% risk
          </Badge>
        </div>
      </div>
    </div>
  );
};

const ScreenshotTimeline: React.FC<{
  screenshots: ScreenshotEvidence[];
  selectedIndex: number;
  onSelect: (index: number) => void;
}> = ({ screenshots, selectedIndex, onSelect }) => {
  return (
    <div className="space-y-4">
      <h4 className="text-sm font-semibold flex items-center gap-2">
        <Clock className="w-4 h-4" />
        Screenshot Timeline
      </h4>
      
      <div className="flex gap-2 overflow-x-auto pb-2">
        {screenshots.map((screenshot, index) => (
          <div
            key={screenshot.id}
            className={`flex-shrink-0 cursor-pointer transition-all duration-200 ${
              index === selectedIndex 
                ? 'ring-2 ring-blue-500 ring-offset-2' 
                : 'hover:ring-1 hover:ring-gray-300'
            }`}
            onClick={() => onSelect(index)}
          >
            <div className="relative">
              <img
                src={screenshot.thumbnail_url}
                alt={`Screenshot ${index + 1}`}
                className="w-24 h-16 object-cover rounded border"
              />
              
              {/* Threat indicator */}
              <div className="absolute top-1 right-1">
                <Badge 
                  variant={screenshot.threat_score >= 0.7 ? 'destructive' : 'secondary'}
                  className="text-xs px-1 py-0"
                >
                  {(screenshot.threat_score * 100).toFixed(0)}%
                </Badge>
              </div>
              
              {/* Hop indicator */}
              <div className="absolute bottom-1 left-1">
                <Badge variant="outline" className="text-xs px-1 py-0">
                  {index + 1}
                </Badge>
              </div>
            </div>
            
            <div className="text-center mt-1">
              <div className="text-xs text-gray-600 truncate w-24">
                {new URL(screenshot.url).hostname.split('.')[0]}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const ComparisonView: React.FC<{
  before: ScreenshotEvidence;
  after: ScreenshotEvidence;
}> = ({ before, after }) => {
  const [showDifferences, setShowDifferences] = useState(false);
  
  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h4 className="text-sm font-semibold flex items-center gap-2">
          <Compare className="w-4 h-4" />
          Before/After Comparison
        </h4>
        
        <Button 
          size="sm" 
          variant={showDifferences ? "default" : "outline"}
          onClick={() => setShowDifferences(!showDifferences)}
        >
          {showDifferences ? 'Hide' : 'Show'} Differences
        </Button>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Before (Hop {before.hop_index + 1})</CardTitle>
          </CardHeader>
          <CardContent>
            <img
              src={before.thumbnail_url}
              alt="Before screenshot"
              className="w-full h-48 object-cover rounded border"
            />
            <div className="mt-2 space-y-1">
              <div className="flex justify-between text-xs">
                <span>Threat Score:</span>
                <Badge variant={before.threat_score >= 0.7 ? 'destructive' : 'secondary'}>
                  {(before.threat_score * 100).toFixed(0)}%
                </Badge>
              </div>
              <div className="text-xs text-gray-600 truncate">
                {before.url}
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">After (Hop {after.hop_index + 1})</CardTitle>
          </CardHeader>
          <CardContent>
            <img
              src={after.thumbnail_url}
              alt="After screenshot"
              className="w-full h-48 object-cover rounded border"
            />
            <div className="mt-2 space-y-1">
              <div className="flex justify-between text-xs">
                <span>Threat Score:</span>
                <Badge variant={after.threat_score >= 0.7 ? 'destructive' : 'secondary'}>
                  {(after.threat_score * 100).toFixed(0)}%
                </Badge>
              </div>
              <div className="text-xs text-gray-600 truncate">
                {after.url}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
      
      {/* Similarity analysis */}
      {before.annotations?.visual_similarity && after.annotations?.visual_similarity && (
        <Alert>
          <Eye className="h-4 w-4" />
          <AlertDescription>
            <strong>Visual similarity detected:</strong> Both pages show {before.annotations.visual_similarity.similarity_score > 0.8 ? 'high' : 'moderate'} similarity to {before.annotations.visual_similarity.matched_brand} branding.
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};

const ScreenshotEvidenceViewer: React.FC<ScreenshotEvidenceProps> = ({ 
  screenshots, 
  selectedIndex = 0, 
  onScreenshotSelect,
  showTimeline = true,
  allowExport = true
}) => {
  const [currentIndex, setCurrentIndex] = useState(selectedIndex);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showAnnotations, setShowAnnotations] = useState(false);
  const [activeTab, setActiveTab] = useState('viewer');
  
  const currentScreenshot = screenshots[currentIndex];
  
  useEffect(() => {
    setCurrentIndex(selectedIndex);
  }, [selectedIndex]);
  
  const handleNext = () => {
    const nextIndex = (currentIndex + 1) % screenshots.length;
    setCurrentIndex(nextIndex);
    onScreenshotSelect?.(screenshots[nextIndex], nextIndex);
  };
  
  const handlePrevious = () => {
    const prevIndex = currentIndex === 0 ? screenshots.length - 1 : currentIndex - 1;
    setCurrentIndex(prevIndex);
    onScreenshotSelect?.(screenshots[prevIndex], prevIndex);
  };
  
  const handleExport = async () => {
    try {
      const response = await fetch(currentScreenshot.full_url);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      
      const link = document.createElement('a');
      link.href = url;
      link.download = `screenshot-${currentScreenshot.hop_index + 1}-${new Date(currentScreenshot.timestamp).getTime()}.png`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to export screenshot:', error);
    }
  };
  
  if (!currentScreenshot) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <FileImage className="w-12 h-12 mx-auto text-gray-400 mb-4" />
          <p className="text-gray-600">No screenshots available</p>
        </CardContent>
      </Card>
    );
  }
  
  return (
    <>
      <Card className="w-full">
        <CardHeader>
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Camera className="w-5 h-5" />
                Screenshot Evidence
              </CardTitle>
              <div className="text-sm text-gray-600 mt-1">
                {currentIndex + 1} of {screenshots.length} • 
                Captured {new Date(currentScreenshot.timestamp).toLocaleString()}
              </div>
            </div>
            
            <div className="flex gap-2">
              {screenshots.length > 1 && (
                <>
                  <Button size="sm" variant="outline" onClick={handlePrevious}>
                    <ChevronLeft className="w-4 h-4" />
                  </Button>
                  <Button size="sm" variant="outline" onClick={handleNext}>
                    <ChevronRight className="w-4 h-4" />
                  </Button>
                </>
              )}
              <Button size="sm" variant="outline" onClick={() => setIsFullscreen(true)}>
                <Maximize2 className="w-4 h-4" />
              </Button>
              {allowExport && (
                <Button size="sm" variant="outline" onClick={handleExport}>
                  <Download className="w-4 h-4" />
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="viewer">Screenshot</TabsTrigger>
              {showTimeline && <TabsTrigger value="timeline">Timeline</TabsTrigger>}
              {screenshots.length > 1 && <TabsTrigger value="compare">Compare</TabsTrigger>}
            </TabsList>
            
            <TabsContent value="viewer">
              <ScreenshotViewer
                screenshot={currentScreenshot}
                showAnnotations={showAnnotations}
                onAnnotationToggle={() => setShowAnnotations(!showAnnotations)}
              />
            </TabsContent>
            
            {showTimeline && (
              <TabsContent value="timeline">
                <ScreenshotTimeline
                  screenshots={screenshots}
                  selectedIndex={currentIndex}
                  onSelect={(index) => {
                    setCurrentIndex(index);
                    onScreenshotSelect?.(screenshots[index], index);
                  }}
                />
              </TabsContent>
            )}
            
            {screenshots.length > 1 && (
              <TabsContent value="compare">
                <ComparisonView
                  before={screenshots[0]}
                  after={screenshots[screenshots.length - 1]}
                />
              </TabsContent>
            )}
          </Tabs>
        </CardContent>
      </Card>
      
      {/* Fullscreen Modal */}
      <Dialog open={isFullscreen} onOpenChange={setIsFullscreen}>
        <DialogContent className="max-w-screen-2xl h-screen max-h-screen p-0">
          <DialogHeader className="absolute top-4 left-4 z-20 bg-black/70 text-white p-2 rounded">
            <DialogTitle className="flex items-center gap-2">
              <Camera className="w-5 h-5" />
              Screenshot Evidence - Full View
            </DialogTitle>
          </DialogHeader>
          
          <Button
            className="absolute top-4 right-4 z-20"
            size="sm"
            variant="secondary"
            onClick={() => setIsFullscreen(false)}
          >
            <X className="w-4 h-4" />
          </Button>
          
          <ScreenshotViewer
            screenshot={currentScreenshot}
            isFullscreen
            showAnnotations={showAnnotations}
            onAnnotationToggle={() => setShowAnnotations(!showAnnotations)}
          />
        </DialogContent>
      </Dialog>
    </>
  );
};

export default ScreenshotEvidenceViewer;
export type { ScreenshotEvidence, ScreenshotEvidenceProps };