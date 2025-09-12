import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Activity, 
  Database, 
  Clock, 
  Zap,
  TrendingUp,
  BarChart3,
  RefreshCw,
  Settings
} from 'lucide-react';
import { useCachePerformance } from '../hooks/useClientCache';

export interface PerformanceMetrics {
  renderTime: number;
  dataLoadTime: number;
  cacheHitRate: number;
  memoryUsage: number;
  totalRequests: number;
  errorRate: number;
  lastUpdate: number;
}

export interface PerformanceMonitorProps {
  className?: string;
  showDetails?: boolean;
  autoRefresh?: boolean;
  refreshInterval?: number;
  onMetricsUpdate?: (metrics: PerformanceMetrics) => void;
}

// Performance measurement utilities
class PerformanceTracker {
  private static instance: PerformanceTracker;
  private metrics: Map<string, number> = new Map();
  private requestCounts: Map<string, number> = new Map();
  private errorCounts: Map<string, number> = new Map();
  private observers: ((metrics: PerformanceMetrics) => void)[] = [];

  static getInstance(): PerformanceTracker {
    if (!PerformanceTracker.instance) {
      PerformanceTracker.instance = new PerformanceTracker();
    }
    return PerformanceTracker.instance;
  }

  startTimer(key: string): () => void {
    const startTime = performance.now();
    return () => {
      const endTime = performance.now();
      this.metrics.set(key, endTime - startTime);
      this.notifyObservers();
    };
  }

  recordRequest(endpoint: string, success: boolean = true): void {
    const currentCount = this.requestCounts.get(endpoint) || 0;
    this.requestCounts.set(endpoint, currentCount + 1);
    
    if (!success) {
      const errorCount = this.errorCounts.get(endpoint) || 0;
      this.errorCounts.set(endpoint, errorCount + 1);
    }
    
    this.notifyObservers();
  }

  getMetrics(): PerformanceMetrics {
    const totalRequests = Array.from(this.requestCounts.values()).reduce((sum, count) => sum + count, 0);
    const totalErrors = Array.from(this.errorCounts.values()).reduce((sum, count) => sum + count, 0);
    
    return {
      renderTime: this.metrics.get('render') || 0,
      dataLoadTime: this.metrics.get('dataLoad') || 0,
      cacheHitRate: this.metrics.get('cacheHitRate') || 0,
      memoryUsage: this.metrics.get('memoryUsage') || 0,
      totalRequests,
      errorRate: totalRequests > 0 ? totalErrors / totalRequests : 0,
      lastUpdate: Date.now(),
    };
  }

  subscribe(callback: (metrics: PerformanceMetrics) => void): () => void {
    this.observers.push(callback);
    return () => {
      const index = this.observers.indexOf(callback);
      if (index > -1) {
        this.observers.splice(index, 1);
      }
    };
  }

  private notifyObservers(): void {
    const metrics = this.getMetrics();
    this.observers.forEach(callback => callback(metrics));
  }

  updateCacheMetrics(hitRate: number, memoryUsage: number): void {
    this.metrics.set('cacheHitRate', hitRate);
    this.metrics.set('memoryUsage', memoryUsage);
    this.notifyObservers();
  }

  clear(): void {
    this.metrics.clear();
    this.requestCounts.clear();
    this.errorCounts.clear();
    this.notifyObservers();
  }
}

// Hook for measuring component performance
export const usePerformanceMetrics = () => {
  const tracker = PerformanceTracker.getInstance();
  
  const measureRender = useCallback(() => {
    return tracker.startTimer('render');
  }, [tracker]);

  const measureDataLoad = useCallback(() => {
    return tracker.startTimer('dataLoad');
  }, [tracker]);

  const recordApiCall = useCallback((endpoint: string, success: boolean = true) => {
    tracker.recordRequest(endpoint, success);
  }, [tracker]);

  return {
    measureRender,
    measureDataLoad,
    recordApiCall,
    getMetrics: () => tracker.getMetrics(),
  };
};

// Performance monitoring component
export const PerformanceMonitor: React.FC<PerformanceMonitorProps> = ({
  className = '',
  showDetails = false,
  autoRefresh = true,
  refreshInterval = 5000,
  onMetricsUpdate,
}) => {
  const [metrics, setMetrics] = useState<PerformanceMetrics | null>(null);
  const [isExpanded, setIsExpanded] = useState(showDetails);
  const { performanceData, getTotalStats } = useCachePerformance();
  const tracker = PerformanceTracker.getInstance();

  // Update performance metrics
  useEffect(() => {
    const updateMetrics = () => {
      const currentMetrics = tracker.getMetrics();
      const totalStats = getTotalStats();
      
      // Update cache metrics in tracker
      tracker.updateCacheMetrics(totalStats.averageHitRate, totalStats.totalMemory);
      
      const updatedMetrics = tracker.getMetrics();
      setMetrics(updatedMetrics);
      onMetricsUpdate?.(updatedMetrics);
    };

    updateMetrics();

    if (autoRefresh) {
      const interval = setInterval(updateMetrics, refreshInterval);
      return () => clearInterval(interval);
    }
  }, [autoRefresh, refreshInterval, tracker, getTotalStats, onMetricsUpdate]);

  // Subscribe to tracker updates
  useEffect(() => {
    const unsubscribe = tracker.subscribe(setMetrics);
    return unsubscribe;
  }, [tracker]);

  const formatTime = (time: number): string => {
    if (time < 1000) return `${time.toFixed(1)}ms`;
    return `${(time / 1000).toFixed(2)}s`;
  };

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatPercentage = (value: number): string => {
    return `${(value * 100).toFixed(1)}%`;
  };

  const getPerformanceColor = (value: number, thresholds: { good: number; warning: number }): string => {
    if (value <= thresholds.good) return 'text-green-400';
    if (value <= thresholds.warning) return 'text-yellow-400';
    return 'text-red-400';
  };

  if (!metrics) {
    return (
      <div className={`flex items-center space-x-2 ${className}`}>
        <Activity className="h-4 w-4 text-gray-400 animate-pulse" />
        <span className="text-sm text-gray-400">Loading metrics...</span>
      </div>
    );
  }

  const totalStats = getTotalStats();

  return (
    <div className={`bg-gray-900 border border-gray-700 rounded-lg ${className}`}>
      {/* Header */}
      <div 
        className="flex items-center justify-between p-3 cursor-pointer hover:bg-gray-800 transition-colors"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center space-x-3">
          <Activity className="h-5 w-5 text-blue-400" />
          <div>
            <h3 className="text-sm font-medium text-white">Performance Monitor</h3>
            <div className="flex items-center space-x-4 text-xs text-gray-400">
              <span className="flex items-center space-x-1">
                <Zap className="h-3 w-3" />
                <span>{formatTime(metrics.renderTime)} render</span>
              </span>
              <span className="flex items-center space-x-1">
                <Database className="h-3 w-3" />
                <span>{formatPercentage(totalStats.averageHitRate)} cache hit</span>
              </span>
              <span className="flex items-center space-x-1">
                <BarChart3 className="h-3 w-3" />
                <span>{formatBytes(totalStats.totalMemory)} memory</span>
              </span>
            </div>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          <button
            onClick={(e) => {
              e.stopPropagation();
              tracker.clear();
            }}
            className="p-1 text-gray-400 hover:text-white transition-colors"
            title="Clear metrics"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
          <Settings className={`h-4 w-4 text-gray-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
        </div>
      </div>

      {/* Detailed metrics */}
      {isExpanded && (
        <div className="p-3 border-t border-gray-700 space-y-4">
          {/* Performance metrics */}
          <div>
            <h4 className="text-sm font-medium text-gray-300 mb-2">Performance Metrics</h4>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-gray-800 p-3 rounded">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-400">Render Time</span>
                  <Clock className="h-4 w-4 text-gray-400" />
                </div>
                <div className={`text-lg font-mono ${getPerformanceColor(metrics.renderTime, { good: 16, warning: 50 })}`}>
                  {formatTime(metrics.renderTime)}
                </div>
              </div>
              
              <div className="bg-gray-800 p-3 rounded">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-400">Data Load Time</span>
                  <Activity className="h-4 w-4 text-gray-400" />
                </div>
                <div className={`text-lg font-mono ${getPerformanceColor(metrics.dataLoadTime, { good: 200, warning: 1000 })}`}>
                  {formatTime(metrics.dataLoadTime)}
                </div>
              </div>
              
              <div className="bg-gray-800 p-3 rounded">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-400">Error Rate</span>
                  <TrendingUp className="h-4 w-4 text-gray-400" />
                </div>
                <div className={`text-lg font-mono ${getPerformanceColor(metrics.errorRate, { good: 0.01, warning: 0.05 })}`}>
                  {formatPercentage(metrics.errorRate)}
                </div>
              </div>
              
              <div className="bg-gray-800 p-3 rounded">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-400">Total Requests</span>
                  <BarChart3 className="h-4 w-4 text-gray-400" />
                </div>
                <div className="text-lg font-mono text-white">
                  {metrics.totalRequests.toLocaleString()}
                </div>
              </div>
            </div>
          </div>

          {/* Cache statistics */}
          <div>
            <h4 className="text-sm font-medium text-gray-300 mb-2">Cache Performance</h4>
            <div className="space-y-2">
              {Object.entries(performanceData).map(([cacheType, stats]) => (
                <div key={cacheType} className="bg-gray-800 p-3 rounded">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-white capitalize">{cacheType}</span>
                    <span className={`text-sm ${getPerformanceColor(1 - stats.hitRate, { good: 0.2, warning: 0.5 })}`}>
                      {formatPercentage(stats.hitRate)} hit rate
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs text-gray-400">
                    <div>
                      <span className="block">Items</span>
                      <span className="text-white">{stats.itemCount}</span>
                    </div>
                    <div>
                      <span className="block">Memory</span>
                      <span className="text-white">{formatBytes(stats.memoryUsed)}</span>
                    </div>
                    <div>
                      <span className="block">Hits/Misses</span>
                      <span className="text-white">{stats.totalHits}/{stats.totalMisses}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Last updated */}
          <div className="text-xs text-gray-500 text-center">
            Last updated: {new Date(metrics.lastUpdate).toLocaleTimeString()}
          </div>
        </div>
      )}
    </div>
  );
};

// Hook for integrating performance monitoring with components
export const useComponentPerformance = (componentName: string) => {
  const { measureRender, measureDataLoad, recordApiCall } = usePerformanceMetrics();

  useEffect(() => {
    const stopTimer = measureRender();
    return stopTimer;
  });

  const trackAsyncOperation = useCallback(async (
    operation: () => Promise<any>,
    operationType: 'render' | 'dataLoad' = 'dataLoad'
  ): Promise<any> => {
    const stopTimer = operationType === 'render' ? measureRender() : measureDataLoad();
    
    try {
      const result = await operation();
      stopTimer();
      return result;
    } catch (error) {
      stopTimer();
      throw error;
    }
  }, [measureRender, measureDataLoad]);

  return {
    trackAsyncOperation,
    recordApiCall,
  };
};

export default PerformanceMonitor;
