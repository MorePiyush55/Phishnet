import React, { useState, useEffect } from 'react';
import { AlertCircle, Wifi, WifiOff, Database, Clock, CheckCircle, XCircle, Activity } from 'lucide-react';

// Types for service health and cache status
interface ServiceHealth {
  service_name: string;
  is_healthy: boolean;
  circuit_breaker_state: string;
  last_success?: string;
  last_failure?: string;
  quota_remaining?: number;
  error_message?: string;
}

interface CacheStats {
  cache_hits: number;
  cache_misses: number;
  hit_rate: number;
  total_keys: number;
  memory_usage: string;
  status: string;
}

interface ThreatAnalysisResult {
  resource: string;
  resource_type: string;
  aggregated_score: number;
  confidence: number;
  sources_used: string[];
  cache_hit: boolean;
  privacy_protected: boolean;
  processing_time: number;
  errors: string[];
}

// Service status indicator component
const ServiceStatusIndicator: React.FC<{ health: ServiceHealth }> = ({ health }) => {
  const getStatusColor = () => {
    if (!health.is_healthy) return 'text-red-500';
    if (health.circuit_breaker_state === 'half_open') return 'text-yellow-500';
    return 'text-green-500';
  };

  const getStatusIcon = () => {
    if (!health.is_healthy) return <XCircle className="w-4 h-4" />;
    if (health.circuit_breaker_state === 'half_open') return <AlertCircle className="w-4 h-4" />;
    return <CheckCircle className="w-4 h-4" />;
  };

  const getStatusText = () => {
    if (!health.is_healthy) return 'Offline';
    if (health.circuit_breaker_state === 'half_open') return 'Degraded';
    if (health.circuit_breaker_state === 'open') return 'Circuit Open';
    return 'Online';
  };

  return (
    <div className="flex items-center space-x-2 p-2 bg-gray-50 rounded-lg">
      <div className={`flex items-center space-x-1 ${getStatusColor()}`}>
        {getStatusIcon()}
        <span className="font-medium capitalize">{health.service_name}</span>
      </div>
      
      <div className="flex-1">
        <div className="text-sm text-gray-600">{getStatusText()}</div>
        {health.quota_remaining !== undefined && (
          <div className="text-xs text-gray-500">
            Quota: {health.quota_remaining} remaining
          </div>
        )}
      </div>
      
      {health.error_message && (
        <div className="text-xs text-red-600 truncate max-w-32" title={health.error_message}>
          {health.error_message}
        </div>
      )}
    </div>
  );
};

// Cache status component
const CacheStatusCard: React.FC<{ stats: CacheStats }> = ({ stats }) => {
  const hitRateColor = stats.hit_rate >= 0.8 ? 'text-green-600' : stats.hit_rate >= 0.5 ? 'text-yellow-600' : 'text-red-600';
  
  return (
    <div className="bg-white rounded-lg shadow p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-lg font-semibold flex items-center">
          <Database className="w-5 h-5 mr-2 text-blue-500" />
          Cache Performance
        </h3>
        <div className={`px-2 py-1 rounded text-sm font-medium ${
          stats.status === 'healthy' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
        }`}>
          {stats.status}
        </div>
      </div>
      
      <div className="grid grid-cols-2 gap-4 mb-3">
        <div className="text-center">
          <div className="text-2xl font-bold text-blue-600">{stats.cache_hits}</div>
          <div className="text-sm text-gray-600">Cache Hits</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-orange-600">{stats.cache_misses}</div>
          <div className="text-sm text-gray-600">Cache Misses</div>
        </div>
      </div>
      
      <div className="mb-3">
        <div className="flex justify-between items-center mb-1">
          <span className="text-sm text-gray-600">Hit Rate</span>
          <span className={`text-sm font-medium ${hitRateColor}`}>
            {(stats.hit_rate * 100).toFixed(1)}%
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div 
            className={`h-2 rounded-full ${stats.hit_rate >= 0.8 ? 'bg-green-500' : stats.hit_rate >= 0.5 ? 'bg-yellow-500' : 'bg-red-500'}`}
            style={{ width: `${stats.hit_rate * 100}%` }}
          ></div>
        </div>
      </div>
      
      <div className="flex justify-between text-sm text-gray-600">
        <span>Total Keys: {stats.total_keys}</span>
        <span>Memory: {stats.memory_usage}</span>
      </div>
    </div>
  );
};

// Result source indicator
const ResultSourceIndicator: React.FC<{ result: ThreatAnalysisResult }> = ({ result }) => {
  const getSourceIcon = (source: string) => {
    switch (source) {
      case 'virustotal':
        return <Activity className="w-4 h-4 text-red-500" />;
      case 'abuseipdb':
        return <AlertCircle className="w-4 h-4 text-orange-500" />;
      case 'gemini':
        return <Activity className="w-4 h-4 text-purple-500" />;
      default:
        return <Activity className="w-4 h-4 text-gray-500" />;
    }
  };

  return (
    <div className="bg-white rounded-lg border p-3">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center space-x-2">
          {result.cache_hit ? (
            <Database className="w-4 h-4 text-blue-500" />
          ) : (
            <Wifi className="w-4 h-4 text-green-500" />
          )}
          <span className="text-sm font-medium">
            {result.cache_hit ? 'Cached Result' : 'Live Analysis'}
          </span>
        </div>
        
        <div className="flex items-center space-x-1 text-xs text-gray-500">
          <Clock className="w-3 h-3" />
          <span>{(result.processing_time * 1000).toFixed(0)}ms</span>
        </div>
      </div>
      
      <div className="flex items-center space-x-2 mb-2">
        <span className="text-sm text-gray-600">Sources:</span>
        <div className="flex space-x-1">
          {result.sources_used.map((source) => (
            <div key={source} className="flex items-center space-x-1 px-2 py-1 bg-gray-100 rounded text-xs">
              {getSourceIcon(source)}
              <span className="capitalize">{source}</span>
            </div>
          ))}
        </div>
      </div>
      
      {result.privacy_protected && (
        <div className="flex items-center space-x-1 text-xs text-green-600">
          <CheckCircle className="w-3 h-3" />
          <span>Privacy Protected</span>
        </div>
      )}
      
      {result.errors.length > 0 && (
        <div className="mt-2">
          {result.errors.map((error, index) => (
            <div key={index} className="flex items-center space-x-1 text-xs text-red-600">
              <XCircle className="w-3 h-3" />
              <span>{error}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Main dashboard component
const ThreatIntelligenceDashboard: React.FC = () => {
  const [serviceHealth, setServiceHealth] = useState<Record<string, ServiceHealth>>({});
  const [cacheStats, setCacheStats] = useState<CacheStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchServiceHealth = async () => {
    try {
      const response = await fetch('/api/threat-intelligence/health');
      if (!response.ok) throw new Error('Failed to fetch service health');
      const data = await response.json();
      setServiceHealth(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    }
  };

  const fetchCacheStats = async () => {
    try {
      const response = await fetch('/api/threat-intelligence/cache-stats');
      if (!response.ok) throw new Error('Failed to fetch cache stats');
      const data = await response.json();
      setCacheStats(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    }
  };

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      await Promise.all([fetchServiceHealth(), fetchCacheStats()]);
      setLoading(false);
    };

    fetchData();
    
    // Refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        <span className="ml-2 text-gray-600">Loading threat intelligence status...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <div className="flex items-center">
          <XCircle className="w-5 h-5 text-red-500 mr-2" />
          <span className="text-red-800">Error loading dashboard: {error}</span>
        </div>
      </div>
    );
  }

  const healthyServices = Object.values(serviceHealth).filter(s => s.is_healthy).length;
  const totalServices = Object.values(serviceHealth).length;

  return (
    <div className="space-y-6">
      {/* Service Health Overview */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold">Threat Intelligence Services</h2>
          <div className={`px-3 py-1 rounded-full text-sm font-medium ${
            healthyServices === totalServices 
              ? 'bg-green-100 text-green-800' 
              : healthyServices > 0 
                ? 'bg-yellow-100 text-yellow-800'
                : 'bg-red-100 text-red-800'
          }`}>
            {healthyServices}/{totalServices} Services Online
          </div>
        </div>
        
        <div className="grid gap-3">
          {Object.values(serviceHealth).map((health) => (
            <ServiceStatusIndicator key={health.service_name} health={health} />
          ))}
        </div>
      </div>

      {/* Cache Statistics */}
      {cacheStats && <CacheStatusCard stats={cacheStats} />}

      {/* Service Connection Status */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold mb-4">Connection Status</h3>
        <div className="space-y-2">
          {Object.entries(serviceHealth).map(([serviceName, health]) => (
            <div key={serviceName} className="flex items-center justify-between p-2 border rounded">
              <div className="flex items-center space-x-2">
                {health.is_healthy ? (
                  <Wifi className="w-4 h-4 text-green-500" />
                ) : (
                  <WifiOff className="w-4 h-4 text-red-500" />
                )}
                <span className="capitalize">{serviceName}</span>
              </div>
              
              <div className="text-right text-sm">
                {health.last_success && (
                  <div className="text-green-600">
                    Last success: {new Date(health.last_success).toLocaleTimeString()}
                  </div>
                )}
                {health.last_failure && (
                  <div className="text-red-600">
                    Last failure: {new Date(health.last_failure).toLocaleTimeString()}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ThreatIntelligenceDashboard;
export { ServiceStatusIndicator, CacheStatusCard, ResultSourceIndicator };