/**
 * Pipeline Progress UI Components for Real-time Email Scanning Status
 * React components that integrate with the backend orchestrator to show pipeline progress.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { 
  CheckCircle, 
  Clock, 
  AlertCircle, 
  RefreshCw, 
  Mail, 
  Search, 
  Shield, 
  BarChart3,
  Eye,
  Zap
} from 'lucide-react';

// Types for pipeline status
interface PipelineStage {
  name: string;
  status: 'pending' | 'active' | 'completed' | 'failed';
  startTime?: number;
  endTime?: number;
  duration?: number;
  error?: string;
}

interface JobStatus {
  job_id: string;
  email_id: string;
  stage: string;
  status: 'processing' | 'completed' | 'failed';
  progress_percent: number;
  created_at: number;
  updated_at: number;
  processing_time: number;
  error_count: number;
  last_error?: string;
  stage_times: Record<string, number>;
  estimated_completion?: number;
  results: {
    parsed_data: boolean;
    extracted_resources: number;
    sandbox_results: boolean;
    api_results: boolean;
    final_score?: any;
  };
}

interface OrchestratorStats {
  active_jobs: number;
  is_running: boolean;
  stage_distribution: Record<string, number>;
  worker_pool_stats: any;
  queue_stats: any;
  timestamp: number;
}

// Pipeline stage configuration
const PIPELINE_STAGES = [
  { 
    key: 'queued', 
    name: 'Queued', 
    icon: Clock, 
    description: 'Email queued for processing',
    color: 'text-gray-500'
  },
  { 
    key: 'parsing', 
    name: 'Parsing', 
    icon: Mail, 
    description: 'Extracting email content and metadata',
    color: 'text-blue-500'
  },
  { 
    key: 'extracting', 
    name: 'Extracting', 
    icon: Search, 
    description: 'Finding URLs, IPs, domains, and hashes',
    color: 'text-purple-500'
  },
  { 
    key: 'sandbox_analysis', 
    name: 'Sandbox', 
    icon: Eye, 
    description: 'Analyzing redirects and browser behavior',
    color: 'text-orange-500'
  },
  { 
    key: 'api_analysis', 
    name: 'Threat Intel', 
    icon: Shield, 
    description: 'Checking against threat intelligence APIs',
    color: 'text-red-500'
  },
  { 
    key: 'aggregating', 
    name: 'Aggregating', 
    icon: BarChart3, 
    description: 'Combining analysis results',
    color: 'text-green-500'
  },
  { 
    key: 'scoring', 
    name: 'Scoring', 
    icon: Zap, 
    description: 'Calculating final threat score',
    color: 'text-yellow-500'
  },
  { 
    key: 'completed', 
    name: 'Completed', 
    icon: CheckCircle, 
    description: 'Analysis complete',
    color: 'text-green-600'
  }
];

// Progress bar component
const ProgressBar: React.FC<{ progress: number; className?: string }> = ({ 
  progress, 
  className = '' 
}) => {
  return (
    <div className={`w-full bg-gray-200 rounded-full h-2 ${className}`}>
      <div 
        className="bg-blue-600 h-2 rounded-full transition-all duration-300 ease-out"
        style={{ width: `${Math.min(progress, 100)}%` }}
      />
    </div>
  );
};

// Individual stage component
const PipelineStageComponent: React.FC<{
  stage: typeof PIPELINE_STAGES[0];
  currentStage: string;
  status: JobStatus;
  isActive: boolean;
  isCompleted: boolean;
  isFailed: boolean;
}> = ({ stage, currentStage, status, isActive, isCompleted, isFailed }) => {
  const Icon = stage.icon;
  
  const getStatusColor = () => {
    if (isFailed) return 'text-red-500 bg-red-50 border-red-200';
    if (isCompleted) return 'text-green-500 bg-green-50 border-green-200';
    if (isActive) return `${stage.color} bg-blue-50 border-blue-200`;
    return 'text-gray-400 bg-gray-50 border-gray-200';
  };
  
  const getStageTime = () => {
    const stageTime = status.stage_times[stage.key];
    if (stageTime) {
      return `${stageTime.toFixed(1)}s`;
    }
    return null;
  };
  
  return (
    <div className="flex items-center space-x-4">
      {/* Stage Icon */}
      <div className={`
        flex items-center justify-center w-10 h-10 rounded-full border-2
        ${getStatusColor()}
        transition-all duration-300
      `}>
        {isActive && !isFailed ? (
          <RefreshCw className="w-5 h-5 animate-spin" />
        ) : isFailed ? (
          <AlertCircle className="w-5 h-5" />
        ) : (
          <Icon className="w-5 h-5" />
        )}
      </div>
      
      {/* Stage Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between">
          <h4 className={`
            text-sm font-medium
            ${isActive || isCompleted ? 'text-gray-900' : 'text-gray-500'}
          `}>
            {stage.name}
          </h4>
          {getStageTime() && (
            <span className="text-xs text-gray-500">
              {getStageTime()}
            </span>
          )}
        </div>
        <p className="text-xs text-gray-500 mt-1">
          {stage.description}
        </p>
        {isFailed && status.last_error && (
          <p className="text-xs text-red-600 mt-1 truncate">
            Error: {status.last_error}
          </p>
        )}
      </div>
    </div>
  );
};

// Main pipeline progress component
export const PipelineProgress: React.FC<{
  jobId: string;
  emailId: string;
  onComplete?: (result: any) => void;
  refreshInterval?: number;
}> = ({ 
  jobId, 
  emailId, 
  onComplete, 
  refreshInterval = 2000 
}) => {
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch job status from API
  const fetchStatus = useCallback(async () => {
    try {
      const response = await fetch(`/api/jobs/${jobId}/status`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      setStatus(data);
      setError(null);
      
      // Check if job is complete
      if (data.status === 'completed' && onComplete) {
        onComplete(data.results);
      }
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch status');
      console.error('Error fetching job status:', err);
    } finally {
      setLoading(false);
    }
  }, [jobId, onComplete]);

  // Set up polling
  useEffect(() => {
    fetchStatus();
    
    const interval = setInterval(() => {
      if (status?.status !== 'completed' && status?.status !== 'failed') {
        fetchStatus();
      }
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [fetchStatus, refreshInterval, status?.status]);

  // Estimate completion time
  const getEstimatedCompletion = () => {
    if (!status?.estimated_completion) return null;
    
    const remainingTime = status.estimated_completion - Date.now() / 1000;
    if (remainingTime <= 0) return 'Completing...';
    
    if (remainingTime < 60) {
      return `~${Math.ceil(remainingTime)}s remaining`;
    } else {
      return `~${Math.ceil(remainingTime / 60)}m remaining`;
    }
  };

  // Format processing time
  const formatProcessingTime = (seconds: number) => {
    if (seconds < 60) {
      return `${seconds.toFixed(1)}s`;
    } else {
      const minutes = Math.floor(seconds / 60);
      const remainingSeconds = Math.floor(seconds % 60);
      return `${minutes}m ${remainingSeconds}s`;
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg border p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="space-y-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="flex items-center space-x-4">
                <div className="w-10 h-10 bg-gray-200 rounded-full"></div>
                <div className="flex-1">
                  <div className="h-3 bg-gray-200 rounded w-1/3 mb-2"></div>
                  <div className="h-2 bg-gray-200 rounded w-2/3"></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-white rounded-lg border p-6">
        <div className="flex items-center space-x-3 text-red-600">
          <AlertCircle className="w-5 h-5" />
          <div>
            <h3 className="font-medium">Error Loading Pipeline Status</h3>
            <p className="text-sm text-red-500 mt-1">{error}</p>
          </div>
        </div>
        <button 
          onClick={fetchStatus}
          className="mt-4 px-4 py-2 bg-red-100 text-red-700 rounded hover:bg-red-200 transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!status) {
    return null;
  }

  const currentStageIndex = PIPELINE_STAGES.findIndex(s => s.key === status.stage);
  const isJobFailed = status.status === 'failed';

  return (
    <div className="bg-white rounded-lg border">
      {/* Header */}
      <div className="p-6 border-b">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Email Scan Progress
            </h3>
            <p className="text-sm text-gray-500 mt-1">
              Email ID: {emailId} • Job ID: {jobId.slice(0, 8)}...
            </p>
          </div>
          <div className="text-right">
            <div className={`
              inline-flex items-center px-3 py-1 rounded-full text-sm font-medium
              ${status.status === 'completed' ? 'bg-green-100 text-green-800' :
                status.status === 'failed' ? 'bg-red-100 text-red-800' :
                'bg-blue-100 text-blue-800'}
            `}>
              {status.status === 'processing' ? 'Processing' : 
               status.status === 'completed' ? 'Completed' : 
               status.status === 'failed' ? 'Failed' : status.status}
            </div>
          </div>
        </div>
        
        {/* Overall Progress */}
        <div className="mt-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-600">Overall Progress</span>
            <span className="text-sm font-medium text-gray-900">
              {status.progress_percent}%
            </span>
          </div>
          <ProgressBar progress={status.progress_percent} />
        </div>
        
        {/* Timing Info */}
        <div className="mt-4 grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-gray-500">Processing Time:</span>
            <span className="ml-2 font-medium">
              {formatProcessingTime(status.processing_time)}
            </span>
          </div>
          {getEstimatedCompletion() && (
            <div>
              <span className="text-gray-500">Estimated:</span>
              <span className="ml-2 font-medium">
                {getEstimatedCompletion()}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Pipeline Stages */}
      <div className="p-6">
        <div className="space-y-6">
          {PIPELINE_STAGES.filter(s => s.key !== 'failed').map((stage, index) => {
            const isActive = stage.key === status.stage && !isJobFailed;
            const isCompleted = index < currentStageIndex || status.status === 'completed';
            const isFailed = isJobFailed && stage.key === status.stage;
            
            return (
              <PipelineStageComponent
                key={stage.key}
                stage={stage}
                currentStage={status.stage}
                status={status}
                isActive={isActive}
                isCompleted={isCompleted}
                isFailed={isFailed}
              />
            );
          })}
        </div>
      </div>

      {/* Results Summary */}
      {status.status === 'completed' && (
        <div className="p-6 border-t bg-gray-50">
          <h4 className="text-sm font-medium text-gray-900 mb-3">
            Analysis Results
          </h4>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-500">Resources Found:</span>
              <span className="ml-2 font-medium">
                {status.results.extracted_resources}
              </span>
            </div>
            <div>
              <span className="text-gray-500">Sandbox Analysis:</span>
              <span className="ml-2 font-medium">
                {status.results.sandbox_results ? 'Completed' : 'Skipped'}
              </span>
            </div>
            <div>
              <span className="text-gray-500">API Analysis:</span>
              <span className="ml-2 font-medium">
                {status.results.api_results ? 'Completed' : 'Skipped'}
              </span>
            </div>
            {status.results.final_score && (
              <div>
                <span className="text-gray-500">Threat Score:</span>
                <span className="ml-2 font-medium">
                  {status.results.final_score.threat_score}/100
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Error Details */}
      {isJobFailed && (
        <div className="p-6 border-t bg-red-50">
          <div className="flex items-start space-x-3">
            <AlertCircle className="w-5 h-5 text-red-500 mt-0.5" />
            <div>
              <h4 className="text-sm font-medium text-red-900">
                Pipeline Failed
              </h4>
              {status.last_error && (
                <p className="text-sm text-red-700 mt-1">
                  {status.last_error}
                </p>
              )}
              <p className="text-xs text-red-600 mt-2">
                Failed after {status.error_count} error(s) in {formatProcessingTime(status.processing_time)}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Dashboard component for multiple jobs
export const PipelineDashboard: React.FC = () => {
  const [stats, setStats] = useState<OrchestratorStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch('/api/orchestrator/stats');
        const data = await response.json();
        setStats(data);
      } catch (err) {
        console.error('Error fetching orchestrator stats:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);

    return () => clearInterval(interval);
  }, []);

  if (loading || !stats) {
    return <div>Loading dashboard...</div>;
  }

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-6 rounded-lg border">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <RefreshCw className="h-8 w-8 text-blue-500" />
            </div>
            <div className="ml-4">
              <div className="text-sm font-medium text-gray-500">Active Jobs</div>
              <div className="text-2xl font-bold text-gray-900">{stats.active_jobs}</div>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <CheckCircle className="h-8 w-8 text-green-500" />
            </div>
            <div className="ml-4">
              <div className="text-sm font-medium text-gray-500">Completed</div>
              <div className="text-2xl font-bold text-gray-900">
                {stats.stage_distribution.completed || 0}
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Clock className="h-8 w-8 text-yellow-500" />
            </div>
            <div className="ml-4">
              <div className="text-sm font-medium text-gray-500">Queued</div>
              <div className="text-2xl font-bold text-gray-900">
                {stats.stage_distribution.queued || 0}
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <AlertCircle className="h-8 w-8 text-red-500" />
            </div>
            <div className="ml-4">
              <div className="text-sm font-medium text-gray-500">Failed</div>
              <div className="text-2xl font-bold text-gray-900">
                {stats.stage_distribution.failed || 0}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Pipeline Stage Distribution */}
      <div className="bg-white p-6 rounded-lg border">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Pipeline Stage Distribution
        </h3>
        <div className="space-y-3">
          {PIPELINE_STAGES.filter(s => s.key !== 'failed').map(stage => {
            const count = stats.stage_distribution[stage.key] || 0;
            const percentage = stats.active_jobs > 0 ? (count / stats.active_jobs) * 100 : 0;
            
            return (
              <div key={stage.key} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <stage.icon className={`w-4 h-4 ${stage.color}`} />
                  <span className="text-sm font-medium text-gray-900">
                    {stage.name}
                  </span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-20 bg-gray-200 rounded-full h-2">
                    <div 
                      className="bg-blue-600 h-2 rounded-full"
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                  <span className="text-sm text-gray-500 w-8 text-right">
                    {count}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default PipelineProgress;
