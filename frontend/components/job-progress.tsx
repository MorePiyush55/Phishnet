/**
 * Job Progress Component
 * Displays real-time progress for background email analysis jobs
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  CheckCircle, 
  Clock, 
  AlertCircle, 
  XCircle, 
  RefreshCw,
  Eye,
  Download,
  Trash2
} from 'lucide-react';

interface JobProgress {
  job_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  analysis_type: 'quick' | 'standard' | 'comprehensive';
  estimated_completion?: string;
  result?: any;
  error?: string;
  created_at: string;
  updated_at: string;
  processing_time?: number;
}

interface JobProgressCardProps {
  job: JobProgress;
  onCancel?: (jobId: string) => void;
  onRetry?: (jobId: string) => void;
  onViewResult?: (jobId: string, result: any) => void;
  onDownload?: (jobId: string, result: any) => void;
  showActions?: boolean;
}

const JobProgressCard: React.FC<JobProgressCardProps> = ({
  job,
  onCancel,
  onRetry,
  onViewResult,
  onDownload,
  showActions = true
}) => {
  const getStatusIcon = () => {
    switch (job.status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'processing':
        return <RefreshCw className="w-5 h-5 text-blue-500 animate-spin" />;
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'cancelled':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />;
      default:
        return <Clock className="w-5 h-5 text-gray-500" />;
    }
  };

  const getStatusColor = () => {
    switch (job.status) {
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'processing':
        return 'bg-blue-100 text-blue-800';
      case 'failed':
        return 'bg-red-100 text-red-800';
      case 'cancelled':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getAnalysisTypeColor = () => {
    switch (job.analysis_type) {
      case 'quick':
        return 'bg-green-100 text-green-800';
      case 'comprehensive':
        return 'bg-purple-100 text-purple-800';
      default:
        return 'bg-blue-100 text-blue-800';
    }
  };

  const formatTime = (seconds?: number) => {
    if (!seconds) return 'N/A';
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds.toFixed(0)}s`;
  };

  return (
    <Card className="mb-4">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {getStatusIcon()}
            <div>
              <p className="font-medium text-sm">Job {job.job_id.slice(0, 8)}...</p>
              <div className="flex items-center space-x-2 mt-1">
                <Badge className={getStatusColor()}>
                  {job.status.toUpperCase()}
                </Badge>
                <Badge className={getAnalysisTypeColor()}>
                  {job.analysis_type.toUpperCase()}
                </Badge>
              </div>
            </div>
          </div>
          
          {showActions && (
            <div className="flex items-center space-x-2">
              {job.status === 'completed' && job.result && (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => onViewResult?.(job.job_id, job.result)}
                  >
                    <Eye className="w-4 h-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => onDownload?.(job.job_id, job.result)}
                  >
                    <Download className="w-4 h-4" />
                  </Button>
                </>
              )}
              
              {job.status === 'failed' && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => onRetry?.(job.job_id)}
                >
                  <RefreshCw className="w-4 h-4" />
                </Button>
              )}
              
              {(job.status === 'pending' || job.status === 'processing') && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => onCancel?.(job.job_id)}
                >
                  <XCircle className="w-4 h-4" />
                </Button>
              )}
            </div>
          )}
        </div>
      </CardHeader>

      <CardContent>
        {/* Progress Bar */}
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span>Progress</span>
            <span>{job.progress}%</span>
          </div>
          <Progress 
            value={job.progress} 
            className={`w-full ${
              job.status === 'failed' ? 'bg-red-100' : 
              job.status === 'completed' ? 'bg-green-100' : ''
            }`}
          />
        </div>

        {/* Job Details */}
        <div className="mt-4 space-y-2 text-sm text-gray-600">
          <div className="flex justify-between">
            <span>Created:</span>
            <span>{new Date(job.created_at).toLocaleString()}</span>
          </div>
          
          {job.processing_time && (
            <div className="flex justify-between">
              <span>Processing Time:</span>
              <span>{formatTime(job.processing_time)}</span>
            </div>
          )}
          
          {job.estimated_completion && job.status !== 'completed' && (
            <div className="flex justify-between">
              <span>Est. Completion:</span>
              <span>{job.estimated_completion}</span>
            </div>
          )}
        </div>

        {/* Error Message */}
        {job.error && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
            <p className="text-sm text-red-800 font-medium">Error:</p>
            <p className="text-sm text-red-700 mt-1">{job.error}</p>
          </div>
        )}

        {/* Success Summary */}
        {job.status === 'completed' && job.result && (
          <div className="mt-4 p-3 bg-green-50 border border-green-200 rounded-md">
            <p className="text-sm text-green-800 font-medium">Analysis Complete</p>
            <div className="mt-2 space-y-1 text-sm text-green-700">
              {job.result.is_phishing !== undefined && (
                <p>Phishing Detected: {job.result.is_phishing ? 'Yes' : 'No'}</p>
              )}
              {job.result.confidence && (
                <p>Confidence: {(job.result.confidence * 100).toFixed(1)}%</p>
              )}
              {job.result.risk_level && (
                <p>Risk Level: {job.result.risk_level}</p>
              )}
              {job.result.threats_detected && (
                <p>Threats: {job.result.threats_detected.length} detected</p>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

interface JobTrackerProps {
  jobs: JobProgress[];
  onRefresh?: () => void;
  onCancelJob?: (jobId: string) => void;
  onRetryJob?: (jobId: string) => void;
  onViewResult?: (jobId: string, result: any) => void;
  onDownloadResult?: (jobId: string, result: any) => void;
  onClearCompleted?: () => void;
  loading?: boolean;
}

const JobTracker: React.FC<JobTrackerProps> = ({
  jobs,
  onRefresh,
  onCancelJob,
  onRetryJob,
  onViewResult,
  onDownloadResult,
  onClearCompleted,
  loading = false
}) => {
  const [filter, setFilter] = useState<string>('all');

  const filteredJobs = jobs.filter(job => {
    if (filter === 'all') return true;
    return job.status === filter;
  });

  const getStatusCounts = () => {
    return jobs.reduce((acc, job) => {
      acc[job.status] = (acc[job.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  };

  const statusCounts = getStatusCounts();

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Job Progress Tracker</h3>
          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={onRefresh}
              disabled={loading}
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={onClearCompleted}
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>
        </div>
        
        {/* Status Filter Tabs */}
        <div className="flex space-x-2 mt-4">
          {['all', 'pending', 'processing', 'completed', 'failed'].map((status) => (
            <Button
              key={status}
              variant={filter === status ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilter(status)}
              className="capitalize"
            >
              {status} {statusCounts[status] && `(${statusCounts[status]})`}
            </Button>
          ))}
        </div>
      </CardHeader>

      <CardContent>
        {filteredJobs.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Clock className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p>No jobs found</p>
            <p className="text-sm mt-1">
              {filter === 'all' ? 'Submit an email for analysis to get started' : `No ${filter} jobs`}
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredJobs.map((job) => (
              <JobProgressCard
                key={job.job_id}
                job={job}
                onCancel={onCancelJob}
                onRetry={onRetryJob}
                onViewResult={onViewResult}
                onDownload={onDownloadResult}
              />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export { JobProgressCard, JobTracker };
export type { JobProgress, JobProgressCardProps, JobTrackerProps };