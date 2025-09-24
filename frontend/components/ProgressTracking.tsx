import React, { useState, useEffect } from 'react';

interface SyncProgress {
  status: string;
  total_messages: number | null;
  processed_messages: number;
  failed_messages: number;
  progress_percentage: number;
  start_time: string | null;
  estimated_completion: string | null;
  current_batch: number;
  last_error: string | null;
}

interface ProgressTrackingProps {
  userId: number;
  onSyncComplete?: () => void;
}

const ProgressTracking: React.FC<ProgressTrackingProps> = ({ userId, onSyncComplete }) => {
  const [progress, setProgress] = useState<SyncProgress | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchProgress();
    
    // Poll for progress updates every 2 seconds
    const interval = setInterval(fetchProgress, 2000);
    
    return () => clearInterval(interval);
  }, [userId]);

  const fetchProgress = async () => {
    try {
      const response = await fetch('/api/v1/gmail/sync/progress', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch progress');
      }
      
      const data = await response.json();
      setProgress(data);
      
      // Check if sync completed
      if (data.status === 'completed' && onSyncComplete) {
        onSyncComplete();
      }
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const pauseSync = async () => {
    try {
      const response = await fetch('/api/v1/gmail/sync/pause', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (!response.ok) throw new Error('Failed to pause sync');
      fetchProgress(); // Refresh progress
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to pause sync');
    }
  };

  const resumeSync = async () => {
    try {
      const response = await fetch('/api/v1/gmail/sync/resume', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (!response.ok) throw new Error('Failed to resume sync');
      fetchProgress(); // Refresh progress
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to resume sync');
    }
  };

  const formatTimeEstimate = (isoString: string | null) => {
    if (!isoString) return 'Unknown';
    
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = date.getTime() - now.getTime();
    
    if (diffMs <= 0) return 'Complete';
    
    const diffMins = Math.round(diffMs / (1000 * 60));
    if (diffMins < 60) return `${diffMins} minutes`;
    
    const diffHours = Math.round(diffMins / 60);
    if (diffHours < 24) return `${diffHours} hours`;
    
    const diffDays = Math.round(diffHours / 24);
    return `${diffDays} days`;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return '#10b981'; // green
      case 'initial_sync': return '#3b82f6'; // blue
      case 'paused': return '#f59e0b'; // amber
      case 'failed': return '#ef4444'; // red
      default: return '#6b7280'; // gray
    }
  };

  if (loading) {
    return (
      <div className="bg-white p-6 rounded-lg shadow-md">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-3/4 mb-4"></div>
          <div className="h-2 bg-gray-200 rounded mb-4"></div>
          <div className="grid grid-cols-4 gap-4">
            <div className="h-4 bg-gray-200 rounded"></div>
            <div className="h-4 bg-gray-200 rounded"></div>
            <div className="h-4 bg-gray-200 rounded"></div>
            <div className="h-4 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 p-4 rounded-lg">
        <div className="text-red-800">
          <strong>Error:</strong> {error}
        </div>
      </div>
    );
  }

  if (!progress || progress.status === 'not_started') {
    return (
      <div className="bg-gray-50 p-6 rounded-lg text-center">
        <div className="text-gray-500 mb-4">
          <svg className="w-16 h-16 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
          <h3 className="text-lg font-medium text-gray-900">No Sync in Progress</h3>
          <p className="text-gray-500">Start an initial sync to monitor progress here</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white p-6 rounded-lg shadow-md space-y-6">
      {/* Status Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div 
            className="w-3 h-3 rounded-full"
            style={{ backgroundColor: getStatusColor(progress.status) }}
          ></div>
          <h3 className="text-lg font-medium capitalize">
            {progress.status.replace('_', ' ')} Sync
          </h3>
        </div>
        
        <div className="flex space-x-2">
          {progress.status === 'initial_sync' && (
            <button
              onClick={pauseSync}
              className="px-3 py-1 text-sm bg-yellow-100 text-yellow-800 rounded-md hover:bg-yellow-200 transition-colors"
            >
              ⏸️ Pause
            </button>
          )}
          {progress.status === 'paused' && (
            <button
              onClick={resumeSync}
              className="px-3 py-1 text-sm bg-green-100 text-green-800 rounded-md hover:bg-green-200 transition-colors"
            >
              ▶️ Resume
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      <div className="space-y-2">
        <div className="flex justify-between text-sm text-gray-600">
          <span>Progress</span>
          <span>{Math.round(progress.progress_percentage)}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div
            className="bg-blue-500 h-2 rounded-full transition-all duration-300"
            style={{ width: `${Math.min(100, progress.progress_percentage)}%` }}
          ></div>
        </div>
      </div>

      {/* Statistics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="text-center p-3 bg-gray-50 rounded-lg">
          <div className="text-2xl font-bold text-blue-600">
            {progress.processed_messages.toLocaleString()}
          </div>
          <div className="text-sm text-gray-600">Processed</div>
        </div>
        
        <div className="text-center p-3 bg-gray-50 rounded-lg">
          <div className="text-2xl font-bold text-gray-800">
            {progress.total_messages?.toLocaleString() || '?'}
          </div>
          <div className="text-sm text-gray-600">Total</div>
        </div>
        
        <div className="text-center p-3 bg-gray-50 rounded-lg">
          <div className="text-2xl font-bold text-red-600">
            {progress.failed_messages}
          </div>
          <div className="text-sm text-gray-600">Failed</div>
        </div>
        
        <div className="text-center p-3 bg-gray-50 rounded-lg">
          <div className="text-lg font-bold text-green-600">
            {formatTimeEstimate(progress.estimated_completion)}
          </div>
          <div className="text-sm text-gray-600">ETA</div>
        </div>
      </div>

      {/* Additional Info */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
        <div>
          <span className="font-medium text-gray-700">Current Batch:</span>
          <span className="ml-2 text-gray-600">#{progress.current_batch}</span>
        </div>
        
        {progress.start_time && (
          <div>
            <span className="font-medium text-gray-700">Started:</span>
            <span className="ml-2 text-gray-600">
              {new Date(progress.start_time).toLocaleString()}
            </span>
          </div>
        )}
      </div>

      {/* Error Display */}
      {progress.last_error && (
        <div className="bg-red-50 border border-red-200 p-3 rounded-lg">
          <div className="text-red-800 text-sm">
            <strong>Last Error:</strong> {progress.last_error}
          </div>
        </div>
      )}

      {/* Success Message */}
      {progress.status === 'completed' && (
        <div className="bg-green-50 border border-green-200 p-4 rounded-lg">
          <div className="flex items-center">
            <svg className="w-5 h-5 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
            <span className="text-green-800 font-medium">
              Sync completed successfully! {progress.processed_messages.toLocaleString()} messages processed.
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProgressTracking;