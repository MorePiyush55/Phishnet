import React, { useState, useEffect, useCallback } from 'react';
import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { 
  Button 
} from '@/components/ui/button';
import { 
  Alert, 
  AlertDescription 
} from '@/components/ui/alert';
import { 
  Progress 
} from '@/components/ui/progress';
import { 
  Badge 
} from '@/components/ui/badge';
import { 
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { 
  Mail, 
  Play, 
  Pause, 
  Square, 
  RefreshCw, 
  AlertTriangle,
  CheckCircle,
  Clock,
  BarChart3,
  Settings
} from 'lucide-react';
import { toast } from 'sonner';

interface SyncProgress {
  status: string;
  total_messages?: number;
  processed_messages: number;
  failed_messages: number;
  progress_percentage: number;
  start_time?: string;
  estimated_completion?: string;
  current_batch: number;
  last_error?: string;
}

interface SyncStats {
  total_messages: number;
  processed_messages: number;
  pending_messages: number;
  failed_messages: number;
  recent_24h_messages: number;
  oldest_message?: string;
  newest_message?: string;
  sync_progress?: SyncProgress;
}

interface BackfillJob {
  job_id: string;
  status: string;
  processed: number;
  failed: number;
  progress_percent: number;
  start_date?: string;
  end_date?: string;
  started_at?: string;
  completed_at?: string;
  current_query?: string;
  error_message?: string;
}

const GmailSyncManager: React.FC = () => {
  const [syncProgress, setSyncProgress] = useState<SyncProgress | null>(null);
  const [syncStats, setSyncStats] = useState<SyncStats | null>(null);
  const [backfillJobs, setBackfillJobs] = useState<BackfillJob[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showConfirmDialog, setShowConfirmDialog] = useState(false);
  const [confirmationData, setConfirmationData] = useState<any>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Fetch current sync progress
  const fetchSyncProgress = useCallback(async () => {
    try {
      const response = await fetch('/api/gmail/sync-progress');
      const data = await response.json();
      
      if (data.status !== 'no_sync_active') {
        setSyncProgress(data);
      } else {
        setSyncProgress(null);
      }
    } catch (error) {
      console.error('Failed to fetch sync progress:', error);
    }
  }, []);

  // Fetch sync statistics
  const fetchSyncStats = useCallback(async () => {
    try {
      const response = await fetch('/api/gmail/statistics');
      const data = await response.json();
      setSyncStats(data);
    } catch (error) {
      console.error('Failed to fetch sync stats:', error);
    }
  }, []);

  // Fetch backfill jobs
  const fetchBackfillJobs = useCallback(async () => {
    try {
      const response = await fetch('/api/gmail/backfill/jobs');
      const data = await response.json();
      setBackfillJobs(data.jobs || []);
    } catch (error) {
      console.error('Failed to fetch backfill jobs:', error);
    }
  }, []);

  // Auto-refresh data
  useEffect(() => {
    fetchSyncProgress();
    fetchSyncStats();
    fetchBackfillJobs();

    if (autoRefresh) {
      const interval = setInterval(() => {
        fetchSyncProgress();
        fetchSyncStats();
        fetchBackfillJobs();
      }, 5000); // Refresh every 5 seconds

      return () => clearInterval(interval);
    }
  }, [autoRefresh, fetchSyncProgress, fetchSyncStats, fetchBackfillJobs]);

  // Start initial sync
  const handleStartSync = async (confirmLarge: boolean = false) => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/gmail/start-initial-sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm_large_mailbox: confirmLarge })
      });
      
      const data = await response.json();
      
      if (data.status === 'confirmation_required') {
        setConfirmationData(data);
        setShowConfirmDialog(true);
      } else if (data.status === 'success') {
        toast.success('Initial sync started successfully');
        fetchSyncProgress();
      } else {
        toast.error(data.message || 'Failed to start sync');
      }
    } catch (error) {
      toast.error('Failed to start sync');
      console.error('Sync start error:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Pause sync
  const handlePauseSync = async () => {
    try {
      const response = await fetch('/api/gmail/pause-sync', { method: 'POST' });
      const data = await response.json();
      
      if (data.status === 'success') {
        toast.success('Sync paused');
        fetchSyncProgress();
      } else {
        toast.error(data.message || 'Failed to pause sync');
      }
    } catch (error) {
      toast.error('Failed to pause sync');
    }
  };

  // Resume sync
  const handleResumeSync = async () => {
    try {
      const response = await fetch('/api/gmail/resume-sync', { method: 'POST' });
      const data = await response.json();
      
      if (data.status === 'success') {
        toast.success('Sync resumed');
        fetchSyncProgress();
      } else {
        toast.error(data.message || 'Failed to resume sync');
      }
    } catch (error) {
      toast.error('Failed to resume sync');
    }
  };

  // Start backfill job
  const handleStartBackfill = async () => {
    try {
      const response = await fetch('/api/gmail/backfill/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          start_date: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year ago
          chunk_size_days: 30
        })
      });
      
      const data = await response.json();
      
      if (data.status === 'success') {
        toast.success('Backfill job started');
        fetchBackfillJobs();
      } else {
        toast.error('Failed to start backfill job');
      }
    } catch (error) {
      toast.error('Failed to start backfill job');
    }
  };

  // Control backfill job
  const handleBackfillControl = async (jobId: string, action: 'pause' | 'resume' | 'cancel') => {
    try {
      const response = await fetch(`/api/gmail/backfill/${jobId}/${action}`, { method: 'POST' });
      const data = await response.json();
      
      if (data.status === 'success') {
        toast.success(`Backfill job ${action}d`);
        fetchBackfillJobs();
      } else {
        toast.error(`Failed to ${action} backfill job`);
      }
    } catch (error) {
      toast.error(`Failed to ${action} backfill job`);
    }
  };

  // Format time estimates
  const formatTimeEstimate = (isoString?: string) => {
    if (!isoString) return 'Unknown';
    const date = new Date(isoString);
    const now = new Date();
    const diff = date.getTime() - now.getTime();
    
    if (diff <= 0) return 'Any moment';
    
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  };

  // Get status badge color
  const getStatusBadge = (status: string) => {
    const statusMap: Record<string, { variant: any; label: string }> = {
      'initial_sync': { variant: 'default', label: 'Syncing' },
      'incremental': { variant: 'success', label: 'Real-time' },
      'paused': { variant: 'secondary', label: 'Paused' },
      'failed': { variant: 'destructive', label: 'Failed' },
      'completed': { variant: 'success', label: 'Complete' },
      'running': { variant: 'default', label: 'Running' },
      'pending': { variant: 'secondary', label: 'Pending' }
    };
    
    const config = statusMap[status] || { variant: 'secondary', label: status };
    return (
      <Badge variant={config.variant as any}>
        {config.label}
      </Badge>
    );
  };

  return (
    <div className="space-y-6">
      {/* Sync Status Overview */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5" />
            Gmail Sync Status
          </CardTitle>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={autoRefresh ? 'text-green-600' : 'text-gray-600'}
            >
              <RefreshCw className={`h-4 w-4 ${autoRefresh ? 'animate-spin' : ''}`} />
            </Button>
            {syncStats && getStatusBadge(syncProgress?.status || 'not_started')}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {syncProgress ? (
            <div className="space-y-4">
              {/* Progress Bar */}
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Progress: {syncProgress.processed_messages.toLocaleString()} messages</span>
                  <span>{syncProgress.progress_percentage.toFixed(1)}%</span>
                </div>
                <Progress value={syncProgress.progress_percentage} className="h-2" />
              </div>

              {/* Sync Details */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <div className="font-medium">Total Messages</div>
                  <div>{syncProgress.total_messages?.toLocaleString() || 'Unknown'}</div>
                </div>
                <div>
                  <div className="font-medium">Processed</div>
                  <div className="text-green-600">{syncProgress.processed_messages.toLocaleString()}</div>
                </div>
                <div>
                  <div className="font-medium">Failed</div>
                  <div className="text-red-600">{syncProgress.failed_messages.toLocaleString()}</div>
                </div>
                <div>
                  <div className="font-medium">ETA</div>
                  <div className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {formatTimeEstimate(syncProgress.estimated_completion)}
                  </div>
                </div>
              </div>

              {/* Control Buttons */}
              <div className="flex gap-2">
                {syncProgress.status === 'initial_sync' && (
                  <Button variant="outline" size="sm" onClick={handlePauseSync}>
                    <Pause className="h-4 w-4 mr-1" />
                    Pause
                  </Button>
                )}
                {syncProgress.status === 'paused' && (
                  <Button variant="outline" size="sm" onClick={handleResumeSync}>
                    <Play className="h-4 w-4 mr-1" />
                    Resume
                  </Button>
                )}
              </div>

              {/* Error Display */}
              {syncProgress.last_error && (
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    Last error: {syncProgress.last_error}
                  </AlertDescription>
                </Alert>
              )}
            </div>
          ) : (
            <div className="text-center py-8">
              <Mail className="h-12 w-12 mx-auto text-gray-400 mb-4" />
              <h3 className="text-lg font-medium mb-2">No Active Sync</h3>
              <p className="text-gray-600 mb-4">
                Start syncing your Gmail inbox to analyze messages for threats.
              </p>
              <Button onClick={() => handleStartSync()} disabled={isLoading}>
                {isLoading ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Play className="h-4 w-4 mr-2" />
                )}
                Start Initial Sync
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Statistics */}
      {syncStats && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5" />
              Inbox Statistics
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold">{syncStats.total_messages.toLocaleString()}</div>
                <div className="text-sm text-gray-600">Total Messages</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">{syncStats.processed_messages.toLocaleString()}</div>
                <div className="text-sm text-gray-600">Processed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">{syncStats.pending_messages.toLocaleString()}</div>
                <div className="text-sm text-gray-600">Pending</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">{syncStats.failed_messages.toLocaleString()}</div>
                <div className="text-sm text-gray-600">Failed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-600">{syncStats.recent_24h_messages.toLocaleString()}</div>
                <div className="text-sm text-gray-600">Last 24h</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Backfill Jobs */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Historical Backfill
          </CardTitle>
          <Button variant="outline" size="sm" onClick={handleStartBackfill}>
            Start Backfill
          </Button>
        </CardHeader>
        <CardContent>
          {backfillJobs.length > 0 ? (
            <div className="space-y-4">
              {backfillJobs.map((job) => (
                <div key={job.job_id} className="border rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {getStatusBadge(job.status)}
                      <span className="text-sm font-medium">
                        Job {job.job_id.substring(0, 8)}...
                      </span>
                    </div>
                    <div className="flex gap-1">
                      {job.status === 'running' && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleBackfillControl(job.job_id, 'pause')}
                        >
                          <Pause className="h-3 w-3" />
                        </Button>
                      )}
                      {job.status === 'paused' && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleBackfillControl(job.job_id, 'resume')}
                        >
                          <Play className="h-3 w-3" />
                        </Button>
                      )}
                      {['running', 'paused'].includes(job.status) && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleBackfillControl(job.job_id, 'cancel')}
                        >
                          <Square className="h-3 w-3" />
                        </Button>
                      )}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Progress: {job.processed.toLocaleString()} processed</span>
                      <span>{job.progress_percent.toFixed(1)}%</span>
                    </div>
                    <Progress value={job.progress_percent} className="h-1" />
                  </div>

                  <div className="grid grid-cols-2 gap-4 text-xs text-gray-600">
                    <div>
                      <span className="font-medium">Date Range:</span>
                      <br />
                      {job.start_date && new Date(job.start_date).toLocaleDateString()} - 
                      {job.end_date && new Date(job.end_date).toLocaleDateString()}
                    </div>
                    <div>
                      <span className="font-medium">Failed:</span> {job.failed}
                      {job.error_message && (
                        <div className="text-red-600 mt-1">{job.error_message}</div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-600">
              <p>No backfill jobs found.</p>
              <p className="text-sm">Start a backfill job to scan historical emails.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Confirmation Dialog */}
      <Dialog open={showConfirmDialog} onOpenChange={setShowConfirmDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Large Mailbox Detected</DialogTitle>
            <DialogDescription>
              Your mailbox contains {confirmationData?.total_messages?.toLocaleString()} messages.
              This sync may take significant time and use API quota.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="bg-yellow-50 border border-yellow-200 rounded p-4">
              <h4 className="font-medium text-yellow-800">Estimated Impact:</h4>
              <ul className="text-sm text-yellow-700 mt-2 space-y-1">
                <li>• Time: ~{confirmationData?.estimated_time_minutes} minutes</li>
                <li>• API calls: ~{confirmationData?.estimated_api_calls?.toLocaleString()}</li>
                <li>• You can pause/resume at any time</li>
              </ul>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowConfirmDialog(false)}>
              Cancel
            </Button>
            <Button onClick={() => {
              setShowConfirmDialog(false);
              handleStartSync(true);
            }}>
              Start Sync
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default GmailSyncManager;