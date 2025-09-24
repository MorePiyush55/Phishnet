import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Mail, 
  RefreshCw, 
  Pause, 
  Play, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  Server,
  Database
} from 'lucide-react';

interface GmailStatus {
  gmail_connected: boolean;
  monitoring_enabled: boolean;
  sync_status: string;
  last_sync: string | null;
  watch_expires: string | null;
  sync_progress: SyncProgress | null;
  backfill_jobs: number;
  active_backfill_jobs: number;
  recent_scans_24h: number;
}

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

interface BackfillJob {
  job_id: string;
  status: string;
  processed: number;
  failed: number;
  progress_percent: number;
  start_date: string | null;
  end_date: string | null;
  started_at: string | null;
  current_query: string | null;
  error_message: string | null;
}

const GmailSyncDashboard: React.FC = () => {
  const [gmailStatus, setGmailStatus] = useState<GmailStatus | null>(null);
  const [backfillJobs, setBackfillJobs] = useState<BackfillJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showConfirmSync, setShowConfirmSync] = useState(false);
  const [estimatedSync, setEstimatedSync] = useState<any>(null);

  useEffect(() => {
    fetchGmailStatus();
    fetchBackfillJobs();
    
    // Set up polling for real-time updates
    const interval = setInterval(() => {
      fetchGmailStatus();
      fetchBackfillJobs();
    }, 5000); // Poll every 5 seconds

    return () => clearInterval(interval);
  }, []);

  const fetchGmailStatus = async () => {
    try {
      const response = await fetch('/api/v1/gmail/status', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (!response.ok) throw new Error('Failed to fetch Gmail status');
      
      const data = await response.json();
      setGmailStatus(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const fetchBackfillJobs = async () => {
    try {
      const response = await fetch('/api/v1/gmail/backfill/jobs', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setBackfillJobs(data);
      }
    } catch (err) {
      console.error('Failed to fetch backfill jobs:', err);
    }
  };

  const connectGmail = async () => {
    try {
      const response = await fetch('/api/v1/gmail/connect', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) throw new Error('Failed to initiate Gmail connection');
      
      const data = await response.json();
      if (data.auth_url) {
        window.location.href = data.auth_url;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to connect Gmail');
    }
  };

  const startInitialSync = async (confirm: boolean = false) => {
    try {
      // First, try without confirmation to get estimate
      const response = await fetch('/api/v1/gmail/sync/start', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ confirm_large_mailbox: confirm })
      });
      
      if (!response.ok) throw new Error('Failed to start sync');
      
      const data = await response.json();
      
      if (data.status === 'confirmation_required') {
        setEstimatedSync(data);
        setShowConfirmSync(true);
      } else {
        setShowConfirmSync(false);
        fetchGmailStatus(); // Refresh status
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start sync');
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
      fetchGmailStatus();
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
      fetchGmailStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to resume sync');
    }
  };

  const startBackfill = async () => {
    try {
      const response = await fetch('/api/v1/gmail/backfill/start', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          chunk_size: 500,
          max_messages_per_day: 10000
        })
      });
      
      if (!response.ok) throw new Error('Failed to start backfill');
      fetchBackfillJobs();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start backfill');
    }
  };

  const controlBackfillJob = async (jobId: string, action: 'pause' | 'resume') => {
    try {
      const response = await fetch(`/api/v1/gmail/backfill/${action}/${jobId}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (!response.ok) throw new Error(`Failed to ${action} backfill job`);
      fetchBackfillJobs();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${action} job`);
    }
  };

  const getStatusBadge = (status: string) => {
    const variants: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
      'completed': 'default',
      'initial_sync': 'secondary',
      'incremental': 'default',
      'paused': 'outline',
      'failed': 'destructive',
      'running': 'secondary'
    };
    
    return (
      <Badge variant={variants[status] || 'outline'} className="capitalize">
        {status.replace('_', ' ')}
      </Badge>
    );
  };

  const formatTimeEstimate = (isoString: string | null) => {
    if (!isoString) return 'Unknown';
    
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = date.getTime() - now.getTime();
    
    if (diffMs <= 0) return 'Complete';
    
    const diffMins = Math.round(diffMs / (1000 * 60));
    if (diffMins < 60) return `${diffMins}m`;
    
    const diffHours = Math.round(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h`;
    
    const diffDays = Math.round(diffHours / 24);
    return `${diffDays}d`;
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-8">
          <RefreshCw className="animate-spin mr-2" />
          Loading Gmail status...
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Gmail Connection Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5" />
            Gmail Integration
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!gmailStatus?.gmail_connected ? (
            <div className="text-center py-8">
              <Mail className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <h3 className="text-lg font-medium mb-2">Connect Gmail</h3>
              <p className="text-muted-foreground mb-4">
                Connect your Gmail account to start monitoring for phishing emails
              </p>
              <Button onClick={connectGmail}>
                Connect Gmail Account
              </Button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span className="text-sm">Gmail Connected</span>
              </div>
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-blue-500" />
                <span className="text-sm">
                  Monitoring: {gmailStatus.monitoring_enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-purple-500" />
                <span className="text-sm">
                  24h Scans: {gmailStatus.recent_scans_24h}
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {gmailStatus?.gmail_connected && (
        <Tabs defaultValue="sync" className="space-y-4">
          <TabsList>
            <TabsTrigger value="sync">Initial Sync</TabsTrigger>
            <TabsTrigger value="backfill">Historical Backfill</TabsTrigger>
            <TabsTrigger value="monitoring">Real-time Monitoring</TabsTrigger>
          </TabsList>

          {/* Initial Sync Tab */}
          <TabsContent value="sync">
            <Card>
              <CardHeader>
                <CardTitle>Initial Inbox Sync</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {gmailStatus.sync_progress ? (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Sync Progress</span>
                      {getStatusBadge(gmailStatus.sync_progress.status)}
                    </div>
                    
                    <Progress value={gmailStatus.sync_progress.progress_percentage} />
                    
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <div className="text-muted-foreground">Processed</div>
                        <div className="font-medium">
                          {gmailStatus.sync_progress.processed_messages.toLocaleString()}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Total</div>
                        <div className="font-medium">
                          {gmailStatus.sync_progress.total_messages?.toLocaleString() || 'Unknown'}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Failed</div>
                        <div className="font-medium text-red-500">
                          {gmailStatus.sync_progress.failed_messages}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">ETA</div>
                        <div className="font-medium">
                          {formatTimeEstimate(gmailStatus.sync_progress.estimated_completion)}
                        </div>
                      </div>
                    </div>

                    <div className="flex gap-2">
                      {gmailStatus.sync_progress.status === 'initial_sync' && (
                        <Button onClick={pauseSync} variant="outline" size="sm">
                          <Pause className="h-4 w-4 mr-1" />
                          Pause
                        </Button>
                      )}
                      {gmailStatus.sync_progress.status === 'paused' && (
                        <Button onClick={resumeSync} variant="outline" size="sm">
                          <Play className="h-4 w-4 mr-1" />
                          Resume
                        </Button>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Clock className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <h3 className="text-lg font-medium mb-2">Start Initial Sync</h3>
                    <p className="text-muted-foreground mb-4">
                      Sync your entire Gmail inbox to start threat analysis
                    </p>
                    <Button onClick={() => startInitialSync(false)}>
                      Start Initial Sync
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Backfill Tab */}
          <TabsContent value="backfill">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  Historical Backfill
                  <Button onClick={startBackfill} size="sm">
                    Start New Backfill
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {backfillJobs.length === 0 ? (
                  <div className="text-center py-8">
                    <Database className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <h3 className="text-lg font-medium mb-2">No Backfill Jobs</h3>
                    <p className="text-muted-foreground">
                      Start a backfill job to scan historical emails
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {backfillJobs.map((job) => (
                      <div key={job.job_id} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            {getStatusBadge(job.status)}
                            <span className="text-sm text-muted-foreground">
                              Job {job.job_id.slice(0, 8)}...
                            </span>
                          </div>
                          <div className="flex gap-1">
                            {job.status === 'running' && (
                              <Button 
                                onClick={() => controlBackfillJob(job.job_id, 'pause')}
                                variant="outline" 
                                size="sm"
                              >
                                <Pause className="h-3 w-3" />
                              </Button>
                            )}
                            {job.status === 'paused' && (
                              <Button 
                                onClick={() => controlBackfillJob(job.job_id, 'resume')}
                                variant="outline" 
                                size="sm"
                              >
                                <Play className="h-3 w-3" />
                              </Button>
                            )}
                          </div>
                        </div>
                        
                        <Progress value={job.progress_percent} className="mb-2" />
                        
                        <div className="grid grid-cols-3 gap-4 text-sm">
                          <div>
                            <div className="text-muted-foreground">Processed</div>
                            <div className="font-medium">{job.processed.toLocaleString()}</div>
                          </div>
                          <div>
                            <div className="text-muted-foreground">Failed</div>
                            <div className="font-medium text-red-500">{job.failed}</div>
                          </div>
                          <div>
                            <div className="text-muted-foreground">Started</div>
                            <div className="font-medium">
                              {job.started_at ? new Date(job.started_at).toLocaleDateString() : 'N/A'}
                            </div>
                          </div>
                        </div>
                        
                        {job.error_message && (
                          <Alert variant="destructive" className="mt-2">
                            <AlertDescription>{job.error_message}</AlertDescription>
                          </Alert>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Monitoring Tab */}
          <TabsContent value="monitoring">
            <Card>
              <CardHeader>
                <CardTitle>Real-time Monitoring</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <div className="text-sm font-medium">Sync Status</div>
                    {getStatusBadge(gmailStatus.sync_status)}
                  </div>
                  <div className="space-y-2">
                    <div className="text-sm font-medium">Last Sync</div>
                    <div className="text-sm text-muted-foreground">
                      {gmailStatus.last_sync 
                        ? new Date(gmailStatus.last_sync).toLocaleString()
                        : 'Never'
                      }
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="text-sm font-medium">Watch Expires</div>
                    <div className="text-sm text-muted-foreground">
                      {gmailStatus.watch_expires 
                        ? new Date(gmailStatus.watch_expires).toLocaleString()
                        : 'Not set'
                      }
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="text-sm font-medium">Active Jobs</div>
                    <div className="text-sm text-muted-foreground">
                      {gmailStatus.active_backfill_jobs} running
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      )}

      {/* Confirmation Dialog */}
      {showConfirmSync && estimatedSync && (
        <Card className="border-orange-200 bg-orange-50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-orange-800">
              <AlertTriangle className="h-5 w-5" />
              Large Mailbox Detected
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="text-sm text-orange-700">
              <p>Your mailbox contains <strong>{estimatedSync.total_messages?.toLocaleString()}</strong> messages.</p>
              <p>Estimated sync time: <strong>{estimatedSync.estimated_time_minutes} minutes</strong></p>
              <p>Estimated API calls: <strong>{estimatedSync.estimated_api_calls?.toLocaleString()}</strong></p>
            </div>
            
            <Alert>
              <AlertDescription>
                This may consume significant Gmail API quota and take considerable time. 
                You can pause the sync at any time.
              </AlertDescription>
            </Alert>
            
            <div className="flex gap-2">
              <Button onClick={() => startInitialSync(true)} variant="default">
                Proceed with Sync
              </Button>
              <Button onClick={() => setShowConfirmSync(false)} variant="outline">
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default GmailSyncDashboard;