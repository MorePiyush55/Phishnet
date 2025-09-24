/**
 * Job Management Dashboard
 * Complete interface for managing and monitoring background jobs
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Send, 
  Upload, 
  BarChart3, 
  Settings, 
  Wifi, 
  WifiOff,
  AlertCircle,
  CheckCircle2,
  Clock
} from 'lucide-react';

import { JobTracker, type JobProgress } from './job-progress';
import { useJobWebSocket, useJobsWebSocket, getWebSocketUrl } from '@/hooks/useJobWebSocket';

interface AnalysisRequest {
  subject: string;
  sender: string;
  content: string;
  recipients?: string[];
  analysis_type: 'quick' | 'standard' | 'comprehensive';
}

interface SystemStats {
  active_jobs: number;
  pending_jobs: number;
  completed_jobs_today: number;
  failed_jobs_today: number;
  active_connections: number;
  system_health: string;
}

interface JobManagementDashboardProps {
  apiBaseUrl?: string;
}

const JobManagementDashboard: React.FC<JobManagementDashboardProps> = ({
  apiBaseUrl = '/api/v1'
}) => {
  // State
  const [jobs, setJobs] = useState<JobProgress[]>([]);
  const [systemStats, setSystemStats] = useState<SystemStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('submit');

  // Form state
  const [analysisRequest, setAnalysisRequest] = useState<AnalysisRequest>({
    subject: '',
    sender: '',
    content: '',
    recipients: [],
    analysis_type: 'standard'
  });

  // WebSocket connections
  const wsUrl = getWebSocketUrl();
  const jobIds = jobs.map(job => job.job_id);

  const {
    connections: jobConnections,
    lastUpdates: jobUpdates,
    connectedCount
  } = useJobsWebSocket({
    baseUrl: wsUrl,
    jobIds,
    onJobUpdate: (jobId, update) => {
      setJobs(prevJobs => 
        prevJobs.map(job => 
          job.job_id === jobId 
            ? { 
                ...job, 
                status: update.status || job.status,
                progress: update.progress || job.progress,
                result: update.result || job.result,
                error: update.error || job.error,
                updated_at: update.timestamp
              }
            : job
        )
      );
    },
    onError: (error) => {
      console.error('WebSocket error:', error);
    }
  });

  const {
    isConnected: systemConnected,
    lastUpdate: systemUpdate
  } = useJobWebSocket({
    url: `${wsUrl}/system`,
    onUpdate: (update) => {
      if (update.type === 'system_status' && update.data) {
        setSystemStats(update.data);
      }
    }
  });

  // API calls
  const submitAnalysis = async (request: AnalysisRequest) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${apiBaseUrl}/analysis/submit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request)
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      
      // Add new job to tracking list
      const newJob: JobProgress = {
        job_id: result.job_id,
        status: 'pending',
        progress: 0,
        analysis_type: request.analysis_type,
        estimated_completion: result.estimated_completion,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      setJobs(prev => [newJob, ...prev]);
      
      // Clear form
      setAnalysisRequest({
        subject: '',
        sender: '',
        content: '',
        recipients: [],
        analysis_type: 'standard'
      });

      // Switch to tracking tab
      setActiveTab('tracking');

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit analysis');
    } finally {
      setLoading(false);
    }
  };

  const refreshJobs = async () => {
    // In a real app, this would fetch job history from the API
    console.log('Refreshing jobs...');
  };

  const cancelJob = async (jobId: string) => {
    try {
      const response = await fetch(`${apiBaseUrl}/analysis/cancel/${jobId}`, {
        method: 'DELETE'
      });

      if (!response.ok) {
        throw new Error('Failed to cancel job');
      }

      setJobs(prev => 
        prev.map(job => 
          job.job_id === jobId 
            ? { ...job, status: 'cancelled' as const }
            : job
        )
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to cancel job');
    }
  };

  const retryJob = async (jobId: string) => {
    // Find the original job to get its request data
    const originalJob = jobs.find(job => job.job_id === jobId);
    if (!originalJob) return;

    // Would need to store original request data to retry
    console.log('Retry functionality would resubmit the original request');
  };

  const viewResult = (jobId: string, result: any) => {
    // Open result in a modal or new tab
    console.log('Viewing result for job:', jobId, result);
  };

  const downloadResult = (jobId: string, result: any) => {
    // Download result as JSON
    const dataStr = JSON.stringify(result, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `phishnet-analysis-${jobId}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const clearCompleted = () => {
    setJobs(prev => prev.filter(job => job.status !== 'completed'));
  };

  // Load initial data
  useEffect(() => {
    refreshJobs();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header with Connection Status */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold">Job Management Dashboard</h1>
              <p className="text-gray-600 mt-1">Submit and track email analysis jobs in real-time</p>
            </div>
            
            <div className="flex items-center space-x-4">
              {/* WebSocket Status */}
              <div className="flex items-center space-x-2">
                {systemConnected ? (
                  <Wifi className="w-5 h-5 text-green-500" />
                ) : (
                  <WifiOff className="w-5 h-5 text-red-500" />
                )}
                <span className="text-sm">
                  {connectedCount}/{jobIds.length} jobs connected
                </span>
              </div>

              {/* System Health */}
              {systemStats && (
                <Badge variant={systemStats.system_health === 'healthy' ? 'default' : 'destructive'}>
                  {systemStats.system_health}
                </Badge>
              )}
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* System Statistics */}
      {systemStats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <Clock className="w-5 h-5 text-blue-500" />
                <div>
                  <p className="text-2xl font-bold">{systemStats.active_jobs}</p>
                  <p className="text-sm text-gray-600">Active Jobs</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <AlertCircle className="w-5 h-5 text-yellow-500" />
                <div>
                  <p className="text-2xl font-bold">{systemStats.pending_jobs}</p>
                  <p className="text-sm text-gray-600">Pending</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-5 h-5 text-green-500" />
                <div>
                  <p className="text-2xl font-bold">{systemStats.completed_jobs_today}</p>
                  <p className="text-sm text-gray-600">Completed Today</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center space-x-2">
                <BarChart3 className="w-5 h-5 text-purple-500" />
                <div>
                  <p className="text-2xl font-bold">{systemStats.active_connections}</p>
                  <p className="text-sm text-gray-600">Connections</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="submit">Submit Analysis</TabsTrigger>
          <TabsTrigger value="tracking">Job Tracking</TabsTrigger>
          <TabsTrigger value="history">History & Stats</TabsTrigger>
        </TabsList>

        {/* Submit Analysis Tab */}
        <TabsContent value="submit" className="space-y-6">
          <Card>
            <CardHeader>
              <h3 className="text-lg font-semibold">Submit Email for Analysis</h3>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="subject">Email Subject</Label>
                  <Input
                    id="subject"
                    value={analysisRequest.subject}
                    onChange={(e) => setAnalysisRequest(prev => ({ ...prev, subject: e.target.value }))}
                    placeholder="Enter email subject"
                  />
                </div>
                
                <div>
                  <Label htmlFor="sender">Sender Email</Label>
                  <Input
                    id="sender"
                    type="email"
                    value={analysisRequest.sender}
                    onChange={(e) => setAnalysisRequest(prev => ({ ...prev, sender: e.target.value }))}
                    placeholder="sender@example.com"
                  />
                </div>
              </div>

              <div>
                <Label htmlFor="content">Email Content</Label>
                <Textarea
                  id="content"
                  value={analysisRequest.content}
                  onChange={(e) => setAnalysisRequest(prev => ({ ...prev, content: e.target.value }))}
                  placeholder="Paste email content here..."
                  rows={8}
                />
              </div>

              <div>
                <Label htmlFor="analysis-type">Analysis Type</Label>
                <Select 
                  value={analysisRequest.analysis_type}
                  onValueChange={(value: 'quick' | 'standard' | 'comprehensive') => 
                    setAnalysisRequest(prev => ({ ...prev, analysis_type: value }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="quick">Quick (~10 seconds)</SelectItem>
                    <SelectItem value="standard">Standard (~30-60 seconds)</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive (~2-5 minutes)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex space-x-2">
                <Button
                  onClick={() => submitAnalysis(analysisRequest)}
                  disabled={loading || !analysisRequest.subject || !analysisRequest.sender || !analysisRequest.content}
                  className="flex-1"
                >
                  <Send className="w-4 h-4 mr-2" />
                  {loading ? 'Submitting...' : 'Submit Analysis'}
                </Button>
                
                <Button variant="outline" disabled>
                  <Upload className="w-4 h-4 mr-2" />
                  Upload File
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Job Tracking Tab */}
        <TabsContent value="tracking">
          <JobTracker
            jobs={jobs}
            onRefresh={refreshJobs}
            onCancelJob={cancelJob}
            onRetryJob={retryJob}
            onViewResult={viewResult}
            onDownloadResult={downloadResult}
            onClearCompleted={clearCompleted}
            loading={loading}
          />
        </TabsContent>

        {/* History & Stats Tab */}
        <TabsContent value="history">
          <Card>
            <CardHeader>
              <h3 className="text-lg font-semibold">Analysis History & Statistics</h3>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-gray-500">
                <BarChart3 className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>History and statistics feature</p>
                <p className="text-sm mt-1">Coming soon...</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default JobManagementDashboard;