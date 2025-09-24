/**
 * Sandbox Job Status Components
 * 
 * Components for monitoring sandbox job execution status,
 * queue management, and real-time updates.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle,
  Badge,
  Button,
  Progress,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Input,
  Alert,
  AlertDescription
} from '@/components/ui';
import { 
  RefreshCw, 
  Play, 
  Pause, 
  X, 
  Eye, 
  Download,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  Filter,
  Search
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface SandboxJob {
  job_id: string;
  session_id: string;
  target_url_hash: string;
  status: 'queued' | 'preparing' | 'running' | 'completed' | 'failed' | 'timeout' | 'cancelled';
  priority: 'low' | 'normal' | 'high' | 'critical';
  created_at: string;
  started_at?: string;
  completed_at?: string;
  execution_time?: number;
  error_message?: string;
  retry_count: number;
  user_id?: string;
  evidence_path?: string;
}

interface SandboxMetrics {
  total_jobs: number;
  completed_jobs: number;
  failed_jobs: number;
  timeout_jobs: number;
  average_execution_time: number;
  queue_length: number;
  active_containers: number;
  resource_utilization: {
    cpu: number;
    memory: number;
    disk: number;
  };
}

const SandboxJobManager: React.FC = () => {
  const [jobs, setJobs] = useState<SandboxJob[]>([]);
  const [metrics, setMetrics] = useState<SandboxMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [priorityFilter, setPriorityFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState<NodeJS.Timeout | null>(null);
  const { toast } = useToast();

  const fetchJobs = useCallback(async () => {
    try {
      const response = await fetch('/api/sandbox/jobs');
      if (response.ok) {
        const data = await response.json();
        setJobs(data.jobs || []);
        setMetrics(data.metrics || null);
      } else {
        throw new Error('Failed to fetch jobs');
      }
    } catch (error) {
      console.error('Error fetching jobs:', error);
      toast({
        title: "Error",
        description: "Failed to fetch sandbox jobs",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    fetchJobs();
  }, [fetchJobs]);

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(fetchJobs, 5000); // Refresh every 5 seconds
      setRefreshInterval(interval);
      return () => clearInterval(interval);
    } else if (refreshInterval) {
      clearInterval(refreshInterval);
      setRefreshInterval(null);
    }
  }, [autoRefresh, fetchJobs, refreshInterval]);

  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'completed': return 'text-green-600 bg-green-50';
      case 'failed': return 'text-red-600 bg-red-50';
      case 'running': return 'text-blue-600 bg-blue-50';
      case 'queued': return 'text-yellow-600 bg-yellow-50';
      case 'preparing': return 'text-purple-600 bg-purple-50';
      case 'timeout': return 'text-orange-600 bg-orange-50';
      case 'cancelled': return 'text-gray-600 bg-gray-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getPriorityColor = (priority: string): string => {
    switch (priority) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'normal': return 'text-blue-600 bg-blue-50';
      case 'low': return 'text-gray-600 bg-gray-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-600" />;
      case 'running':
        return <Loader2 className="h-4 w-4 text-blue-600 animate-spin" />;
      case 'queued':
        return <Clock className="h-4 w-4 text-yellow-600" />;
      case 'timeout':
        return <AlertTriangle className="h-4 w-4 text-orange-600" />;
      default:
        return <AlertTriangle className="h-4 w-4 text-gray-600" />;
    }
  };

  const cancelJob = async (jobId: string) => {
    try {
      const response = await fetch(`/api/sandbox/jobs/${jobId}/cancel`, {
        method: 'POST'
      });
      
      if (response.ok) {
        toast({
          title: "Success",
          description: "Job cancelled successfully"
        });
        fetchJobs(); // Refresh jobs list
      } else {
        throw new Error('Failed to cancel job');
      }
    } catch (error) {
      console.error('Error cancelling job:', error);
      toast({
        title: "Error",
        description: "Failed to cancel job",
        variant: "destructive"
      });
    }
  };

  const retryJob = async (jobId: string) => {
    try {
      const response = await fetch(`/api/sandbox/jobs/${jobId}/retry`, {
        method: 'POST'
      });
      
      if (response.ok) {
        toast({
          title: "Success",
          description: "Job retry initiated"
        });
        fetchJobs(); // Refresh jobs list
      } else {
        throw new Error('Failed to retry job');
      }
    } catch (error) {
      console.error('Error retrying job:', error);
      toast({
        title: "Error",
        description: "Failed to retry job",
        variant: "destructive"
      });
    }
  };

  const viewEvidence = (jobId: string) => {
    // Navigate to evidence viewer
    window.open(`/sandbox/evidence/${jobId}`, '_blank');
  };

  const downloadEvidence = async (jobId: string) => {
    try {
      const response = await fetch(`/api/sandbox/jobs/${jobId}/evidence/download`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = `sandbox_evidence_${jobId}.zip`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        throw new Error('Failed to download evidence');
      }
    } catch (error) {
      console.error('Error downloading evidence:', error);
      toast({
        title: "Error",
        description: "Failed to download evidence",
        variant: "destructive"
      });
    }
  };

  const filteredJobs = jobs.filter(job => {
    if (statusFilter !== 'all' && job.status !== statusFilter) return false;
    if (priorityFilter !== 'all' && job.priority !== priorityFilter) return false;
    if (searchTerm && !job.job_id.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !job.session_id.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  const formatDuration = (seconds: number): string => {
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds.toFixed(0)}s`;
  };

  const formatRelativeTime = (timestamp: string): string => {
    const now = new Date();
    const time = new Date(timestamp);
    const diffMs = now.getTime() - time.getTime();
    const diffSeconds = Math.floor(diffMs / 1000);
    const diffMinutes = Math.floor(diffSeconds / 60);
    const diffHours = Math.floor(diffMinutes / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffDays > 0) return `${diffDays}d ago`;
    if (diffHours > 0) return `${diffHours}h ago`;
    if (diffMinutes > 0) return `${diffMinutes}m ago`;
    return `${diffSeconds}s ago`;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Metrics Overview */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600">Total Jobs</p>
                  <p className="text-2xl font-bold">{metrics.total_jobs}</p>
                </div>
                <div className="h-8 w-8 bg-blue-100 rounded-full flex items-center justify-center">
                  <Play className="h-4 w-4 text-blue-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600">Queue Length</p>
                  <p className="text-2xl font-bold">{metrics.queue_length}</p>
                </div>
                <div className="h-8 w-8 bg-yellow-100 rounded-full flex items-center justify-center">
                  <Clock className="h-4 w-4 text-yellow-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600">Active Containers</p>
                  <p className="text-2xl font-bold">{metrics.active_containers}</p>
                </div>
                <div className="h-8 w-8 bg-green-100 rounded-full flex items-center justify-center">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600">Avg. Execution</p>
                  <p className="text-2xl font-bold">
                    {formatDuration(metrics.average_execution_time)}
                  </p>
                </div>
                <div className="h-8 w-8 bg-purple-100 rounded-full flex items-center justify-center">
                  <Clock className="h-4 w-4 text-purple-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Resource Utilization */}
      {metrics?.resource_utilization && (
        <Card>
          <CardHeader>
            <CardTitle>Resource Utilization</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>CPU Usage</span>
                  <span>{metrics.resource_utilization.cpu.toFixed(1)}%</span>
                </div>
                <Progress value={metrics.resource_utilization.cpu} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>Memory Usage</span>
                  <span>{metrics.resource_utilization.memory.toFixed(1)}%</span>
                </div>
                <Progress value={metrics.resource_utilization.memory} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>Disk Usage</span>
                  <span>{metrics.resource_utilization.disk.toFixed(1)}%</span>
                </div>
                <Progress value={metrics.resource_utilization.disk} className="h-2" />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Controls */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <CardTitle>Sandbox Jobs</CardTitle>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setAutoRefresh(!autoRefresh)}
              >
                {autoRefresh ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                {autoRefresh ? 'Pause' : 'Start'} Auto-refresh
              </Button>
              <Button variant="outline" size="sm" onClick={fetchJobs}>
                <RefreshCw className="h-4 w-4" />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-4">
            <div className="flex items-center gap-2">
              <Search className="h-4 w-4 text-gray-500" />
              <Input
                placeholder="Search jobs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-48"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="queued">Queued</SelectItem>
                <SelectItem value="preparing">Preparing</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
                <SelectItem value="timeout">Timeout</SelectItem>
                <SelectItem value="cancelled">Cancelled</SelectItem>
              </SelectContent>
            </Select>
            <Select value={priorityFilter} onValueChange={setPriorityFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Priority" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Priorities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="normal">Normal</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Jobs Table */}
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Job ID</TableHead>
                  <TableHead>Priority</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Retries</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredJobs.length > 0 ? (
                  filteredJobs.map((job) => (
                    <TableRow key={job.job_id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {getStatusIcon(job.status)}
                          <Badge className={getStatusColor(job.status)} variant="outline">
                            {job.status}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {job.job_id.substring(0, 8)}...
                      </TableCell>
                      <TableCell>
                        <Badge className={getPriorityColor(job.priority)} variant="outline">
                          {job.priority}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm">
                        {formatRelativeTime(job.created_at)}
                      </TableCell>
                      <TableCell className="text-sm">
                        {job.execution_time ? formatDuration(job.execution_time) : '-'}
                      </TableCell>
                      <TableCell>
                        {job.retry_count > 0 && (
                          <Badge variant="outline">{job.retry_count}</Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          {job.status === 'completed' && job.evidence_path && (
                            <>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => viewEvidence(job.job_id)}
                              >
                                <Eye className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => downloadEvidence(job.job_id)}
                              >
                                <Download className="h-4 w-4" />
                              </Button>
                            </>
                          )}
                          {(job.status === 'queued' || job.status === 'preparing' || job.status === 'running') && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => cancelJob(job.job_id)}
                            >
                              <X className="h-4 w-4" />
                            </Button>
                          )}
                          {job.status === 'failed' && job.retry_count < 2 && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => retryJob(job.job_id)}
                            >
                              <RefreshCw className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-gray-500">
                      No jobs found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Error Messages */}
      {filteredJobs.some(job => job.error_message) && (
        <Card>
          <CardHeader>
            <CardTitle>Recent Errors</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {filteredJobs
              .filter(job => job.error_message)
              .slice(0, 3)
              .map((job) => (
                <Alert key={job.job_id} className="p-3">
                  <XCircle className="h-4 w-4" />
                  <AlertDescription>
                    <div className="flex justify-between items-start">
                      <div>
                        <div className="font-medium">Job {job.job_id.substring(0, 8)}...</div>
                        <div className="text-sm text-gray-600">{job.error_message}</div>
                      </div>
                      <Badge variant="outline" className="ml-2">
                        {formatRelativeTime(job.created_at)}
                      </Badge>
                    </div>
                  </AlertDescription>
                </Alert>
              ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default SandboxJobManager;