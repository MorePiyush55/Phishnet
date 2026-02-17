/**
 * AuditLogViewer - Comprehensive audit log interface with advanced filtering
 * 
 * Features:
 * - Real-time audit log display with pagination
 * - Advanced filtering by user, action, category, severity, date range
 * - Role-based access controls
 * - Export functionality
 * - Security statistics dashboard
 * - Responsive design with dark/light mode support
 */

import React, { useState, useEffect, useCallback } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Eye, 
  Download,
  Filter,
  Search,
  Calendar,
  User,
  Activity,
  BarChart3,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Clock,
  MapPin,
  Smartphone,
  FileText,
  Settings,
  XCircle,
  CheckCircle,
  Info,
  AlertCircle
} from 'lucide-react';

import { SecureText, SecureContent } from './SecureContentRenderer';

// Types
interface AuditLog {
  id: number;
  created_at: string;
  user_id?: number;
  session_id?: string;
  user_ip?: string;
  user_agent?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  category: string;
  description: string;
  details?: Record<string, any>;
  request_path?: string;
  request_method?: string;
  response_status?: number;
  duration_ms?: number;
  is_suspicious: boolean;
  security_violation: boolean;
}

interface AuditLogFilters {
  user_id?: number;
  action?: string;
  category?: string;
  severity?: string;
  resource_type?: string;
  start_date?: string;
  end_date?: string;
  suspicious_only: boolean;
  security_violations_only: boolean;
  search?: string;
}

interface AuditLogResponse {
  logs: AuditLog[];
  pagination: {
    page: number;
    limit: number;
    total_count: number;
    total_pages: number;
    has_next: boolean;
    has_prev: boolean;
  };
  filters_applied: AuditLogFilters;
}

interface AuditStats {
  period: {
    start_date: string;
    end_date: string;
    total_logs: number;
  };
  category_breakdown: Record<string, number>;
  severity_breakdown: Record<string, number>;
  security_summary: {
    suspicious_activities: number;
    security_violations: number;
    security_ratio: number;
  };
  top_actions: Array<{ action: string; count: number }>;
  top_users: Array<{ user_id: number; count: number }>;
  daily_activity: Array<{ date: string; count: number }>;
}

const AuditLogViewer: React.FC = () => {
  // State management
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [showStats, setShowStats] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(false);
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  
  // Filter state
  const [filters, setFilters] = useState<AuditLogFilters>({
    suspicious_only: false,
    security_violations_only: false
  });
  
  // Sort state
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  
  // UI state
  const [expandedLog, setExpandedLog] = useState<number | null>(null);
  const [selectedLogs, setSelectedLogs] = useState<Set<number>>(new Set());

  // Fetch audit logs
  const fetchAuditLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const params = new URLSearchParams({
        page: currentPage.toString(),
        limit: pageSize.toString(),
        sort_by: sortBy,
        sort_order: sortOrder,
        ...Object.fromEntries(
          Object.entries(filters).filter(([_, value]) => value !== undefined && value !== '')
        )
      });
      
      const response = await fetch(`/api/v1/audit/logs?${params}`, {
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        }
      });
      
      if (!response.ok) {
        throw new Error(`Failed to fetch audit logs: ${response.statusText}`);
      }
      
      const data: AuditLogResponse = await response.json();
      setLogs(data.logs);
      setTotalPages(data.pagination.total_pages);
      setTotalCount(data.pagination.total_count);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch audit logs');
      console.error('Error fetching audit logs:', err);
    } finally {
      setLoading(false);
    }
  }, [currentPage, pageSize, sortBy, sortOrder, filters]);

  // Fetch audit statistics
  const fetchAuditStats = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filters.start_date) params.append('start_date', filters.start_date);
      if (filters.end_date) params.append('end_date', filters.end_date);
      
      const response = await fetch(`/api/v1/audit/stats?${params}`, {
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        }
      });
      
      if (response.ok) {
        const data: AuditStats = await response.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Error fetching audit stats:', err);
    }
  }, [filters.start_date, filters.end_date]);

  // Export audit logs
  const exportLogs = async (format: 'csv' | 'json') => {
    try {
      const params = new URLSearchParams({
        format,
        ...Object.fromEntries(
          Object.entries(filters).filter(([_, value]) => value !== undefined && value !== '')
        )
      });
      
      const response = await fetch(`/api/v1/audit/export?${params}`, {
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error('Failed to export audit logs');
      }
      
      // Download file
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit_logs_${new Date().toISOString().split('T')[0]}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export audit logs');
    }
  };

  // Auto-refresh effect
  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(fetchAuditLogs, 30000); // Refresh every 30 seconds
      return () => clearInterval(interval);
    }
  }, [autoRefresh, fetchAuditLogs]);

  // Initial load
  useEffect(() => {
    fetchAuditLogs();
    fetchAuditStats();
  }, [fetchAuditLogs, fetchAuditStats]);

  // Helper functions
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <XCircle className="w-4 h-4 text-red-600" />;
      case 'error': return <AlertCircle className="w-4 h-4 text-red-500" />;
      case 'warning': return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case 'info': 
      default: return <Info className="w-4 h-4 text-blue-500" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'error': return 'bg-red-50 text-red-700 border-red-200';
      case 'warning': return 'bg-yellow-50 text-yellow-700 border-yellow-200';
      case 'info': 
      default: return 'bg-blue-50 text-blue-700 border-blue-200';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'auth': return <User className="w-4 h-4" />;
      case 'security': return <Shield className="w-4 h-4" />;
      case 'email': return <FileText className="w-4 h-4" />;
      case 'scan': return <Activity className="w-4 h-4" />;
      case 'admin': return <Settings className="w-4 h-4" />;
      default: return <Eye className="w-4 h-4" />;
    }
  };

  const formatDateTime = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const handleFilterChange = (key: keyof AuditLogFilters, value: any) => {
    setFilters(prev => ({
      ...prev,
      [key]: value
    }));
    setCurrentPage(1); // Reset to first page when filters change
  };

  const handleLogSelection = (logId: number) => {
    const newSelection = new Set(selectedLogs);
    if (newSelection.has(logId)) {
      newSelection.delete(logId);
    } else {
      newSelection.add(logId);
    }
    setSelectedLogs(newSelection);
  };

  const clearFilters = () => {
    setFilters({
      suspicious_only: false,
      security_violations_only: false
    });
    setCurrentPage(1);
  };

  return (
    <div className="max-w-7xl mx-auto p-6 bg-white dark:bg-gray-900">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <Shield className="w-8 h-8 text-blue-600" />
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                Audit Log Viewer
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Monitor system activities and security events
              </p>
            </div>
          </div>
          
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`inline-flex items-center px-3 py-2 border rounded-md text-sm font-medium transition-colors ${
                autoRefresh 
                  ? 'border-green-300 bg-green-50 text-green-700 hover:bg-green-100'
                  : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
              }`}
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />
              Auto Refresh
            </button>
            
            <button
              onClick={() => setShowStats(!showStats)}
              className="inline-flex items-center px-3 py-2 border border-gray-300 bg-white text-gray-700 rounded-md hover:bg-gray-50 text-sm font-medium"
            >
              <BarChart3 className="w-4 h-4 mr-2" />
              {showStats ? 'Hide Stats' : 'Show Stats'}
            </button>
            
            <div className="flex border border-gray-300 rounded-md">
              <button
                onClick={() => exportLogs('csv')}
                className="px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 border-r border-gray-300"
              >
                CSV
              </button>
              <button
                onClick={() => exportLogs('json')}
                className="px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                JSON
              </button>
            </div>
          </div>
        </div>

        {/* Statistics Dashboard */}
        {showStats && stats && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-blue-600">Total Logs</p>
                  <p className="text-2xl font-bold text-blue-900">{stats.period.total_logs.toLocaleString()}</p>
                </div>
                <FileText className="w-8 h-8 text-blue-600" />
              </div>
            </div>
            
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-yellow-600">Suspicious</p>
                  <p className="text-2xl font-bold text-yellow-900">{stats.security_summary.suspicious_activities}</p>
                </div>
                <AlertTriangle className="w-8 h-8 text-yellow-600" />
              </div>
            </div>
            
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-red-600">Violations</p>
                  <p className="text-2xl font-bold text-red-900">{stats.security_summary.security_violations}</p>
                </div>
                <XCircle className="w-8 h-8 text-red-600" />
              </div>
            </div>
            
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-green-600">Security Score</p>
                  <p className="text-2xl font-bold text-green-900">
                    {(100 - stats.security_summary.security_ratio).toFixed(1)}%
                  </p>
                </div>
                <CheckCircle className="w-8 h-8 text-green-600" />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="mb-6">
        <button
          onClick={() => setShowFilters(!showFilters)}
          className="inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-gray-700 rounded-md hover:bg-gray-50 text-sm font-medium mb-4"
        >
          <Filter className="w-4 h-4 mr-2" />
          {showFilters ? 'Hide Filters' : 'Show Filters'}
          {Object.values(filters).some(v => v && v !== false) && (
            <span className="ml-2 px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded-full">
              Active
            </span>
          )}
        </button>

        {showFilters && (
          <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Search */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Search Description
                </label>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    value={filters.search || ''}
                    onChange={(e) => handleFilterChange('search', e.target.value)}
                    placeholder="Search in descriptions..."
                    className="pl-10 w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
              </div>

              {/* User ID */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  User ID
                </label>
                <input
                  type="number"
                  value={filters.user_id || ''}
                  onChange={(e) => handleFilterChange('user_id', e.target.value ? parseInt(e.target.value) : undefined)}
                  placeholder="Enter user ID"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              {/* Action */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Action
                </label>
                <input
                  type="text"
                  value={filters.action || ''}
                  onChange={(e) => handleFilterChange('action', e.target.value)}
                  placeholder="Action type"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              {/* Category */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Category
                </label>
                <select
                  value={filters.category || ''}
                  onChange={(e) => handleFilterChange('category', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                >
                  <option value="">All Categories</option>
                  <option value="auth">Authentication</option>
                  <option value="email">Email</option>
                  <option value="scan">Scanning</option>
                  <option value="admin">Administration</option>
                  <option value="security">Security</option>
                  <option value="api">API</option>
                </select>
              </div>

              {/* Severity */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Severity
                </label>
                <select
                  value={filters.severity || ''}
                  onChange={(e) => handleFilterChange('severity', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                >
                  <option value="">All Severities</option>
                  <option value="info">Info</option>
                  <option value="warning">Warning</option>
                  <option value="error">Error</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              {/* Start Date */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Start Date
                </label>
                <input
                  type="datetime-local"
                  value={filters.start_date || ''}
                  onChange={(e) => handleFilterChange('start_date', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              {/* End Date */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  End Date
                </label>
                <input
                  type="datetime-local"
                  value={filters.end_date || ''}
                  onChange={(e) => handleFilterChange('end_date', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                />
              </div>

              {/* Resource Type */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Resource Type
                </label>
                <input
                  type="text"
                  value={filters.resource_type || ''}
                  onChange={(e) => handleFilterChange('resource_type', e.target.value)}
                  placeholder="Resource type"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
            </div>

            {/* Security Filters */}
            <div className="flex items-center space-x-6">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={filters.suspicious_only}
                  onChange={(e) => handleFilterChange('suspicious_only', e.target.checked)}
                  className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">Suspicious Activities Only</span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={filters.security_violations_only}
                  onChange={(e) => handleFilterChange('security_violations_only', e.target.checked)}
                  className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">Security Violations Only</span>
              </label>
            </div>

            {/* Filter Actions */}
            <div className="flex items-center justify-between pt-4 border-t border-gray-200">
              <button
                onClick={clearFilters}
                className="text-sm text-gray-600 hover:text-gray-800"
              >
                Clear All Filters
              </button>
              
              <button
                onClick={fetchAuditLogs}
                className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm font-medium"
              >
                Apply Filters
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Error Display */}
      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-center">
            <XCircle className="w-5 h-5 text-red-500 mr-2" />
            <SecureText content={error} className="text-red-700" />
          </div>
        </div>
      )}

      {/* Audit Logs Table */}
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        {/* Table Header */}
        <div className="px-6 py-3 bg-gray-50 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-medium text-gray-900">
              Audit Logs ({totalCount.toLocaleString()} total)
            </h2>
            
            {/* Page Size Selector */}
            <div className="flex items-center space-x-2">
              <span className="text-sm text-gray-700">Show:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(parseInt(e.target.value));
                  setCurrentPage(1);
                }}
                className="px-2 py-1 border border-gray-300 rounded text-sm"
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={200}>200</option>
              </select>
            </div>
          </div>
        </div>

        {/* Loading State */}
        {loading && (
          <div className="p-8 text-center">
            <RefreshCw className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-4" />
            <p className="text-gray-600">Loading audit logs...</p>
          </div>
        )}

        {/* Logs List */}
        {!loading && logs.length > 0 && (
          <div className="divide-y divide-gray-200">
            {logs.map((log) => (
              <div key={log.id} className="px-6 py-4 hover:bg-gray-50">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4 flex-1">
                    {/* Severity and Category Icons */}
                    <div className="flex items-center space-x-2 flex-shrink-0">
                      {getSeverityIcon(log.severity)}
                      {getCategoryIcon(log.category)}
                    </div>

                    {/* Main Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-3 mb-2">
                        <SecureText 
                          content={log.action}
                          className="font-medium text-gray-900"
                          testId={`log-action-${log.id}`}
                        />
                        
                        <span className={`inline-flex items-center px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(log.severity)}`}>
                          {log.severity}
                        </span>
                        
                        <span className="inline-flex items-center px-2 py-1 text-xs font-medium bg-gray-100 text-gray-700 rounded-full">
                          {log.category}
                        </span>
                        
                        {log.is_suspicious && (
                          <span className="inline-flex items-center px-2 py-1 text-xs font-medium bg-yellow-100 text-yellow-800 rounded-full border border-yellow-200">
                            <AlertTriangle className="w-3 h-3 mr-1" />
                            Suspicious
                          </span>
                        )}
                        
                        {log.security_violation && (
                          <span className="inline-flex items-center px-2 py-1 text-xs font-medium bg-red-100 text-red-800 rounded-full border border-red-200">
                            <Shield className="w-3 h-3 mr-1" />
                            Violation
                          </span>
                        )}
                      </div>
                      
                      <SecureText 
                        content={log.description}
                        className="text-gray-700"
                        maxLength={200}
                        testId={`log-description-${log.id}`}
                      />
                      
                      <div className="flex items-center space-x-4 mt-2 text-sm text-gray-500">
                        <div className="flex items-center space-x-1">
                          <Clock className="w-4 h-4" />
                          <span>{formatDateTime(log.created_at)}</span>
                        </div>
                        
                        {log.user_id && (
                          <div className="flex items-center space-x-1">
                            <User className="w-4 h-4" />
                            <span>User {log.user_id}</span>
                          </div>
                        )}
                        
                        {log.user_ip && (
                          <div className="flex items-center space-x-1">
                            <MapPin className="w-4 h-4" />
                            <SecureText content={log.user_ip} />
                          </div>
                        )}
                        
                        {log.resource_type && log.resource_id && (
                          <div className="flex items-center space-x-1">
                            <FileText className="w-4 h-4" />
                            <SecureText content={`${log.resource_type}:${log.resource_id}`} />
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center space-x-2 flex-shrink-0">
                      <button
                        onClick={() => setExpandedLog(expandedLog === log.id ? null : log.id)}
                        className="text-gray-400 hover:text-gray-600"
                        title="View Details"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      
                      <input
                        type="checkbox"
                        checked={selectedLogs.has(log.id)}
                        onChange={() => handleLogSelection(log.id)}
                        className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                      />
                    </div>
                  </div>
                </div>

                {/* Expanded Details */}
                {expandedLog === log.id && (
                  <div className="mt-4 pt-4 border-t border-gray-200">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <h4 className="font-medium text-gray-900 mb-2">Request Details</h4>
                        <dl className="space-y-1">
                          {log.request_path && (
                            <div className="flex">
                              <dt className="font-medium text-gray-500 w-24">Path:</dt>
                              <dd className="text-gray-700">
                                <SecureText content={log.request_path} />
                              </dd>
                            </div>
                          )}
                          {log.request_method && (
                            <div className="flex">
                              <dt className="font-medium text-gray-500 w-24">Method:</dt>
                              <dd className="text-gray-700">{log.request_method}</dd>
                            </div>
                          )}
                          {log.response_status && (
                            <div className="flex">
                              <dt className="font-medium text-gray-500 w-24">Status:</dt>
                              <dd className="text-gray-700">{log.response_status}</dd>
                            </div>
                          )}
                          {log.duration_ms && (
                            <div className="flex">
                              <dt className="font-medium text-gray-500 w-24">Duration:</dt>
                              <dd className="text-gray-700">{log.duration_ms}ms</dd>
                            </div>
                          )}
                        </dl>
                      </div>
                      
                      <div>
                        <h4 className="font-medium text-gray-900 mb-2">Session Details</h4>
                        <dl className="space-y-1">
                          {log.session_id && (
                            <div className="flex">
                              <dt className="font-medium text-gray-500 w-24">Session:</dt>
                              <dd className="text-gray-700">
                                <SecureText content={log.session_id} maxLength={20} />
                              </dd>
                            </div>
                          )}
                          {log.user_agent && (
                            <div className="flex">
                              <dt className="font-medium text-gray-500 w-24">Agent:</dt>
                              <dd className="text-gray-700">
                                <SecureText content={log.user_agent} maxLength={50} />
                              </dd>
                            </div>
                          )}
                        </dl>
                      </div>
                    </div>
                    
                    {log.details && Object.keys(log.details).length > 0 && (
                      <div className="mt-4">
                        <h4 className="font-medium text-gray-900 mb-2">Additional Details</h4>
                        <pre className="bg-gray-50 p-3 rounded-md text-xs overflow-x-auto">
                          <SecureText content={JSON.stringify(log.details, null, 2)} />
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Empty State */}
        {!loading && logs.length === 0 && (
          <div className="p-8 text-center">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No audit logs found</h3>
            <p className="text-gray-600">
              {Object.values(filters).some(v => v && v !== false) 
                ? 'Try adjusting your filters to see more results.'
                : 'No audit logs are available for the selected time period.'
              }
            </p>
          </div>
        )}

        {/* Pagination */}
        {!loading && logs.length > 0 && totalPages > 1 && (
          <div className="px-6 py-3 bg-gray-50 border-t border-gray-200">
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-700">
                Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, totalCount)} of {totalCount.toLocaleString()} results
              </div>
              
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setCurrentPage(currentPage - 1)}
                  disabled={currentPage === 1}
                  className="inline-flex items-center px-3 py-2 border border-gray-300 bg-white text-sm font-medium rounded-md text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronLeft className="w-4 h-4 mr-1" />
                  Previous
                </button>
                
                <span className="text-sm text-gray-700">
                  Page {currentPage} of {totalPages}
                </span>
                
                <button
                  onClick={() => setCurrentPage(currentPage + 1)}
                  disabled={currentPage === totalPages}
                  className="inline-flex items-center px-3 py-2 border border-gray-300 bg-white text-sm font-medium rounded-md text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                  <ChevronRight className="w-4 h-4 ml-1" />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AuditLogViewer;
