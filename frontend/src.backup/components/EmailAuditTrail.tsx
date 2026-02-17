import React, { useState, useEffect } from 'react';
import { 
  Clock, 
  User, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Eye,
  Shield,
  Bot,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Activity,
  FileText,
  Link,
  Scan,
  Database
} from 'lucide-react';

interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  actor: 'system' | 'user' | 'ai' | 'external';
  actor_details?: {
    name?: string;
    service?: string;
    user_id?: number;
  };
  status: 'success' | 'error' | 'warning' | 'info';
  details: Record<string, any>;
  duration_ms?: number;
  metadata?: {
    ip_address?: string;
    user_agent?: string;
    api_version?: string;
  };
}

interface EmailAuditTrailProps {
  emailId: number;
  auditEntries?: AuditEntry[];
  loading?: boolean;
  error?: string;
  showTimeline?: boolean;
  maxHeight?: string;
}

const getActorIcon = (actor: AuditEntry['actor']) => {
  switch (actor) {
    case 'user':
      return <User className="h-4 w-4" />;
    case 'ai':
      return <Bot className="h-4 w-4" />;
    case 'external':
      return <ExternalLink className="h-4 w-4" />;
    default:
      return <Activity className="h-4 w-4" />;
  }
};

const getStatusIcon = (status: AuditEntry['status']) => {
  switch (status) {
    case 'success':
      return <CheckCircle className="h-4 w-4 text-green-500" />;
    case 'error':
      return <XCircle className="h-4 w-4 text-red-500" />;
    case 'warning':
      return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
    default:
      return <Activity className="h-4 w-4 text-blue-500" />;
  }
};

const getActionIcon = (action: string) => {
  if (action.includes('scan') || action.includes('analyze')) {
    return <Scan className="h-4 w-4" />;
  }
  if (action.includes('link')) {
    return <Link className="h-4 w-4" />;
  }
  if (action.includes('quarantine') || action.includes('block')) {
    return <Shield className="h-4 w-4" />;
  }
  if (action.includes('view') || action.includes('read')) {
    return <Eye className="h-4 w-4" />;
  }
  if (action.includes('file') || action.includes('attachment')) {
    return <FileText className="h-4 w-4" />;
  }
  if (action.includes('data') || action.includes('store')) {
    return <Database className="h-4 w-4" />;
  }
  return <Activity className="h-4 w-4" />;
};

const formatDuration = (ms: number): string => {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
};

const formatAction = (action: string): string => {
  return action
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
};

interface AuditEntryItemProps {
  entry: AuditEntry;
  showDetails: boolean;
  onToggleDetails: () => void;
  isTimeline?: boolean;
}

const AuditEntryItem: React.FC<AuditEntryItemProps> = ({
  entry,
  showDetails,
  onToggleDetails,
  isTimeline = false
}) => {
  const actorIcon = getActorIcon(entry.actor);
  const statusIcon = getStatusIcon(entry.status);
  const actionIcon = getActionIcon(entry.action);

  return (
    <div className={`${isTimeline ? 'relative' : ''} bg-white border rounded-lg p-4`}>
      {isTimeline && (
        <div className="absolute left-0 top-6 w-px h-full bg-gray-200 -translate-x-1/2"></div>
      )}
      
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            {statusIcon}
            <div className="text-gray-500">
              {actionIcon}
            </div>
            <div className="text-gray-500">
              {actorIcon}
            </div>
          </div>
          
          <div>
            <div className="font-medium text-gray-900">
              {formatAction(entry.action)}
            </div>
            <div className="text-sm text-gray-500">
              {entry.actor_details?.name || entry.actor_details?.service || entry.actor}
              {entry.duration_ms && (
                <span className="ml-2 text-gray-400">
                  ({formatDuration(entry.duration_ms)})
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <div className="text-right">
            <div className="text-sm text-gray-900">
              {new Date(entry.timestamp).toLocaleTimeString()}
            </div>
            <div className="text-xs text-gray-500">
              {new Date(entry.timestamp).toLocaleDateString()}
            </div>
          </div>
          
          <button
            onClick={onToggleDetails}
            className="p-1 hover:bg-gray-100 rounded"
          >
            {showDetails ? (
              <ChevronDown className="h-4 w-4 text-gray-400" />
            ) : (
              <ChevronRight className="h-4 w-4 text-gray-400" />
            )}
          </button>
        </div>
      </div>

      {/* Details */}
      {showDetails && (
        <div className="mt-4 space-y-3">
          {/* Basic Details */}
          {Object.keys(entry.details).length > 0 && (
            <div className="bg-gray-50 rounded p-3">
              <div className="text-sm font-medium text-gray-700 mb-2">Details</div>
              <div className="space-y-1">
                {Object.entries(entry.details).map(([key, value]) => (
                  <div key={key} className="flex justify-between text-sm">
                    <span className="text-gray-600 capitalize">
                      {key.replace(/_/g, ' ')}:
                    </span>
                    <span className="text-gray-900 font-mono">
                      {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Metadata */}
          {entry.metadata && (
            <div className="bg-blue-50 rounded p-3">
              <div className="text-sm font-medium text-blue-700 mb-2">Metadata</div>
              <div className="space-y-1">
                {entry.metadata.ip_address && (
                  <div className="flex justify-between text-sm">
                    <span className="text-blue-600">IP Address:</span>
                    <span className="text-blue-900 font-mono">{entry.metadata.ip_address}</span>
                  </div>
                )}
                {entry.metadata.user_agent && (
                  <div className="flex justify-between text-sm">
                    <span className="text-blue-600">User Agent:</span>
                    <span className="text-blue-900 font-mono text-xs truncate max-w-xs">
                      {entry.metadata.user_agent}
                    </span>
                  </div>
                )}
                {entry.metadata.api_version && (
                  <div className="flex justify-between text-sm">
                    <span className="text-blue-600">API Version:</span>
                    <span className="text-blue-900 font-mono">{entry.metadata.api_version}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export const EmailAuditTrail: React.FC<EmailAuditTrailProps> = ({
  emailId,
  auditEntries = [],
  loading = false,
  error,
  showTimeline = false,
  maxHeight = '500px'
}) => {
  const [expandedEntries, setExpandedEntries] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<{
    actor?: string;
    status?: string;
    action?: string;
  }>({});

  const toggleEntryDetails = (entryId: string) => {
    const newExpanded = new Set(expandedEntries);
    if (newExpanded.has(entryId)) {
      newExpanded.delete(entryId);
    } else {
      newExpanded.add(entryId);
    }
    setExpandedEntries(newExpanded);
  };

  const filteredEntries = auditEntries.filter(entry => {
    if (filter.actor && entry.actor !== filter.actor) return false;
    if (filter.status && entry.status !== filter.status) return false;
    if (filter.action && !entry.action.includes(filter.action)) return false;
    return true;
  });

  const sortedEntries = [...filteredEntries].sort((a, b) => 
    new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  if (loading) {
    return (
      <div className="bg-white rounded-lg border p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-200 rounded mb-4"></div>
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-16 bg-gray-100 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <div className="flex items-center space-x-2">
          <XCircle className="h-5 w-5 text-red-500" />
          <span className="text-red-700">Failed to load audit trail: {error}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg border">
      {/* Header */}
      <div className="border-b p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">
            Audit Trail
          </h3>
          <div className="text-sm text-gray-500">
            {auditEntries.length} entries
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2">
          <select
            value={filter.actor || ''}
            onChange={(e) => setFilter(prev => ({ ...prev, actor: e.target.value || undefined }))}
            className="text-sm border rounded px-2 py-1"
          >
            <option value="">All Actors</option>
            <option value="system">System</option>
            <option value="user">User</option>
            <option value="ai">AI</option>
            <option value="external">External</option>
          </select>

          <select
            value={filter.status || ''}
            onChange={(e) => setFilter(prev => ({ ...prev, status: e.target.value || undefined }))}
            className="text-sm border rounded px-2 py-1"
          >
            <option value="">All Status</option>
            <option value="success">Success</option>
            <option value="error">Error</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </select>

          <input
            type="text"
            placeholder="Filter by action..."
            value={filter.action || ''}
            onChange={(e) => setFilter(prev => ({ ...prev, action: e.target.value || undefined }))}
            className="text-sm border rounded px-2 py-1 placeholder-gray-400"
          />

          {Object.values(filter).some(v => v) && (
            <button
              onClick={() => setFilter({})}
              className="text-sm text-blue-600 hover:text-blue-800"
            >
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* Entries */}
      <div 
        className="p-4 overflow-y-auto"
        style={{ maxHeight }}
      >
        {sortedEntries.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Activity className="h-12 w-12 mx-auto mb-4 text-gray-300" />
            <div>No audit entries found</div>
            {Object.values(filter).some(v => v) && (
              <div className="text-sm mt-2">Try adjusting your filters</div>
            )}
          </div>
        ) : (
          <div className={`space-y-4 ${showTimeline ? 'relative pl-6' : ''}`}>
            {showTimeline && (
              <div className="absolute left-0 top-0 w-px h-full bg-gray-200 translate-x-3"></div>
            )}
            
            {sortedEntries.map((entry, index) => (
              <div key={entry.id} className={showTimeline ? 'relative' : ''}>
                {showTimeline && (
                  <div className="absolute left-0 top-6 w-6 h-6 bg-white border-2 border-gray-300 rounded-full -translate-x-1/2 flex items-center justify-center">
                    {getStatusIcon(entry.status)}
                  </div>
                )}
                
                <AuditEntryItem
                  entry={entry}
                  showDetails={expandedEntries.has(entry.id)}
                  onToggleDetails={() => toggleEntryDetails(entry.id)}
                  isTimeline={showTimeline}
                />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// Simplified version for email list view
export const EmailAuditSummary: React.FC<{
  emailId: number;
  lastActivity?: string;
  activityCount?: number;
  statusCounts?: Record<string, number>;
}> = ({ emailId, lastActivity, activityCount, statusCounts }) => {
  return (
    <div className="flex items-center space-x-4 text-sm text-gray-500">
      <div className="flex items-center space-x-1">
        <Activity className="h-4 w-4" />
        <span>{activityCount || 0} events</span>
      </div>
      
      {lastActivity && (
        <div className="flex items-center space-x-1">
          <Clock className="h-4 w-4" />
          <span>{new Date(lastActivity).toLocaleString()}</span>
        </div>
      )}
      
      {statusCounts && (
        <div className="flex space-x-2">
          {statusCounts.error > 0 && (
            <div className="flex items-center space-x-1">
              <XCircle className="h-3 w-3 text-red-500" />
              <span>{statusCounts.error}</span>
            </div>
          )}
          {statusCounts.warning > 0 && (
            <div className="flex items-center space-x-1">
              <AlertTriangle className="h-3 w-3 text-yellow-500" />
              <span>{statusCounts.warning}</span>
            </div>
          )}
          {statusCounts.success > 0 && (
            <div className="flex items-center space-x-1">
              <CheckCircle className="h-3 w-3 text-green-500" />
              <span>{statusCounts.success}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
