/**
 * Enhanced Audit History Component
 * 
 * Provides comprehensive audit trail and history tracking:
 * - Detailed action logs with user attribution
 * - Filterable timeline view
 * - Privacy compliance audit trail
 * - System events and automated actions
 * - Export capabilities for compliance reporting
 */

import React, { useState, useEffect, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Calendar } from '@/components/ui/calendar';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  History, 
  User, 
  Shield, 
  Bot, 
  Filter,
  Download,
  Search,
  Calendar as CalendarIcon,
  Clock,
  AlertTriangle,
  CheckCircle,
  Info,
  Settings,
  Eye,
  Lock,
  Globe,
  FileText,
  Trash2,
  RefreshCw,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { format, formatDistanceToNow, subDays, startOfDay, endOfDay } from 'date-fns';

interface AuditEntry {
  id: string;
  timestamp: string;
  event_type: 'user_action' | 'system_event' | 'privacy_event' | 'security_event';
  action: string;
  user_id?: string;
  user_email?: string;
  target_type: 'url' | 'domain' | 'user' | 'system' | 'analysis';
  target_id: string;
  target_description: string;
  details: {
    ip_address?: string;
    user_agent?: string;
    session_id?: string;
    before_state?: any;
    after_state?: any;
    reason?: string;
    metadata?: Record<string, any>;
  };
  severity: 'info' | 'warning' | 'error' | 'critical';
  status: 'completed' | 'pending' | 'failed';
  privacy_sensitive: boolean;
  retention_category: 'operational' | 'security' | 'compliance' | 'analytics';
  expires_at?: string;
}

interface AuditFilters {
  event_types: string[];
  severity_levels: string[];
  users: string[];
  date_range: {
    start: Date | null;
    end: Date | null;
  };
  search_query: string;
  target_type: string;
  status: string;
}

interface EnhancedAuditHistoryProps {
  entries: AuditEntry[];
  onLoadMore?: (filters: AuditFilters) => Promise<AuditEntry[]>;
  onExport?: (filters: AuditFilters) => Promise<void>;
  userRole?: 'user' | 'admin' | 'analyst' | 'compliance';
  showPrivacyCompliance?: boolean;
  organizationId?: string;
}

const AuditEntryCard: React.FC<{
  entry: AuditEntry;
  isExpanded: boolean;
  onToggleExpand: () => void;
  showPrivacyInfo?: boolean;
}> = ({ entry, isExpanded, onToggleExpand, showPrivacyInfo = false }) => {
  const getEventIcon = (type: string) => {
    switch (type) {
      case 'user_action': return User;
      case 'system_event': return Bot;
      case 'privacy_event': return Lock;
      case 'security_event': return Shield;
      default: return Info;
    }
  };
  
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'error': return 'text-red-500 bg-red-50';
      case 'warning': return 'text-orange-500 bg-orange-50';
      case 'info': return 'text-blue-500 bg-blue-50';
      default: return 'text-gray-500 bg-gray-50';
    }
  };
  
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-3 h-3 text-green-500" />;
      case 'pending': return <Clock className="w-3 h-3 text-yellow-500" />;
      case 'failed': return <AlertTriangle className="w-3 h-3 text-red-500" />;
      default: return <Info className="w-3 h-3 text-gray-500" />;
    }
  };
  
  const EventIcon = getEventIcon(entry.event_type);
  
  return (
    <Card className={`${entry.severity === 'critical' ? 'border-red-300' : ''} ${entry.privacy_sensitive ? 'border-l-4 border-l-purple-500' : ''}`}>
      <CardContent className="p-4">
        <div 
          className="flex items-start justify-between cursor-pointer"
          onClick={onToggleExpand}
        >
          <div className="flex items-start gap-3 flex-1">
            <div className={`p-2 rounded-full ${getSeverityColor(entry.severity)}`}>
              <EventIcon className="w-4 h-4" />
            </div>
            
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-semibold text-sm">
                  {entry.action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </span>
                {getStatusIcon(entry.status)}
                {entry.privacy_sensitive && showPrivacyInfo && (
                  <Badge variant="outline" className="text-xs">
                    <Lock className="w-2 h-2 mr-1" />
                    Privacy Sensitive
                  </Badge>
                )}
              </div>
              
              <div className="text-sm text-gray-600 mb-2">
                {entry.target_description}
              </div>
              
              <div className="flex items-center gap-4 text-xs text-gray-500">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {formatDistanceToNow(new Date(entry.timestamp), { addSuffix: true })}
                </span>
                
                {entry.user_email && (
                  <span className="flex items-center gap-1">
                    <User className="w-3 h-3" />
                    {entry.user_email}
                  </span>
                )}
                
                <Badge variant="outline" className="text-xs">
                  {entry.event_type.replace('_', ' ')}
                </Badge>
              </div>
            </div>
          </div>
          
          <Button variant="ghost" size="sm">
            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </Button>
        </div>
        
        {isExpanded && (
          <div className="mt-4 pt-4 border-t space-y-4">
            {/* Detailed Information */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <h5 className="font-semibold text-gray-700 mb-2">Event Details</h5>
                <div className="space-y-1">
                  <div>
                    <span className="text-gray-500">Event ID:</span> 
                    <span className="ml-2 font-mono">{entry.id}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Timestamp:</span> 
                    <span className="ml-2">{format(new Date(entry.timestamp), 'PPpp')}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Target Type:</span> 
                    <span className="ml-2">{entry.target_type}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Target ID:</span> 
                    <span className="ml-2 font-mono">{entry.target_id}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Retention Category:</span> 
                    <Badge variant="outline" className="ml-2 text-xs">
                      {entry.retention_category}
                    </Badge>
                  </div>
                  {entry.expires_at && (
                    <div>
                      <span className="text-gray-500">Expires:</span> 
                      <span className="ml-2">{format(new Date(entry.expires_at), 'PPP')}</span>
                    </div>
                  )}
                </div>
              </div>
              
              {entry.details && (
                <div>
                  <h5 className="font-semibold text-gray-700 mb-2">Technical Details</h5>
                  <div className="space-y-1">
                    {entry.details.ip_address && (
                      <div>
                        <span className="text-gray-500">IP Address:</span>
                        <span className="ml-2 font-mono">{entry.details.ip_address}</span>
                      </div>
                    )}
                    {entry.details.session_id && (
                      <div>
                        <span className="text-gray-500">Session:</span>
                        <span className="ml-2 font-mono">{entry.details.session_id.substring(0, 8)}...</span>
                      </div>
                    )}
                    {entry.details.reason && (
                      <div>
                        <span className="text-gray-500">Reason:</span>
                        <span className="ml-2">{entry.details.reason}</span>
                      </div>
                    )}
                    {entry.details.user_agent && (
                      <div>
                        <span className="text-gray-500">User Agent:</span>
                        <span className="ml-2 text-xs font-mono truncate">{entry.details.user_agent}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
            
            {/* State Changes */}
            {(entry.details.before_state || entry.details.after_state) && (
              <div>
                <h5 className="font-semibold text-gray-700 mb-2">State Changes</h5>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {entry.details.before_state && (
                    <div>
                      <h6 className="text-xs font-semibold text-gray-600 mb-1">Before</h6>
                      <pre className="text-xs bg-gray-100 p-2 rounded font-mono overflow-x-auto">
                        {JSON.stringify(entry.details.before_state, null, 2)}
                      </pre>
                    </div>
                  )}
                  {entry.details.after_state && (
                    <div>
                      <h6 className="text-xs font-semibold text-gray-600 mb-1">After</h6>
                      <pre className="text-xs bg-gray-100 p-2 rounded font-mono overflow-x-auto">
                        {JSON.stringify(entry.details.after_state, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            )}
            
            {/* Metadata */}
            {entry.details.metadata && Object.keys(entry.details.metadata).length > 0 && (
              <div>
                <h5 className="font-semibold text-gray-700 mb-2">Additional Metadata</h5>
                <pre className="text-xs bg-gray-100 p-2 rounded font-mono overflow-x-auto">
                  {JSON.stringify(entry.details.metadata, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

const AuditFiltersPanel: React.FC<{
  filters: AuditFilters;
  onFiltersChange: (filters: AuditFilters) => void;
  availableUsers: string[];
}> = ({ filters, onFiltersChange, availableUsers }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  
  const eventTypes = [
    { value: 'user_action', label: 'User Actions' },
    { value: 'system_event', label: 'System Events' },
    { value: 'privacy_event', label: 'Privacy Events' },
    { value: 'security_event', label: 'Security Events' }
  ];
  
  const severityLevels = [
    { value: 'info', label: 'Info' },
    { value: 'warning', label: 'Warning' },
    { value: 'error', label: 'Error' },
    { value: 'critical', label: 'Critical' }
  ];
  
  const targetTypes = [
    { value: '', label: 'All Types' },
    { value: 'url', label: 'URLs' },
    { value: 'domain', label: 'Domains' },
    { value: 'user', label: 'Users' },
    { value: 'system', label: 'System' },
    { value: 'analysis', label: 'Analysis' }
  ];
  
  const statusOptions = [
    { value: '', label: 'All Statuses' },
    { value: 'completed', label: 'Completed' },
    { value: 'pending', label: 'Pending' },
    { value: 'failed', label: 'Failed' }
  ];
  
  const quickDateRanges = [
    { label: 'Last 24 hours', days: 1 },
    { label: 'Last 7 days', days: 7 },
    { label: 'Last 30 days', days: 30 },
    { label: 'Last 90 days', days: 90 }
  ];
  
  const setQuickDateRange = (days: number) => {
    onFiltersChange({
      ...filters,
      date_range: {
        start: startOfDay(subDays(new Date(), days)),
        end: endOfDay(new Date())
      }
    });
  };
  
  return (
    <Card>
      <CardHeader>
        <div className="flex justify-between items-center">
          <CardTitle className="flex items-center gap-2">
            <Filter className="w-4 h-4" />
            Filters
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </Button>
        </div>
      </CardHeader>
      
      {isExpanded && (
        <CardContent className="pt-0">
          <div className="space-y-4">
            {/* Search */}
            <div>
              <label className="text-sm font-medium">Search</label>
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-gray-500" />
                <Input
                  placeholder="Search audit logs..."
                  value={filters.search_query}
                  onChange={(e) => onFiltersChange({ ...filters, search_query: e.target.value })}
                  className="pl-8"
                />
              </div>
            </div>
            
            {/* Date Range */}
            <div>
              <label className="text-sm font-medium mb-2 block">Date Range</label>
              <div className="flex gap-2 mb-2">
                {quickDateRanges.map(range => (
                  <Button
                    key={range.days}
                    variant="outline"
                    size="sm"
                    onClick={() => setQuickDateRange(range.days)}
                  >
                    {range.label}
                  </Button>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Popover>
                  <PopoverTrigger asChild>
                    <Button variant="outline" className="justify-start">
                      <CalendarIcon className="mr-2 h-4 w-4" />
                      {filters.date_range.start ? format(filters.date_range.start, 'PPP') : 'Start date'}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="w-auto p-0">
                    <Calendar
                      mode="single"
                      selected={filters.date_range.start}
                      onSelect={(date) => onFiltersChange({
                        ...filters,
                        date_range: { ...filters.date_range, start: date }
                      })}
                      initialFocus
                    />
                  </PopoverContent>
                </Popover>
                
                <Popover>
                  <PopoverTrigger asChild>
                    <Button variant="outline" className="justify-start">
                      <CalendarIcon className="mr-2 h-4 w-4" />
                      {filters.date_range.end ? format(filters.date_range.end, 'PPP') : 'End date'}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="w-auto p-0">
                    <Calendar
                      mode="single"
                      selected={filters.date_range.end}
                      onSelect={(date) => onFiltersChange({
                        ...filters,
                        date_range: { ...filters.date_range, end: date }
                      })}
                      initialFocus
                    />
                  </PopoverContent>
                </Popover>
              </div>
            </div>
            
            {/* Event Types */}
            <div>
              <label className="text-sm font-medium mb-2 block">Event Types</label>
              <div className="space-y-2">
                {eventTypes.map(type => (
                  <label key={type.value} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={filters.event_types.includes(type.value)}
                      onChange={(e) => {
                        const newTypes = e.target.checked
                          ? [...filters.event_types, type.value]
                          : filters.event_types.filter(t => t !== type.value);
                        onFiltersChange({ ...filters, event_types: newTypes });
                      }}
                    />
                    <span className="text-sm">{type.label}</span>
                  </label>
                ))}
              </div>
            </div>
            
            {/* Severity Levels */}
            <div>
              <label className="text-sm font-medium mb-2 block">Severity Levels</label>
              <div className="space-y-2">
                {severityLevels.map(level => (
                  <label key={level.value} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={filters.severity_levels.includes(level.value)}
                      onChange={(e) => {
                        const newLevels = e.target.checked
                          ? [...filters.severity_levels, level.value]
                          : filters.severity_levels.filter(l => l !== level.value);
                        onFiltersChange({ ...filters, severity_levels: newLevels });
                      }}
                    />
                    <span className="text-sm">{level.label}</span>
                  </label>
                ))}
              </div>
            </div>
            
            {/* Target Type */}
            <div>
              <label className="text-sm font-medium">Target Type</label>
              <Select value={filters.target_type} onValueChange={(value) => onFiltersChange({ ...filters, target_type: value })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {targetTypes.map(type => (
                    <SelectItem key={type.value} value={type.value}>{type.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            
            {/* Status */}
            <div>
              <label className="text-sm font-medium">Status</label>
              <Select value={filters.status} onValueChange={(value) => onFiltersChange({ ...filters, status: value })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {statusOptions.map(status => (
                    <SelectItem key={status.value} value={status.value}>{status.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            
            {/* Clear Filters */}
            <Button
              variant="outline"
              onClick={() => onFiltersChange({
                event_types: [],
                severity_levels: [],
                users: [],
                date_range: { start: null, end: null },
                search_query: '',
                target_type: '',
                status: ''
              })}
              className="w-full"
            >
              Clear All Filters
            </Button>
          </div>
        </CardContent>
      )}
    </Card>
  );
};

const ComplianceSummary: React.FC<{
  entries: AuditEntry[];
  timeRange: { start: Date | null; end: Date | null };
}> = ({ entries, timeRange }) => {
  const summary = useMemo(() => {
    const privacySensitive = entries.filter(e => e.privacy_sensitive);
    const byRetentionCategory = entries.reduce((acc, entry) => {
      acc[entry.retention_category] = (acc[entry.retention_category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    const byEventType = entries.reduce((acc, entry) => {
      acc[entry.event_type] = (acc[entry.event_type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    return {
      total: entries.length,
      privacySensitive: privacySensitive.length,
      byRetentionCategory,
      byEventType,
      expiringWithin30Days: entries.filter(e => 
        e.expires_at && new Date(e.expires_at) < new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      ).length
    };
  }, [entries]);
  
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileText className="w-4 h-4" />
          Compliance Summary
        </CardTitle>
        {timeRange.start && timeRange.end && (
          <div className="text-sm text-gray-600">
            {format(timeRange.start, 'PPP')} - {format(timeRange.end, 'PPP')}
          </div>
        )}
      </CardHeader>
      
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="text-center">
            <div className="text-2xl font-bold">{summary.total}</div>
            <div className="text-sm text-gray-600">Total Events</div>
          </div>
          
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-600">{summary.privacySensitive}</div>
            <div className="text-sm text-gray-600">Privacy Sensitive</div>
          </div>
          
          <div className="text-center">
            <div className="text-2xl font-bold text-orange-600">{summary.expiringWithin30Days}</div>
            <div className="text-sm text-gray-600">Expiring Soon</div>
          </div>
          
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">
              {Object.keys(summary.byRetentionCategory).length}
            </div>
            <div className="text-sm text-gray-600">Retention Categories</div>
          </div>
        </div>
        
        <div className="space-y-4">
          <div>
            <h4 className="text-sm font-semibold mb-2">By Event Type</h4>
            <div className="space-y-1">
              {Object.entries(summary.byEventType).map(([type, count]) => (
                <div key={type} className="flex justify-between items-center">
                  <span className="text-sm capitalize">{type.replace('_', ' ')}</span>
                  <Badge variant="outline">{count}</Badge>
                </div>
              ))}
            </div>
          </div>
          
          <div>
            <h4 className="text-sm font-semibold mb-2">By Retention Category</h4>
            <div className="space-y-1">
              {Object.entries(summary.byRetentionCategory).map(([category, count]) => (
                <div key={category} className="flex justify-between items-center">
                  <span className="text-sm capitalize">{category}</span>
                  <Badge variant="outline">{count}</Badge>
                </div>
              ))}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

const EnhancedAuditHistory: React.FC<EnhancedAuditHistoryProps> = ({ 
  entries,
  onLoadMore,
  onExport,
  userRole = 'user',
  showPrivacyCompliance = false,
  organizationId
}) => {
  const [filters, setFilters] = useState<AuditFilters>({
    event_types: [],
    severity_levels: [],
    users: [],
    date_range: { start: null, end: null },
    search_query: '',
    target_type: '',
    status: ''
  });
  
  const [expandedEntries, setExpandedEntries] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab] = useState('events');
  const [isLoading, setIsLoading] = useState(false);
  
  const toggleExpanded = (id: string) => {
    setExpandedEntries(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };
  
  const filteredEntries = useMemo(() => {
    return entries.filter(entry => {
      // Apply filters
      if (filters.event_types.length > 0 && !filters.event_types.includes(entry.event_type)) {
        return false;
      }
      
      if (filters.severity_levels.length > 0 && !filters.severity_levels.includes(entry.severity)) {
        return false;
      }
      
      if (filters.target_type && entry.target_type !== filters.target_type) {
        return false;
      }
      
      if (filters.status && entry.status !== filters.status) {
        return false;
      }
      
      if (filters.search_query) {
        const query = filters.search_query.toLowerCase();
        const searchableText = `
          ${entry.action} ${entry.target_description} ${entry.user_email || ''} 
          ${entry.details.reason || ''} ${entry.target_id}
        `.toLowerCase();
        
        if (!searchableText.includes(query)) {
          return false;
        }
      }
      
      if (filters.date_range.start && new Date(entry.timestamp) < filters.date_range.start) {
        return false;
      }
      
      if (filters.date_range.end && new Date(entry.timestamp) > filters.date_range.end) {
        return false;
      }
      
      return true;
    });
  }, [entries, filters]);
  
  const availableUsers = useMemo(() => {
    return [...new Set(entries.map(e => e.user_email).filter(Boolean))];
  }, [entries]);
  
  const handleExport = async () => {
    setIsLoading(true);
    try {
      if (onExport) {
        await onExport(filters);
      }
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleLoadMore = async () => {
    setIsLoading(true);
    try {
      if (onLoadMore) {
        await onLoadMore(filters);
      }
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="flex items-center gap-2">
                <History className="w-5 h-5" />
                Audit History
              </CardTitle>
              <div className="text-sm text-gray-600 mt-1">
                Showing {filteredEntries.length} of {entries.length} entries
              </div>
            </div>
            
            <div className="flex gap-2">
              {onExport && (
                <Button 
                  variant="outline" 
                  onClick={handleExport}
                  disabled={isLoading}
                >
                  <Download className="w-4 h-4 mr-2" />
                  Export
                </Button>
              )}
              
              <Button 
                variant="outline" 
                onClick={handleLoadMore}
                disabled={isLoading}
              >
                <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>
      
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-1">
          <AuditFiltersPanel
            filters={filters}
            onFiltersChange={setFilters}
            availableUsers={availableUsers}
          />
          
          {showPrivacyCompliance && (
            <div className="mt-4">
              <ComplianceSummary
                entries={filteredEntries}
                timeRange={filters.date_range}
              />
            </div>
          )}
        </div>
        
        <div className="lg:col-span-3">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="events">Audit Events</TabsTrigger>
              {showPrivacyCompliance && <TabsTrigger value="compliance">Compliance View</TabsTrigger>}
            </TabsList>
            
            <TabsContent value="events" className="space-y-4">
              {filteredEntries.length === 0 ? (
                <Card>
                  <CardContent className="p-8 text-center">
                    <History className="w-12 h-12 mx-auto text-gray-400 mb-4" />
                    <p className="text-gray-600">No audit entries found matching your filters</p>
                  </CardContent>
                </Card>
              ) : (
                <>
                  {filteredEntries.map(entry => (
                    <AuditEntryCard
                      key={entry.id}
                      entry={entry}
                      isExpanded={expandedEntries.has(entry.id)}
                      onToggleExpand={() => toggleExpanded(entry.id)}
                      showPrivacyInfo={showPrivacyCompliance}
                    />
                  ))}
                  
                  {entries.length > filteredEntries.length && (
                    <Card>
                      <CardContent className="p-4 text-center">
                        <Button 
                          variant="outline" 
                          onClick={handleLoadMore}
                          disabled={isLoading}
                        >
                          {isLoading ? (
                            <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                          ) : (
                            <RefreshCw className="w-4 h-4 mr-2" />
                          )}
                          Load More Entries
                        </Button>
                      </CardContent>
                    </Card>
                  )}
                </>
              )}
            </TabsContent>
            
            {showPrivacyCompliance && (
              <TabsContent value="compliance">
                <ComplianceSummary
                  entries={filteredEntries}
                  timeRange={filters.date_range}
                />
              </TabsContent>
            )}
          </Tabs>
        </div>
      </div>
    </div>
  );
};

export default EnhancedAuditHistory;
export type { AuditEntry, AuditFilters, EnhancedAuditHistoryProps };