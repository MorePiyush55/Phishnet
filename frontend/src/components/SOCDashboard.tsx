import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { 
  Shield, 
  AlertTriangle, 
  Eye, 
  Search, 
  Filter, 
  Clock, 
  Mail, 
  Link, 
  FileText, 
  Trash2, 
  Archive, 
  ExternalLink,
  Activity,
  Users,
  Globe,
  ChevronDown,
  X,
  Play,
  Camera,
  BarChart3,
  TrendingUp,
  RefreshCw,
  Settings,
  LogOut,
  Bell,
  CheckCircle
} from 'lucide-react';

// Import hooks and services
import { useEmails, useSystemStats, useUpdateEmailStatus, useDeleteEmail, useBulkUpdateEmails } from '../hooks/useApiQueries';
import { useUIStore } from '../stores/uiStore';
import { useWebSocket } from '../hooks/useWebSocket';
import { useAuth, usePermissions } from '../hooks/useAuth';
import { OAuthService, UserStatus } from '../services/oauthService';
import EmailAnalysis from './EmailAnalysis';
import { GmailEmailList } from './GmailEmailList';

// Types
interface Email {
  id: number;
  sender: string;
  subject: string;
  timestamp: string;
  risk_score: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  recipient: string;
  status: 'quarantined' | 'analyzing' | 'safe' | 'pending';
  ai_verdict?: string;
  vt_score?: string;
  links_count: number;
  attachments_count: number;
  created_at: string;
  updated_at: string;
}

const SOCDashboard = () => {
  // Hooks
  const { user, logout } = useAuth();
  const { canDeleteEmails, canViewAudits } = usePermissions();
  const { isConnected: wsConnected } = useWebSocket();
  const [searchParams, setSearchParams] = useSearchParams();
  
  // OAuth Status
  const [oauthStatus, setOauthStatus] = useState<UserStatus | null>(null);
  
  // UI State
  const {
    filters,
    selectedEmailId,
    filterOpen,
    notifications,
    wsConnected: wsStatus,
    setFilter,
    setFilterOpen,
    setSelectedEmailId,
    removeNotification,
  } = useUIStore();

  // Check if user is authenticated via OAuth
  const userEmail = localStorage.getItem('user_email');
  const isOAuthUser = localStorage.getItem('oauth_success') === 'true';

  // API Queries - Only use traditional email API for non-OAuth users
  const { data: emailsData, isLoading: emailsLoading, error: emailsError, refetch: refetchEmails } = useEmails();
  // Disable system stats temporarily to prevent page issues
  const systemStats = {
    emails_processed_today: 0,
    emails_quarantined: 0,
    active_threats: 0,
    system_status: 'healthy'
  };
  const statsLoading = false;
  
  // Mutations
  const updateEmailStatus = useUpdateEmailStatus();
  const deleteEmail = useDeleteEmail();
  const bulkUpdateEmails = useBulkUpdateEmails();

  // Local state
  const [selectedEmails, setSelectedEmails] = useState<number[]>([]);
  const [showBulkActions, setShowBulkActions] = useState(false);
  const [selectedGmailEmail, setSelectedGmailEmail] = useState<any>(null);

  const emails = emailsData?.emails || [];
  const selectedEmail = emails.find(email => email.id === selectedEmailId);

  // Utility functions
  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getRiskTextColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'quarantined': return 'bg-red-900 text-red-200';
      case 'analyzing': return 'bg-yellow-900 text-yellow-200';
      case 'safe': return 'bg-green-900 text-green-200';
      case 'pending': return 'bg-blue-900 text-blue-200';
      default: return 'bg-gray-900 text-gray-200';
    }
  };

  const formatTimestamp = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return date.toLocaleDateString();
  };

  // Event handlers
  const handleEmailSelect = (email: Email) => {
    setSelectedEmailId(email.id);
  };

  const handleEmailAction = async (emailId: number, action: string, reason?: string) => {
    try {
      if (action === 'delete' && canDeleteEmails()) {
        await deleteEmail.mutateAsync(emailId);
        setSelectedEmailId(null);
      } else {
        await updateEmailStatus.mutateAsync({ id: emailId, status: action, reason });
      }
    } catch (error) {
      console.error('Email action failed:', error);
    }
  };

  const handleBulkAction = async (action: string) => {
    if (selectedEmails.length === 0) return;

    try {
      await bulkUpdateEmails.mutateAsync({
        emailIds: selectedEmails,
        action,
        reason: `Bulk ${action} action`,
      });
      setSelectedEmails([]);
      setShowBulkActions(false);
    } catch (error) {
      console.error('Bulk action failed:', error);
    }
  };

  const handleEmailSelection = (emailId: number, checked: boolean) => {
    if (checked) {
      setSelectedEmails(prev => [...prev, emailId]);
    } else {
      setSelectedEmails(prev => prev.filter(id => id !== emailId));
    }
  };

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedEmails(emails.map(email => email.id));
    } else {
      setSelectedEmails([]);
    }
  };

  // Effects
  useEffect(() => {
    setShowBulkActions(selectedEmails.length > 0);
  }, [selectedEmails]);

  // Check OAuth status on component mount
  useEffect(() => {
    const checkOAuthStatus = async () => {
      try {
        const status = await OAuthService.getUserStatus();
        setOauthStatus(status);
      } catch (error) {
        console.log('OAuth status check failed:', error);
        setOauthStatus(null);
      }
    };

    checkOAuthStatus();
  }, []);

  // Handle OAuth success from URL parameters
  useEffect(() => {
    const oauthSuccess = searchParams.get('oauth_success');
    const email = searchParams.get('email');
    
    if (oauthSuccess === 'true') {
      // Show success notification
      const { addNotification } = useUIStore.getState();
      addNotification({
        type: 'success',
        message: `Gmail account ${email} successfully connected! Real-time protection is now active.`,
        autoHide: false // Keep the success message visible
      });
      
      // Clean up URL parameters
      setSearchParams({});
      
      // Refresh OAuth status
      const checkOAuthStatus = async () => {
        try {
          const status = await OAuthService.getUserStatus();
          setOauthStatus(status);
        } catch (error) {
          console.log('OAuth status refresh failed:', error);
        }
      };
      checkOAuthStatus();
    }
  }, [searchParams, setSearchParams]);

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      {/* Notifications */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {notifications.map((notification) => (
          <div
            key={notification.id}
            className={`p-4 rounded-lg shadow-lg max-w-md ${
              notification.type === 'error' ? 'bg-red-600' :
              notification.type === 'warning' ? 'bg-yellow-600' :
              notification.type === 'success' ? 'bg-green-600' :
              'bg-blue-600'
            }`}
          >
            <div className="flex items-center justify-between">
              <p className="text-white">{notification.message}</p>
              <button
                onClick={() => removeNotification(notification.id)}
                className="text-white hover:text-gray-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Shield className="w-8 h-8 text-blue-400" />
            <h1 className="text-2xl font-bold text-white">PhishNet SOC Dashboard</h1>
            
            {/* Navigation */}
            <nav className="flex items-center space-x-4 ml-8">
              <a 
                href="/dashboard" 
                className="px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-700 rounded-md transition-colors"
              >
                Dashboard
              </a>
              <a 
                href="/test" 
                className="px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-700 rounded-md transition-colors"
              >
                Email Test
              </a>
            </nav>
          </div>
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2 text-sm text-gray-300">
              <Activity className="w-4 h-4" />
              <span>Real-time Feed</span>
              <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
            </div>
            <div className="flex items-center space-x-2 text-sm text-gray-300">
              <Mail className="w-4 h-4" />
              <span>Gmail</span>
              <div className={`w-2 h-2 rounded-full ${
                oauthStatus?.status === 'connected' ? 'bg-green-500 animate-pulse' : 'bg-orange-500'
              }`}></div>
              {oauthStatus?.status === 'connected' && (
                <CheckCircle className="w-4 h-4 text-green-400" />
              )}
            </div>
            <div className="flex items-center space-x-2 text-sm text-gray-300">
              <Users className="w-4 h-4" />
              <span>{user?.username}</span>
              <span className="text-gray-500">({user?.role})</span>
            </div>
            <button
              onClick={logout}
              className="flex items-center space-x-1 px-3 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex h-[calc(100vh-80px)]">
        {/* Left Panel - Email Feed */}
        <div className="w-2/3 border-r border-gray-700 flex flex-col">
          {/* Controls */}
          <div className="bg-gray-800 p-4 border-b border-gray-700">
            <div className="flex items-center space-x-4 mb-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search emails, domains, or recipients..."
                  className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  value={filters.searchTerm}
                  onChange={(e) => setFilter('searchTerm', e.target.value)}
                />
              </div>
              <button
                onClick={() => setFilterOpen(!filterOpen)}
                className="flex items-center space-x-2 px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg hover:bg-gray-600 transition-colors"
              >
                <Filter className="w-4 h-4" />
                <span>Filters</span>
                <ChevronDown className={`w-4 h-4 transition-transform ${filterOpen ? 'rotate-180' : ''}`} />
              </button>
              <button
                onClick={() => refetchEmails()}
                className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                disabled={emailsLoading}
              >
                <RefreshCw className={`w-4 h-4 ${emailsLoading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
            </div>

            {filterOpen && (
              <div className="flex items-center space-x-4">
                <select
                  value={filters.selectedRiskLevel}
                  onChange={(e) => setFilter('selectedRiskLevel', e.target.value)}
                  className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-blue-500"
                >
                  <option value="all">All Risk Levels</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <select
                  value={filters.statusFilter}
                  onChange={(e) => setFilter('statusFilter', e.target.value)}
                  className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-blue-500"
                >
                  <option value="all">All Statuses</option>
                  <option value="quarantined">Quarantined</option>
                  <option value="analyzing">Analyzing</option>
                  <option value="safe">Safe</option>
                  <option value="pending">Pending</option>
                </select>
                <select
                  value={filters.timeRange}
                  onChange={(e) => setFilter('timeRange', e.target.value)}
                  className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-blue-500"
                >
                  <option value="1h">Last Hour</option>
                  <option value="24h">Last 24 Hours</option>
                  <option value="7d">Last 7 Days</option>
                  <option value="30d">Last 30 Days</option>
                </select>
              </div>
            )}

            {/* Bulk Actions */}
            {showBulkActions && (
              <div className="mt-4 flex items-center space-x-4 p-3 bg-gray-700 rounded-lg">
                <span className="text-sm text-gray-300">
                  {selectedEmails.length} emails selected
                </span>
                <button
                  onClick={() => handleBulkAction('quarantine')}
                  className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-sm transition-colors"
                  disabled={bulkUpdateEmails.isPending}
                >
                  Quarantine
                </button>
                <button
                  onClick={() => handleBulkAction('safe')}
                  className="px-3 py-1 bg-green-600 hover:bg-green-700 rounded text-sm transition-colors"
                  disabled={bulkUpdateEmails.isPending}
                >
                  Mark Safe
                </button>
                {canDeleteEmails() && (
                  <button
                    onClick={() => handleBulkAction('delete')}
                    className="px-3 py-1 bg-red-700 hover:bg-red-800 rounded text-sm transition-colors"
                    disabled={bulkUpdateEmails.isPending}
                  >
                    Delete
                  </button>
                )}
                <button
                  onClick={() => setSelectedEmails([])}
                  className="px-3 py-1 bg-gray-600 hover:bg-gray-500 rounded text-sm transition-colors"
                >
                  Clear Selection
                </button>
              </div>
            )}
          </div>

          {/* Email List Header */}
          <div className="bg-gray-800 p-3 border-b border-gray-700 flex items-center">
            <input
              type="checkbox"
              checked={selectedEmails.length === emails.length && emails.length > 0}
              onChange={(e) => handleSelectAll(e.target.checked)}
              className="mr-3"
            />
            <span className="text-sm text-gray-400">Select All</span>
          </div>

          {/* Email List */}
          <div className="flex-1 overflow-y-auto">
            {isOAuthUser && userEmail ? (
              <GmailEmailList 
                userEmail={userEmail} 
                onEmailSelect={setSelectedGmailEmail}
              />
            ) : (
              <>
                {emailsLoading ? (
                  <div className="flex items-center justify-center h-full">
                    <div className="text-gray-400">Loading emails...</div>
                  </div>
                ) : emailsError ? (
                  <div className="flex items-center justify-center h-full">
                    <div className="text-red-400">Error loading emails: {emailsError.message}</div>
                  </div>
                ) : emails.length === 0 ? (
                  <div className="flex items-center justify-center h-full">
                    <div className="text-gray-400">No emails found</div>
                  </div>
                ) : (
                  emails.map((email) => (
                    <div
                      key={email.id}
                      onClick={() => handleEmailSelect(email)}
                      className={`p-4 border-b border-gray-700 hover:bg-gray-800 cursor-pointer transition-colors ${
                        selectedEmailId === email.id ? 'bg-gray-800 border-l-4 border-l-blue-500' : ''
                      }`}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center space-x-3">
                          <input
                            type="checkbox"
                            checked={selectedEmails.includes(email.id)}
                            onChange={(e) => {
                              e.stopPropagation();
                              handleEmailSelection(email.id, e.target.checked);
                            }}
                            className="mt-1"
                          />
                          <div className={`w-3 h-3 rounded-full ${getRiskColor(email.risk_level)}`}></div>
                          <div>
                            <div className="font-medium text-white truncate max-w-xs">{email.sender}</div>
                            <div className="text-sm text-gray-400">{email.recipient}</div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className={`text-lg font-bold ${getRiskTextColor(email.risk_level)}`}>
                            {email.risk_score}
                          </div>
                          <div className="text-xs text-gray-500">{formatTimestamp(email.timestamp)}</div>
                        </div>
                      </div>
                      
                      <div className="mb-2">
                        <div className="font-medium text-gray-200 truncate">{email.subject}</div>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4 text-sm text-gray-400">
                          <span className="flex items-center space-x-1">
                            <Link className="w-3 h-3" />
                            <span>{email.links_count}</span>
                          </span>
                          <span className="flex items-center space-x-1">
                            <FileText className="w-3 h-3" />
                            <span>{email.attachments_count}</span>
                          </span>
                          {email.vt_score && <span>VT: {email.vt_score}</span>}
                        </div>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(email.status)}`}>
                          {email.status}
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </>
            )}
          </div>
        </div>

        {/* Right Panel */}
        <div className="w-1/3 flex flex-col">
          {/* System Stats */}
          <div className="bg-gray-800 p-4 border-b border-gray-700">
            <h3 className="text-lg font-semibold text-white mb-3 flex items-center">
              <BarChart3 className="w-5 h-5 mr-2 text-blue-400" />
              System Overview
            </h3>
            {statsLoading ? (
              <div className="text-gray-400">Loading stats...</div>
            ) : systemStats ? (
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-700 p-3 rounded">
                  <div className="text-2xl font-bold text-white">{systemStats.emails_processed_today}</div>
                  <div className="text-sm text-gray-400">Processed Today</div>
                </div>
                <div className="bg-gray-700 p-3 rounded">
                  <div className="text-2xl font-bold text-red-400">{systemStats.emails_quarantined}</div>
                  <div className="text-sm text-gray-400">Quarantined</div>
                </div>
                <div className="bg-gray-700 p-3 rounded">
                  <div className="text-2xl font-bold text-orange-400">{systemStats.active_threats}</div>
                  <div className="text-sm text-gray-400">Active Threats</div>
                </div>
                <div className="bg-gray-700 p-3 rounded">
                  <div className={`text-2xl font-bold ${
                    systemStats.system_status === 'healthy' ? 'text-green-400' :
                    systemStats.system_status === 'degraded' ? 'text-yellow-400' :
                    'text-red-400'
                  }`}>
                    {systemStats.system_status}
                  </div>
                  <div className="text-sm text-gray-400">System Status</div>
                </div>
              </div>
            ) : (
              <div className="text-red-400">Failed to load stats</div>
            )}
          </div>

          {/* Email Analysis Panel */}
          <div className="flex-1 p-4 overflow-y-auto">
            {selectedEmail ? (
              <EmailAnalysisPanel 
                email={selectedEmail} 
                onAction={handleEmailAction}
                canDelete={canDeleteEmails()}
              />
            ) : (
              <div className="flex items-center justify-center h-full text-gray-500">
                <div className="text-center">
                  <Eye className="w-12 h-12 mx-auto mb-4 text-gray-600" />
                  <p>Select an email to view analysis</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Footer Stats */}
      <footer className="bg-gray-800 border-t border-gray-700 px-6 py-3">
        <div className="flex items-center justify-between text-sm text-gray-400">
          <div className="flex items-center space-x-6">
            <span className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-red-500 rounded-full"></div>
              <span>Critical: {emails.filter(e => e.risk_level === 'critical').length}</span>
            </span>
            <span className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
              <span>High: {emails.filter(e => e.risk_level === 'high').length}</span>
            </span>
            <span className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
              <span>Medium: {emails.filter(e => e.risk_level === 'medium').length}</span>
            </span>
            <span className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-green-500 rounded-full"></div>
              <span>Low: {emails.filter(e => e.risk_level === 'low').length}</span>
            </span>
          </div>
          <div className="flex items-center space-x-4">
            <span>Last updated: {new Date().toLocaleTimeString()}</span>
            <span className="flex items-center space-x-1">
              <TrendingUp className="w-4 h-4" />
              <span>Total: {emailsData?.total || 0} emails</span>
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
};

// Email Analysis Panel Component
interface EmailAnalysisPanelProps {
  email: Email;
  onAction: (emailId: number, action: string, reason?: string) => void;
  canDelete: boolean;
}

const EmailAnalysisPanel: React.FC<EmailAnalysisPanelProps> = ({ email, onAction, canDelete }) => {
  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-white">Email Analysis</h3>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-400">ID: {email.id}</span>
        </div>
      </div>

      {/* Risk Score Card */}
      <div className="bg-gray-800 rounded-lg p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h4 className="font-semibold text-white">Risk Assessment</h4>
          <div className={`text-2xl font-bold ${
            email.risk_level === 'critical' ? 'text-red-400' :
            email.risk_level === 'high' ? 'text-orange-400' :
            email.risk_level === 'medium' ? 'text-yellow-400' :
            'text-green-400'
          }`}>
            {email.risk_score}/100
          </div>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-2 mb-3">
          <div
            className={`h-2 rounded-full ${
              email.risk_level === 'critical' ? 'bg-red-500' :
              email.risk_level === 'high' ? 'bg-orange-500' :
              email.risk_level === 'medium' ? 'bg-yellow-500' :
              'bg-green-500'
            }`}
            style={{ width: `${email.risk_score}%` }}
          ></div>
        </div>
        <div className="text-sm text-gray-300">{email.ai_verdict || 'AI analysis pending...'}</div>
      </div>

      {/* Actions */}
      <div className="grid grid-cols-2 gap-2 mb-4">
        <button 
          onClick={() => onAction(email.id, 'quarantined')}
          className="flex items-center justify-center space-x-2 px-3 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-white transition-colors"
          disabled={email.status === 'quarantined'}
        >
          <Archive className="w-4 h-4" />
          <span>Quarantine</span>
        </button>
        {canDelete && (
          <button 
            onClick={() => onAction(email.id, 'delete')}
            className="flex items-center justify-center space-x-2 px-3 py-2 bg-red-700 hover:bg-red-800 rounded-lg text-white transition-colors"
          >
            <Trash2 className="w-4 h-4" />
            <span>Delete</span>
          </button>
        )}
        <button 
          onClick={() => onAction(email.id, 'safe')}
          className="flex items-center justify-center space-x-2 px-3 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white transition-colors"
          disabled={email.status === 'safe'}
        >
          <Shield className="w-4 h-4" />
          <span>Mark Safe</span>
        </button>
      </div>

      {/* Email Details */}
      <div className="bg-gray-800 rounded-lg p-4 mb-4">
        <h4 className="font-semibold text-white mb-3 flex items-center">
          <Mail className="w-4 h-4 mr-2" />
          Email Details
        </h4>
        <div className="space-y-2 text-sm">
          <div>
            <span className="text-gray-400">From:</span>
            <span className="text-white ml-2">{email.sender}</span>
          </div>
          <div>
            <span className="text-gray-400">To:</span>
            <span className="text-white ml-2">{email.recipient}</span>
          </div>
          <div>
            <span className="text-gray-400">Subject:</span>
            <span className="text-white ml-2">{email.subject}</span>
          </div>
          <div>
            <span className="text-gray-400">Received:</span>
            <span className="text-white ml-2">{new Date(email.timestamp).toLocaleString()}</span>
          </div>
          <div>
            <span className="text-gray-400">Status:</span>
            <span className={`ml-2 px-2 py-1 rounded text-xs ${
              email.status === 'quarantined' ? 'bg-red-900 text-red-200' :
              email.status === 'analyzing' ? 'bg-yellow-900 text-yellow-200' :
              email.status === 'safe' ? 'bg-green-900 text-green-200' :
              'bg-blue-900 text-blue-200'
            }`}>
              {email.status}
            </span>
          </div>
        </div>
      </div>

      {/* Link Analysis */}
      <div className="bg-gray-800 rounded-lg p-4">
        <h4 className="font-semibold text-white mb-3 flex items-center">
          <Link className="w-4 h-4 mr-2" />
          Links & Attachments
        </h4>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-400">Links:</span>
            <span className="text-white">{email.links_count}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Attachments:</span>
            <span className="text-white">{email.attachments_count}</span>
          </div>
          {email.vt_score && (
            <div className="flex justify-between">
              <span className="text-gray-400">VirusTotal:</span>
              <span className="text-red-400">{email.vt_score}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SOCDashboard;
