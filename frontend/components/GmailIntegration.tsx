import React, { useState, useEffect } from 'react';
import ProgressTracking from './ProgressTracking';

interface GmailIntegrationProps {
  userId: number;
}

interface GmailStatus {
  gmail_connected: boolean;
  monitoring_enabled: boolean;
  sync_status: string;
  last_sync: string | null;
  watch_expires: string | null;
  recent_scans_24h: number;
}

const GmailIntegration: React.FC<GmailIntegrationProps> = ({ userId }) => {
  const [gmailStatus, setGmailStatus] = useState<GmailStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showConfirmDialog, setShowConfirmDialog] = useState(false);
  const [syncEstimate, setSyncEstimate] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'sync' | 'backfill' | 'monitoring'>('sync');

  useEffect(() => {
    fetchGmailStatus();
    
    // Set up periodic status refresh
    const interval = setInterval(fetchGmailStatus, 30000); // Every 30 seconds
    return () => clearInterval(interval);
  }, [userId]);

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

  const connectGmail = async () => {
    try {
      setError(null);
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
        // Open OAuth URL in popup or redirect
        window.location.href = data.auth_url;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to connect Gmail');
    }
  };

  const startInitialSync = async (confirmed = false) => {
    try {
      setError(null);
      const response = await fetch('/api/v1/gmail/sync/start', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ confirm_large_mailbox: confirmed })
      });
      
      if (!response.ok) throw new Error('Failed to start sync');
      
      const data = await response.json();
      
      if (data.status === 'confirmation_required') {
        setSyncEstimate(data);
        setShowConfirmDialog(true);
      } else {
        setShowConfirmDialog(false);
        fetchGmailStatus(); // Refresh status
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start sync');
    }
  };

  const startBackfill = async () => {
    try {
      setError(null);
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
      
      const data = await response.json();
      alert(`Backfill job started: ${data.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start backfill');
    }
  };

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto p-6">
        <div className="bg-white rounded-lg shadow-md p-8">
          <div className="animate-pulse">
            <div className="h-8 bg-gray-200 rounded w-1/2 mb-6"></div>
            <div className="space-y-4">
              <div className="h-4 bg-gray-200 rounded"></div>
              <div className="h-4 bg-gray-200 rounded w-3/4"></div>
              <div className="h-32 bg-gray-200 rounded"></div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 flex items-center">
              <svg className="w-8 h-8 mr-3 text-red-500" fill="currentColor" viewBox="0 0 24 24">
                <path d="M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.273H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-.904.732-1.636 1.636-1.636h3.819v9.273L12 8.183l6.545 4.91V3.82h3.819c.904 0 1.636.733 1.636 1.637z"/>
              </svg>
              Gmail Integration
            </h1>
            <p className="text-gray-600 mt-1">
              Connect and sync your Gmail inbox for phishing analysis
            </p>
          </div>
          
          {gmailStatus?.gmail_connected && (
            <div className="text-right">
              <div className="text-sm text-gray-500">24h Scans</div>
              <div className="text-2xl font-bold text-blue-600">
                {gmailStatus.recent_scans_24h}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center">
            <svg className="w-5 h-5 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span className="text-red-800">{error}</span>
          </div>
        </div>
      )}

      {!gmailStatus?.gmail_connected ? (
        /* Gmail Connection Setup */
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <div className="max-w-md mx-auto">
            <svg className="w-16 h-16 text-gray-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            
            <h2 className="text-xl font-semibold text-gray-900 mb-2">
              Connect Your Gmail Account
            </h2>
            <p className="text-gray-600 mb-6">
              Securely connect your Gmail account to start monitoring for phishing emails. 
              We only access email metadata for analysis.
            </p>
            
            <button
              onClick={connectGmail}
              className="bg-red-600 hover:bg-red-700 text-white font-medium py-3 px-6 rounded-lg transition-colors inline-flex items-center"
            >
              <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 24 24">
                <path d="M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.273H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-.904.732-1.636 1.636-1.636h3.819v9.273L12 8.183l6.545 4.91V3.82h3.819c.904 0 1.636.733 1.636 1.637z"/>
              </svg>
              Connect Gmail
            </button>
            
            <div className="mt-6 text-xs text-gray-500">
              <p>🔒 Your data is encrypted and secure</p>
              <p>📧 We only analyze email metadata, not content</p>
              <p>⚡ Real-time threat detection</p>
            </div>
          </div>
        </div>
      ) : (
        /* Gmail Connected - Main Interface */
        <div className="space-y-6">
          {/* Status Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-white rounded-lg shadow-md p-4">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-green-500 rounded-full mr-3"></div>
                <div>
                  <div className="text-sm text-gray-600">Connection</div>
                  <div className="font-medium">Gmail Connected</div>
                </div>
              </div>
            </div>
            
            <div className="bg-white rounded-lg shadow-md p-4">
              <div className="flex items-center">
                <div className={`w-3 h-3 rounded-full mr-3 ${
                  gmailStatus.monitoring_enabled ? 'bg-blue-500' : 'bg-gray-400'
                }`}></div>
                <div>
                  <div className="text-sm text-gray-600">Monitoring</div>
                  <div className="font-medium">
                    {gmailStatus.monitoring_enabled ? 'Active' : 'Inactive'}
                  </div>
                </div>
              </div>
            </div>
            
            <div className="bg-white rounded-lg shadow-md p-4">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-purple-500 rounded-full mr-3"></div>
                <div>
                  <div className="text-sm text-gray-600">Sync Status</div>
                  <div className="font-medium capitalize">
                    {gmailStatus.sync_status.replace('_', ' ')}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="bg-white rounded-lg shadow-md">
            <div className="border-b">
              <nav className="flex space-x-8 px-6">
                {[
                  { id: 'sync', label: 'Initial Sync', icon: '🔄' },
                  { id: 'backfill', label: 'Historical Backfill', icon: '📚' },
                  { id: 'monitoring', label: 'Real-time Monitoring', icon: '👁️' }
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`py-4 px-2 border-b-2 font-medium text-sm transition-colors ${
                      activeTab === tab.id
                        ? 'border-blue-500 text-blue-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    <span className="mr-2">{tab.icon}</span>
                    {tab.label}
                  </button>
                ))}
              </nav>
            </div>

            <div className="p-6">
              {activeTab === 'sync' && (
                <div className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Initial Inbox Sync</h3>
                    <p className="text-gray-600 mb-4">
                      Sync your entire Gmail inbox to enable comprehensive threat analysis.
                    </p>
                  </div>
                  
                  {gmailStatus.sync_status === 'not_started' ? (
                    <div className="text-center py-8">
                      <button
                        onClick={() => startInitialSync(false)}
                        className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-6 rounded-lg transition-colors"
                      >
                        Start Initial Sync
                      </button>
                    </div>
                  ) : (
                    <ProgressTracking 
                      userId={userId} 
                      onSyncComplete={() => fetchGmailStatus()}
                    />
                  )}
                </div>
              )}

              {activeTab === 'backfill' && (
                <div className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Historical Backfill</h3>
                    <p className="text-gray-600 mb-4">
                      Scan historical emails in chunks to analyze older messages for threats.
                    </p>
                  </div>
                  
                  <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                    <div className="flex items-start">
                      <svg className="w-5 h-5 text-yellow-600 mt-0.5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 15.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                      <div className="text-sm text-yellow-800">
                        <p className="font-medium">Large Mailbox Warning</p>
                        <p>Backfill operations may consume significant API quota and take considerable time for large mailboxes.</p>
                      </div>
                    </div>
                  </div>
                  
                  <button
                    onClick={startBackfill}
                    className="bg-purple-600 hover:bg-purple-700 text-white font-medium py-2 px-4 rounded-lg transition-colors"
                  >
                    Start Historical Backfill
                  </button>
                </div>
              )}

              {activeTab === 'monitoring' && (
                <div className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Real-time Monitoring</h3>
                    <p className="text-gray-600 mb-4">
                      Real-time monitoring status and recent activity.
                    </p>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div>
                        <div className="text-sm font-medium text-gray-700">Last Sync</div>
                        <div className="text-gray-600">
                          {gmailStatus.last_sync 
                            ? new Date(gmailStatus.last_sync).toLocaleString()
                            : 'Never'
                          }
                        </div>
                      </div>
                      
                      <div>
                        <div className="text-sm font-medium text-gray-700">Watch Expires</div>
                        <div className="text-gray-600">
                          {gmailStatus.watch_expires 
                            ? new Date(gmailStatus.watch_expires).toLocaleString()
                            : 'Not set'
                          }
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                      <div className="flex items-center">
                        <svg className="w-5 h-5 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <div>
                          <div className="font-medium text-green-800">Monitoring Active</div>
                          <div className="text-sm text-green-600">
                            Real-time threat detection is running
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Dialog */}
      {showConfirmDialog && syncEstimate && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl max-w-md mx-4 p-6">
            <div className="flex items-center mb-4">
              <svg className="w-6 h-6 text-orange-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 15.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
              <h3 className="text-lg font-medium">Large Mailbox Detected</h3>
            </div>
            
            <div className="space-y-3 mb-6 text-sm text-gray-600">
              <p>Your mailbox contains <strong>{syncEstimate.total_messages?.toLocaleString()}</strong> messages.</p>
              <p>Estimated sync time: <strong>{syncEstimate.estimated_time_minutes} minutes</strong></p>
              <p>Estimated API calls: <strong>{syncEstimate.estimated_api_calls?.toLocaleString()}</strong></p>
            </div>
            
            <div className="bg-blue-50 border border-blue-200 rounded p-3 mb-6 text-sm text-blue-800">
              This operation may take significant time and consume Gmail API quota. You can pause the sync at any time.
            </div>
            
            <div className="flex space-x-3">
              <button
                onClick={() => startInitialSync(true)}
                className="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors"
              >
                Proceed with Sync
              </button>
              <button
                onClick={() => setShowConfirmDialog(false)}
                className="flex-1 bg-gray-300 hover:bg-gray-400 text-gray-800 font-medium py-2 px-4 rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GmailIntegration;