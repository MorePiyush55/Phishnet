import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { OAuthService, UserStatus } from '../services/oauthService';
import GmailConnect from '../components/GmailConnect';
import ConnectionStatus from '../components/ConnectionStatus';
import RealtimeNotifications from '../components/RealtimeNotifications';
import PrivacyControls from '../components/PrivacyControls';
import { ErrorDisplay } from '../components/ErrorHandling';
import { Shield, Settings, Bell, Lock } from 'lucide-react';

export const OAuthDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'notifications' | 'privacy' | 'settings'>('overview');

  // Query user OAuth status
  const { data: userStatus, isLoading, error } = useQuery<UserStatus, Error>({
    queryKey: ['userStatus'],
    queryFn: OAuthService.getUserStatus,
    retry: (failureCount, error) => {
      // Don't retry on 404 (user not connected)
      if (error.message.includes('not connected')) return false;
      return failureCount < 2;
    },
    refetchInterval: 30000 // Refresh every 30 seconds
  });

  const isConnected = userStatus?.status === 'connected';

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Shield },
    { id: 'notifications', label: 'Live Updates', icon: Bell },
    { id: 'privacy', label: 'Privacy & Security', icon: Lock },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <div>
                <h1 className="text-xl font-semibold text-gray-900">PhishNet</h1>
                <p className="text-sm text-gray-600">Gmail Security Monitoring</p>
              </div>
            </div>
            
            {isConnected && (
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-gray-600">Connected as {userStatus?.email}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Error Display */}
        <ErrorDisplay className="mb-6" showDetails={process.env.NODE_ENV === 'development'} />

        {/* Main Content */}
        {!isConnected && !isLoading ? (
          /* Not connected - show connect UI */
          <div className="max-w-2xl mx-auto">
            <GmailConnect 
              onConnectionChange={(connected) => {
                if (connected) {
                  window.location.reload(); // Refresh to update status
                }
              }}
            />
          </div>
        ) : (
          /* Connected - show full dashboard */
          <div className="space-y-6">
            {/* Tab Navigation */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200">
              <div className="border-b border-gray-200">
                <nav className="flex space-x-8 px-6" aria-label="Tabs">
                  {tabs.map((tab) => {
                    const Icon = tab.icon;
                    return (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id as any)}
                        className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 ${
                          activeTab === tab.id
                            ? 'border-blue-500 text-blue-600'
                            : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                        }`}
                      >
                        <Icon className="h-4 w-4" />
                        {tab.label}
                      </button>
                    );
                  })}
                </nav>
              </div>

              {/* Tab Content */}
              <div className="p-6">
                {activeTab === 'overview' && (
                  <div className="space-y-6">
                    {isLoading ? (
                      <div className="animate-pulse space-y-4">
                        <div className="h-4 bg-gray-200 rounded w-1/4"></div>
                        <div className="h-32 bg-gray-200 rounded"></div>
                      </div>
                    ) : (
                      <ConnectionStatus />
                    )}
                  </div>
                )}

                {activeTab === 'notifications' && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-medium text-gray-900 mb-2">Real-time Updates</h3>
                      <p className="text-sm text-gray-600">
                        Live notifications for scan results and connection status changes.
                      </p>
                    </div>
                    <RealtimeNotifications maxNotifications={10} />
                  </div>
                )}

                {activeTab === 'privacy' && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-medium text-gray-900 mb-2">Privacy & Security</h3>
                      <p className="text-sm text-gray-600">
                        Manage your data, export information, and control privacy settings.
                      </p>
                    </div>
                    <PrivacyControls />
                  </div>
                )}

                {activeTab === 'settings' && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-medium text-gray-900 mb-2">Settings</h3>
                      <p className="text-sm text-gray-600">
                        Configure your PhishNet experience and preferences.
                      </p>
                    </div>
                    
                    {/* Settings content */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-gray-50 rounded-lg p-4">
                        <h4 className="font-medium text-gray-900 mb-2">Notification Preferences</h4>
                        <div className="space-y-2">
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" defaultChecked />
                            <span className="ml-2 text-sm text-gray-700">Email scan alerts</span>
                          </label>
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" defaultChecked />
                            <span className="ml-2 text-sm text-gray-700">Connection status changes</span>
                          </label>
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" />
                            <span className="ml-2 text-sm text-gray-700">Daily security reports</span>
                          </label>
                        </div>
                      </div>

                      <div className="bg-gray-50 rounded-lg p-4">
                        <h4 className="font-medium text-gray-900 mb-2">Scan Settings</h4>
                        <div className="space-y-2">
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" defaultChecked />
                            <span className="ml-2 text-sm text-gray-700">Auto-quarantine malicious emails</span>
                          </label>
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" defaultChecked />
                            <span className="ml-2 text-sm text-gray-700">Scan attachments</span>
                          </label>
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" />
                            <span className="ml-2 text-sm text-gray-700">Scan sent emails</span>
                          </label>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default OAuthDashboard;