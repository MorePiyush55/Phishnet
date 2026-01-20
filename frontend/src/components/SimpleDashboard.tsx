import React, { useState, useEffect } from 'react';
import { Shield, Mail, Eye, LogOut, Link, Activity } from 'lucide-react';
import { GmailEmailList } from './GmailEmailList';
import { useNavigate } from 'react-router-dom';
import { useWebSocket } from '../hooks/useWebSocket';

interface GmailEmail {
  id: string;
  subject: string;
  sender: string;
  received_at: string;
  snippet: string;
  phishing_analysis: {
    risk_score: number;
    risk_level: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH';
    indicators: string[];
    summary: string;
  };
}

const SimpleDashboard: React.FC = () => {
  const [selectedEmail, setSelectedEmail] = useState<GmailEmail | null>(null);
  const navigate = useNavigate();
  const userEmail = localStorage.getItem('user_email') || '';
  const isOAuthUser = localStorage.getItem('oauth_success') === 'true';

  // WebSocket Connection
  const wsUrl = import.meta.env.VITE_WS_BASE_URL || 'ws://localhost:8080';
  const { isConnected, lastMessage } = useWebSocket(`${wsUrl}/ws`);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    if (lastMessage?.type === 'ANALYSIS_COMPLETE') {
      // Trigger refresh when new analysis arrives
      setRefreshTrigger(prev => prev + 1);
    }
  }, [lastMessage]);

  const handleLogout = () => {
    // Clear authentication
    localStorage.removeItem('oauth_success');
    localStorage.removeItem('user_email');
    localStorage.removeItem('access_token');
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('authMethod');
    localStorage.removeItem('authTimestamp');

    // Redirect to home
    window.location.href = '/';
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-blue-400" />
            <h1 className="text-2xl font-bold">PhishNet Analysis Inbox</h1>
          </div>

          <div className="flex items-center space-x-4">
            <button
              onClick={() => navigate('/link-analysis')}
              className="flex items-center space-x-2 px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              <Link className="h-4 w-4" />
              <span>Link Analysis</span>
            </button>
            <div className="flex items-center space-x-2 text-sm text-gray-300">
              <Activity className={`h-4 w-4 ${isConnected ? 'text-green-400' : 'text-red-400'}`} />
              <span className="hidden md:inline">{isConnected ? 'Live Monitoring' : 'Offline'}</span>
            </div>
            <div className="flex items-center space-x-2 text-sm text-gray-300">
              <Mail className="h-4 w-4" />
              <span>{userEmail}</span>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center space-x-2 px-3 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
            >
              <LogOut className="h-4 w-4" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1 overflow-hidden">
        <div className="flex h-full">
          {/* Email List Panel */}
          <div className="w-1/2 border-r border-gray-700 overflow-hidden flex flex-col">
            <div className="p-4 border-b border-gray-700 flex justify-between items-center">
              <h2 className="text-lg font-semibold text-blue-400">Incoming Emails</h2>
            </div>

            <div className="flex-1 overflow-y-auto">
              {isOAuthUser && userEmail ? (
                <GmailEmailList
                  userEmail={userEmail}
                  onEmailSelect={setSelectedEmail}
                  refreshTrigger={refreshTrigger}
                />
              ) : (
                <div className="p-6 text-center text-gray-400">
                  <Mail className="h-12 w-12 mx-auto mb-4 text-gray-500" />
                  <p>No Gmail connection found</p>
                  <p className="text-sm">Please authenticate with Gmail to view emails</p>
                </div>
              )}
            </div>
          </div>

          {/* Email Detail Panel */}
          <div className="w-1/2 overflow-hidden flex flex-col bg-gray-900 bg-opacity-50">
            <div className="p-4 border-b border-gray-700">
              <h2 className="text-lg font-semibold text-blue-400">Threat Analysis</h2>
            </div>

            <div className="flex-1 overflow-y-auto p-4">
              {selectedEmail ? (
                <div className="space-y-4">
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h3 className="text-lg font-semibold mb-2 text-white">{selectedEmail.subject}</h3>
                    <div className="space-y-2 text-sm text-gray-300">
                      <p><strong>From:</strong> {selectedEmail.sender}</p>
                      <p><strong>Received:</strong> {new Date(selectedEmail.received_at).toLocaleString()}</p>
                    </div>
                  </div>

                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h4 className="font-semibold mb-2 text-blue-400">Content Snippet</h4>
                    <p className="text-gray-300 text-sm italic">"{selectedEmail.snippet}"</p>
                  </div>

                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h4 className="font-semibold mb-4 text-blue-400">Security Verdict</h4>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between p-3 rounded-lg bg-gray-900">
                        <span className="text-gray-300">Risk Assessment:</span>
                        <span className={`px-3 py-1 rounded text-sm font-bold ${selectedEmail.phishing_analysis.risk_level === 'HIGH' ? 'bg-red-600 text-white' :
                          selectedEmail.phishing_analysis.risk_level === 'MEDIUM' ? 'bg-orange-600 text-white' :
                            selectedEmail.phishing_analysis.risk_level === 'LOW' ? 'bg-yellow-600 text-black' :
                              'bg-green-600 text-white'
                          }`}>
                          {selectedEmail.phishing_analysis.risk_level}
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-3 rounded-lg bg-gray-900">
                        <span className="text-gray-300">Confidence Score:</span>
                        <div className="flex flex-col items-end">
                          <span className="text-lg font-mono text-blue-400">{selectedEmail.phishing_analysis.risk_score}%</span>
                          <div className="w-32 h-2 bg-gray-700 rounded-full mt-1">
                            <div
                              className={`h-full rounded-full ${selectedEmail.phishing_analysis.risk_score > 70 ? 'bg-red-500' : selectedEmail.phishing_analysis.risk_score > 30 ? 'bg-yellow-500' : 'bg-green-500'}`}
                              style={{ width: `${selectedEmail.phishing_analysis.risk_score}%` }}
                            ></div>
                          </div>
                        </div>
                      </div>
                      {selectedEmail.phishing_analysis.summary && (
                        <div className="p-3 rounded-lg bg-gray-900 border-l-4 border-blue-500">
                          <p className="font-medium text-gray-200">AI Summary:</p>
                          <p className="text-gray-300 text-sm mt-1">{selectedEmail.phishing_analysis.summary}</p>
                        </div>
                      )}
                      {selectedEmail.phishing_analysis.indicators.length > 0 && (
                        <div className="p-3 rounded-lg bg-gray-900">
                          <p className="font-medium text-gray-200 mb-2">Detected Indicators:</p>
                          <ul className="space-y-1">
                            {selectedEmail.phishing_analysis.indicators.map((indicator, index) => (
                              <li key={index} className="flex items-center space-x-2 text-sm text-gray-300">
                                <span className="h-1.5 w-1.5 rounded-full bg-red-400"></span>
                                <span>{indicator}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-400">
                  <div className="text-center">
                    <Eye className="h-12 w-12 mx-auto mb-4 text-gray-600" />
                    <p className="text-lg">Select an email to view detailed threat analysis</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default SimpleDashboard;
