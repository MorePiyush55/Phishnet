import React, { useState } from 'react';
import { Shield, Mail, RefreshCw, Eye, LogOut } from 'lucide-react';
import { GmailEmailList } from './GmailEmailList';

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
  const userEmail = localStorage.getItem('user_email') || '';
  const isOAuthUser = localStorage.getItem('oauth_success') === 'true';

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
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-blue-400" />
            <h1 className="text-2xl font-bold">PhishNet SOC Dashboard</h1>
          </div>
          
          <div className="flex items-center space-x-4">
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

      <div className="flex h-[calc(100vh-80px)]">
        {/* Email List Panel */}
        <div className="w-1/2 border-r border-gray-700 overflow-hidden flex flex-col">
          <div className="p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold">Email Analysis</h2>
          </div>
          
          <div className="flex-1 overflow-y-auto">
            {isOAuthUser && userEmail ? (
              <GmailEmailList 
                userEmail={userEmail} 
                onEmailSelect={setSelectedEmail}
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
        <div className="w-1/2 overflow-hidden flex flex-col">
          <div className="p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold">Email Details</h2>
          </div>
          
          <div className="flex-1 overflow-y-auto p-4">
            {selectedEmail ? (
              <div className="space-y-4">
                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="text-lg font-semibold mb-2">{selectedEmail.subject}</h3>
                  <div className="space-y-2 text-sm text-gray-300">
                    <p><strong>From:</strong> {selectedEmail.sender}</p>
                    <p><strong>Received:</strong> {new Date(selectedEmail.received_at).toLocaleString()}</p>
                  </div>
                </div>

                <div className="bg-gray-800 rounded-lg p-4">
                  <h4 className="font-semibold mb-2">Content Preview</h4>
                  <p className="text-gray-300 text-sm">{selectedEmail.snippet}</p>
                </div>

                <div className="bg-gray-800 rounded-lg p-4">
                  <h4 className="font-semibold mb-2">Phishing Analysis</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span>Risk Level:</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        selectedEmail.phishing_analysis.risk_level === 'HIGH' ? 'bg-red-900 text-red-300' :
                        selectedEmail.phishing_analysis.risk_level === 'MEDIUM' ? 'bg-orange-900 text-orange-300' :
                        selectedEmail.phishing_analysis.risk_level === 'LOW' ? 'bg-yellow-900 text-yellow-300' :
                        'bg-green-900 text-green-300'
                      }`}>
                        {selectedEmail.phishing_analysis.risk_level}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Risk Score:</span>
                      <span className="font-mono">{selectedEmail.phishing_analysis.risk_score}/100</span>
                    </div>
                    {selectedEmail.phishing_analysis.summary && (
                      <div>
                        <p className="font-medium">Summary:</p>
                        <p className="text-gray-300 text-sm mt-1">{selectedEmail.phishing_analysis.summary}</p>
                      </div>
                    )}
                    {selectedEmail.phishing_analysis.indicators.length > 0 && (
                      <div>
                        <p className="font-medium">Indicators:</p>
                        <ul className="list-disc list-inside text-gray-300 text-sm mt-1">
                          {selectedEmail.phishing_analysis.indicators.map((indicator, index) => (
                            <li key={index}>{indicator}</li>
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
                  <Eye className="h-12 w-12 mx-auto mb-4 text-gray-500" />
                  <p>Select an email to view analysis</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SimpleDashboard;