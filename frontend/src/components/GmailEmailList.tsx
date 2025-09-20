import React, { useState, useEffect } from 'react';
import { Mail, Shield, AlertTriangle, CheckCircle, RefreshCw, Eye, Clock, User } from 'lucide-react';

interface PhishingAnalysis {
  risk_score: number;
  risk_level: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH';
  indicators: string[];
  summary: string;
}

interface GmailEmail {
  id: string;
  subject: string;
  sender: string;
  received_at: string;
  snippet: string;
  phishing_analysis: PhishingAnalysis;
}

interface GmailEmailsResponse {
  total_emails: number;
  emails: GmailEmail[];
}

interface GmailEmailListProps {
  userEmail: string;
  onEmailSelect?: (email: GmailEmail) => void;
}

export const GmailEmailList: React.FC<GmailEmailListProps> = ({ userEmail, onEmailSelect }) => {
  const [emails, setEmails] = useState<GmailEmail[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastFetch, setLastFetch] = useState<Date | null>(null);

  const fetchEmails = async () => {
    if (!userEmail) {
      setError('No user email provided');
      return;
    }

    setLoading(true);
    setError(null);
    
    try {
      console.log('Fetching Gmail emails for:', userEmail);
      
      const apiUrl = 'https://phishnet-backend-iuoc.onrender.com';
      
      // First test if the endpoint is reachable
      console.log('Testing Gmail API endpoint...');
      
      const response = await fetch(`${apiUrl}/api/gmail/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user_email: userEmail,
          max_emails: 5  // Start with fewer emails to test
        }),
      });

      console.log('Gmail API response status:', response.status);
      console.log('Gmail API response headers:', response.headers);

      if (!response.ok) {
        let errorData;
        try {
          errorData = await response.json();
        } catch (e) {
          errorData = { detail: await response.text() };
        }
        
        console.error('Gmail API error response:', errorData);
        throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
      }

      const data: GmailEmailsResponse = await response.json();
      console.log('Gmail emails received:', data);
      
      if (data && data.emails) {
        setEmails(data.emails);
        setLastFetch(new Date());
        console.log(`Successfully loaded ${data.emails.length} emails`);
      } else {
        console.warn('No emails in response:', data);
        setEmails([]);
      }
      
    } catch (err) {
      console.error('Gmail email fetch error:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch Gmail emails';
      setError(errorMessage);
      
      // For debugging - show a mock email if the API fails
      if (errorMessage.includes('Gmail service temporarily unavailable') || errorMessage.includes('503')) {
        setEmails([{
          id: 'mock-1',
          subject: 'Test Email - API Unavailable',
          sender: 'test@example.com',
          received_at: new Date().toISOString(),
          snippet: 'This is a mock email shown because the Gmail API is temporarily unavailable.',
          phishing_analysis: {
            risk_score: 25,
            risk_level: 'LOW',
            indicators: ['Mock analysis'],
            summary: 'Gmail service is currently unavailable, showing mock data.'
          }
        }]);
        setError('Gmail service temporarily unavailable. Showing mock data.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (userEmail) {
      fetchEmails();
    }
  }, [userEmail]);

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'HIGH': return 'text-red-300 bg-red-900 bg-opacity-50 border-red-700';
      case 'MEDIUM': return 'text-orange-300 bg-orange-900 bg-opacity-50 border-orange-700';
      case 'LOW': return 'text-yellow-300 bg-yellow-900 bg-opacity-50 border-yellow-700';
      case 'SAFE': return 'text-green-300 bg-green-900 bg-opacity-50 border-green-700';
      default: return 'text-gray-300 bg-gray-800 border-gray-600';
    }
  };

  const getRiskIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case 'HIGH': return <AlertTriangle className="h-4 w-4" />;
      case 'MEDIUM': return <AlertTriangle className="h-4 w-4" />;
      case 'LOW': return <Shield className="h-4 w-4" />;
      case 'SAFE': return <CheckCircle className="h-4 w-4" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  if (!userEmail) {
    return (
      <div className="p-6 text-center text-gray-400">
        <User className="h-12 w-12 mx-auto mb-4 text-gray-500" />
        <p>No user email available. Please ensure you're properly authenticated.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4 p-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Mail className="h-5 w-5 text-blue-400" />
          <h3 className="text-lg font-semibold text-white">Gmail Emails</h3>
          <span className="text-sm text-gray-400">({userEmail})</span>
        </div>
        <button
          onClick={fetchEmails}
          disabled={loading}
          className="flex items-center space-x-2 px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Last fetch info */}
      {lastFetch && (
        <div className="flex items-center space-x-2 text-sm text-gray-400">
          <Clock className="h-4 w-4" />
          <span>Last updated: {lastFetch.toLocaleTimeString()}</span>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="text-center py-8">
          <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-4 text-blue-400" />
          <p className="text-gray-400">Loading Gmail emails...</p>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className="bg-red-900 bg-opacity-50 border border-red-700 rounded-lg p-4">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="h-5 w-5 text-red-400" />
            <p className="text-red-300 font-medium">Error loading emails</p>
          </div>
          <p className="text-red-400 mt-2">{error}</p>
          <button
            onClick={fetchEmails}
            className="mt-3 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
          >
            Try Again
          </button>
        </div>
      )}

      {/* Email List */}
      {!loading && !error && emails.length === 0 && (
        <div className="text-center py-8 text-gray-400">
          <Mail className="h-12 w-12 mx-auto mb-4 text-gray-500" />
          <p>No emails found</p>
          <p className="text-sm">Try refreshing or check your Gmail connection</p>
        </div>
      )}

      {!loading && emails.length > 0 && (
        <div className="space-y-2">
          {emails.map((email) => (
            <div
              key={email.id}
              onClick={() => onEmailSelect?.(email)}
              className="border border-gray-700 rounded-lg p-4 hover:bg-gray-800 cursor-pointer transition-colors bg-gray-900"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-3 mb-2">
                    <h4 className="text-sm font-medium text-white truncate">
                      {email.subject || '(No Subject)'}
                    </h4>
                    <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border ${getRiskColor(email.phishing_analysis.risk_level)}`}>
                      {getRiskIcon(email.phishing_analysis.risk_level)}
                      <span className="ml-1">{email.phishing_analysis.risk_level}</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-4 text-sm text-gray-400 mb-2">
                    <span>From: {email.sender}</span>
                    <span>{formatDate(email.received_at)}</span>
                  </div>
                  
                  <p className="text-sm text-gray-300 line-clamp-2">
                    {email.snippet}
                  </p>
                  
                  {email.phishing_analysis.summary && (
                    <div className="mt-2 p-2 bg-gray-800 rounded text-xs text-gray-300">
                      <strong>Analysis:</strong> {email.phishing_analysis.summary}
                    </div>
                  )}
                </div>
                
                <div className="ml-4 flex-shrink-0">
                  <div className="text-right">
                    <div className="text-sm font-medium text-white">
                      Risk: {email.phishing_analysis.risk_score}/100
                    </div>
                    {email.phishing_analysis.indicators.length > 0 && (
                      <div className="text-xs text-gray-400 mt-1">
                        {email.phishing_analysis.indicators.length} indicators
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};