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
  fetched_emails: number;
  next_page_token?: string;
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
  const [nextPageToken, setNextPageToken] = useState<string | null>(null);
  const [totalEmails, setTotalEmails] = useState<number>(0);
  const [fetchedEmails, setFetchedEmails] = useState<number>(0);

  // Mock data for testing
  const mockEmails: GmailEmail[] = [
    {
      id: 'mock-1',
      subject: 'Urgent: Your account needs verification',
      sender: 'security@suspicious-bank.com',
      received_at: new Date().toISOString(),
      snippet: 'Your account will be suspended if you do not verify immediately...',
      phishing_analysis: {
        risk_score: 85,
        risk_level: 'HIGH',
        indicators: ['Suspicious sender domain', 'Urgent action required', 'Account suspension threat'],
        summary: 'High risk phishing attempt. Requests urgent account verification with threats.'
      }
    },
    {
      id: 'mock-2',
      subject: 'Team meeting reminder',
      sender: 'colleague@yourcompany.com',
      received_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
      snippet: 'Just a reminder about our team meeting scheduled for tomorrow at 2 PM...',
      phishing_analysis: {
        risk_score: 15,
        risk_level: 'SAFE',
        indicators: [],
        summary: 'Safe internal communication from known colleague.'
      }
    },
    {
      id: 'mock-3',
      subject: 'Limited time offer - 90% off!',
      sender: 'deals@promocompany.net',
      received_at: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
      snippet: 'Amazing discount! Get 90% off premium products. Limited time only...',
      phishing_analysis: {
        risk_score: 55,
        risk_level: 'MEDIUM',
        indicators: ['Promotional content', 'Time pressure tactics', 'Unrealistic discount'],
        summary: 'Medium risk promotional email with aggressive marketing tactics.'
      }
    }
  ];

  const fetchEmails = async (pageToken?: string, append: boolean = false) => {
    if (!userEmail) {
      setError('No user email provided');
      return;
    }

    setLoading(true);
    setError(null);
    
    try {
      console.log('Fetching Gmail emails for:', userEmail, pageToken ? `Page token: ${pageToken}` : 'Initial fetch');
      
      const apiUrl = 'https://phishnet-backend-iuoc.onrender.com';
      
      const requestBody: any = {
        user_email: userEmail,
        max_emails: 50  // Fetch reasonable number of emails
      };
      
      if (pageToken) {
        requestBody.page_token = pageToken;
      }
      
      const response = await fetch(`${apiUrl}/api/gmail-simple/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      console.log('Gmail API response status:', response.status);

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
        if (append) {
          setEmails(prev => [...prev, ...data.emails]);
        } else {
          setEmails(data.emails);
        }
        setLastFetch(new Date());
        setNextPageToken(data.next_page_token || null);
        setTotalEmails(data.total_emails || 0);
        setFetchedEmails(append ? fetchedEmails + data.emails.length : data.emails.length);
        console.log(`Successfully loaded ${data.emails.length} emails (${append ? 'appended' : 'new'})`);
      } else {
        console.warn('No emails in response:', data);
        if (!append) setEmails([]);
      }
      
    } catch (err) {
      console.error('Gmail email fetch error:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch Gmail emails';
      setError(errorMessage);
      
      // Fallback to mock data if API fails
      console.log('Using mock data fallback due to API error...');
      setEmails(mockEmails);
      
    } finally {
      setLoading(false);
    }
  };

  const loadMoreEmails = async () => {
    if (nextPageToken && !loading) {
      await fetchEmails(nextPageToken, true);
    }
  };

  const refreshEmails = async () => {
    if (!loading) {
      await fetchEmails();
    }
  };

  useEffect(() => {
    if (userEmail) {
      fetchEmails();
    } else {
      // Show mock data immediately if no user email
      setEmails(mockEmails);
      setLoading(false);
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
          onClick={refreshEmails}
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
            onClick={refreshEmails}
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

        {/* Pagination Info and Load More Button */}
        {!loading && !error && emails.length > 0 && (
          <div className="mt-6 space-y-4">
            {/* Email Count Info */}
            <div className="text-center text-sm text-gray-400">
              Showing {fetchedEmails} of {totalEmails} emails
            </div>
            
            {/* Load More Button */}
            {nextPageToken && (
              <div className="text-center">
                <button
                  onClick={loadMoreEmails}
                  disabled={loading}
                  className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center space-x-2 mx-auto"
                >
                  <Mail className="h-4 w-4" />
                  <span>Load More Emails</span>
                  {loading && <RefreshCw className="h-4 w-4 animate-spin" />}
                </button>
              </div>
            )}
            
            {/* No More Emails Message */}
            {!nextPageToken && totalEmails > 0 && (
              <div className="text-center text-sm text-gray-500">
                All emails loaded ({totalEmails} total)
              </div>
            )}
          </div>
        )}
      )}
    </div>
  );
};