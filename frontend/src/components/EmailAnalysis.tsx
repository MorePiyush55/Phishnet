import React, { useState, useEffect } from 'react';
import { Mail, Shield, AlertTriangle, CheckCircle, RefreshCw, Eye, Clock } from 'lucide-react';

interface PhishingAnalysis {
  risk_score: number;
  risk_level: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH';
  indicators: string[];
  summary: string;
}

interface EmailData {
  id: string;
  subject: string;
  sender: string;
  received_at: string;
  snippet: string;
  phishing_analysis: PhishingAnalysis;
}

interface EmailAnalysisResponse {
  total_emails: number;
  emails: EmailData[];
}

interface EmailAnalysisProps {
  userEmail: string;
}

export const EmailAnalysis: React.FC<EmailAnalysisProps> = ({ userEmail }) => {
  const [emails, setEmails] = useState<EmailData[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedEmail, setSelectedEmail] = useState<EmailData | null>(null);
  const [maxEmails, setMaxEmails] = useState(10);

  const analyzeEmails = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'https://phishnet-backend-iuoc.onrender.com';
      
      const response = await fetch(`${apiUrl}/api/gmail/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user_email: userEmail,
          max_emails: maxEmails
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
      }

      const data: EmailAnalysisResponse = await response.json();
      setEmails(data.emails);
    } catch (err) {
      console.error('Email analysis error:', err);
      setError(err instanceof Error ? err.message : 'Failed to analyze emails');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (userEmail) {
      analyzeEmails();
    }
  }, [userEmail]);

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'HIGH': return 'text-red-600 bg-red-50 border-red-200';
      case 'MEDIUM': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'LOW': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'SAFE': return 'text-green-600 bg-green-50 border-green-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getRiskIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case 'HIGH': return <AlertTriangle className="h-5 w-5" />;
      case 'MEDIUM': return <AlertTriangle className="h-5 w-5" />;
      case 'LOW': return <Shield className="h-5 w-5" />;
      case 'SAFE': return <CheckCircle className="h-5 w-5" />;
      default: return <Shield className="h-5 w-5" />;
    }
  };

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6">
        <div className="flex items-center space-x-3">
          <AlertTriangle className="h-6 w-6 text-red-600" />
          <div>
            <h3 className="text-lg font-medium text-red-800">Analysis Failed</h3>
            <p className="text-red-700">{error}</p>
            <button
              onClick={analyzeEmails}
              className="mt-3 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
            >
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Mail className="h-8 w-8 text-blue-600" />
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Email Security Analysis</h2>
            <p className="text-gray-600">Analyzing emails for: {userEmail}</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <label htmlFor="maxEmails" className="text-sm font-medium text-gray-700">
              Max emails:
            </label>
            <select
              id="maxEmails"
              value={maxEmails}
              onChange={(e) => setMaxEmails(Number(e.target.value))}
              className="border border-gray-300 rounded px-3 py-1 text-sm"
            >
              <option value={5}>5</option>
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={50}>50</option>
            </select>
          </div>
          
          <button
            onClick={analyzeEmails}
            disabled={loading}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Analyzing...' : 'Refresh Analysis'}</span>
          </button>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <div className="text-center space-y-4">
            <RefreshCw className="h-8 w-8 text-blue-600 animate-spin mx-auto" />
            <p className="text-gray-600">Analyzing your emails for phishing threats...</p>
          </div>
        </div>
      )}

      {/* Email List */}
      {!loading && emails.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900">
              Analysis Results ({emails.length} emails)
            </h3>
            
            {/* Risk Summary */}
            <div className="flex items-center space-x-4 text-sm">
              {['HIGH', 'MEDIUM', 'LOW', 'SAFE'].map((level) => {
                const count = emails.filter(e => e.phishing_analysis.risk_level === level).length;
                if (count === 0) return null;
                
                return (
                  <div key={level} className={`flex items-center space-x-1 px-2 py-1 rounded ${getRiskColor(level)}`}>
                    {getRiskIcon(level)}
                    <span className="font-medium">{count} {level}</span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="grid gap-4">
            {emails.map((email) => (
              <div
                key={email.id}
                className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow cursor-pointer"
                onClick={() => setSelectedEmail(email)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-3 mb-2">
                      <h4 className="text-lg font-medium text-gray-900 truncate">
                        {email.subject || '(No Subject)'}
                      </h4>
                      
                      <div className={`flex items-center space-x-1 px-2 py-1 rounded text-sm font-medium ${getRiskColor(email.phishing_analysis.risk_level)}`}>
                        {getRiskIcon(email.phishing_analysis.risk_level)}
                        <span>{email.phishing_analysis.risk_level}</span>
                        <span className="text-xs">({email.phishing_analysis.risk_score}%)</span>
                      </div>
                    </div>
                    
                    <div className="flex items-center text-sm text-gray-600 space-x-4 mb-2">
                      <span className="font-medium">From: {email.sender}</span>
                      <div className="flex items-center space-x-1">
                        <Clock className="h-4 w-4" />
                        <span>{formatDate(email.received_at)}</span>
                      </div>
                    </div>
                    
                    <p className="text-gray-700 text-sm line-clamp-2">
                      {email.snippet}
                    </p>
                    
                    {email.phishing_analysis.indicators.length > 0 && (
                      <div className="mt-3">
                        <p className="text-sm font-medium text-gray-900 mb-1">
                          ⚠️ {email.phishing_analysis.indicators.length} warning{email.phishing_analysis.indicators.length !== 1 ? 's' : ''}:
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {email.phishing_analysis.indicators.slice(0, 3).map((indicator, index) => (
                            <span
                              key={index}
                              className="inline-block px-2 py-1 bg-orange-100 text-orange-800 text-xs rounded"
                            >
                              {indicator}
                            </span>
                          ))}
                          {email.phishing_analysis.indicators.length > 3 && (
                            <span className="inline-block px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded">
                              +{email.phishing_analysis.indicators.length - 3} more
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                  
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedEmail(email);
                    }}
                    className="ml-4 p-2 text-gray-400 hover:text-gray-600 transition-colors"
                    title="View details"
                  >
                    <Eye className="h-5 w-5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Empty State */}
      {!loading && emails.length === 0 && !error && (
        <div className="text-center py-12">
          <Mail className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No emails found</h3>
          <p className="text-gray-600">
            Try connecting your Gmail account or check if you have any emails in your inbox.
          </p>
        </div>
      )}

      {/* Email Detail Modal */}
      {selectedEmail && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-hidden">
            <div className="p-6 border-b border-gray-200">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-gray-900">Email Details</h3>
                <button
                  onClick={() => setSelectedEmail(null)}
                  className="text-gray-400 hover:text-gray-600 transition-colors"
                >
                  <span className="sr-only">Close</span>
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
            
            <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
              <div className="space-y-6">
                {/* Email Header */}
                <div className="bg-gray-50 rounded-lg p-4">
                  <h4 className="font-semibold text-gray-900 mb-3">
                    {selectedEmail.subject || '(No Subject)'}
                  </h4>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium text-gray-700">From:</span>
                      <div className="text-gray-900">{selectedEmail.sender}</div>
                    </div>
                    
                    <div>
                      <span className="font-medium text-gray-700">Received:</span>
                      <div className="text-gray-900">{formatDate(selectedEmail.received_at)}</div>
                    </div>
                  </div>
                </div>

                {/* Risk Analysis */}
                <div className="bg-white border rounded-lg p-4">
                  <h5 className="font-semibold text-gray-900 mb-3">Security Analysis</h5>
                  
                  <div className={`inline-flex items-center space-x-2 px-3 py-2 rounded-lg ${getRiskColor(selectedEmail.phishing_analysis.risk_level)}`}>
                    {getRiskIcon(selectedEmail.phishing_analysis.risk_level)}
                    <span className="font-medium">
                      {selectedEmail.phishing_analysis.risk_level} RISK
                    </span>
                    <span className="text-sm">
                      (Score: {selectedEmail.phishing_analysis.risk_score}/100)
                    </span>
                  </div>
                  
                  <p className="mt-3 text-gray-700">{selectedEmail.phishing_analysis.summary}</p>
                  
                  {selectedEmail.phishing_analysis.indicators.length > 0 && (
                    <div className="mt-4">
                      <h6 className="font-medium text-gray-900 mb-2">Warning Indicators:</h6>
                      <ul className="space-y-1">
                        {selectedEmail.phishing_analysis.indicators.map((indicator, index) => (
                          <li key={index} className="flex items-start space-x-2 text-sm">
                            <span className="text-orange-500 mt-0.5">•</span>
                            <span className="text-gray-700">{indicator}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Email Content */}
                <div className="bg-white border rounded-lg p-4">
                  <h5 className="font-semibold text-gray-900 mb-3">Email Content</h5>
                  <div className="text-sm text-gray-700 bg-gray-50 p-3 rounded border max-h-60 overflow-y-auto">
                    {selectedEmail.snippet || 'No content preview available'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EmailAnalysis;