/**
 * Email Analysis Testing Component
 * Simple interface to test phishing detection capabilities
 */

import React, { useState } from 'react';
import { Mail, Shield, AlertTriangle, CheckCircle, Loader2, Upload } from 'lucide-react';
import { apiService } from '../services/apiService';

interface AnalysisResult {
  is_phishing: boolean;
  confidence: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threats_detected: string[];
  analysis_details: {
    sender_analysis: any;
    content_analysis: any;
    link_analysis: any;
    attachment_analysis: any;
  };
  recommendations: string[];
  timestamp: string;
}

interface EmailData {
  subject: string;
  sender: string;
  content: string;
  headers?: Record<string, string>;
}

export const EmailAnalysisTest: React.FC = () => {
  const [emailData, setEmailData] = useState<EmailData>({
    subject: '',
    sender: '',
    content: ''
  });
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Sample phishing emails for testing
  const sampleEmails = [
    {
      name: "Suspicious PayPal",
      data: {
        subject: "Urgent: Your PayPal account will be suspended",
        sender: "no-reply@paypal-security.com",
        content: `Dear Customer,

We detected unusual activity on your PayPal account. Your account will be suspended within 24 hours unless you verify your information immediately.

Click here to verify: http://paypal-verify.suspicious-site.com/login

Failure to verify will result in permanent account closure.

Best regards,
PayPal Security Team`
      }
    },
    {
      name: "Fake Bank Alert",
      data: {
        subject: "Security Alert: Unauthorized Access Detected",
        sender: "alerts@bank-security.net",
        content: `SECURITY ALERT

We detected an unauthorized login attempt from a new device.

Location: Unknown
Time: Just now

Click here immediately to secure your account:
https://secure-banking.fake-site.org/verify-account

If you don't act within 2 hours, your account will be locked for security reasons.

Thank you,
Security Department`
      }
    },
    {
      name: "Legitimate Email",
      data: {
        subject: "Your monthly newsletter from GitHub",
        sender: "noreply@github.com",
        content: `Hi there!

Here's what's happening this month at GitHub:

• New features in GitHub Actions
• Security improvements
• Community highlights

Check out the full newsletter at github.com/newsletter

Thanks for being part of the GitHub community!

The GitHub Team`
      }
    }
  ];

  const handleAnalyze = async () => {
    if (!emailData.subject || !emailData.sender || !emailData.content) {
      setError('Please fill in all required fields');
      return;
    }

    setAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const analysisResult = await apiService.analyzeEmail(emailData);
      setResult(analysisResult);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze email');
      console.error('Analysis error:', err);
    } finally {
      setAnalyzing(false);
    }
  };

  const loadSampleEmail = (sample: typeof sampleEmails[0]) => {
    setEmailData(sample.data);
    setResult(null);
    setError(null);
  };

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'LOW': return 'text-green-600 bg-green-50 border-green-200';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'HIGH': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'CRITICAL': return 'text-red-600 bg-red-50 border-red-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getRiskIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case 'LOW': return <CheckCircle className="w-5 h-5" />;
      case 'MEDIUM': return <AlertTriangle className="w-5 h-5" />;
      case 'HIGH': return <AlertTriangle className="w-5 h-5" />;
      case 'CRITICAL': return <Shield className="w-5 h-5" />;
      default: return <Mail className="w-5 h-5" />;
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <div className="flex items-center space-x-3 mb-4">
          <Shield className="w-8 h-8 text-blue-600" />
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Email Analysis Test</h1>
            <p className="text-gray-600">Test PhishNet's phishing detection capabilities</p>
          </div>
        </div>

        {/* Sample Emails */}
        <div className="mb-6">
          <h3 className="text-sm font-medium text-gray-700 mb-3">Quick Test Samples:</h3>
          <div className="flex flex-wrap gap-2">
            {sampleEmails.map((sample, index) => (
              <button
                key={index}
                onClick={() => loadSampleEmail(sample)}
                className="px-3 py-2 text-sm bg-blue-50 text-blue-700 rounded-md hover:bg-blue-100 transition-colors"
              >
                {sample.name}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Email Input Form */}
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Email Details</h2>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Subject *</label>
            <input
              type="text"
              value={emailData.subject}
              onChange={(e) => setEmailData(prev => ({ ...prev, subject: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="Enter email subject"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Sender *</label>
            <input
              type="email"
              value={emailData.sender}
              onChange={(e) => setEmailData(prev => ({ ...prev, sender: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="sender@example.com"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Email Content *</label>
            <textarea
              value={emailData.content}
              onChange={(e) => setEmailData(prev => ({ ...prev, content: e.target.value }))}
              rows={8}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="Paste email content here..."
            />
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
            <p className="text-red-700 text-sm">{error}</p>
          </div>
        )}

        <div className="mt-6">
          <button
            onClick={handleAnalyze}
            disabled={analyzing}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-md transition-colors flex items-center justify-center space-x-2"
          >
            {analyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Analyzing Email...</span>
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                <span>Analyze for Phishing</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Analysis Results */}
      {result && (
        <div className="bg-white rounded-lg shadow-sm border p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Analysis Results</h2>
          
          {/* Risk Assessment */}
          <div className={`p-4 rounded-lg border mb-6 ${getRiskColor(result.risk_level)}`}>
            <div className="flex items-center space-x-3">
              {getRiskIcon(result.risk_level)}
              <div>
                <h3 className="font-semibold">
                  {result.is_phishing ? 'PHISHING DETECTED' : 'EMAIL APPEARS SAFE'}
                </h3>
                <p className="text-sm">
                  Risk Level: {result.risk_level} | Confidence: {(result.confidence * 100).toFixed(1)}%
                </p>
              </div>
            </div>
          </div>

          {/* Threats Detected */}
          {result.threats_detected.length > 0 && (
            <div className="mb-6">
              <h4 className="font-medium text-gray-900 mb-2">Threats Detected:</h4>
              <ul className="space-y-1">
                {result.threats_detected.map((threat, index) => (
                  <li key={index} className="flex items-center space-x-2 text-red-700">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="text-sm">{threat}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommendations */}
          {result.recommendations.length > 0 && (
            <div className="mb-6">
              <h4 className="font-medium text-gray-900 mb-2">Recommendations:</h4>
              <ul className="space-y-1">
                {result.recommendations.map((rec, index) => (
                  <li key={index} className="flex items-center space-x-2 text-blue-700">
                    <CheckCircle className="w-4 h-4" />
                    <span className="text-sm">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Detailed Analysis */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-gray-50 p-4 rounded-lg">
              <h5 className="font-medium text-gray-900 mb-2">Sender Analysis</h5>
              <div className="text-xs text-gray-600 space-y-1">
                <p>Domain Trust: {result.analysis_details.sender_analysis?.domain_trust || 'N/A'}</p>
                <p>SPF/DKIM: {result.analysis_details.sender_analysis?.auth_status || 'N/A'}</p>
              </div>
            </div>

            <div className="bg-gray-50 p-4 rounded-lg">
              <h5 className="font-medium text-gray-900 mb-2">Content Analysis</h5>
              <div className="text-xs text-gray-600 space-y-1">
                <p>Suspicious Keywords: {result.analysis_details.content_analysis?.suspicious_patterns || 0}</p>
                <p>Urgency Score: {result.analysis_details.content_analysis?.urgency_score || 'N/A'}</p>
              </div>
            </div>
          </div>

          <div className="mt-4 text-xs text-gray-500">
            Analysis completed at: {new Date(result.timestamp).toLocaleString()}
          </div>
        </div>
      )}
    </div>
  );
};