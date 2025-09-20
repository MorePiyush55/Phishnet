import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { CheckCircle2, AlertTriangle, Loader2, ArrowRight, Shield, Mail, Eye, BarChart3 } from 'lucide-react';

interface UserInfo {
  email: string;
  name?: string;
}

export const ConnectedPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const handleOAuthCallback = async () => {
      try {
        // Check for OAuth success parameters
        const oauthSuccess = searchParams.get('oauth_success');
        const userEmail = searchParams.get('email');
        const oauthError = searchParams.get('oauth_error');
        
        if (oauthError) {
          setError(`OAuth error: ${oauthError}`);
          setStatus('error');
          return;
        }

        if (oauthSuccess === 'true' && userEmail) {
          // OAuth was successful
          setUserInfo({ email: userEmail });
          setStatus('success');
          
          // Store authentication info
          localStorage.setItem('user_email', userEmail);
          localStorage.setItem('access_token', 'oauth_authenticated');
          localStorage.setItem('oauth_success', 'true');
          localStorage.setItem('phishnet_auth', JSON.stringify({
            connected: true,
            email: userEmail,
            timestamp: Date.now()
          }));
          
          // Auto-redirect to dashboard after showing success
          setTimeout(() => {
            navigate('/emails');
          }, 4000);
        } else {
          setError('No OAuth success parameters found. Please try connecting again.');
          setStatus('error');
        }
      } catch (err: any) {
        console.error('OAuth callback error:', err);
        setError(err.message || 'Failed to process Gmail connection');
        setStatus('error');
      }
    };

    handleOAuthCallback();
  }, [searchParams, navigate]);

  const handleManualContinue = () => {
    navigate('/emails');
  };

  const handleRetry = () => {
    // Clear any stored auth and redirect to main page
    localStorage.removeItem('user_email');
    localStorage.removeItem('access_token');
    localStorage.removeItem('oauth_success');
    localStorage.removeItem('phishnet_auth');
    navigate('/');
  };

  if (status === 'loading') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 flex items-center justify-center">
        <div className="bg-white rounded-xl shadow-xl p-8 max-w-md w-full mx-4">
          <div className="text-center">
            <Loader2 className="h-12 w-12 text-blue-600 animate-spin mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-gray-900 mb-2">
              Connecting Gmail Account
            </h2>
            <p className="text-gray-600">
              Processing your Gmail connection and setting up security monitoring...
            </p>
            <div className="mt-4 text-sm text-gray-500">
              This usually takes a few seconds
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (status === 'success' && userInfo) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-green-50 via-white to-blue-50">
        {/* Header */}
        <div className="bg-white border-b border-gray-200">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-green-600" />
              <div>
                <h1 className="text-xl font-bold text-gray-900">PhishNet</h1>
                <p className="text-sm text-gray-500">Gmail Successfully Connected</p>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          {/* Success Message */}
          <div className="text-center mb-12">
            <div className="mx-auto mb-6 w-16 h-16 bg-green-100 rounded-full flex items-center justify-center">
              <CheckCircle2 className="h-10 w-10 text-green-600" />
            </div>
            <h2 className="text-3xl font-bold text-gray-900 mb-4">
              🎉 Gmail Connected Successfully!
            </h2>
            <p className="text-lg text-gray-600 mb-2">
              Welcome <span className="font-semibold text-blue-600">{userInfo.email}</span>
            </p>
            <p className="text-gray-500">
              Your email is now protected by PhishNet's advanced AI security
            </p>
          </div>

          {/* Features Overview */}
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
            <div className="bg-white rounded-lg p-6 shadow-md text-center">
              <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                <Eye className="h-6 w-6 text-blue-600" />
              </div>
              <h3 className="font-semibold text-gray-900 mb-2">Real-time Monitoring</h3>
              <p className="text-sm text-gray-600">24/7 scanning of incoming emails</p>
            </div>
            
            <div className="bg-white rounded-lg p-6 shadow-md text-center">
              <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                <Shield className="h-6 w-6 text-green-600" />
              </div>
              <h3 className="font-semibold text-gray-900 mb-2">AI Protection</h3>
              <p className="text-sm text-gray-600">Advanced phishing detection</p>
            </div>
            
            <div className="bg-white rounded-lg p-6 shadow-md text-center">
              <div className="w-12 h-12 bg-yellow-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                <Mail className="h-6 w-6 text-yellow-600" />
              </div>
              <h3 className="font-semibold text-gray-900 mb-2">Email Analysis</h3>
              <p className="text-sm text-gray-600">Detailed threat assessment</p>
            </div>
            
            <div className="bg-white rounded-lg p-6 shadow-md text-center">
              <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                <BarChart3 className="h-6 w-6 text-purple-600" />
              </div>
              <h3 className="font-semibold text-gray-900 mb-2">Security Analytics</h3>
              <p className="text-sm text-gray-600">Comprehensive reporting</p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="text-center space-y-4">
            <button
              onClick={handleManualContinue}
              className="inline-flex items-center px-8 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors space-x-2"
            >
              <span>View Email Analysis Dashboard</span>
              <ArrowRight className="h-5 w-5" />
            </button>
            
            <p className="text-sm text-gray-500">
              Redirecting automatically in <span id="countdown">4</span> seconds...
            </p>
          </div>

          {/* Security Notice */}
          <div className="mt-12 bg-blue-50 border border-blue-200 rounded-lg p-6">
            <div className="flex items-start space-x-3">
              <Shield className="h-5 w-5 text-blue-600 mt-0.5" />
              <div className="text-sm">
                <p className="font-medium text-blue-900 mb-1">Security & Privacy</p>
                <p className="text-blue-700 mb-2">
                  PhishNet uses read-only access to your Gmail. We cannot send emails, delete messages, or access other Google services.
                </p>
                <p className="text-blue-600">
                  Your email data is processed securely and never stored permanently.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="min-h-screen bg-red-50 flex items-center justify-center">
        <div className="bg-white rounded-xl shadow-xl p-8 max-w-md w-full mx-4">
          <div className="text-center">
            <AlertTriangle className="h-12 w-12 text-red-600 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-gray-900 mb-2">
              Connection Failed
            </h2>
            <p className="text-gray-600 mb-6">
              {error || 'Failed to connect your Gmail account. Please try again.'}
            </p>
            <div className="space-y-3">
              <button
                onClick={handleRetry}
                className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                Try Again
              </button>
              <button
                onClick={() => navigate('/')}
                className="w-full px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors"
              >
                Back to Home
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Fallback return
  return null;
};