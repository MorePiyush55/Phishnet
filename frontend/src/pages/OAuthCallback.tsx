import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';

export default function OAuthCallback(): JSX.Element {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<'processing' | 'success' | 'error' | 'unknown'>('processing');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    const success = searchParams.get('oauth_success');
    const error = searchParams.get('oauth_error');

    if (success) {
      setStatus('success');
      setTimeout(() => navigate('/dashboard'), 1000);
      return;
    }

    if (error) {
      setStatus('error');
      setErrorMsg(error);
      return;
    }

    setStatus('unknown');
  }, [searchParams, navigate]);

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h2 className="text-2xl font-semibold mb-2">Connecting Gmail</h2>
      {status === 'processing' && <p>Finalizing connection — please wait...</p>}
      {status === 'success' && <p>Gmail connected. Redirecting to dashboard...</p>}
      {status === 'error' && (
        <div>
          <p className="text-red-600">Connection failed: {errorMsg}</p>
          <p className="mt-2">Try reconnecting or contact support if the problem persists.</p>
        </div>
      )}
      {status === 'unknown' && <p>Unexpected response from OAuth provider.</p>}
    </div>
  );
}
import React, { useEffect, useState } from 'react';
import { useSearchParams, Navigate } from 'react-router-dom';
import { Shield, CheckCircle, AlertCircle, Loader } from 'lucide-react';

const OAuthCallback: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [error, setError] = useState<string | null>(null);
  const [userInfo, setUserInfo] = useState<any>(null);

  useEffect(() => {
    const handleCallback = async () => {
      try {
        const code = searchParams.get('code');
        const error = searchParams.get('error');
        const token = searchParams.get('token');

        if (error) {
          setStatus('error');
          switch (error) {
            case 'access_denied':
              setError('Access denied. Gmail permissions are required for phishing protection.');
              break;
            case 'invalid_request':
              setError('Invalid authentication request.');
              break;
            case 'temporarily_unavailable':
              setError('Google services temporarily unavailable. Please try again.');
              break;
            case 'auth_failed':
              setError('Authentication failed. Please try again.');
              break;
            case 'token_generation_failed':
              setError('Failed to generate authentication token.');
              break;
            default:
              setError(`Authentication failed: ${error}`);
          }
          return;
        }

        if (token) {
          // Store token and redirect to dashboard
          localStorage.setItem('auth_token', token);
          setStatus('success');
          setUserInfo({ email: 'Connected successfully' });
          
          // Redirect to dashboard after a brief success message
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 2000);
          return;
        }

        if (!code) {
          setStatus('error');
          setError('No authorization code received from Google.');
          return;
        }

        // If we have a code but no token, something went wrong
        setStatus('error');
        setError('Authentication completed but token generation failed.');
        
      } catch (err: any) {
        setStatus('error');
        setError(err.message || 'Authentication failed. Please try again.');
      }
    };

    handleCallback();
  }, [searchParams]);

  if (status === 'success' && userInfo) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center py-12 px-4">
      <div className="max-w-md w-full">
        <div className="bg-white/10 backdrop-blur-md rounded-2xl shadow-2xl border border-white/20 p-8 text-center">
          {/* Logo */}
          <div className="mx-auto h-16 w-16 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center mb-6 shadow-lg">
            <Shield className="h-8 w-8 text-white" />
          </div>

          {status === 'processing' && (
            <>
              <div className="mb-4">
                <Loader className="h-8 w-8 text-blue-400 animate-spin mx-auto mb-4" />
                <h2 className="text-2xl font-bold text-white mb-2">
                  Setting up your protection...
                </h2>
                <p className="text-blue-200">
                  We're securely connecting your Gmail account for phishing analysis.
                </p>
              </div>
              <div className="space-y-2 text-sm text-blue-300">
                <div className="flex items-center justify-center space-x-2">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                  <span>Verifying Google authentication</span>
                </div>
                <div className="flex items-center justify-center space-x-2">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse delay-100"></div>
                  <span>Configuring email access permissions</span>
                </div>
                <div className="flex items-center justify-center space-x-2">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse delay-200"></div>
                  <span>Initializing threat detection</span>
                </div>
              </div>
            </>
          )}

          {status === 'success' && userInfo && (
            <>
              <CheckCircle className="h-12 w-12 text-green-400 mx-auto mb-4" />
              <h2 className="text-2xl font-bold text-white mb-2">
                Welcome to PhishNet!
              </h2>
              <p className="text-blue-200 mb-4">
                Your Gmail account has been successfully connected.
              </p>
              <div className="bg-white/5 rounded-lg p-4 mb-4">
                <p className="text-sm text-blue-300">
                  <strong>Protection Status:</strong> Active
                </p>
                <p className="text-sm text-blue-300">
                  <strong>AI Detection:</strong> Enabled
                </p>
              </div>
              <p className="text-xs text-blue-300">
                Redirecting to your dashboard...
              </p>
            </>
          )}

          {status === 'error' && (
            <>
              <AlertCircle className="h-12 w-12 text-red-400 mx-auto mb-4" />
              <h2 className="text-2xl font-bold text-white mb-2">
                Connection Failed
              </h2>
              <p className="text-red-300 mb-4">{error}</p>
              <div className="space-y-3">
                <button
                  onClick={() => window.location.href = '/login'}
                  className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                >
                  Try Again
                </button>
                <button
                  onClick={() => window.location.href = '/'}
                  className="w-full py-2 px-4 border border-white/20 text-white rounded-lg hover:bg-white/5 transition-colors"
                >
                  Go Home
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default OAuthCallback;