import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { CheckCircle2, AlertTriangle, Loader2, ArrowRight } from 'lucide-react';
import { OAuthService, UserStatus } from '../services/oauthService';

export const ConnectedPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [userStatus, setUserStatus] = useState<UserStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const handleOAuthCallback = async () => {
      try {
        // Check for error parameters from OAuth callback
        const error = searchParams.get('error');
        const errorDescription = searchParams.get('error_description');
        
        if (error) {
          setError(errorDescription || `OAuth error: ${error}`);
          setStatus('error');
          return;
        }

        // Verify state parameter for CSRF protection
        const state = searchParams.get('state');
        const storedState = sessionStorage.getItem('oauth_state');
        
        if (state && storedState && state !== storedState) {
          setError('Invalid state parameter. Possible CSRF attack.');
          setStatus('error');
          return;
        }

        // Clean up stored state
        sessionStorage.removeItem('oauth_state');

        // Give backend time to process the callback
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Check user connection status
        const userStatus = await OAuthService.getUserStatus();
        setUserStatus(userStatus);

        if (userStatus.status === 'connected') {
          setStatus('success');
          
          // Store connection success for dashboard
          localStorage.setItem('phishnet_auth', JSON.stringify({
            connected: true,
            timestamp: Date.now()
          }));
          
          // Auto-redirect to dashboard after 3 seconds
          setTimeout(() => {
            navigate('/dashboard');
          }, 3000);
        } else {
          setError('Gmail connection was not successful. Please try again.');
          setStatus('error');
        }
      } catch (err: any) {
        console.error('OAuth callback error:', err);
        setError(err.message || 'Failed to verify Gmail connection');
        setStatus('error');
      }
    };

    handleOAuthCallback();
  }, [searchParams, navigate]);

  const handleRetry = () => {
    navigate('/dashboard');
  };

  const handleManualContinue = () => {
    navigate('/dashboard');
  };

  if (status === 'loading') {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full mx-4">
          <div className="text-center">
            <Loader2 className="h-12 w-12 text-blue-600 animate-spin mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-gray-900 mb-2">
              Connecting Gmail Account
            </h2>
            <p className="text-gray-600">
              Verifying your Gmail connection and setting up security monitoring...
            </p>
            <div className="mt-4 text-sm text-gray-500">
              This usually takes a few seconds
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full mx-4">
          <div className="text-center">
            <AlertTriangle className="h-12 w-12 text-red-600 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-gray-900 mb-2">
              Connection Failed
            </h2>
            <p className="text-gray-600 mb-4">
              {error}
            </p>
            <div className="space-y-3">
              <button
                onClick={handleRetry}
                className="w-full bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
              >
                Try Again
              </button>
              <button
                onClick={handleManualContinue}
                className="w-full border border-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-50"
              >
                Continue to Dashboard
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Success state
  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center">
      <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full mx-4">
        <div className="text-center">
          <CheckCircle2 className="h-12 w-12 text-green-600 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">
            Gmail Connected Successfully!
          </h2>
          
          {userStatus && (
            <div className="space-y-3 mb-6">
              <p className="text-gray-600">
                Connected as <strong>{userStatus.email}</strong>
              </p>
              
              <div className="bg-green-50 border border-green-200 rounded-md p-3">
                <p className="text-sm text-green-800">
                  ✓ Real-time phishing detection enabled
                </p>
                <p className="text-sm text-green-800">
                  ✓ Email monitoring active
                </p>
                {userStatus.is_watch_active && (
                  <p className="text-sm text-green-800">
                    ✓ Push notifications configured
                  </p>
                )}
              </div>

              <div className="text-xs text-gray-500">
                <p>Scopes granted: {userStatus.scopes.join(', ')}</p>
                <p>Connected at: {new Date(userStatus.connected_at || '').toLocaleString()}</p>
              </div>
            </div>
          )}

          <div className="space-y-3">
            <button
              onClick={handleManualContinue}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 flex items-center justify-center gap-2"
            >
              Go to Dashboard
              <ArrowRight className="h-4 w-4" />
            </button>
            
            <p className="text-sm text-gray-500">
              Redirecting automatically in a few seconds...
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ConnectedPage;