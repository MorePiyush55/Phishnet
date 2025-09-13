import React, { useState, useEffect } from 'react';
import { Shield, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';

interface GoogleOAuthButtonProps {
  onSuccess: (authCode: string) => void;
  onError: (error: string) => void;
  disabled?: boolean;
}

export const GoogleOAuthButton: React.FC<GoogleOAuthButtonProps> = ({
  onSuccess,
  onError,
  disabled = false
}) => {
  const [isLoading, setIsLoading] = useState(false);

  const handleGoogleSignIn = () => {
    setIsLoading(true);
    
    try {
      const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;
      const redirectUri = `${window.location.origin}/auth/callback`;
      
      const scope = [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email'
      ].join(' ');
      
      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope,
        access_type: 'offline',
        prompt: 'consent',
        state: generateState()
      });
      
      localStorage.setItem('oauth_state', generateState());
      window.location.href = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
    } catch (error) {
      setIsLoading(false);
      onError('Failed to initiate Google OAuth');
    }
  };

  const generateState = () => {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  };

  return (
    <button
      onClick={handleGoogleSignIn}
      disabled={disabled || isLoading}
      className="group relative inline-flex items-center justify-center px-8 py-4 bg-white border-2 border-gray-200 hover:border-blue-300 text-gray-700 hover:text-blue-700 font-semibold rounded-lg transition-all duration-200 shadow-md hover:shadow-lg transform hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
    >
      {isLoading ? (
        <>
          <Loader2 className="h-5 w-5 mr-3 animate-spin" />
          Connecting...
        </>
      ) : (
        <>
          <img 
            src="https://developers.google.com/identity/images/g-logo.png" 
            alt="Google" 
            className="h-5 w-5 mr-3"
          />
          Continue with Google
        </>
      )}
    </button>
  );
};

interface OAuthCallbackHandlerProps {
  onSuccess: (tokens: any) => void;
  onError: (error: string) => void;
}

export const OAuthCallbackHandler: React.FC<OAuthCallbackHandlerProps> = ({
  onSuccess,
  onError
}) => {
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [message, setMessage] = useState('Processing authentication...');

  useEffect(() => {
    const handleCallback = async () => {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');

        if (error) {
          throw new Error(`OAuth error: ${error}`);
        }

        if (!code) {
          throw new Error('No authorization code received');
        }

        const storedState = localStorage.getItem('oauth_state');
        if (state !== storedState) {
          throw new Error('Invalid state parameter');
        }

        setMessage('Exchanging authorization code...');

        // Exchange code for tokens via backend
        const response = await fetch(`${import.meta.env.VITE_API_URL}/api/v1/auth/google/callback`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            code,
            redirect_uri: `${window.location.origin}/auth/callback`
          }),
        });

        if (!response.ok) {
          throw new Error('Failed to exchange authorization code');
        }

        const tokens = await response.json();
        
        setStatus('success');
        setMessage('Authentication successful!');
        
        // Store tokens
        localStorage.setItem('access_token', tokens.access_token);
        localStorage.setItem('refresh_token', tokens.refresh_token);
        localStorage.setItem('user_info', JSON.stringify(tokens.user_info));
        
        // Clean up
        localStorage.removeItem('oauth_state');
        
        setTimeout(() => onSuccess(tokens), 1500);
        
      } catch (error) {
        console.error('OAuth callback error:', error);
        setStatus('error');
        setMessage(error instanceof Error ? error.message : 'Authentication failed');
        onError(error instanceof Error ? error.message : 'Authentication failed');
      }
    };

    handleCallback();
  }, [onSuccess, onError]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 flex items-center justify-center">
      <div className="bg-white rounded-2xl shadow-xl p-8 max-w-md w-full mx-4">
        <div className="text-center space-y-6">
          <div className="flex justify-center">
            <Shield className="h-16 w-16 text-blue-600" />
          </div>
          
          <div className="space-y-2">
            <h2 className="text-2xl font-bold text-gray-900">PhishNet Authentication</h2>
            <p className="text-gray-600">Securely connecting your account...</p>
          </div>

          <div className="space-y-4">
            {status === 'processing' && (
              <div className="flex items-center justify-center space-x-3">
                <Loader2 className="h-6 w-6 text-blue-600 animate-spin" />
                <span className="text-gray-700">{message}</span>
              </div>
            )}
            
            {status === 'success' && (
              <div className="flex items-center justify-center space-x-3 text-green-600">
                <CheckCircle className="h-6 w-6" />
                <span className="font-medium">{message}</span>
              </div>
            )}
            
            {status === 'error' && (
              <div className="flex items-center justify-center space-x-3 text-red-600">
                <AlertCircle className="h-6 w-6" />
                <span className="font-medium">{message}</span>
              </div>
            )}
          </div>

          <div className="text-sm text-gray-500 space-y-1">
            <p>🔒 Your data is encrypted and secure</p>
            <p>📧 Gmail access is read-only</p>
            <p>🛡️ Enterprise-grade privacy protection</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState(null);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const accessToken = localStorage.getItem('access_token');
      const userInfo = localStorage.getItem('user_info');
      
      if (accessToken && userInfo) {
        // Verify token is still valid
        const response = await fetch(`${import.meta.env.VITE_API_URL}/api/v1/auth/verify`, {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        });
        
        if (response.ok) {
          setUser(JSON.parse(userInfo));
          setIsAuthenticated(true);
        } else {
          // Token is invalid, clear storage
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          localStorage.removeItem('user_info');
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 flex items-center justify-center">
        <div className="text-center space-y-4">
          <Loader2 className="h-8 w-8 text-blue-600 animate-spin mx-auto" />
          <p className="text-gray-600">Loading PhishNet...</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      {children}
    </div>
  );
};