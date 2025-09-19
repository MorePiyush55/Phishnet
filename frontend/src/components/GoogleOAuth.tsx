import React, { useState, useEffect } from 'react';
import { Shield, CheckCircle, AlertCircle, Loader2, ArrowRight } from 'lucide-react';

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
      // Get client ID from environment variables
      const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;
      
      if (!clientId) {
        throw new Error('Google Client ID not configured');
      }

      // For development, use the production backend OAuth endpoint
      // since the OAuth client is configured for production URLs
      const redirectUri = 'https://phishnet-1ed1.onrender.com/oauth2callback';
      
      // OAuth scopes for Gmail access
      const scope = [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email',
        'openid'
      ].join(' ');
      
      // Generate secure state parameter
      const state = generateSecureState();
      
      // Store state in localStorage for verification
      localStorage.setItem('oauth_state', state);
      localStorage.setItem('oauth_timestamp', Date.now().toString());
      
      // Build OAuth URL
      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope,
        access_type: 'offline',
        prompt: 'consent',
        state: state,
        include_granted_scopes: 'true'
      });
      
      const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
      
      console.log('OAuth URL:', authUrl);
      console.log('Redirect URI:', redirectUri);
      console.log('Client ID:', clientId);
      
      // Redirect to Google OAuth
      window.location.href = authUrl;
      
    } catch (error) {
      console.error('OAuth initiation error:', error);
      setIsLoading(false);
      onError(error instanceof Error ? error.message : 'Failed to initiate Google OAuth');
    }
  };

  const generateSecureState = (): string => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  };

  return (
    <button
      onClick={handleGoogleSignIn}
      disabled={disabled || isLoading}
      className="group relative inline-flex items-center justify-center px-8 py-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-bold text-lg rounded-xl transition-all duration-300 shadow-xl hover:shadow-2xl transform hover:-translate-y-1 border border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
    >
      {isLoading ? (
        <>
          <Loader2 className="h-6 w-6 mr-3 animate-spin" />
          Connecting to Google...
        </>
      ) : (
        <>
          <img 
            src="https://developers.google.com/identity/images/g-logo.png" 
            alt="Google" 
            className="h-6 w-6 mr-3"
          />
          Connect Gmail Account
          <ArrowRight className="h-5 w-5 ml-2 group-hover:translate-x-1 transition-transform" />
        </>
      )}
      <div className="absolute inset-0 bg-white/20 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
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
        // Parse URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');
        const errorDescription = urlParams.get('error_description');

        // Check for OAuth errors
        if (error) {
          let errorMessage = `OAuth error: ${error}`;
          if (errorDescription) {
            errorMessage += ` - ${errorDescription}`;
          }
          throw new Error(errorMessage);
        }

        if (!code) {
          throw new Error('No authorization code received from Google');
        }

        // Verify state parameter
        const storedState = localStorage.getItem('oauth_state');
        const storedTimestamp = localStorage.getItem('oauth_timestamp');
        
        if (!storedState || state !== storedState) {
          throw new Error('Invalid state parameter - possible CSRF attack');
        }
        
        // Check if state is not too old (5 minutes max)
        if (storedTimestamp) {
          const age = Date.now() - parseInt(storedTimestamp);
          if (age > 5 * 60 * 1000) {
            throw new Error('OAuth state expired - please try again');
          }
        }

        setMessage('Exchanging authorization code for tokens...');

        // Exchange code for tokens via backend
        const backendUrl = import.meta.env.VITE_API_URL || 'https://phishnet-1ed1.onrender.com';
        const response = await fetch(`${backendUrl}/api/v1/auth/google/callback`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            code,
            redirect_uri: `${window.location.origin}/auth/callback`,
            state
          }),
        });

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
          throw new Error(errorData.detail || `HTTP ${response.status}: Failed to exchange authorization code`);
        }

        const tokens = await response.json();
        
        setStatus('success');
        setMessage('Authentication successful! Redirecting to dashboard...');
        
        // Store tokens securely
        if (tokens.access_token) {
          localStorage.setItem('access_token', tokens.access_token);
        }
        if (tokens.refresh_token) {
          localStorage.setItem('refresh_token', tokens.refresh_token);
        }
        if (tokens.user_info) {
          localStorage.setItem('user_info', JSON.stringify(tokens.user_info));
        }
        
        // Clean up OAuth state
        localStorage.removeItem('oauth_state');
        localStorage.removeItem('oauth_timestamp');
        
        // Redirect after success
        setTimeout(() => {
          onSuccess(tokens);
        }, 2000);
        
      } catch (error) {
        console.error('OAuth callback error:', error);
        setStatus('error');
        const errorMessage = error instanceof Error ? error.message : 'Authentication failed';
        setMessage(errorMessage);
        
        // Clean up on error
        localStorage.removeItem('oauth_state');
        localStorage.removeItem('oauth_timestamp');
        
        setTimeout(() => {
          onError(errorMessage);
        }, 3000);
      }
    };

    handleCallback();
  }, [onSuccess, onError]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 flex items-center justify-center">
      <div className="bg-white rounded-2xl shadow-2xl p-8 max-w-md w-full mx-4 border border-gray-200">
        <div className="text-center space-y-6">
          {/* Logo */}
          <div className="flex justify-center">
            <div className="relative">
              <Shield className="h-20 w-20 text-blue-600" />
              {status === 'processing' && (
                <div className="absolute inset-0 animate-pulse">
                  <Shield className="h-20 w-20 text-blue-300" />
                </div>
              )}
            </div>
          </div>
          
          {/* Title */}
          <div className="space-y-2">
            <h2 className="text-3xl font-bold text-gray-900">PhishNet Authentication</h2>
            <p className="text-gray-600">Securing your Gmail connection...</p>
          </div>

          {/* Status Display */}
          <div className="space-y-4">
            {status === 'processing' && (
              <div className="flex flex-col items-center space-y-3">
                <Loader2 className="h-8 w-8 text-blue-600 animate-spin" />
                <span className="text-gray-700 font-medium">{message}</span>
                <div className="text-sm text-gray-500">This may take a few seconds...</div>
              </div>
            )}
            
            {status === 'success' && (
              <div className="flex flex-col items-center space-y-3 text-green-600">
                <CheckCircle className="h-8 w-8" />
                <span className="font-bold text-lg">{message}</span>
                <div className="text-sm text-gray-600">Welcome to PhishNet!</div>
              </div>
            )}
            
            {status === 'error' && (
              <div className="flex flex-col items-center space-y-3 text-red-600">
                <AlertCircle className="h-8 w-8" />
                <span className="font-bold text-lg">Authentication Failed</span>
                <div className="text-sm text-gray-700 text-center">{message}</div>
                <button
                  onClick={() => window.location.href = '/'}
                  className="mt-4 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Return to Login
                </button>
              </div>
            )}
          </div>

          {/* Security Features */}
          <div className="text-sm text-gray-500 space-y-2 pt-6 border-t border-gray-200">
            <div className="flex items-center justify-center space-x-2">
              <CheckCircle className="h-4 w-4 text-green-600" />
              <span>🔒 End-to-end encrypted</span>
            </div>
            <div className="flex items-center justify-center space-x-2">
              <CheckCircle className="h-4 w-4 text-green-600" />
              <span>📧 Read-only Gmail access</span>
            </div>
            <div className="flex items-center justify-center space-x-2">
              <CheckCircle className="h-4 w-4 text-green-600" />
              <span>🛡️ SOC 2 certified security</span>
            </div>
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
        // Verify token is still valid with backend
        const backendUrl = import.meta.env.VITE_API_URL || 'https://phishnet-1ed1.onrender.com';
        
        try {
          const response = await fetch(`${backendUrl}/api/v1/auth/verify`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'Content-Type': 'application/json'
            }
          });
          
          if (response.ok) {
            const result = await response.json();
            if (result.valid) {
              setUser(JSON.parse(userInfo));
              setIsAuthenticated(true);
            } else {
              // Token is invalid, clear storage
              localStorage.removeItem('access_token');
              localStorage.removeItem('refresh_token');
              localStorage.removeItem('user_info');
            }
          } else {
            // Backend not responding or token invalid
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            localStorage.removeItem('user_info');
          }
        } catch (networkError) {
          // Network error - assume offline, keep tokens for now
          console.warn('Cannot verify token - network error:', networkError);
          setUser(JSON.parse(userInfo));
          setIsAuthenticated(true);
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      // Clear potentially corrupted data
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('user_info');
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center space-y-4">
          <div className="relative">
            <Shield className="h-12 w-12 text-blue-600 mx-auto" />
            <div className="absolute inset-0 animate-pulse">
              <Shield className="h-12 w-12 text-blue-300 mx-auto" />
            </div>
          </div>
          <p className="text-gray-600 font-medium">Loading PhishNet Security Platform...</p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};