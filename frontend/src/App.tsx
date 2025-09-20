import React, { useState, useEffect } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { RequireAuth } from './hooks/useAuth';
import SOCDashboard from './components/SOCDashboard';
import LoginPage from './components/LoginPage';
import { ConnectedPage } from './pages/ConnectedPage';
import { OAuthTest } from './pages/OAuthTest';
import { EmailAnalysisTest } from './components/EmailAnalysisTest';
import { ErrorProvider } from './components/ErrorHandling';
import { AuthLandingPage } from './components/AuthLandingPage';
import { GoogleOAuthButton, OAuthCallbackHandler, AuthProvider } from './components/GoogleOAuth';
import { OAuthService } from './services/oauthService';
import EmailAnalysis from './components/EmailAnalysis';

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error: any) => {
        // Don't retry on auth errors
        if (error?.response?.status === 401) return false;
        return failureCount < 3;
      },
      staleTime: 5 * 60 * 1000, // 5 minutes
      gcTime: 10 * 60 * 1000, // 10 minutes (formerly cacheTime)
    },
    mutations: {
      retry: (failureCount, error: any) => {
        // Don't retry on auth errors or client errors
        if (error?.response?.status >= 400 && error?.response?.status < 500) return false;
        return failureCount < 2;
      },
    },
  },
});

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check for OAuth callback parameters
    const urlParams = new URLSearchParams(window.location.search);
    const oauthSuccess = urlParams.get('oauth_success');
    const oauthError = urlParams.get('oauth_error');
    const userEmail = urlParams.get('email');

    if (oauthSuccess === 'true') {
      // OAuth was successful
      console.log('OAuth success! User email:', userEmail);
      setIsAuthenticated(true);
      setIsLoading(false);
      
      // Store user info in localStorage
      if (userEmail) {
        localStorage.setItem('user_email', userEmail);
        localStorage.setItem('access_token', 'oauth_authenticated'); // Simple token for auth check
        localStorage.setItem('oauth_success', 'true');
      }
      
      // Don't redirect here, let the ConnectedPage handle the flow
    } else if (oauthError) {
      // OAuth failed
      console.error('OAuth error:', oauthError);
      setIsAuthenticated(false);
      setIsLoading(false);
      // Clear URL parameters
      window.history.replaceState({}, document.title, window.location.pathname);
      // Show error to user
      alert(`OAuth failed: ${oauthError}`);
    } else {
      // No OAuth callback, check existing auth state
      checkAuthStatus();
    }
  }, []);

  useEffect(() => {
    // Only run checkAuthStatus if we haven't already processed OAuth callback
    const urlParams = new URLSearchParams(window.location.search);
    const oauthSuccess = urlParams.get('oauth_success');
    if (!oauthSuccess) {
      checkAuthStatus();
    }
  }, []);

  const checkAuthStatus = () => {
    const accessToken = localStorage.getItem('access_token');
    const userEmail = localStorage.getItem('user_email');
    const oauthSuccess = localStorage.getItem('oauth_success');
    
    // User is authenticated if they have an access token or completed OAuth
    const isAuth = !!(accessToken || (userEmail && oauthSuccess));
    setIsAuthenticated(isAuth);
    setIsLoading(false);
  };

  const handleGoogleSignIn = async () => {
    try {
      // Direct redirect to backend OAuth endpoint
      const backendUrl = import.meta.env.VITE_API_URL || 'https://phishnet-backend-iuoc.onrender.com';
      window.location.href = `${backendUrl}/api/test/oauth`;
    } catch (error) {
      console.error('OAuth error:', error);
    }
  };

  const handleAuthSuccess = (tokens: any) => {
    setIsAuthenticated(true);
    // Redirect to dashboard
    window.location.href = '/dashboard';
  };

  const handleAuthError = (error: string) => {
    console.error('Authentication error:', error);
    setIsAuthenticated(false);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 flex items-center justify-center">
        <div className="text-center space-y-4">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
          <p className="text-gray-600">Loading PhishNet...</p>
        </div>
      </div>
    );
  }

  return (
    <ErrorProvider maxErrors={10} autoRemoveAfter={30}>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <Router>
            <div className="App">
              <Routes>
                {/* Public Routes */}
                <Route 
                  path="/" 
                  element={
                    isAuthenticated ? 
                      <Navigate to="/emails" replace /> : 
                      <AuthLandingPage onGoogleSignIn={handleGoogleSignIn} />
                  } 
                />
                <Route 
                  path="/auth/callback" 
                  element={
                    <OAuthCallbackHandler 
                      onSuccess={handleAuthSuccess}
                      onError={handleAuthError}
                    />
                  } 
                />
                <Route path="/login" element={<LoginPage />} />
                <Route path="/connected" element={<ConnectedPage />} />
                
                {/* Protected routes */}
                <Route 
                  path="/dashboard" 
                  element={
                    <RequireAuth>
                      <SOCDashboard />
                    </RequireAuth>
                  } 
                />
                <Route 
                  path="/emails" 
                  element={
                    <RequireAuth>
                      <EmailAnalysis userEmail={localStorage.getItem('user_email') || ''} />
                    </RequireAuth>
                  } 
                />
                <Route 
                  path="/test" 
                  element={
                    <RequireAuth>
                      <EmailAnalysisTest />
                    </RequireAuth>
                  } 
                />
                <Route 
                  path="/oauth-test" 
                  element={<OAuthTest />} 
                />
                
                {/* Fallback */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </div>
          </Router>
        </AuthProvider>
        
        {/* React Query DevTools */}
        <ReactQueryDevtools initialIsOpen={false} />
      </QueryClientProvider>
    </ErrorProvider>
  );
}

export default App;
