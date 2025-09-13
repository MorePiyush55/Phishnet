import React, { useState, useEffect } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { RequireAuth } from './hooks/useAuth';
import SOCDashboard from './components/SOCDashboard';
import LoginPage from './components/LoginPage';
import ConnectedPage from './pages/ConnectedPage';
import { EmailAnalysisTest } from './components/EmailAnalysisTest';
import { ErrorProvider } from './components/ErrorHandling';
import { AuthLandingPage } from './components/AuthLandingPage';
import { GoogleOAuthButton, OAuthCallbackHandler, AuthProvider } from './components/GoogleOAuth';

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
    checkAuthStatus();
  }, []);

  const checkAuthStatus = () => {
    const accessToken = localStorage.getItem('access_token');
    setIsAuthenticated(!!accessToken);
    setIsLoading(false);
  };

  const handleGoogleSignIn = () => {
    // This will redirect to Google OAuth
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
      state: Math.random().toString(36).substring(2, 15)
    });
    
    window.location.href = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
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
                      <Navigate to="/dashboard" replace /> : 
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
                  path="/test" 
                  element={
                    <RequireAuth>
                      <EmailAnalysisTest />
                    </RequireAuth>
                  } 
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
