import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, RequireAuth } from './contexts/AuthContext';
import SimpleDashboard from './components/SimpleDashboard';
import LoginPage from './components/LoginPage';
import { ConnectedPage } from './pages/ConnectedPage';
import { OAuthTest } from './pages/OAuthTest';
import { EmailAnalysisTest } from './components/EmailAnalysisTest';
import { ErrorProvider } from './components/ErrorHandling';
import { AuthLandingPage } from './components/AuthLandingPage';
import EmailAnalysis from './components/EmailAnalysis';
import LinkAnalysisPage from '../pages/LinkAnalysisPage';

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error: any) => {
        // Don't retry on authentication errors
        if (error?.response?.status === 401 || error?.response?.status === 403) {
          return false;
        }
        // Retry up to 3 times for other errors
        return failureCount < 3;
      },
      staleTime: 5 * 60 * 1000, // 5 minutes
      gcTime: 10 * 60 * 1000, // 10 minutes
    },
  },
});

const App: React.FC = () => {
  const handleGoogleSignIn = () => {
    try {
      // Direct redirect to backend OAuth endpoint
      const backendUrl = 'https://phishnet-backend-iuoc.onrender.com';
      window.location.href = `${backendUrl}/api/test/auth/google`;
    } catch (error) {
      console.error('OAuth error:', error);
    }
  };

  return (
    <QueryClientProvider client={queryClient}>
      <ErrorProvider maxErrors={10} autoRemoveAfter={30}>
        <AuthProvider>
          <Router>
            <Routes>
              {/* Public Routes */}
              <Route path="/" element={<AuthLandingPage onGoogleSignIn={handleGoogleSignIn} />} />
              <Route path="/login" element={<LoginPage />} />
              <Route path="/connected" element={<ConnectedPage />} />
              <Route path="/oauth-test" element={<OAuthTest />} />
              
              {/* Protected Routes */}
              <Route 
                path="/dashboard" 
                element={
                  <RequireAuth>
                    <SimpleDashboard />
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
                path="/link-analysis" 
                element={
                  <RequireAuth>
                    <LinkAnalysisPage />
                  </RequireAuth>
                } 
              />
              
              {/* Default redirect */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Router>
        </AuthProvider>
        
        {/* React Query DevTools */}
        <ReactQueryDevtools initialIsOpen={false} />
      </ErrorProvider>
    </QueryClientProvider>
  );
};

export default App;