import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { RequireAuth } from './hooks/useAuth';
import SOCDashboard from './components/SOCDashboard';
import LoginPage from './components/LoginPage';
import ConnectedPage from './pages/ConnectedPage';
import { ErrorProvider } from './components/ErrorHandling';

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
  return (
    <ErrorProvider maxErrors={10} autoRemoveAfter={30}>
      <QueryClientProvider client={queryClient}>
        <Router>
          <div className="App">
            <Routes>
              {/* Login route */}
              <Route path="/login" element={<LoginPage />} />
              
              {/* OAuth callback route */}
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
              
              {/* Default redirect */}
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              
              {/* Catch all */}
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
          </div>
        </Router>
        
        {/* React Query DevTools */}
        <ReactQueryDevtools initialIsOpen={false} />
      </QueryClientProvider>
    </ErrorProvider>
  );
}

export default App;
