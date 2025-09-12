import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { apiService, LoginRequest } from '../services/apiService';
import { useUIStore } from '../stores/uiStore';

interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  tenant_id?: string;
  permissions?: string[];
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  tokenExpiry: number | null;
  sessionExpired: boolean;
}

export function useAuth() {
  const [authState, setAuthState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    error: null,
    tokenExpiry: null,
    sessionExpired: false,
  });

  const navigate = useNavigate();
  const location = useLocation();
  const addNotification = useUIStore(state => state.addNotification);

  // Check token expiry and auto-refresh
  useEffect(() => {
    const checkTokenExpiry = () => {
      const token = apiService.getAccessToken();
      const expiry = apiService.getTokenExpiry();
      
      if (token && expiry) {
        const now = Date.now() / 1000;
        const timeUntilExpiry = expiry - now;
        
        // If token expires in less than 5 minutes, try to refresh
        if (timeUntilExpiry < 300 && timeUntilExpiry > 0) {
          refreshAuth();
        }
        // If token is already expired, mark session as expired
        else if (timeUntilExpiry <= 0) {
          setAuthState(prev => ({ 
            ...prev, 
            sessionExpired: true,
            isAuthenticated: false 
          }));
          
          addNotification({
            type: 'warning',
            message: 'Your session has expired. Please log in again.',
            autoHide: false,
          });
        }
      }
    };

    // Check immediately and then every minute
    checkTokenExpiry();
    const interval = setInterval(checkTokenExpiry, 60000);
    
    return () => clearInterval(interval);
  }, [addNotification]);

  // Check if user is authenticated on mount
  useEffect(() => {
    const checkAuth = async () => {
      const token = apiService.getAccessToken();
      
      if (!token) {
        setAuthState(prev => ({ ...prev, isLoading: false }));
        return;
      }

      try {
        // Try to fetch user profile to validate token
        const response = await fetch('/api/v1/auth/me', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const user = await response.json();
          const expiry = apiService.getTokenExpiry();
          
          setAuthState({
            user,
            isAuthenticated: true,
            isLoading: false,
            error: null,
            tokenExpiry: expiry,
            sessionExpired: false,
          });
        } else {
          // Token is invalid
          await apiService.logout();
          setAuthState({
            user: null,
            isAuthenticated: false,
            isLoading: false,
            error: null,
            tokenExpiry: null,
            sessionExpired: response.status === 401,
          });
        }
      } catch (error) {
        console.error('Auth check failed:', error);
        setAuthState({
          user: null,
          isAuthenticated: false,
          isLoading: false,
          error: 'Authentication check failed',
          tokenExpiry: null,
          sessionExpired: false,
        });
      }
    };

    checkAuth();
  }, []);

  const login = useCallback(async (credentials: LoginRequest) => {
    setAuthState(prev => ({ 
      ...prev, 
      isLoading: true, 
      error: null, 
      sessionExpired: false 
    }));

    try {
      const response = await apiService.login(credentials);
      const expiry = apiService.getTokenExpiry();
      
      setAuthState({
        user: response.user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
        tokenExpiry: expiry,
        sessionExpired: false,
      });

      addNotification({
        type: 'success',
        message: `Welcome back, ${response.user.username}!`,
        autoHide: true,
      });

      // Redirect to intended location or dashboard
      const redirectTo = (location.state as any)?.from?.pathname || '/dashboard';
      navigate(redirectTo, { replace: true });

      return response;
    } catch (error: any) {
      const errorMessage = error?.response?.data?.detail || error.message || 'Login failed';
      
      setAuthState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: errorMessage,
        tokenExpiry: null,
        sessionExpired: false,
      });

      addNotification({
        type: 'error',
        message: errorMessage,
        autoHide: false,
      });

      throw error;
    }
  }, [navigate, location.state, addNotification]);

  const logout = useCallback(async () => {
    setAuthState(prev => ({ ...prev, isLoading: true }));

    try {
      await apiService.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setAuthState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
        tokenExpiry: null,
        sessionExpired: false,
      });

      addNotification({
        type: 'info',
        message: 'You have been logged out',
        autoHide: true,
      });

      navigate('/login', { replace: true });
    }
  }, [navigate, addNotification]);

  const refreshAuth = useCallback(async () => {
    try {
      const newToken = await apiService.silentRefresh();
      if (newToken) {
        const expiry = apiService.getTokenExpiry();
        setAuthState(prev => ({
          ...prev,
          tokenExpiry: expiry,
          sessionExpired: false,
        }));
        return true;
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
      setAuthState(prev => ({ 
        ...prev, 
        sessionExpired: true,
        isAuthenticated: false 
      }));
      
      addNotification({
        type: 'warning',
        message: 'Session expired. Please log in again.',
        autoHide: false,
      });
      
      return false;
    }
    return false;
  }, [addNotification]);

  const clearSessionExpired = useCallback(() => {
    setAuthState(prev => ({ ...prev, sessionExpired: false }));
  }, []);

  return {
    ...authState,
    login,
    logout,
    refreshAuth,
    clearSessionExpired,
  };
}

// Enhanced Route Guard Components
interface RequireAuthProps {
  children: React.ReactNode;
  requiredRole?: string;
  fallback?: React.ReactNode;
}

export function RequireAuth({ children, requiredRole, fallback }: RequireAuthProps) {
  const { isAuthenticated, isLoading, user, sessionExpired, clearSessionExpired } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isLoading && (!isAuthenticated || sessionExpired)) {
      // Redirect to login with current location
      navigate('/login', { 
        state: { 
          from: location,
          sessionExpired 
        },
        replace: true 
      });
    }
  }, [isAuthenticated, isLoading, sessionExpired, navigate, location]);

  // Session expired modal/overlay
  if (sessionExpired) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-6 max-w-md mx-4">
          <div className="text-center">
            <div className="w-12 h-12 mx-auto mb-4 text-orange-500">
              <svg fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-gray-900 mb-2">Session Expired</h2>
            <p className="text-gray-600 mb-4">
              Your session has expired for security reasons. Please log in again to continue.
            </p>
            <button
              onClick={() => {
                clearSessionExpired();
                navigate('/login', { 
                  state: { from: location },
                  replace: true 
                });
              }}
              className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
            >
              Go to Login
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white mx-auto mb-4"></div>
          <div>Loading...</div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return fallback || null;
  }

  // Check role if required
  if (requiredRole && user?.role !== requiredRole) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white text-center">
          <h1 className="text-2xl font-bold mb-4">Access Denied</h1>
          <p>You don't have permission to access this page.</p>
          <p className="text-gray-400 mt-2">Required role: {requiredRole}</p>
          <p className="text-gray-400">Your role: {user?.role}</p>
          <button
            onClick={() => navigate('/dashboard')}
            className="mt-4 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
          >
            Go to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}

// Hook for checking permissions
export function usePermissions() {
  const { user } = useAuth();

  const hasRole = useCallback((role: string): boolean => {
    return user?.role === role;
  }, [user?.role]);

  const hasAnyRole = useCallback((roles: string[]): boolean => {
    return roles.some(role => user?.role === role);
  }, [user?.role]);

  const hasPermission = useCallback((permission: string): boolean => {
    return user?.permissions?.includes(permission) || false;
  }, [user?.permissions]);

  const isAdmin = useCallback((): boolean => {
    return user?.role === 'admin';
  }, [user?.role]);

  const isAnalyst = useCallback((): boolean => {
    return user?.role === 'analyst' || user?.role === 'admin';
  }, [user?.role]);

  const canManageUsers = useCallback((): boolean => {
    return user?.role === 'admin';
  }, [user?.role]);

  const canDeleteEmails = useCallback((): boolean => {
    return user?.role === 'admin' || user?.role === 'analyst';
  }, [user?.role]);

  const canViewAudits = useCallback((): boolean => {
    return user?.role === 'admin' || user?.role === 'analyst';
  }, [user?.role]);

  const canQuarantine = useCallback((): boolean => {
    return user?.role === 'admin' || user?.role === 'analyst';
  }, [user?.role]);

  const canWhitelist = useCallback((): boolean => {
    return user?.role === 'admin';
  }, [user?.role]);

  const canViewTenant = useCallback((tenantId: string): boolean => {
    return user?.tenant_id === tenantId || user?.role === 'admin';
  }, [user?.tenant_id, user?.role]);

  const canBulkAction = useCallback((): boolean => {
    return user?.role === 'admin' || user?.role === 'analyst';
  }, [user?.role]);

  return {
    user,
    hasRole,
    hasAnyRole,
    hasPermission,
    isAdmin,
    isAnalyst,
    canManageUsers,
    canDeleteEmails,
    canViewAudits,
    canQuarantine,
    canWhitelist,
    canViewTenant,
    canBulkAction,
  };
}
