import { useState, useEffect, useCallback } from 'react';
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
  });

  const navigate = useNavigate();
  const location = useLocation();
  const addNotification = useUIStore(state => state.addNotification);

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
          setAuthState({
            user,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } else {
          // Token is invalid
          await apiService.logout();
          setAuthState({
            user: null,
            isAuthenticated: false,
            isLoading: false,
            error: null,
          });
        }
      } catch (error) {
        console.error('Auth check failed:', error);
        setAuthState({
          user: null,
          isAuthenticated: false,
          isLoading: false,
          error: 'Authentication check failed',
        });
      }
    };

    checkAuth();
  }, []);

  const login = useCallback(async (credentials: LoginRequest) => {
    setAuthState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await apiService.login(credentials);
      
      setAuthState({
        user: response.user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
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
        // Optionally refresh user data
        return true;
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
      await logout();
      return false;
    }
    return false;
  }, [logout]);

  return {
    ...authState,
    login,
    logout,
    refreshAuth,
  };
}

// Route Guard Components
interface RequireAuthProps {
  children: React.ReactNode;
  requiredRole?: string;
  fallback?: React.ReactNode;
}

export function RequireAuth({ children, requiredRole, fallback }: RequireAuthProps) {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      // Redirect to login with current location
      navigate('/login', { 
        state: { from: location },
        replace: true 
      });
    }
  }, [isAuthenticated, isLoading, navigate, location]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white">Loading...</div>
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

  return {
    user,
    hasRole,
    hasAnyRole,
    isAdmin,
    isAnalyst,
    canManageUsers,
    canDeleteEmails,
    canViewAudits,
  };
}
