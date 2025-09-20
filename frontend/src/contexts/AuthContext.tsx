import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

interface AuthUser {
  email: string;
  name?: string;
  id?: string;
  picture?: string;
}

interface AuthContextType {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, name?: string) => void;
  logout: () => void;
  checkAuthStatus: () => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuthContext = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuthContext must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  const checkAuthStatus = (): boolean => {
    try {
      // Check for OAuth authentication with enhanced validation
      const oauthSuccess = localStorage.getItem('oauth_success');
      const userEmail = localStorage.getItem('user_email');
      const accessToken = localStorage.getItem('access_token');
      const isAuthenticated = localStorage.getItem('isAuthenticated');
      const authMethod = localStorage.getItem('authMethod');

      console.log('Checking auth status:', { 
        oauthSuccess, 
        userEmail, 
        accessToken, 
        isAuthenticated,
        authMethod 
      });

      // Check OAuth authentication
      if (oauthSuccess === 'true' && userEmail && accessToken && isAuthenticated === 'true') {
        return true;
      }

      // Check for regular API authentication
      const apiToken = localStorage.getItem('token') || localStorage.getItem('authToken');
      if (apiToken) {
        return true;
      }

      console.log('No valid authentication found');
      return false;
    } catch (error) {
      console.error('Error checking auth status:', error);
      return false;
    }
  };

  const login = (email: string, name?: string) => {
    const authUser: AuthUser = {
      email,
      name,
      id: email, // Use email as ID for OAuth users
    };

    setUser(authUser);
    setIsAuthenticated(true);
    
    // Store authentication data
    localStorage.setItem('oauth_success', 'true');
    localStorage.setItem('user_email', email);
    localStorage.setItem('access_token', 'oauth_authenticated');
    
    if (name) {
      localStorage.setItem('user_name', name);
    }

    console.log('User logged in:', authUser);
  };

  const logout = () => {
    setUser(null);
    setIsAuthenticated(false);
    
    // Clear all auth-related localStorage items
    localStorage.removeItem('oauth_success');
    localStorage.removeItem('user_email');
    localStorage.removeItem('user_name');
    localStorage.removeItem('access_token');
    localStorage.removeItem('token');
    localStorage.removeItem('authToken');
    
    console.log('User logged out');
  };

  // Check authentication status on mount and when localStorage changes
  useEffect(() => {
    const initAuth = () => {
      setIsLoading(true);
      
      if (checkAuthStatus()) {
        const userEmail = localStorage.getItem('user_email');
        const userName = localStorage.getItem('user_name');
        
        if (userEmail) {
          const authUser: AuthUser = {
            email: userEmail,
            name: userName || undefined,
            id: userEmail,
          };
          
          setUser(authUser);
          setIsAuthenticated(true);
          console.log('Restored user session:', authUser);
        }
      }
      
      setIsLoading(false);
    };

    initAuth();

    // Listen for storage changes (e.g., from other tabs)
    const handleStorageChange = () => {
      initAuth();
    };

    window.addEventListener('storage', handleStorageChange);
    
    return () => {
      window.removeEventListener('storage', handleStorageChange);
    };
  }, []);

  const value: AuthContextType = {
    user,
    isAuthenticated,
    isLoading,
    login,
    logout,
    checkAuthStatus,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// RequireAuth component for protecting routes
interface RequireAuthProps {
  children: ReactNode;
  fallback?: ReactNode;
}

export const RequireAuth: React.FC<RequireAuthProps> = ({ 
  children, 
  fallback = null 
}) => {
  const { isAuthenticated, isLoading } = useAuthContext();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500 mx-auto"></div>
          <p className="mt-4 text-white">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return fallback || (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-center text-white">
          <h2 className="text-2xl font-bold mb-4">Authentication Required</h2>
          <p>Please log in to access this page.</p>
          <a
            href="/login"
            className="mt-4 inline-block bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
          >
            Go to Login
          </a>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};