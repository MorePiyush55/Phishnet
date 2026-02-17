import { useState, useEffect, useCallback } from 'react';
import { OAuthService, UserStatus, ConnectionMonitor } from '../services/oauthService';

interface OAuthState {
  user: UserStatus | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
  isOnline: boolean;
}

/**
 * Production-ready OAuth authentication hook for Vercel deployment
 * Handles Gmail OAuth flow with comprehensive error handling and connection monitoring
 */
export function useOAuth() {
  const [oauthState, setOAuthState] = useState<OAuthState>({
    user: null,
    isLoading: true,
    isAuthenticated: false,
    error: null,
    isOnline: ConnectionMonitor.online,
  });

  // Check authentication status
  const checkAuth = useCallback(async () => {
    setOAuthState(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      const user = await OAuthService.checkAuthStatus();
      setOAuthState(prev => ({
        ...prev,
        user,
        isAuthenticated: !!user,
        isLoading: false,
      }));
    } catch (error: any) {
      setOAuthState(prev => ({
        ...prev,
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: error.message,
      }));
    }
  }, []);

  // Start OAuth flow
  const startOAuth = useCallback(async () => {
    try {
      setOAuthState(prev => ({ ...prev, error: null }));
      await OAuthService.startOAuth();
    } catch (error: any) {
      setOAuthState(prev => ({ ...prev, error: error.message }));
    }
  }, []);

  // Logout/Disconnect
  const disconnect = useCallback(async () => {
    try {
      setOAuthState(prev => ({ ...prev, isLoading: true, error: null }));
      await OAuthService.revokeAccess();
      setOAuthState(prev => ({
        ...prev,
        user: null,
        isAuthenticated: false,
        isLoading: false,
      }));
    } catch (error: any) {
      setOAuthState(prev => ({
        ...prev,
        isLoading: false,
        error: error.message,
      }));
    }
  }, []);

  // Trigger email scan
  const triggerScan = useCallback(async () => {
    try {
      const result = await OAuthService.triggerScan();
      return result;
    } catch (error: any) {
      setOAuthState(prev => ({ ...prev, error: error.message }));
      throw error;
    }
  }, []);

  // Get scan history
  const getScanHistory = useCallback(async (page: number = 1, limit: number = 20) => {
    try {
      const history = await OAuthService.getScanHistory(page, limit);
      return history;
    } catch (error: any) {
      setOAuthState(prev => ({ ...prev, error: error.message }));
      throw error;
    }
  }, []);

  // Clear errors
  const clearError = useCallback(() => {
    setOAuthState(prev => ({ ...prev, error: null }));
  }, []);

  // Listen for connection changes
  useEffect(() => {
    const handleConnectionChange = (online: boolean) => {
      setOAuthState(prev => ({ ...prev, isOnline: online }));
      
      // Recheck auth when coming back online
      if (online && oauthState.isAuthenticated) {
        checkAuth();
      }
    };

    ConnectionMonitor.addListener(handleConnectionChange);
    return () => ConnectionMonitor.removeListener(handleConnectionChange);
  }, [checkAuth, oauthState.isAuthenticated]);

  // Listen for auth events
  useEffect(() => {
    const handleAuthLogout = () => {
      setOAuthState(prev => ({
        ...prev,
        user: null,
        isAuthenticated: false,
        error: 'Session expired',
      }));
    };

    const handleAuthStatusChecked = (event: CustomEvent) => {
      const { status, authenticated } = event.detail;
      setOAuthState(prev => ({
        ...prev,
        user: status,
        isAuthenticated: authenticated,
        isLoading: false,
      }));
    };

    const handleRateLimit = (event: CustomEvent) => {
      setOAuthState(prev => ({
        ...prev,
        error: event.detail.message,
      }));
    };

    window.addEventListener('auth:logout', handleAuthLogout);
    window.addEventListener('auth:status-checked', handleAuthStatusChecked as EventListener);
    window.addEventListener('auth:rate-limited', handleRateLimit as EventListener);

    return () => {
      window.removeEventListener('auth:logout', handleAuthLogout);
      window.removeEventListener('auth:status-checked', handleAuthStatusChecked as EventListener);
      window.removeEventListener('auth:rate-limited', handleRateLimit as EventListener);
    };
  }, []);

  // Initial auth check
  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  return {
    // State
    ...oauthState,
    
    // Actions
    startOAuth,
    disconnect,
    checkAuth,
    triggerScan,
    getScanHistory,
    clearError,
    
    // Computed properties
    canScan: oauthState.isAuthenticated && oauthState.isOnline,
    needsReconnection: !oauthState.isAuthenticated && oauthState.isOnline,
    isGmailConnected: oauthState.isAuthenticated && oauthState.user?.status === 'connected',
    hasValidScopes: (oauthState.user?.scopes?.length ?? 0) > 0,
    watchActive: oauthState.user?.is_watch_active || false,
  };
}