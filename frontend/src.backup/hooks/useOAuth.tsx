import { useCallback } from 'react';
import { apiService } from '../services/apiService';

export function useOAuth() {
  const startOAuth = useCallback(async () => {
    try {
      // Use the API service method instead of direct navigation
      const response = await apiService.startGmailOAuth();
      
      if (response.success && response.authorization_url) {
        // Redirect to the OAuth URL returned by the backend
        window.location.href = response.authorization_url;
      } else {
        throw new Error(response.message || 'Failed to start OAuth flow');
      }
    } catch (error) {
      console.error('OAuth start error:', error);
      throw error;
    }
  }, []);

  return { startOAuth };
}
