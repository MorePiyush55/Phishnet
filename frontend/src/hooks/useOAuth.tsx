import { useCallback } from 'react';

// Use Vite environment variables (import.meta.env)
const API_BASE = (
  import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || ''
).toString();

export function useOAuth() {
  const startOAuth = useCallback((redirectTo = '/') => {
    const url = `${API_BASE}/api/v1/auth/gmail/start?redirect_to=${encodeURIComponent(
      redirectTo
    )}`;
    // Navigate to backend start endpoint so backend can set server-side state/cookies
    window.location.href = url;
  }, []);

  return { startOAuth };
}
