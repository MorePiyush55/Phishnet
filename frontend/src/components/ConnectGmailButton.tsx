import React, { useState } from 'react';
import { useOAuth } from '../hooks/useOAuth';

export function ConnectGmailButton({ redirectTo = '/' }: { redirectTo?: string }) {
  const { startOAuth } = useOAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleConnect = async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      await startOAuth();
    } catch (error) {
      console.error('OAuth error:', error);
      setError(error instanceof Error ? error.message : 'Failed to connect Gmail');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <button
        onClick={handleConnect}
        disabled={isLoading}
        className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
      >
        {isLoading ? 'Connecting...' : 'Connect Gmail'}
      </button>
      {error && (
        <p className="text-red-500 text-sm mt-2">{error}</p>
      )}
    </div>
  );
}

export default ConnectGmailButton;
