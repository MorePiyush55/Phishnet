import React from 'react';
import { useOAuth } from '../hooks/useOAuth';

export function ConnectGmailButton({ redirectTo = '/' }: { redirectTo?: string }) {
  const { startOAuth } = useOAuth();

  return (
    <button
      onClick={() => startOAuth()}
      className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
    >
      Connect Gmail
    </button>
  );
}

export default ConnectGmailButton;
