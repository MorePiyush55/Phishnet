import React, { useState, useEffect } from 'react';

export const OAuthTest: React.FC = () => {
  const [logs, setLogs] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  };

  const startOAuth = async () => {
    setIsLoading(true);
    addLog('Starting OAuth flow...');
    
    try {
      // Direct redirect to backend OAuth endpoint
      const backendUrl = 'https://phishnet-backend-iuoc.onrender.com';
      const oauthUrl = `${backendUrl}/api/test/auth/google`;
      
      addLog(`Redirecting to: ${oauthUrl}`);
      
      // Redirect to OAuth
      window.location.href = oauthUrl;
      
    } catch (error) {
      addLog(`Error: ${error}`);
      setIsLoading(false);
    }
  };

  const testBackendHealth = async () => {
    addLog('Testing backend health...');
    
    try {
      const response = await fetch('https://phishnet-backend-iuoc.onrender.com/health');
      const data = await response.json();
      addLog(`Backend health: ${JSON.stringify(data)}`);
    } catch (error) {
      addLog(`Backend health error: ${error}`);
    }
  };

  const testOAuthEndpoint = async () => {
    addLog('Testing OAuth endpoint...');
    
    try {
      const response = await fetch('https://phishnet-backend-iuoc.onrender.com/test-oauth');
      const data = await response.json();
      addLog(`OAuth endpoint: ${JSON.stringify(data)}`);
    } catch (error) {
      addLog(`OAuth endpoint error: ${error}`);
    }
  };

  useEffect(() => {
    // Check for OAuth callback parameters
    const urlParams = new URLSearchParams(window.location.search);
    const oauthSuccess = urlParams.get('oauth_success');
    const oauthError = urlParams.get('oauth_error');
    const userEmail = urlParams.get('email');

    if (oauthSuccess) {
      addLog(`OAuth SUCCESS! Email: ${userEmail}`);
    } else if (oauthError) {
      addLog(`OAuth ERROR: ${oauthError}`);
    }
  }, []);

  return (
    <div className="min-h-screen bg-gray-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        <div className="bg-white shadow-xl rounded-lg p-6">
          <h1 className="text-3xl font-bold text-gray-900 mb-6">OAuth Debug Tool</h1>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <button
              onClick={testBackendHealth}
              className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
            >
              Test Backend Health
            </button>
            
            <button
              onClick={testOAuthEndpoint}
              className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
            >
              Test OAuth Config
            </button>
            
            <button
              onClick={startOAuth}
              disabled={isLoading}
              className={`font-bold py-2 px-4 rounded text-white ${
                isLoading 
                  ? 'bg-gray-400 cursor-not-allowed' 
                  : 'bg-red-500 hover:bg-red-700'
              }`}
            >
              {isLoading ? 'Starting OAuth...' : 'Start OAuth Flow'}
            </button>
          </div>

          <div className="bg-gray-900 text-green-400 p-4 rounded-lg h-96 overflow-y-auto">
            <h3 className="text-lg font-semibold mb-2">Debug Logs:</h3>
            {logs.length === 0 ? (
              <p className="text-gray-400">No logs yet. Click a button to start testing.</p>
            ) : (
              logs.map((log, index) => (
                <div key={index} className="mb-1 font-mono text-sm">
                  {log}
                </div>
              ))
            )}
          </div>
          
          <div className="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
            <h3 className="text-lg font-semibold text-yellow-800 mb-2">Instructions:</h3>
            <ol className="list-decimal list-inside text-yellow-700 space-y-1">
              <li>First, test backend health to ensure the server is running</li>
              <li>Test OAuth config to verify credentials are set up</li>
              <li>Start OAuth flow to test the complete authentication process</li>
              <li>Check the logs for any errors or issues</li>
            </ol>
          </div>
          
          <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <h3 className="text-lg font-semibold text-blue-800 mb-2">Current URL Parameters:</h3>
            <pre className="text-blue-700 text-sm font-mono">
              {window.location.search || 'No parameters'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};