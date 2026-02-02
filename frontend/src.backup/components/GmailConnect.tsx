import React, { useState } from 'react';
import { Shield, Mail, AlertTriangle, CheckCircle2, Clock, ExternalLink } from 'lucide-react';
import { OAuthService, RateLimiter } from '../services/oauthService';

interface GmailConnectProps {
  onConnectionChange?: (connected: boolean) => void;
  className?: string;
}

export const GmailConnect: React.FC<GmailConnectProps> = ({ 
  onConnectionChange, 
  className = '' 
}) => {
  const [isConnecting, setIsConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showConsent, setShowConsent] = useState(false);

  const handleConnect = async () => {
    // Check rate limiting
    if (!RateLimiter.canMakeRequest('oauth_start', 3, 300000)) { // 3 requests per 5 minutes
      const waitTime = Math.ceil(RateLimiter.getTimeUntilNextRequest('oauth_start', 3, 300000) / 1000);
      setError(`Rate limit exceeded. Please wait ${waitTime} seconds before trying again.`);
      return;
    }

    setIsConnecting(true);
    setError(null);

    try {
      await OAuthService.startOAuth();
      // OAuth service will redirect to Google, so we won't reach here normally
    } catch (err: any) {
      setError(err.message);
      setIsConnecting(false);
    }
  };

  const ConsentDialog = () => (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-md mx-4">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="h-6 w-6 text-blue-600" />
          <h3 className="text-lg font-semibold">Gmail Access Permission</h3>
        </div>
        
        <div className="space-y-4 text-sm text-gray-600">
          <p>
            <strong>PhishNet</strong> will access your Gmail to:
          </p>
          
          <ul className="space-y-2 ml-4">
            <li className="flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
              <span>Scan incoming emails for phishing attempts</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
              <span>Automatically quarantine suspicious messages</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
              <span>Monitor new emails in real-time</span>
            </li>
          </ul>

          <div className="bg-yellow-50 border border-yellow-200 rounded p-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-medium text-yellow-800">Why offline access?</p>
                <p className="text-yellow-700 text-xs mt-1">
                  We need offline access to continuously monitor your emails for security threats, 
                  even when you're not actively using PhishNet.
                </p>
              </div>
            </div>
          </div>

          <div className="bg-blue-50 border border-blue-200 rounded p-3">
            <div className="flex items-start gap-2">
              <Shield className="h-4 w-4 text-blue-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-medium text-blue-800">Your Privacy</p>
                <p className="text-blue-700 text-xs mt-1">
                  Email analysis happens in our secure sandbox. Raw email content is never 
                  shared with third parties. You can revoke access anytime.
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="flex gap-3 mt-6">
          <button
            onClick={() => setShowConsent(false)}
            className="flex-1 px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              setShowConsent(false);
              handleConnect();
            }}
            className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            Continue to Google
          </button>
        </div>

        <p className="text-xs text-gray-500 mt-3 text-center">
          By continuing, you agree to our{' '}
          <a href="/privacy" className="text-blue-600 hover:underline">Privacy Policy</a>
          {' '}and{' '}
          <a href="/terms" className="text-blue-600 hover:underline">Terms of Service</a>
        </p>
      </div>
    </div>
  );

  return (
    <>
      <div className={`bg-white rounded-lg border border-gray-200 p-6 ${className}`}>
        <div className="text-center">
          <div className="mx-auto w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mb-4">
            <Mail className="h-8 w-8 text-red-600" />
          </div>
          
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            Connect Your Gmail Account
          </h3>
          
          <p className="text-gray-600 mb-6">
            Secure your inbox with AI-powered phishing detection. 
            Connect Gmail to start monitoring for threats.
          </p>

          {error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-md">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-red-600 mt-0.5 flex-shrink-0" />
                <p className="text-sm text-red-700">{error}</p>
              </div>
            </div>
          )}

          <button
            onClick={() => setShowConsent(true)}
            disabled={isConnecting}
            className="w-full bg-blue-600 text-white px-6 py-3 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {isConnecting ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
                Connecting...
              </>
            ) : (
              <>
                <Mail className="h-4 w-4" />
                Connect Gmail Account
                <ExternalLink className="h-4 w-4" />
              </>
            )}
          </button>

          <div className="mt-4 space-y-2 text-xs text-gray-500">
            <div className="flex items-center justify-center gap-1">
              <Shield className="h-3 w-3" />
              <span>Secured with Google OAuth 2.0</span>
            </div>
            <div className="flex items-center justify-center gap-1">
              <Clock className="h-3 w-3" />
              <span>Connection expires automatically</span>
            </div>
          </div>
        </div>
      </div>

      {showConsent && <ConsentDialog />}
    </>
  );
};

export default GmailConnect;