import React from 'react';import React, { useEffect, useState } from 'react';import React, { useEffect, useState } from 'react';import React, { useEffect, useState } from 'react';

import { Navigate } from 'react-router-dom';

import { useSearchParams, Navigate } from 'react-router-dom';

const OAuthCallback: React.FC = () => {

  return <Navigate to="/dashboard" replace />;import { Shield, CheckCircle, AlertCircle, Loader } from 'lucide-react';import { useSearchParams, Navigate } from 'react-router-dom';import { useSearchParams, useNavigate } from 'react-router-dom';

};



export default OAuthCallback;
const OAuthCallback: React.FC = () => {import { Shield, CheckCircle, AlertCircle, Loader } from 'lucide-react';

  const [searchParams] = useSearchParams();

  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');export default function OAuthCallback(): JSX.Element {

  const [errorMessage, setErrorMessage] = useState<string>('');

const OAuthCallback: React.FC = () => {  const [searchParams] = useSearchParams();

  useEffect(() => {

    const success = searchParams.get('oauth_success');  const [searchParams] = useSearchParams();  const navigate = useNavigate();

    const error = searchParams.get('oauth_error');

    const code = searchParams.get('code');  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');  const [status, setStatus] = useState<'processing' | 'success' | 'error' | 'unknown'>('processing');

    const state = searchParams.get('state');

  const [errorMessage, setErrorMessage] = useState<string>('');  const [errorMsg, setErrorMsg] = useState<string | null>(null);

    if (success === 'true') {

      setStatus('success');  const [redirectCountdown, setRedirectCountdown] = useState<number>(3);

      setTimeout(() => {

        window.location.href = '/dashboard';  useEffect(() => {

      }, 2000);

    } else if (error) {  useEffect(() => {    const success = searchParams.get('oauth_success');

      setStatus('error');

      setErrorMessage(decodeURIComponent(error));    const success = searchParams.get('oauth_success');    const error = searchParams.get('oauth_error');

    } else if (code && state) {

      setStatus('success');    const error = searchParams.get('oauth_error');

      setTimeout(() => {

        window.location.href = '/dashboard';    const code = searchParams.get('code');    if (success) {

      }, 2000);

    } else {    const state = searchParams.get('state');      setStatus('success');

      setStatus('error');

      setErrorMessage('Invalid OAuth response - missing required parameters');      setTimeout(() => navigate('/dashboard'), 1000);

    }

  }, [searchParams]);    if (success === 'true') {      return;



  if (status === 'success') {      setStatus('success');    }

    return <Navigate to="/dashboard" replace />;

  }      



  return (      // Start countdown    if (error) {

    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-indigo-900">

      <div className="min-h-screen flex items-center justify-center px-4">      const timer = setInterval(() => {      setStatus('error');

        <div className="bg-white/10 backdrop-blur-md rounded-2xl border border-white/20 shadow-2xl max-w-md w-full">

          <div className="p-8 text-center">        setRedirectCountdown((prev) => {      setErrorMsg(error);

            <div className="mb-6">

              <Shield className="w-16 h-16 text-blue-400 mx-auto mb-4" />          if (prev <= 1) {      return;

              <h1 className="text-2xl font-bold text-white mb-2">

                {status === 'processing' && 'Connecting Gmail...'}            clearInterval(timer);    }

                {status === 'success' && 'Connection Successful!'}

                {status === 'error' && 'Connection Failed'}            window.location.href = '/dashboard';

              </h1>

            </div>            return 0;    setStatus('unknown');



            {status === 'processing' && (          }  }, [searchParams, navigate]);

              <>

                <Loader className="w-8 h-8 text-blue-400 mx-auto mb-4 animate-spin" />          return prev - 1;

                <p className="text-white/80 mb-4">

                  Please wait while we establish a secure connection to your Gmail account...        });  return (

                </p>

              </>      }, 1000);    <div className="p-6 max-w-2xl mx-auto">

            )}

      <h2 className="text-2xl font-semibold mb-2">Connecting Gmail</h2>

            {status === 'success' && (

              <>      return () => clearInterval(timer);      {status === 'processing' && <p>Finalizing connection — please wait...</p>}

                <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />

                <p className="text-white/80 mb-4">    } else if (error) {      {status === 'success' && <p>Gmail connected. Redirecting to dashboard...</p>}

                  Your Gmail account has been successfully connected to PhishNet!

                </p>      setStatus('error');      {status === 'error' && (

                <button

                  onClick={() => window.location.href = '/dashboard'}      setErrorMessage(decodeURIComponent(error));        <div>

                  className="w-full py-2 px-4 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"

                >    } else if (code && state) {          <p className="text-red-600">Connection failed: {errorMsg}</p>

                  Go to Dashboard Now

                </button>      // OAuth flow completed, success expected          <p className="mt-2">Try reconnecting or contact support if the problem persists.</p>

              </>

            )}      setStatus('success');        </div>



            {status === 'error' && (      setTimeout(() => {      )}

              <>

                <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />        window.location.href = '/dashboard';      {status === 'unknown' && <p>Unexpected response from OAuth provider.</p>}

                <p className="text-white/80 mb-4">

                  We encountered an issue while connecting your Gmail account.      }, 2000);    </div>

                </p>

                {errorMessage && (    } else {  );

                  <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 mb-6">

                    <p className="text-red-400 text-sm font-mono">      setStatus('error');}

                      {errorMessage}

                    </p>      setErrorMessage('Invalid OAuth response - missing required parameters');import React, { useEffect, useState } from 'react';

                  </div>

                )}    }import { useSearchParams, Navigate } from 'react-router-dom';

                <div className="space-y-3">

                  <button  }, [searchParams]);import { Shield, CheckCircle, AlertCircle, Loader } from 'lucide-react';

                    onClick={() => window.location.href = '/login'}

                    className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"

                  >

                    Try Again  if (status === 'success') {const OAuthCallback: React.FC = () => {

                  </button>

                  <button    return <Navigate to="/dashboard" replace />;  const [searchParams] = useSearchParams();

                    onClick={() => window.location.href = '/'}

                    className="w-full py-2 px-4 border border-white/20 text-white rounded-lg hover:bg-white/5 transition-colors"  }  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');

                  >

                    Go Home  const [error, setError] = useState<string | null>(null);

                  </button>

                </div>  return (  const [userInfo, setUserInfo] = useState<any>(null);

              </>

            )}    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-indigo-900">

          </div>

        </div>      <div className="min-h-screen flex items-center justify-center px-4">  useEffect(() => {

      </div>

    </div>        <div className="bg-white/10 backdrop-blur-md rounded-2xl border border-white/20 shadow-2xl max-w-md w-full">    const handleCallback = async () => {

  );

};          <div className="p-8 text-center">      try {



export default OAuthCallback;            <div className="mb-6">        const code = searchParams.get('code');

              <Shield className="w-16 h-16 text-blue-400 mx-auto mb-4" />        const error = searchParams.get('error');

              <h1 className="text-2xl font-bold text-white mb-2">        const token = searchParams.get('token');

                {status === 'processing' && 'Connecting Gmail...'}

                {status === 'success' && 'Connection Successful!'}        if (error) {

                {status === 'error' && 'Connection Failed'}          setStatus('error');

              </h1>          switch (error) {

            </div>            case 'access_denied':

              setError('Access denied. Gmail permissions are required for phishing protection.');

            {status === 'processing' && (              break;

              <>            case 'invalid_request':

                <Loader className="w-8 h-8 text-blue-400 mx-auto mb-4 animate-spin" />              setError('Invalid authentication request.');

                <p className="text-white/80 mb-4">              break;

                  Please wait while we establish a secure connection to your Gmail account...            case 'temporarily_unavailable':

                </p>              setError('Google services temporarily unavailable. Please try again.');

                <div className="bg-white/5 rounded-lg p-4">              break;

                  <div className="flex items-center justify-center space-x-2 text-sm text-white/60">            case 'auth_failed':

                    <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>              setError('Authentication failed. Please try again.');

                    <span>Authenticating with Gmail</span>              break;

                  </div>            case 'token_generation_failed':

                </div>              setError('Failed to generate authentication token.');

              </>              break;

            )}            default:

              setError(`Authentication failed: ${error}`);

            {status === 'success' && (          }

              <>          return;

                <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />        }

                <p className="text-white/80 mb-4">

                  Your Gmail account has been successfully connected to PhishNet!        if (token) {

                </p>          // Store token and redirect to dashboard

                <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 mb-6">          localStorage.setItem('auth_token', token);

                  <p className="text-green-400 text-sm">          setStatus('success');

                    Redirecting to dashboard in {redirectCountdown} seconds...          setUserInfo({ email: 'Connected successfully' });

                  </p>          

                </div>          // Redirect to dashboard after a brief success message

                <button          setTimeout(() => {

                  onClick={() => window.location.href = '/dashboard'}            window.location.href = '/dashboard';

                  className="w-full py-2 px-4 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"          }, 2000);

                >          return;

                  Go to Dashboard Now        }

                </button>

              </>        if (!code) {

            )}          setStatus('error');

          setError('No authorization code received from Google.');

            {status === 'error' && (          return;

              <>        }

                <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />

                <p className="text-white/80 mb-4">        // If we have a code but no token, something went wrong

                  We encountered an issue while connecting your Gmail account.        setStatus('error');

                </p>        setError('Authentication completed but token generation failed.');

                {errorMessage && (        

                  <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 mb-6">      } catch (err: any) {

                    <p className="text-red-400 text-sm font-mono">        setStatus('error');

                      {errorMessage}        setError(err.message || 'Authentication failed. Please try again.');

                    </p>      }

                  </div>    };

                )}

                <div className="space-y-3">    handleCallback();

                  <button  }, [searchParams]);

                    onClick={() => window.location.href = '/login'}

                    className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"  if (status === 'success' && userInfo) {

                  >    return <Navigate to="/dashboard" replace />;

                    Try Again  }

                  </button>

                  <button  return (

                    onClick={() => window.location.href = '/'}    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center py-12 px-4">

                    className="w-full py-2 px-4 border border-white/20 text-white rounded-lg hover:bg-white/5 transition-colors"      <div className="max-w-md w-full">

                  >        <div className="bg-white/10 backdrop-blur-md rounded-2xl shadow-2xl border border-white/20 p-8 text-center">

                    Go Home          {/* Logo */}

                  </button>          <div className="mx-auto h-16 w-16 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center mb-6 shadow-lg">

                </div>            <Shield className="h-8 w-8 text-white" />

              </>          </div>

            )}

          </div>          {status === 'processing' && (

        </div>            <>

      </div>              <div className="mb-4">

    </div>                <Loader className="h-8 w-8 text-blue-400 animate-spin mx-auto mb-4" />

  );                <h2 className="text-2xl font-bold text-white mb-2">

};                  Setting up your protection...

                </h2>

export default OAuthCallback;                <p className="text-blue-200">
                  We're securely connecting your Gmail account for phishing analysis.
                </p>
              </div>
              <div className="space-y-2 text-sm text-blue-300">
                <div className="flex items-center justify-center space-x-2">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                  <span>Verifying Google authentication</span>
                </div>
                <div className="flex items-center justify-center space-x-2">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse delay-100"></div>
                  <span>Configuring email access permissions</span>
                </div>
                <div className="flex items-center justify-center space-x-2">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse delay-200"></div>
                  <span>Initializing threat detection</span>
                </div>
              </div>
            </>
          )}

          {status === 'success' && userInfo && (
            <>
              <CheckCircle className="h-12 w-12 text-green-400 mx-auto mb-4" />
              <h2 className="text-2xl font-bold text-white mb-2">
                Welcome to PhishNet!
              </h2>
              <p className="text-blue-200 mb-4">
                Your Gmail account has been successfully connected.
              </p>
              <div className="bg-white/5 rounded-lg p-4 mb-4">
                <p className="text-sm text-blue-300">
                  <strong>Protection Status:</strong> Active
                </p>
                <p className="text-sm text-blue-300">
                  <strong>AI Detection:</strong> Enabled
                </p>
              </div>
              <p className="text-xs text-blue-300">
                Redirecting to your dashboard...
              </p>
            </>
          )}

          {status === 'error' && (
            <>
              <AlertCircle className="h-12 w-12 text-red-400 mx-auto mb-4" />
              <h2 className="text-2xl font-bold text-white mb-2">
                Connection Failed
              </h2>
              <p className="text-red-300 mb-4">{error}</p>
              <div className="space-y-3">
                <button
                  onClick={() => window.location.href = '/login'}
                  className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                >
                  Try Again
                </button>
                <button
                  onClick={() => window.location.href = '/'}
                  className="w-full py-2 px-4 border border-white/20 text-white rounded-lg hover:bg-white/5 transition-colors"
                >
                  Go Home
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default OAuthCallback;