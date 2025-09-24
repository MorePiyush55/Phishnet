import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import { setStoredUser, storeTokens } from '../../utils/auth';

export default function Callback() {
  const router = useRouter();
  const [status, setStatus] = useState('Processing...');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const error = params.get('error');
    
    // Check for JWT tokens from OAuth redirect
    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');
    const userEmail = params.get('user_email');

    async function handleOAuthCallback() {
      if (error) {
        console.error('OAuth error', error);
        setStatus('OAuth authentication failed');
        setTimeout(() => router.replace('/login'), 2000);
        return;
      }

      // Handle JWT tokens from our OAuth redirect
      if (accessToken && refreshToken) {
        try {
          // Store the tokens
          storeTokens({ accessToken, refreshToken });
          
          // Create user object from the provided data
          if (userEmail) {
            const user = {
              email: userEmail,
              display_name: userEmail.split('@')[0],
              authenticated: true
            };
            setStoredUser(user);
          }
          
          setStatus('Authentication successful! Redirecting...');
          setTimeout(() => router.replace('/dashboard'), 1000);
          
        } catch (e) {
          console.error('Error storing authentication data:', e);
          setStatus('Failed to store authentication data');
          setTimeout(() => router.replace('/login'), 2000);
        }
      } else {
        // Fallback to old OAuth code flow
        const code = params.get('code');
        if (code) {
          await handleLegacyCodeFlow(code);
        } else {
          setStatus('No authentication data received');
          setTimeout(() => router.replace('/login'), 2000);
        }
      }
    }

    async function handleLegacyCodeFlow(code) {
      try {
        const backend = process.env.NEXT_PUBLIC_BACKEND_URL || '';
        const resp = await fetch(`${backend}/auth/google/callback?code=${encodeURIComponent(code)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });
        
        if (resp.ok) {
          const data = await resp.json();
          storeTokens({ accessToken: data.accessToken, refreshToken: data.refreshToken });
          setStoredUser(data.user);
          setStatus('Authentication successful! Redirecting...');
          setTimeout(() => router.replace('/dashboard'), 1000);
        } else {
          console.error('Token exchange failed');
          setStatus('Token exchange failed');
          setTimeout(() => router.replace('/login'), 2000);
        }
      } catch (e) {
        console.error(e);
        setStatus('Authentication error occurred');
        setTimeout(() => router.replace('/login'), 2000);
      }
    }

    handleOAuthCallback();
  }, [router]);

  return (
    <div style={{ 
      display: 'flex', 
      justifyContent: 'center', 
      alignItems: 'center', 
      height: '100vh',
      flexDirection: 'column'
    }}>
      <div>Handling sign-in...</div>
      <div style={{ marginTop: '10px', color: '#666' }}>{status}</div>
    </div>
  );
}
