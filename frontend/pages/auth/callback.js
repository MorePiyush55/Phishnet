import React, { useEffect } from 'react';
import { useRouter } from 'next/router';
import { setStoredUser, storeTokens } from '../../utils/auth';
import { fetchWithRetry } from '../../utils/auth';

export default function Callback() {
  const router = useRouter();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const error = params.get('error');

    async function exchange() {
      if (error) {
        console.error('OAuth error', error);
        router.replace('/login');
        return;
      }

      if (code) {
        try {
          const backend = process.env.NEXT_PUBLIC_BACKEND_URL || '';
          const resp = await fetchWithRetry(`${backend}/auth/google/callback?code=${encodeURIComponent(code)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
          }, 3, 500);
          if (resp.ok) {
            const data = await resp.json();
            storeTokens({ accessToken: data.accessToken, refreshToken: data.refreshToken });
            setStoredUser(data.user);
            router.replace('/dashboard');
          } else {
            console.error('Token exchange failed');
            router.replace('/login');
          }
        } catch (e) {
          console.error(e);
          router.replace('/login');
        }
      }
    }

    exchange();
  }, [router]);

  return <div>Handling sign-in...</div>;
}
