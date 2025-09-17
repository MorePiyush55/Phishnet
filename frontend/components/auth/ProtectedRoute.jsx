import React, { useEffect } from 'react';
import { useRouter } from 'next/router';
import useAuth from '../../hooks/useAuth';

export default function ProtectedRoute({ children }) {
  const router = useRouter();
  const { user } = useAuth() || {};

  useEffect(() => {
    if (user === null) {
      router.replace('/login');
    }
  }, [user]);

  if (!user) return <div>Redirecting to login...</div>;
  return <>{children}</>;
}
