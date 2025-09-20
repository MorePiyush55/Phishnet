import React, { useState } from 'react';

export default function LoginButton() {
  const [loading, setLoading] = useState(false);

  const handleClick = async () => {
    try {
      setLoading(true);
      // Redirect to backend OAuth initiation endpoint
      const backend = process.env.NEXT_PUBLIC_BACKEND_URL || 'https://phishnet-backend-iuoc.onrender.com';
      // small delay for UX
      setTimeout(() => {
        window.location.href = `${backend}/api/test/oauth/start`;
      }, 250);
    } finally {
      setLoading(false);
    }
  };

  return (
    <button onClick={handleClick} className="google-login-btn" disabled={loading}>
      {loading ? 'Connecting...' : 'Continue with Google'}
    </button>
  );
}
