import React from 'react';
import LoginButton from './LoginButton';

export default function LoginPage() {
  return (
    <div style={{display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh'}}>
      <div style={{width: 420, padding: 24, background: '#fff', borderRadius: 12}}>
        <h1>PhishNet</h1>
        <p>Sign in with Google to continue</p>
        <LoginButton />
      </div>
    </div>
  );
}
